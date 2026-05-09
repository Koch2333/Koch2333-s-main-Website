# CTF 静态分析报告 — `start.exe` kernel32 磁盘类型检测

## 文件基本信息

| 字段 | 值 |
|------|-----|
| 文件名 | `f37044cb-start.exe` |
| 格式 | PE32 / x86 (GUI) |
| ImageBase | `0x00400000` |
| EntryPoint | `0x0002AAC6` (VA `0x0042AAC6`) |
| PDB 路径 | `\disk2017\src\disk\Release\bookplayer.pdb` |
| 关键导入 | `KERNEL32!GetDriveTypeW`、`KERNEL32!GetModuleFileNameW`、`KERNEL32!CopyFileW` |

---

## 保护机制概述

程序是一个"bookplayer"（有声书/音乐播放器），附带**光盘驱动器检测**保护：
若可执行文件不在光驱（CD-ROM）盘符下运行，则执行额外的注册/许可证校验，校验失败则返回错误码 `0xFFFFFD89A` 并退出。

---

## 调用链

```
0x00401986  main_validate()
  └─ 0x004019A3  call  outer_check()          @ 0x00409EB8
                 test al, al
                 jne  0x4019B6               ; al==0 → 返回错误
  └─ 0x004019AC  eax = 0xFFFFFD89A → exit   ; ← 保护失败路径
```

---

## 核心函数逐一分析

### 1. `is_cdrom_drive()` — `0x00409CB5`

```asm
0x409CEC   push 0x1FA0                    ; nSize = 8096
0x409CED   push esi                       ; lpFilename = buf
0x409CEE   push 0                         ; hModule = NULL (当前进程)
0x409CF0   call [GetModuleFileNameW]      ; 获取 exe 完整路径，如 "D:\game\start.exe"

0x409CFF   push 3                         ; 取前 3 个字符
0x409D01   lea  eax, [ebp-0x14]
0x409D04   push eax                       ; 输出缓冲区
0x409D05   lea  ecx, [ebp-0x10]
0x409D08   call 0x405E8D                  ; string.substr(0,3) → "D:\"

0x409D10   push esi                       ; lpRootPathName = "D:\"
0x409D11   call [GetDriveTypeW]           ; ← 关键调用
           ; 返回值含义：
           ;   2 = DRIVE_REMOVABLE (U 盘)
           ;   3 = DRIVE_FIXED     (本地硬盘)
           ;   4 = DRIVE_REMOTE    (网络盘)
           ;   5 = DRIVE_CDROM     (光盘)  ← 目标值
           ;   6 = DRIVE_RAMDISK

0x409D17   cmp  eax, 5                    ; 是否为光盘？
0x409D1A   lea  ecx, [esi-0x10]
0x409D1D   sete bl                        ; bl = (eax==5) ? 1 : 0
           ; ...
0x409D30   mov  al, bl
0x409D32   ret                            ; 返回：1=光盘，0=非光盘
```

**结论**：该函数通过 `GetModuleFileNameW` 获取 exe 所在盘符，再调用 `GetDriveTypeW` 判断是否为 CD-ROM（类型 5）。

---

### 2. `outer_check()` — `0x00409EB8`（整体校验逻辑）

```asm
0x409EC4   lea  eax, [ebp-0x29]           ; 驱动器路径 buffer
0x409ECB   call 0x4263F0                  ; 获取配置信息（可能读注册表）

0x409ED8   push 0x4BCF6C                  ; L"true"
0x409EDD   push [ebp-0x3C]               ; 配置值
0x409EE0   call 0x42A3B8                  ; 字符串比较
0x409EE8   test eax, eax
0x409EEA   je   0x409FA0                  ; 配置不为"true" → 直接成功（旁路！）

0x409EF0   call 0x409CB5                  ; is_cdrom_drive()
0x409EF5   test al, al
0x409EF7   jne  0x409FA0                  ; IS 光盘 → 跳至成功路径

; ─── 以下为"硬盘运行"时的许可证校验 ───────────────────────────────
0x409F0D   call 0x409D38                  ; enumerate_drives()：从命令行参数获取驱动器列表
           ; 循环遍历每个驱动器：
0x409F28   call 0x409FF3                  ; process_drive_path()
0x409F6D   call 0x409DA5                  ; check_license_content()
0x409F78   test al, al
0x409F7A   jne  0x409F8F                  ; 通过 → 成功

0x409FA0:  mov  bl, 1                     ; ← 成功路径
           ; ...
0x409FAD   mov  al, bl
           ret                            ; 返回 1 = 通过
```

---

### 3. `check_license_content()` — `0x00409DA5`（许可证文件解析）

```asm
0x409DC6   call 0x409800                  ; read_disk_content()：读取并 Base64 解码磁盘文件
0x409DCB   test al, al
0x409DCD   je   0x409EA4                  ; 读取失败 → 退出

; 解码后的数据结构校验：
0x409E30   mov  edi, 0x4BE200             ; L"expired"
0x409E44   cmp  [eax], esi               ; 检查内容哈希/索引 ≠ expired 标记
0x409E46   je   0x409E87                  ; 已过期 → 失败

0x409E51   mov  al, [eax+0x0E]
0x409E54   shr  al, 7
0x409E57   test al, 1                     ; 检查许可标志位（bit 7 of byte[0x0E]）
0x409E59   je   0x409E87                  ; 未设置 → 失败

0x409E6E   push 0x989680                  ; 10,000,000 字节 (约10MB)
0x409E7B   cmp  edx, esi                  ; 检查文件大小 < 10 MB
0x409E7D   jg   0x409E87                  ; 超过 → 失败
```

---

### 4. `base64_decode_char()` — `0x004099AA`（标准 Base64 字母表查表）

```asm
; A-Z → 0-25   (cl-0x41)
; a-z → 26-51  (cl-0x47)
; 0-9 → 52-61  (cl+4)
; '+'  → 62
; '/'  → 63
; 其他 → 0xFF  (无效字符)
```

`0x409800` 实现标准 Base64 解码，处理 `=` 填充，将磁盘文件内容解码后做许可证校验。

---

## Flash OCX 安装逻辑（附带功能）

程序还通过 `CopyFileW` 自动安装 Flash OCX，调试日志字符串可见：
- `L"flash ocx src=%s\n"` — 源路径
- `L"flash ocx dst=%s\n"` — 目标路径
- `L"flash ocx copy status=%s, errorCode=%u\n"` — 复制结果

---

## Patch 方案

### 方案 A（推荐）— 让 `is_cdrom_drive()` 始终返回 1

| 字段 | 值 |
|------|----|
| VA | `0x00409D1D` |
| 文件偏移 | `0x0911D` |
| 原始字节 | `0F 94 C3` (`sete bl`) |
| 补丁字节 | `B3 01 90` (`mov bl, 1 ; nop`) |

**效果**：无论驱动器类型如何，函数一律返回"是光盘"，`outer_check()` 跳至成功路径。

### 方案 B（配合 A 双重保险）— 强制跳过硬盘校验分支

| 字段 | 值 |
|------|----|
| VA | `0x00409EF7` |
| 文件偏移 | `0x092F7` |
| 原始字节 | `0F 85 A3 00 00 00` (`jne 0x409FA0`) |
| 补丁字节 | `0F 89 A3 00 00 00` (`jns 0x409FA0`) |

**效果**：`test al, al` 后 SF 始终为 0（al < 0x80），`jns` 无条件跳转至成功路径，完全跳过命令行驱动器枚举和许可证验证。

### 二进制差异摘要

```
偏移 0x0911D: 0F 94 C3 → B3 01 90   (sete bl → mov bl,1 + nop)
偏移 0x092F8: 85       → 89         (jne → jns, 1字节改动)
```

---

## 保护逻辑总结图

```
outer_check()
│
├─ [配置是否包含 "true"？]
│   └─ 否 ──────────────────────────────→ 返回 1（成功，直接通过）
│
├─ is_cdrom_drive()
│   GetModuleFileNameW → 取前3字符 → GetDriveTypeW → cmp eax,5
│   └─ 是光盘(==5) ─────────────────────→ 返回 1（成功，光盘保护通过）
│
└─ [命令行参数中枚举驱动器]
    └─ 对每个驱动器：
        读取文件 → Base64解码 → 检查 "expired" / 标志位 / 大小
        └─ 校验通过 ────────────────────→ 返回 1（成功）
    └─ 全部失败 ────────────────────────→ 返回 0（失败 → 错误码 0xFFFFFD89A）

Patch A 攻击点: sete bl → mov bl,1    (VA 0x409D1D)
Patch B 攻击点: jne → jns             (VA 0x409EF7)
```
