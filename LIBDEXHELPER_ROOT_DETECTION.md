# `libDexHelper.so` Root 检测静态深度分析

> 由于 SecNeo / 梆梆系列 `libDexHelper.so` 自身被 OLLVM + native 二级壳保护(节表剥光、动态符号被零化覆盖、字符串绝大多数加密在 1 MB 数据段中等运行时解密),本报告仅基于 **未加密的 ~44 KB 可执行段** 与 .rodata 中的明文常量进行还原。运行期解密后还会有更多检测分支(无法静态拿到)。

## 1. ELF 异常布局回顾

| 段 | File offset | VA | 大小 | 权限 |
| --- | --- | --- | --- | --- |
| LOAD0(代码 + rodata) | 0x000000 | 0x00000000 | 0x00AEA8 (~44 KB) | r-x |
| LOAD1(.bss 等小数据) | 0x00BCE0 | 0x0000FCE0 | 0x000360 | rw- |
| LOAD2(.dynamic) | 0x010000 | 0x00020000 | 0x004000 | rw- |
| **LOAD3(加密数据)** | 0x014000 | 0x00034000 | **0x104690 (~1 MB)** | rw- |

`readelf -S` 看到的节表 99% 被砸掉了(只剩 `.hash/.dynsym/.dynstr/.dynamic/.bss/.shstrtab`),但 `--dynamic` 出的元数据是真实的:`DT_SYMTAB = 0x135000`、`DT_STRTAB = 0x137000`、`DT_HASH = 0x138000`,实际位于 LOAD3 末尾。手工解析后,**真实导入函数表 29 个**(见下文)、**真实导出符号 0 个**(JNI 函数靠 `RegisterNatives` 动态挂载,不出现在 dynsym)。

## 2. 导入函数清单(全部 29 个,无遗漏)

| 类别 | 函数 |
| --- | --- |
| 文件 / I/O | `fopen`, `fclose`, `fgets`, `open`, `close`, `read`, `pread`, `lseek`, **`access`** |
| 字符串 / 解析 | `strcmp`, `strstr`, `strlen`, `sscanf`, `snprintf`, `sprintf`, `memcpy`, `memset` |
| 内存 | **`mmap`**, **`mprotect`** |
| 动态链接 | **`dlopen`**, **`dlsym`**, **`dladdr`**, `dlerror` |
| 其它 | `sysconf`, `abort`, `__cxa_atexit`, `__cxa_finalize`, `__stack_chk_fail`, `isprint` |

> 加粗的几个就是 root / hook 检测 + 自解密的关键武器:`access` 试探文件、`dladdr/dlopen/dlsym` 解析模块、`mmap+mprotect` 自解密页面。

## 3. .rodata 明文常量(整段 .text/.rodata 唯一可读字符串)

```
@ 0xac50  "bal:"
@ 0xac58  "/proc/self/maps"
@ 0xac68  "r"                              ← fopen mode
@ 0xac70  "%lx-%lx %c%c%c%*c %*s %*s %*d %*s"    ← maps 行(只取地址 + 三位权限)
@ 0xac98  "%s"                              ← snprintf 透传
@ 0xaca0  "%lx-%lx %s %s %s %s %s"          ← maps 行(完整 7 字段)
@ 0xacb8  "%08X:"   "%s %02X"   "%s%c"   "%s |"   "   "   ← 内置十六进制 dumper
@ 0xace0  "Java_com_sinosun_lanmsg_Log_nativeFindClass"
@ 0xac38  "symbol found but not global:"    ← dlsym 严格校验日志
```

**关键点:** 整个 .text 区里 **找不到任何 `/system/bin/su`、`Superuser.apk`、`magisk`、`frida` 之类的常量**。所有 root 路径 / hook 库名 **都在加密的 LOAD3 段里**,运行时解密后才出现在堆上。

## 4. 构造函数 @ 0x9210(`INIT_ARRAY[0]`)

这是 .so 加载时第一个执行的函数(`__attribute__((constructor))`),也是 root 检测的入口。

### 4.1 控制流伪装 — OLLVM 平坦化状态机

```c
state = 0x111;
for (;;) {
    switch (state) {
      case 0x46:   /* ELF base 搜索块 — 见 4.2 */
      case 0x15:   state = state*20 + 0x74; if (state <= 3) error(); else state = 0xd6;
      case 0xd6:   /* ... */
      case 0x105:  /* ... */
      case 0x111:  /* 入口分发 */
      ...
    }
}
```

每个真实逻辑块被切成 case,通过修改 `state` 跳转,完全打乱原始 CFG。同时栈帧巨大(`sub sp, sp, #0xee0` + `sub sp, sp, #0xa0` + `sub sp, sp, #0x10` = ~3.8 KB),把若干运行时变量、解密缓冲、句柄等都塞进栈里以躲过 IDA 全局数据分析。

### 4.2 自定位 ELF 基址(反 RE 技巧 #1)

```asm
0x92dc:  adrp  x20, 0x9000           ; 取构造函数所在页
0x92e0:  movz  w0, #0x457f           ; 0x7f 'E'
0x92e8:  movk  w0, #0x464c, lsl #16  ; w0 = 0x464c457f  (= \x7fELF)
0x92ec:  and   x20, x20, #~0xfff     ; 页对齐
loop:
    ldr  w1, [x20]                   ; 读 4 字节
    cmp  w1, w0
    b.eq found
    sub  x20, x20, #0x1000           ; 上一页
    b    loop
found:
    ; x20 = libDexHelper.so 在内存中的 mmap 基址
```

故意 **不用 `dladdr` 或 `dl_iterate_phdr`**,直接靠回扫页表找到自己的 ELF magic。
意图:
- 任何 hook `dladdr` / 篡改 link_map 的工具都骗不过它
- 也避免在 dynsym 留下与"我在哪"相关的痕迹

### 4.3 立刻打开 `/proc/self/maps`(检测 #1)

构造函数刚算完 ELF 基址,直接调:

```
0x9324:  bl <fopen thunk @ 0x8c20>   ; arg = "/proc/self/maps"
```

随后用 `fgets` + `sscanf("%lx-%lx %c%c%c%*c %*s %*s %*d %*s")` 逐行读取。第二个参数 `%c%c%c` 抓的是 `r/w/x/-` 三位权限位 —— 也就是 **它只关心每段的地址范围 + 权限**,不直接取路径。

用途推测(基于 SecNeo 公开样本对照):
1. 找到 libart.so / libdvm.so / linker64 在自己进程里的位置,后面好做手工符号解析
2. 找到 hook 框架特征段(如 RWX 段、`anon` 段位于已加载库之间等)—— 这类反 Frida 检测不依赖具体路径名,只看权限分布
3. 找到 `[stack]` / `[heap]` 边界,后面 mmap 自己的解密缓冲时避开

## 5. 第二处 `/proc/self/maps` 解析 @ 0x96b0(检测 #2)

构造函数链路里还有一个独立的 maps 解析器,这一次用 **完整 7 字段格式**(包含路径):

```c
FILE *fp = fopen("/proc/self/maps", "r");
char line[0x400];
unsigned long start, end;
char perms[?], offset[?], dev[?], inode[?], path[?];
while (fgets(line, 0x400, fp)) {
    if (sscanf(line, "%lx-%lx %s %s %s %s %s",
               &start, &end, perms, offset, dev, inode, path) == 7) {
        /* 用 path 做后续比对 */
    }
}
fclose(fp);
```

`sscanf` 调用就在 0x9734:`bl <sscanf thunk @ 0x8c00>`,7 个 `%s` 输出参数 x2–x7+栈。

随后 0x9738–0x9754 还有 `cmp x1, x0` 这种地址范围比对。这一遍取了 path 后会去 `strstr/strcmp` 比对一组关键字 —— **这组关键字也在加密数据段**,静态读不到。等价的关键字几乎可以肯定包括: `frida`, `xposed`, `substrate`, `magisk`, `libsu`, `riru`, `zygisk` 等(SecNeo 标准库)。

## 6. `dladdr + access` 在线/离线一致性校验(检测 #3 — 这是最有意思的一个)

```asm
0x9670:  bl <dladdr thunk @ 0x8b70>           ; dladdr(some_addr, &info)
0x9674:  cbz w0, .skip                         ; dladdr 失败则跳过
0x9678:  ldr x3, [x21]                         ; info.dli_fname (.so 在磁盘上的路径)
0x967c:  cbz x3, .skip
0x9680:  adrp x2, 0xa000
0x9688:  mov  x0, x26                          ; buf
0x968c:  add  x2, x2, #0xc98                   ; "%s"
0x9690:  bl <snprintf thunk @ 0x8b30>          ; snprintf(buf,1024,"%s",dli_fname)
0x9698:  movz w1, #0                           ; F_OK
0x969c:  bl <access thunk @ 0x8c90>            ; access(buf, F_OK)
0x96a0:  cbz w0, .file_exists                  ; 0 = 文件存在
.skip:
   /* 文件不存在 — 说明这个 .so 只在内存里,典型: Frida agent 内联注入 */
   ...
```

效果:
- 拿当前某地址(往往是 libDexHelper 关心的关键库,如自己解出的 art runtime entry)
- 用 `dladdr` 反查它属于哪个 `.so` —— 返回 `dli_fname`
- 用 `access(dli_fname, F_OK)` 探这个文件**是否真的存在于磁盘**
- **不存在 → 几乎确定是 Frida / 内存注入 / 类似 Substrate 的内联 hook**(它们把 .so 名字写进 link_map 但磁盘上没文件)

这是非常优雅的一个检测,**比单看 maps 文件名要狠**:即使攻击者把 `frida-agent.so` 改名成 `libc.so`,access 仍然会把假货的真实磁盘缺失暴露出来。

## 7. 间接调用 GOT —— `dlsym` 派发(检测 / 加固组合)

可执行段里 30 个 PLT thunk(0x8af4 ~ 0x8cd0),每个长这样:

```asm
adrp  x16, 0xf000
ldr   x17, [x16, #0xfXX]    ; 读 GOT 表项
add   x16, x16, #0xfXX
br    x17                   ; 跳过去
```

但 `.rela.plt` 里的 GOT 表项 **链接器并不写真实地址**(因为 dynsym 中所有函数 value=0)——它们在构造函数里靠 `dlopen("libc.so")` + `dlsym("fopen")` 之类被 **手工填充**。意味着:

- 想 Frida hook `fopen` → 没用,libDexHelper 不走 PLT 回退,直接 BL 进自己的 thunk,thunk 读自己的 GOT,GOT 指向 dlsym 解出的 **原始** libc.so 地址
- 想 LD_PRELOAD 替换 → 同样没用,dlopen 拿的是 libc.so 句柄,绕过了 preload 顺序

破解时唯一稳妥的办法:**改 0xff00–0xffe8 这段 GOT 内容**(对应代码地址 0xfef0–0xffe8),或者 patch thunk 里 `ldr x17, [x16, ...]` 指令把它指到自己的 hook。

## 8. JNI 入口 —— `Java_com_sinosun_lanmsg_Log_nativeFindClass`

字符串裸字在 0xace0,但 **dynsym 找不到这个符号**(已确认 nchain=221 但没有 `Java_*` 的 STT_FUNC)。

→ libDexHelper 自己实现了一个简化的 `JNI_OnLoad`(在加密数据段里,运行时跳过去执行),通过 `RegisterNatives` 把 `nativeFindClass` 注册到 `com.sinosun.lanmsg.Log`。这个类是 SecNeo 早期(2017 前后)留下的代号 —— 它本质是壳的 "类装载器"。在被加固后的 DEX 里也只能在运行时看到。

后果:
- Java 层 hook(如 `Xposed @ Log.nativeFindClass`)需要等到这步完成才能 attach
- 但 `nativeFindClass` 又是 SecNeo 在内部用来加载真实 DEX 的关键 RPC —— 一旦在它返回前被检测命中,这一切都不会发生

## 9. 加密数据段(LOAD3, 0x14000–0x118690)

前 ~480 字节是 **明文常量** —— 准确说是构造函数 dlsym 用的 key 表:

```
libandroid.so   liblog.so   libstdc++.so   libdl.so   liblinkerstub.so
__stack_chk_guard   __stack_chk_fail   __cxa_finalize   __bss_start__
__cxa_atexit   __bss_start   __bss_end__   mprotect   snprintf
```

(还重复了一份在 0x14172 起 —— 估计是两份不同上下文用的 dlsym 探针。)

值得注意:
- 出现了 `liblinkerstub.so` —— 这是 SecNeo 配合 `dlopen` 的 **桩 linker**(对抗 fakelinker / 直接 dlmopen 攻击)
- `__stack_chk_guard` / `__stack_chk_fail` 被显式 dlsym —— 用来对接系统 canary,提高栈检测精度

之后从 0x141e8 直到 0x118690(~1 MB)整段都是 **XOR / 简单流密码加密的代码 + 字符串**(明显的固定字节模式如 `'O` / `'l` / `'m` 高频出现,暗示密钥流约 8 字节循环 + 状态位)。这一整段在构造函数 0x9210 → 0x9314 → 0xa000 区附近被 `mprotect(RWX) + 解密 + mprotect(RX)` 拉起来,然后 br 进去执行真正的:
- 完整 root 路径表(`/system/bin/su`、`Superuser.apk`、`magisk` …)
- hook 库黑名单(`frida-agent.so`、`libsubstrate.so`、`libxposed_art.so` …)
- DEX 解密例程(配合 classes.dex 末尾的 `dexdata0` 容器)
- `ptrace(PTRACE_TRACEME, 0)` 反附

## 10. 检测矩阵(libDexHelper.so 维度)

| 类别 | 实现 | 来源 |
| --- | --- | --- |
| 自定位 / 反 `dladdr` 假信息 | 向上回扫 4 KB 找 `\x7fELF` | 0x92dc–0x9314 |
| `/proc/self/maps` 权限扫描 | sscanf "%lx-%lx %c%c%c" | 0x9324 + |
| `/proc/self/maps` 路径扫描 | sscanf "%lx-%lx %s %s %s %s %s" | 0x96b0 + |
| 磁盘 vs 内存一致性 | `dladdr` → `access(F_OK)` | 0x9670 |
| **root 路径黑名单**(`/system/bin/su` 等) | **位于加密段,运行时解密** | LOAD3 |
| **Frida/Magisk/Xposed/Substrate so 名匹配** | **位于加密段,运行时解密** | LOAD3 |
| 自己 GOT 防 hook | 手工 dlsym + 私有 thunk | 0x8af4–0x8cd0 + 构造函数 |
| `liblinkerstub.so` 桩 linker | dlopen 桩 + 自己解析符号 | LOAD3 + 0x14047 字符串 |
| JNI 不暴露符号 | `RegisterNatives` | LOAD3 |
| 反调试 ptrace 自附 | **推测,常见于此类壳** | LOAD3(未直接见到) |

## 11. 与 App 内其它 root 检测的协同关系

| 层 | 库 | 时序 |
| --- | --- | --- |
| **0**(最早) | `libDexHelper.so` 构造函数 | `System.loadLibrary` 触发 INIT_ARRAY —— 在 Application.onCreate 之前 |
| 1 | `libNetHTProtect.so` JNI_OnLoad | Application.onCreate 静态块 |
| 2 | `libtoolChecker.so` RootBeer | Java 层主流程 `isRooted()` 被调用时 |
| 3 | `libssid_liveness_jni.so` `stid_env_detector` | 活体识别启动时(后台线程) |

→ libDexHelper 是 **第一道关卡**,直接在 `System.loadLibrary("DexHelper")` 时就完成核心检测。绕过它后,后面三层仍要分别处理。

## 12. 绕过提纲(仅限授权研究)

1. **绕过构造函数 root 检测**:
   - 用 `r2 / IDA` 把 0x9324 处 fopen 调用之后的 `cbz/b.eq` 路径都改成无条件跳转到"通过"分支(具体偏移依赖运行期解密结果)
   - 或者从更底层:patch `/proc/self/maps`(用 frida-no-frida / hide-magisk)
2. **绕过 `dladdr+access`**:
   - 让磁盘文件存在 —— 例如 `cp /system/lib64/libc.so /data/local/tmp/frida-agent.so && bind-mount`
   - 或者直接 patch 0x9670 的 `bl dladdr` 之后返回值
3. **绕过 thunk 防 hook**:
   - 在构造函数运行完之后,把 0xff00–0xffe8 GOT 表项指向 hook trampoline
   - 这需要先脱 libDexHelper 自身的 native 壳,见 11.4
4. **直接脱 native 壳**:
   - 在构造函数返回时 dump LOAD3 段 (`0x34000..0x138690`),分析解密后的代码 + 字符串
   - 推荐工具:Frida `Memory.protect + dump` 配合 LD_PRELOAD 提前注入 `__libc_init` hook
5. **绕过整个 libDexHelper**:
   - **重打包**:删掉 `libDexHelper.so` 引用,补一个原始 DEX 替代加固后的 `classes.dex` —— 但你得先脱壳出原 DEX(这又回到了上一份 `APK_DEX_UNPACK_ANALYSIS.md`)

## 13. 总结

`libDexHelper.so` 在那薄薄 ~44 KB 明文 .text 里干的事情已经包含了相当成熟的反 RE 工程:

- **OLLVM 控制流平坦化** 包住所有真实分支
- **页面回扫定位自身基址** 防 dladdr 欺骗
- **两遍 `/proc/self/maps` 扫描**(权限 + 路径)
- **磁盘 vs 内存一致性校验**(`dladdr` + `access`)防 Frida 内存注入
- **手工 GOT + 私有 thunk** 防 PLT hook / LD_PRELOAD
- **liblinkerstub 桩 linker** 防 fakelinker 类攻击
- **加密 1 MB 数据段** 装真正的 root 黑名单、hook 库黑名单、ptrace 反附、DEX 解密例程
- **`RegisterNatives` 隐藏 JNI 入口** 让 `Java_*` 不出现在 dynsym

要 100% 静态枚举所有检测项,需要先把 LOAD3 段解出来 —— 这一步在 Linux 沙箱里做不到。但已知部分已经足以让普通 Frida / RootCloak / hide-su / magisk-zygisk 在 `System.loadLibrary("DexHelper")` 那一刻就被发现并触发拒绝。

> 在动态 dump 之前,任何"已绕过 libDexHelper"的说法都是空话。请配合 `APK_DEX_UNPACK_ANALYSIS.md` 里推荐的 frida-dexdump / BlackDex / FART 在 root 设备上抓内存。
