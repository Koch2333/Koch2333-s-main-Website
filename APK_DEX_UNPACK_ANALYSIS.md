# APK DEX 加固脱壳分析报告

## 样本

- 来源:7 个分卷压缩包(`za.z01`–`za.z06` + `za.zip`,共 ~177 MB)
- 解压后:`android.apk`,大小 180,125,407 字节(~172 MB)

## 加固识别

**结论:SecNeo(爱加密)企业级加固**

| 证据 | 内容 |
| --- | --- |
| 桩 DEX 首类 | `Lcom/secneo/apkwrapper/AP;`(继承 `android.app.AppComponentFactory`) |
| Native 解密库 | `lib/arm64-v8a/libDexHelper.so`(1,152,266 字节)+ `libDexHelper-x86.so` |
| 私有容器标识 | `dexdata0`(SecNeo DEX 包装器签名) |
| 字符串 `secneo` | 出现于 `classes.dex` @ `0x1B77` |

## `classes.dex` 容器结构

文件总长 `130,919,220` 字节,DEX header 字段:

| 字段 | 值 |
| --- | --- |
| magic | `dex\n037\0` |
| file_size | `130,919,220` (假声明=整个文件) |
| header_size | `0x70` (112) |
| map_off | `0x5A44` (23,108) ← **真实 stub DEX 终止位置** |
| string_ids_size | 356 |

布局:

```
0x00000000  [桩 DEX 23,108 字节]   ← 包含 com.secneo.apkwrapper.AP 等壳类
0x00005A44  [字段重建表 220 字节]  ← 17 项 (key, value),记录原始 DEX 的偏移/大小
0x00005B20  [容器头 32 字节]
              14 50 CD 07           ← 总长 0x07CD5014 (130,891,796)
              08 00 00 00           ← 名称长度 8
              "dexdata0"            ← SecNeo 容器名
              00 50 CD 07           ← 负载长 0x07CD5000 (130,891,776)
0x00005B30  [AES 加密的真实 DEX]   ← 130 MB,熵 7.9972 bits/byte
EOF
```

## 加密强度评估

| 指标 | 结果 |
| --- | --- |
| 数据熵 | 7.9972 bits/byte(~随机) |
| 单字节 XOR | 不通过 |
| 重复 8 / 16 字节 keystream | 不通过(已知明文检验冲突) |
| zlib / gzip | 不通过 |

→ 标准 AES(分组模式 CBC 或 CTR),密钥在运行时派生。

## `libDexHelper.so` 状况

| 检查 | 结果 |
| --- | --- |
| ELF 类型 | aarch64 little-endian |
| 节表(Section Headers) | 仅剩 `.hash / .dynsym / .dynstr / .dynamic / .bss / .shstrtab`,**其余被剥** |
| 动态符号表 | 38+ 项全部清零(`STT_NOTYPE @ 0x0`) |
| 可执行段 | 仅 `0x0–0xAEA8`(~44 KB),含初始化 stub |
| RW 数据段 | `0x14000–0x118690`(~1 MB),**Native 二级加密 payload**,运行时自解密 |
| AES SBOX / RCON | 静态搜索 **未命中** |
| 可读字符串 | 仅 `libDexHelper.so` 字面量,无任何 API/路径 |

→ Native 层本身用 SecNeo 的 native 壳保护过。即便耗时还原 AES 例程,密钥也依赖运行期派生(常见因子:APK 签名 SHA1、包名、UID、设备特征)。

## 静态脱壳为何不可行

1. AES 真实密钥不在文件里,需 `JNI_OnLoad` 触发后从 ART/系统调用上下文动态拼接
2. `libDexHelper.so` 的解密例程本身被加壳,需先脱 native 壳
3. 即便完成上述两步,SecNeo 还可能做指令级 VMP / 反调试 / 完整性校验

## 推荐脱壳路径(动态)

| 工具 | 适用场景 | 说明 |
| --- | --- | --- |
| **frida-dexdump** | Root 设备 / 模拟器 | `frida-dexdump -U -f <pkg>`,扫 ART 加载内存中的 `dex\n035/037/038/039` 头 |
| **BlackDex** | Android 8–13,**免 root** | App 形式,解析自身进程的 maps 抓 DEX |
| **FART / Youpk** | 定制 ROM | 主动调用每个方法,触发懒加载,适合 SecNeo / 360 / 梆梆 |
| **Magisk + LSPosed + dumpdex 模块** | Root 框架 | 钩 `OpenMemory / dvmDexFileOpenPartial` |

脱壳后预期得到若干 `classes*.dex`(原始 APK 通常 multi-dex),在 jadx-gui / JEB 中即可阅读 Java 代码。

## 在本沙箱中已留存的产物(临时目录 `/tmp/apk_work/`)

| 文件 | 用途 |
| --- | --- |
| `android.apk` | 已解出的完整 APK |
| `apk_extract/classes.dex` | 130 MB 加固后 DEX |
| `apk_extract/lib/arm64-v8a/libDexHelper.so` | Native 解密库,供后续逆向 |
| `stub.dex` | 前 23,108 字节,可被 jadx 直接打开看 stub 类 |
| `extra.bin` | DEX 偏移 23,108 之后的容器(220 B 元数据 + 32 B 头 + 加密负载) |

> 沙箱重启会丢失,需要的话另行打包导出。
