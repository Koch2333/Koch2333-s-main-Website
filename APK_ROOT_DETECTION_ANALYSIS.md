# APK Root 检测行为分析

## 样本基本信息

| 项 | 值 |
| --- | --- |
| Package | `com.zhongan.ibank`(众安银行) |
| versionName | 3.9.15 |
| versionCode | 1031431 |
| minSdk / target | 24 / 35 |

> Java 主代码被 SecNeo 加固加密(详见 `APK_DEX_UNPACK_ANALYSIS.md`),**Java 层 root 检测逻辑无法在不脱壳的情况下读取**。本报告基于 native 层(.so)静态分析。

## Native 层检测组件总览

App 在 native 层至少叠加了 **4 套独立的 root / 环境检测**:

| Native 库 | 来源 | 作用 |
| --- | --- | --- |
| `libtoolChecker.so` (5.5 KB) | 开源 [scottyab/rootbeer](https://github.com/scottyab/rootbeer) | 通用 root 检测(通过 JNI 暴露给 Java) |
| `libssid_liveness_jni.so` (10 MB) | SenseTime SenseID Liveness SDK | `stid_env_detector` 框架:root + Frida + Xposed |
| `libssid_spark_jni.so` (858 KB) | SenseTime SenseID Spark SDK | 备份的 su 路径列表(同源) |
| `libNetHTProtect.so` (4.6 MB) | 自研(符号被混淆为 `oOOO00Oo...`) | ptrace 反调试 + `/proc/self/maps` 自检 + `linker64/app_process64` 完整性 |
| `libhtpcrash.so` / `libhtpcrash_dumper.so` | 自研 crash handler | ptrace 事件监听(反附加) |

---

## 1. RootBeer(`libtoolChecker.so`)

JNI 导出函数(对外完全公开):

```
Java_com_scottyab_rootbeer_RootBeerNative_setLogDebugMessages
Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot
```

`checkForRoot(String[] paths)` 反汇编还原 C 伪码:

```c
jint Java_..._checkForRoot(JNIEnv *env, jobject thiz, jobjectArray paths) {
    int n = (*env)->GetArrayLength(env, paths);
    int found = 0;
    for (int i = 0; i < n; i++) {
        jstring js = (*env)->GetObjectArrayElement(env, paths, i);
        const char *cpath = (*env)->GetStringUTFChars(env, js, NULL);
        FILE *fp = fopen(cpath, "r");
        if (fp) {
            fclose(fp);
            found++;
            __android_log_print(4, "RootBeer", "LOOKING FOR BINARY: %s PRESENT!!!", cpath);
        } else {
            __android_log_print(4, "RootBeer", "LOOKING FOR BINARY: %s Absent :(", cpath);
        }
    }
    return found > 0 ? 1 : 0;
}
```

native 侧仅做"二进制存在性"检测,**实际待检路径列表来自 Java 层**(被加固),按 RootBeer 上游默认值即:

```
/system/app/Superuser.apk  /sbin/su  /system/bin/su  /system/xbin/su
/data/local/xbin/su  /data/local/bin/su  /system/sd/xbin/su
/system/bin/failsafe/su  /data/local/su  /su/bin/su  /su/bin
/system/etc/init.d/99SuperSUDaemon  /dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu
```

加上 RootBeer Java 层的 `BINARIES`:`su / busybox / supersu / Superuser.apk / KingoUser.apk / SuperSu.apk / magisk`。

---

## 2. SenseTime `stid_env_detector`(`libssid_liveness_jni.so`)

在 SenseTime 活体检测 SDK 内部嵌了一套独立的环境检测框架:`stid_env_detector::EnvExceptionDetector`(单例,后台线程持续巡检)。

关键导出符号:

```
env_exception_detect_android_root      ← root 检测
env_exception_detect_frida             ← Frida 检测
env_exception_detect_xposed            ← Xposed 检测
set_frida_detect_libraries             ← 设置 Frida 库黑名单
register_env_exception_callback        ← 向 Java 注册回调
get_env_exception_type                 ← 查询触发的异常类型
disable_env_exception                  ← Java 配置开关
```

类层次:

```
stid_env_detector::EnvExceptionDetector::Instance()
stid_env_detector::EnvExceptionDetector::RunDetectThread(map<exception_t, function<bool(bool*)>>)
stid_env_detector::EnvExceptionDetector::RegisterEnvExceptionCallback(...)
stid_env_detector::EnvExceptionDetector::GetEnvExceptionType()
kspark::liveness::details::LivenessImpl::ProcEnvExceptionCallback(stid_env_exception_t)
```

→ `RunDetectThread` 在独立线程里轮询每种检测函数,命中后通过回调把 `stid_env_exception_t` 枚举(ROOT / FRIDA / XPOSED)抛给 `LivenessImpl::ProcEnvExceptionCallback`,最终回到 Java 触发活体识别失败。

### 2.1 root 路径列表(从 .rodata 提取的明文字符串)

```
/data/local/bin/su
/data/local/su
/data/local/xbin/su
/sbin/su
/su/bin/su
/system/app/Superuser.apk
/system/bin/failsafe/su
/system/bin/su
/system/priv-app/Superuser.apk
/system/sbin/su
/system/sd/xbin/su
/system/xbin/su
/vendor/bin/su
```

> 比 RootBeer 默认列表多了 `/system/sbin/su`、`/system/priv-app/Superuser.apk`、`/vendor/bin/su` —— 覆盖了 Magisk 早期的 `/sbin` 重定向 和 vendor 分区方案。

### 2.2 Xposed 检测

- 函数:`is_xposed_maps(procmaps_iterator*)`
- 实现:遍历 `/proc/self/maps`,匹配 Xposed 框架特征模块(典型为 `XposedBridge.jar`、`/system/framework/XposedBridge.jar`、`de.robv.android.xposed`)
- 有 `pmparser_*` 系列函数(`pmparser_parse / pmparser_next / pmparser_free / pmparser_print`),即 [pmparser](https://github.com/ouadev/proc_maps_parser) 公共解析库

### 2.3 Frida 检测

- `set_frida_detect_libraries`:Java 层可下发待匹配的 .so 名单(常见 `frida-agent`、`gum-js-loop`、`gmain`、`linjector`)
- 检测点结合 `/proc/self/maps`、`/proc/self/task/*/status`(对线程名做匹配)、`/proc/self/fd`(检查 unix socket)

### 2.4 调试器/沙箱辅助检测

附带的字符串显示该模块还会读:

```
/proc/%d/cmdline      /proc/%d/maps      /proc/%u/maps
/proc/self/cmdline    /proc/self/fd      /proc/self/fd/%d
/proc/self/maps       /proc/self/task    /proc/self/task/%s/status
ro.product.board   ro.product.model   ro.product.name
```

→ 通过 `getprop` 读机型字段判断是否为模拟器(典型黑名单:`generic / sdk / google_sdk / unknown`),这是 SenseTime 防活体伪造的标准做法。

---

## 3. `libssid_spark_jni.so`

更短的 su 路径列表(同 SenseTime SDK 系列):

```
/data/local/bin/su   /data/local/su   /data/local/xbin/su
/su/bin/su   /system/app/Superuser.apk   /system/bin/failsafe/su
/system/bin/su   /system/priv-app/Superuser.apk   /system/sbin/su
/system/sd/xbin/su   /system/xbin/su   /vendor/bin/su
```

属于 SenseTime SenseID Spark(KSpark)子组件的备份检测,在不加载完整活体 SDK 时也能独立校验。

---

## 4. `libNetHTProtect.so`(自研 RASP)

| 特征 | 值 |
| --- | --- |
| 大小 | 4.6 MB |
| 导出名 | 全部混淆为 `oOOO00Oo / OoOoOo0o0...` 风格 |
| 入口 | 标准 `JNI_OnLoad`,Java 层动态绑定 |
| 关键字符串 | `/proc/self/maps`、`/system/bin/app_process64`、`/system/bin/linker64`、`/system/bin/sh`、`ptrace`、`Friday`、`mounted` |

行为推断:

1. **`linker64` / `app_process64` / `sh` 文件指纹/ inode 校验**:对比设备上的关键二进制是否被替换(典型对抗 Magisk 模块 / Riru / Zygisk 注入)
2. **`/proc/self/maps` 异常段扫描**:查可疑 .so(magisk、frida、substrate 等)
3. **`mounted` 字符串**:检查是否存在 RW 挂载的 `/system`(检 `/proc/self/mounts` 中 `/system` 的挂载选项)
4. **`ptrace`**:`ptrace(PTRACE_TRACEME, 0)` 自防附,失败即认定被 gdb/jdb 调试
5. **`Friday`**:疑似产品代号(蚂蚁集团 Friday 风控?或自研 RASP 内部代号)

> 由于符号被随机化、且很可能配合 OLLVM 控制流平坦化,完整还原需 IDA + 人工动态调试。

---

## 5. `libhtpcrash.so` 系列

| 字符串 | 含义 |
| --- | --- |
| `PTRACE_EVENT_CLONE/FORK/EXEC/EXIT/STOP/SECCOMP/VFORK[_DONE]` | 注册成 `tracer` 监听子进程事件 |
| `THREAD: ptrace GETREGSET failed` | 内部错误日志 |
| `/system/bin/logcat -b %s -d -v threadtime -t %u %s*:%c` | 崩溃时收集 logcat 用作上报 |

→ 所谓 "crash handler",但同时充当 **anti-debug**:通过 `ptrace(PTRACE_ATTACH)` 抢先 attach 自身,使外部 gdb / frida 无法再次 attach(经典 "self-ptrace" 防附加)。

---

## 综合检测矩阵

| 检测项 | RootBeer (Java 主控) | SenseTime EnvDetector | NetHTProtect |
| --- | --- | --- | --- |
| su 二进制 | ✅ | ✅(13 路径) | ✅(完整性) |
| Superuser/SuperSU APK | ✅ | ✅(`/system/app` + `/system/priv-app`) | — |
| Magisk 关键字 | ✅(Java 层) | ⚠️ 间接(走 maps) | ✅(maps) |
| BusyBox | ✅ | — | — |
| `ro.build.tags=test-keys` | ✅(Java 层) | — | — |
| `ro.debuggable / ro.secure` | ✅(Java 层) | — | — |
| `/system` 可写挂载 | ✅(Java 层) | — | ✅ |
| Xposed | ⚠️(Java 层有) | ✅(`is_xposed_maps`) | — |
| Frida | — | ✅(可配置库名) | ✅(maps) |
| ptrace 反调试 | — | — | ✅(主) + `libhtpcrash` |
| 模拟器 | ⚠️(Java 层) | ✅(`ro.product.*`) | — |
| linker64/app_process 篡改 | — | — | ✅ |

---

## 绕过思路(仅供逆向研究)

1. **绕 RootBeer**:hook `Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot` 直接 `return 0`;Java 层多个 `RootBeer.isRooted*()` 也要一并 patch(命名固定,容易写脚本)
2. **绕 stid_env_detector**:
   - 不卸载 frida 时:把 `set_frida_detect_libraries` 的下发列表清空,或 hook `EnvExceptionDetector::Instance().GetEnvExceptionType` 永远返回 0
   - 更稳:hook `LivenessImpl::ProcEnvExceptionCallback`,丢弃所有事件
3. **绕 NetHTProtect**:符号被混淆,但 `JNI_OnLoad` 注册的 native 方法名固定;通过 `RegisterNatives` hook 拦截 → 全部 stub 化即可
4. **绕 ptrace 自附**:Magisk + LSPosed `riru-momohook` 或 frida-stalker 早 attach;或者直接 patch `.so` 中调用 `ptrace` 的指令为 `mov x0, #0; ret`
5. **完整脱壳后**:再覆盖一遍 Java 层的 `RootBeer.isRooted()` / `EmulatorDetector` 等高层调用链

> 上述操作仅适用于**作者授权的逆向 / 安全研究 / CTF**。该 APK 是金融银行类产品,在生产环境中绕过其完整性检测会直接违反 App 用户协议、相关法律法规(《刑法》285、286 条)。

## 建议下一步(动态侧)

1. 用 frida-dexdump / BlackDex 把 SecNeo 壳脱掉,读 Java 层完整 root 检测策略(预期能看到 `RootBeer` 实例化、`isRooted()` / `isRootedWithoutBusyBoxCheck()` 调用、`detectTestKeys()`、`checkForBinary()`、`detectRootManagementApps()` 等标准方法)
2. 用 `frida-trace -i 'env_exception_detect_*'` 跟踪 `stid_env_detector` 的命中点
3. 用 `objection` 的 `android root disable` 命令快速验证哪些路径走的是 RootBeer / SenseTime / NetHTProtect
