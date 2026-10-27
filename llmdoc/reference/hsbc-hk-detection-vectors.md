# 汇丰香港越狱检测向量

## 目的

本文档汇总汇丰香港 App 已查明的检测组件、退出机制排查结论与当前进度。
**状态：排查中，没有可用版本。死因已确认为主动 `exit(1)`，但退出路径未定位。**

## 目标与背景

- 目标 App：`hk.com.hsbc.hsbchkmobilebanking`
- 当前版本：**`3.69.12`（build 125629）**，2026-10 实测
- 主 Binary：`HongKong.app/HongKong`（arm64, ~232 MB）
- 包含 279 个 framework，其中与设备安全相关的不超过 8 个
- 数据容器：`/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29`
- 测试设备：iPhone 13 Pro / iOS 15.4.1（22215，rootless Dopamine + ElleKit）
- 对应 tweak：项目目录 `hsbchkbypass/`，包名 `page.0x01.hsbchkbypass`

> ⚠️ **汇丰香港与汇丰中国是两套完全不相干的技术栈。** 中国版 3.75.0 用 ZDefend，
> 香港版既没有 ZDefend 也没有 Promon，更没有 OneSpan 的 RASP 实现。中国版的做法
> （把自杀线程入口改 `ret`、让威胁列表返回空）在香港版上不起任何作用。
> 中国版见 `llmdoc/reference/hsbc-china-detection-vectors.md`。

## 检测栈

| 组件 | 大小 | 作用 |
|---|---|---|
| `TransmitSDK3.framework` | 4.1 MB | 含 `libDeviceSecurityAssessment`，**内嵌开源 IOSSecuritySuite**，另有自建 `JailbreakCheck` 枚举 |
| `TechnicalPlatform.framework` | 31.8 MB | 含 `WafMobileSdk.JailBrokenHelper`（F5/Shape 的 WAF 移动端 SDK），读 `/Applications/Cydia.app` 一类路径 |
| `DataProvider.framework` | 3.9 MB | 把各项结果汇成 `deviceJailbroken`、`applicationRepackaged`、`debuggerAttached`、`hookingFrameworks`、`nativeCodeHooks` 等布尔标记 |
| `RASPFramework.framework` | 179 KB | 只渲染拦截页的 Swift VIPER 界面层，不做判定 |
| `MobileSecurity.framework` | 159 KB | Keychain、LAContext、加密，不是检测器 |
| `LegacyVASCODSK.framework` | 1.3 MB | 只有一句 `The jailbreak status is invalid`，是 OneSpan 的旧设备签名组件 |
| `BioCatchSDK` / `TMXProfiling` / `TMXBehavioSec` | — | 行为生物特征与设备指纹，不判定越狱 |

### 可插拔的 RASP 配置位

主二进制里有 `WithOneSpanRASP.AppSecurityMonitor`、`ActiveOneSpanRASPProvider`，
`FeatureModels` 里还有 `OneSpanRASPCreatorStrategy` 与 `ZimperiumRASPCreatorStrategy`。
这些只是"按配置选择用哪家 RASP"的策略名称，**包里既没有 OneSpan 的 RASP 框架也没有
ZDefend**，所以实际能真正做判定的只有 `TransmitSDK3` 里的 IOSSecuritySuite 和
`TechnicalPlatform` 里的 WAF。不要把策略名称误当成已集成的 SDK。

### IOSSecuritySuite 的相关符号

`TransmitSDK3` 里以 Swift mangled 形式导出，可直接用于定位：

```
libDeviceSecurityAssessment.isJailbroken
libDeviceSecurityAssessment.IOSSecuritySuite.amIJailbroken
libDeviceSecurityAssessment.IOSSecuritySuite.amIJailbrokenWithFailMessage
libDeviceSecurityAssessment.IOSSecuritySuite.amIJailbrokenWithFailedChecks
libDeviceSecurityAssessment.IOSSecuritySuite.amIReverseEngineered
libDeviceSecurityAssessment.IOSSecuritySuite.amIDebugged
libDeviceSecurityAssessment.IOSSecuritySuite.amIProxied
libDeviceSecurityAssessment.IOSSecuritySuite.amIRunInEmulator
libDeviceSecurityAssessment.JailbreakCheck: urlSchemes, symbolicLinks,
    existenceOfSuspiciousFiles, suspiciousFilesCanBeOpened,
    restrictedDirectoriesWriteable, dyld, fork
```

注意这些符号**没有被导出到动态符号表**，`dlsym(RTLD_DEFAULT, ...)` 全部返回 NULL。
要 hook 得按镜像基址加符号偏移算地址，或者遍历 Swift 的 mangled 名段。

### RASPFramework 的策略资源

它是 Swift VIPER 结构（`RASPAppController/Interactor/Presenter/Router/ViewController`、
`UntrustedDevice*`），资源里有：

```
acceptJailbroken          JailbrokenStrategy        AppNotTrustStrategy
jailbroken_copy_stop_ios  jailbroken_title_advised_ios
jailbroken_cta_stop_close jailbroken_cta_advised_continue
```

这说明"检测到越狱之后怎么办"由汇丰自己的代码决定（停止 / 建议但可继续），
不是 SDK 直接自杀。但实测这些资源一次都没用上，App 走的是更早的"直接退出"分支。

## 基线行为

不开任何 tweak、点图标启动：

| 时刻 | 现象 |
|------|------|
| 0ms | 主进程出现 |
| 约 500ms | 进程号变更（旧进程退出，系统重新拉起一次） |
| 约 900ms | 进程消失 |
| 之后 | 回到桌面，没有崩溃报告，没有 Jetsam 记录 |

挂着探针时同样在 900ms 左右消失；`uiopen --bundle` 与点图标表现一致。
**挂不挂 tweak 一致**，说明注入本身不是致死原因。界面上从未看到拦截页。

## 退出机制：已确认是主动 `exit(1)`（2026-10-27 Round 1）

上一轮的"尚未定位"是因为缺一把外部尺子。这一轮用 `kqueue` 从进程外拿到确定答案。

### 死因：正常退出，退出码 1

自写的 `tools/procwatch` 用 `EVFILT_PROC | NOTE_EXIT | NOTE_EXITSTATUS` 观察目标 pid：

```
fflags=0x84000000 退出状态 0x100  结束方式：正常退出，退出码 1
```

`0x100` = `WIFEXITED` 且 `WEXITSTATUS == 1`。不是被杀、不是崩溃、不是 Jetsam。
这解释了之前对不上的全部现象：无崩溃报告、无信号、无 Jetsam、`atexit` 不触发
（退出过程没走完 dyld 的析构）。

> **`NOTE_EXITSTATUS` 不能省。** 只带 `NOTE_EXIT` 时 `data` 恒为 0，
> 第一版就因此误判成"退出码 0"。

### 钩子确实有效，"零命中"结论成立

0.0.17 用一个只挂 `exit` 的探针把这件事钉死：

```
exit 前   4 条指令：d503237f a9be4ff4 a9017bfd 910043fd   ← 真实代码，不是跳板
挂钩后    4 条指令：58000050 d61f0200 ...                  ← ElleKit 的 ldr x16,#8; br x16
>>> my_exit 被调用，code=9
```

但条目仍然是**零命中**。所以 App 没有走 `exit`/`_exit`/`abort`/`kill`/`raise`/
`pthread_kill` 这些**符号**。

### App 自己的镜像里没有退出类内联 `svc`

进程内扫了全部 932 个已加载镜像的代码段，按 4 字节编码找 `svc #0x80` / `svc #0x81`，
共 527 处：

| 镜像 | 命中数 |
|---|---|
| `libsystem_kernel.dylib` | 998 |
| `TMXProfiling` / `TMXBehavioSec` / `TMXProfilingConnections` | 24 / 20 / 4 |
| `libellekit.dylib` | 4 |
| `PAFaceDetectSDK` | 2 |
| `IOKit` | 2 |

**主二进制 `HongKong` 与 `hsbchkmobilebankingx` 中一处都没有**（后者 9 MB 整文件按字节
找也只有 1 处，落在非代码区）。

### 仍未能解释的矛盾

`exit(1)` 已确认，但所有 libc 退出符号的钩子都没命中。剩下三条可能：

1. 退出发生在构造函数之前——线程在那之前就被劫持或改写了；
2. 走 `__DATA,__interpose` 或其他间接绑定，绕开了 `dlsym` 返回的地址；
3. `hsbchkmobilebankingx` 里有自己的 libSystem 调用封装。该框架 9 MB，只链
   libSystem.B / Foundation / CoreFoundation，值得优先看。

旁证：构造函数返回后约 70ms，探针的心跳线程与主线程 tick 会**同时**停止；
把主线程在构造函数里按 3 秒（0.0.19）时，心跳能一直跑到 120 拍。
压住我们的东西在主线程上、排在构造函数之后。

### 关于 `exit` 钩子有效性的历史误判

两处误判叠在一起，导致上一轮怀疑钩子失效：

- 观察到的 `58000050 d61f0200` 被当成"hook 前的原始状态"，实际那是**已挂上钩子之后**的地址；
- `kill`、`vm_protect` 的 `dlsym` 地址首字是 `d4200020`（`brk #1`，"不可用"桩），
  ElleKit 挂钩**静默失败**，被误读成"钩子被目标还原"。

### 排除清单（Round 0 + Round 1）

| 手段 | 结果 |
|---|---|
| `kqueue` 外部观察退出状态 | **正常退出，退出码 1** |
| hook 全部 libc 终止原语 | 零命中（已证钩子有效） |
| hook `syscall(2)` | 零命中 |
| `atexit` 回调 | 不触发 |
| 1～31 号信号处理器 | 无信号 |
| Mach 异常端口 | 零消息 |
| `signal`/`sigaction`/`task_set_exception_ports` 接管者记录 | 只有 `hsbchkmobilebankingx` 的 CPU 计数器探测（`CNTPCT_EL0`/`CNTVCT_EL0`），非检测 |
| `mprotect`/`vm_protect` 覆盖到目标页的调用 | 无命中 |
| 全镜像内联 `svc` 扫描 | App 自身镜像零命中 |
| 崩溃报告 / Jetsam | 无（19:46–19:49 那三份是自己探针卡住主线程触发的 `0x8BADF00D`） |

### Round 2：用户态拦截已到尽头（2026-10-27）

这一轮把"能不能拦住退出"问到了底，答案是**不能**，证据链如下。

**pid 与时间轴已对齐。** 之前"心跳 50ms 就停"是别的 tweak 被禁用状态下的假象。
真实情况是同一进程活到约 400ms，最后一拍心跳之后 11ms 退出。

**退出码 1 是真的。** 对照实验：`exit 7` → `0x700`，`kill -9` → `0x9`，
`kill -TERM` → `0xf`，App → `0x100`（正常退出、退出码 1）。

**不注入本探针也一样。** 移走全部 `HSBCHKBypass*`，仍然 `0x100`，约 580ms 结束。
触发条件是越狱环境本身（ElleKit / systemhook 对每个进程都注入）。

**钩子在退出时刻确实有效。** 0.0.36 在启动 386ms 时由自己的线程调 `exit(99)`，
`my_exit` 命中且 procwatch 读到 `0x6300`。所以"App 没走 libc exit"是可信的否定结论。

**逐条堵、逐条无效：**

| 手段 | 结果 |
|---|---|
| 退出类符号入口（首字确认 `58000050`） | 零命中 |
| fishhook 重绑所有镜像 `__got`/`__la_symbol_ptr` | 实测改到 **0 个槽** |
| `syscall` / `__syscall` | 零命中 |
| 非镜像可执行内存里 `movz x16,#1; svc` 改 `ret`（含持续重扫） | 桩改掉，App 照退 |
| Mach 异常端口 / `atexit` | 零消息 / 不触发 |
| 全线程 10ms 采样 | 退出前 6ms 无线程在退出路径 |
| 广泛 hook 文件接口隐藏越狱痕迹 | App 直接 SIGSEGV，已回退 |

**静态事实：** 主二进制 23394 个导入里没有 `exit`/`_exit`/`abort`/`kill`/`syscall`/
`dlopen`/`dlsym` 任何一个；`hsbchkmobilebankingx` 只导入 `_abort`。退出前主线程停在
`hsbchkmobilebankingx` 的哈希循环（`mul`+`ror`，栈帧约 0xc00 字节）里，是虚拟机式的
内存完整性校验。

**推论：** 退出既不走符号、不走 GOT、不走可改写的系统调用桩，`atexit` 不触发又排除了
`exit()`。剩下的可能只有两类——退出发生在观测窗口之外（由 dyld 或 UIKit 私有终止路径
收尾），或由进程外实体完成而内核报成正常退出 1。

### 可继续的方向

1. 离线反向分析 `hsbchkmobilebankingx` 那个虚拟机，定位它调用的退出入口（不碰设备）；
2. 关注 `UIApplication` 的私有终止路径（`_terminateWithStatus:` 一类）；
3. 在越狱本体层面做进程外隐藏（roothide 一类做法）——与「不动越狱本体」的约束冲突，
    需要用户先松开这条约束。

## 排查方法（可复用）

- **探针必须有自检。** 但自检要选对层次：hook `getpid` 自调能证明"机制可用"，
  却证明不了"这个特定地址挂上了"。对每个要 hook 的地址回读首字是否变成
  `58000050 d61f0200`，才是个体级别的确认。
- **判断死因优先用进程外手段。** `kqueue` + `NOTE_EXITSTATUS` 一次就能区分
  "自己退"和"被杀"，比在进程内挂十几个终止原语更省事。
- **日志必须带时间戳。**
- **磁盘上的加密段不能静态扫**（先读 `cryptid`）；但要扫所有镜像时，
  在构造函数里扫内存反而最快——那时镜像都已映射且已解密。
- **hook 的"零命中"要配一张排除表。** 写成"哪个手段、零命中、是否已验证钩子有效"，
  后续才判断得出结论是否还成立。

## 环境限制

- 设备上的 `frida-server` 能启动，但 `frida.spawn` 对所有 App 都返回
  `mach task is gone`（包括能正常运行的汇丰中国），只能 attach、不能 spawn。
- `task_for_pid` 返回 `kr=5`，从外部读不到内存和线程快照，外部观测只有退出状态这类信号。

## 设备操作注意事项

`hsbchkbypass/verify.sh` 会临时把其它 tweak 的 plist 改名 `.plist.off` 做隔离。
改名当次不生效，但**下一次 SpringBoard 重启会让所有 `.off` 一起生效**，
整台设备的 tweak 全部失效。2026-10-27 因此误伤过一次（65 个 tweak 同时失灵）。
脚本现已改为记录清单并在退出时自动恢复；手动跑这类脚本前，先确认它能还原。
