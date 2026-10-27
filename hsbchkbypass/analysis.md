# hsbchkbypass 分析记录

## 目标

让汇丰香港（`hk.com.hsbc.hsbchkmobilebanking`）在越狱设备上正常运行。
当前实测版本 3.69.12（build 125629），可执行文件 `HongKong.app/HongKong`（232 MB），
bundle 路径 `/var/containers/Bundle/Application/080BB1A5-.../HongKong.app`，
数据容器 `/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29`。

**状态：排查中，没有可用版本。**

## 为什么从 hsbcchina 里拆出来

汇丰中国的 1.0.0 做法（把 ZDefend 自杀线程入口改成 `ret`、让威胁列表返回空）对香港版
完全没有作用。香港版没有 ZDefend，也没有 Promon，检测栈完全不同。把两个 App 放在
一个包里名不副实，所以拆成独立项目。

## Round 0 基线（2026-10-27）

不开任何 tweak、用图标点击启动：

| 时刻 | 现象 |
|------|------|
| 0ms | 主进程出现 |
| 约 500ms | 进程号从 11572 变成 11607（旧进程退出，系统重新拉起了一次） |
| 约 900ms | 进程消失 |
| 之后 | 回到桌面，没有崩溃报告，没有 Jetsam 记录 |

挂着探针时同样在 900ms 左右消失。**挂不挂 tweak 表现一致**，说明注入本身不是致死原因，
是 App 自己的判定在启动早期就决定退出。

用户界面上从未看到拦截页——`RASPFramework` 里那些 `acceptJailbroken`、
`JailbrokenStrategy`、`jailbroken_title_advised_ios` 之类的资源一次都没用上，
说明这一版走的是"直接退出"分支，不是"弹页让用户选"。

## 检测栈（静态结论）

`Frameworks` 下 279 个框架，与设备安全相关的是这几个：

| 框架 | 大小 | 作用 |
|------|------|------|
| `TransmitSDK3.framework` | 4.1 MB | 含 `libDeviceSecurityAssessment`，**内嵌开源 IOSSecuritySuite**，另有自己的 `JailbreakCheck` 枚举 |
| `TechnicalPlatform.framework` | 31.8 MB | 含 `WafMobileSdk.JailBrokenHelper`（F5/Shape 的 WAF 移动端 SDK），读 `/Applications/Cydia.app` 一类路径 |
| `DataProvider.framework` | 3.9 MB | 把各项结果汇成 `deviceJailbroken`、`applicationRepackaged`、`debuggerAttached`、`hookingFrameworks`、`nativeCodeHooks` 等布尔标记 |
| `RASPFramework.framework` | 179 KB | 只负责渲染拦截页，是 Swift 的 VIPER 界面层，不做判定 |
| `MobileSecurity.framework` | 159 KB | Keychain、LAContext、加密，不是检测器 |
| `LegacyVASCODSK.framework` | 1.3 MB | 只有一句 `The jailbreak status is invalid`，是 OneSpan 的旧设备签名组件 |
| `BioCatchSDK` / `TMXProfiling` / `TMXBehavioSec` | — | 行为生物特征与设备指纹，不判定越狱 |

主二进制里还有 `WithOneSpanRASP.AppSecurityMonitor`、`ActiveOneSpanRASPProvider`，
以及 `FeatureModels` 里的 `OneSpanRASPCreatorStrategy` / `ZimperiumRASPCreatorStrategy`。
也就是说这一版把 RASP 做成了可插拔的，具体用哪家由配置决定。但从实际加载的镜像看，
包里既没有 OneSpan 的 RASP 框架，也没有 ZDefend，能真正做判定的只有
`TransmitSDK3` 里的 IOSSecuritySuite 和 `TechnicalPlatform` 里的 WAF。

`TransmitSDK3` 里的相关符号（Swift mangled）：

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

## 退出机制：已确认为主动 `exit(1)`（Round 1，2026-10-27）

上一轮把结论写成"尚未定位"，是因为看漏了两件事。这一轮用进程外的手段拿到了确定答案。

### 关键事实：是正常的 `exit(1)`，不是被杀也不是崩溃

自写的 `tools/procwatch` 用 `kqueue` 的 `EVFILT_PROC` 观察目标 pid，
注册时必须同时带 **`NOTE_EXITSTATUS`**，否则 `kevent` 返回的 `data` 恒为 0
（只带 `NOTE_EXIT` 时我第一版就踩了这个坑，误以为退出码是 0）。

```
fflags=0x84000000 退出状态 0x100  结束方式：正常退出，退出码 1
```

`0x100` = `WIFEXITED` 且 `WEXITSTATUS == 1`。这解释了几个一直对不上的现象：
没有崩溃报告、没有 Jetsam、没有信号、`atexit` 不触发。App 是**主动调用退出**的，
连 dyld 的析构都没走完（所以 `atexit` 不可靠，不能反推"不是 exit"）。

### 钩子是有效的，之前"零命中"的结论成立

0.0.17 用一个只有 exit 的探针把这件事钉死：

```
exit 前 4 条指令：d503237f a9be4ff4 a9017bfd 910043fd    ← pacibsp; stp; stp; mov
not a trampoline
挂钩后前 4 条指令：58000050 d61f0200 ...                  ← ElleKit 的 ldr x16,#8; br x16
>>> my_exit 被调用，code=9
```

`exit` 入口原本是**真实代码**，`MSHookFunction` 之后确实被改写成跳板，
替换函数也确实被调用。所以 `exit`/`_exit`/`abort`/`kill`/`raise`/`pthread_kill`
在本进程内零命中，是可信的否定结论——App 没有走这些符号。

> 上一轮之所以怀疑钩子失效，是因为观察到的 `58000050 d61f0200` 被当成了
> "hook 前的原始状态"。实际那次读到的是**已经挂上钩子之后**的地址，
> 加上另一次把 `kill` 的 `brk #1` 桩当成"钩子被还原"，两次误判叠在一起。

### 注意 `vm_protect` / `kill` 这类符号是 `brk #1` 桩

`dlsym` 取到的 `vm_protect`、`kill` 头一个字是 `d4200020`（`brk #1`），
它们在这台设备上被 libsystem 替换成了"不可用"桩。ElleKit 对这类地址挂钩会**静默失败**
（不报错，字节也不变）。判断某个钩子到底装没装上，必须回读首字是否变成
`58000050 d61f0200`，不能只看有没有抛错。

### 内联 `svc` 扫描：App 自己的镜像里没有退出类系统调用

在进程内扫了全部 932 个已加载镜像的代码段（`S_ATTR_PURE_INSTRUCTIONS`），
按 4 字节编码找 `svc #0x80` / `svc #0x81`，命中 527 处，分布是：

| 镜像 | 命中数 |
|------|--------|
| `libsystem_kernel.dylib` | 998（`svc` 封装本体，预期之内） |
| `TMXProfiling` / `TMXBehavioSec` / `TMXProfilingConnections` | 24 / 20 / 4（ThreatMetrix 自己的 syscall 封装） |
| `libellekit.dylib` | 4 |
| `PAFaceDetectSDK` | 2 |
| `IOKit` | 2 |

**主二进制 `HongKong` 与 `hsbchkmobilebankingx` 里一处 `svc` 都没有**
（`hsbchkmobilebankingx` 9 MB 整个文件按字节找也只有 1 处，落在非代码区）。

### 尚未解释的矛盾

`exit(1)` 已确认，但所有 libc 退出符号的钩子都没命中。剩下的可能：

1. 退出走的是**早于我们构造函数**的路径——线程在构造函数期间就被改写或劫持了；
2. 走的是 `__DATA,__interpose` 或其他间接绑定，绕开了 `dlsym` 返回的地址；
3. 结论依赖的"零命中"只覆盖了**符号路径**，而 App 用的是自己在 `hsbchkmobilebankingx`
   里的一份 libSystem 调用封装（该框架只链了 libSystem.B / Foundation / CoreFoundation）。

旁证：构造函数返回后约 70ms，探针自己的心跳线程与主线程 tick 会**同时**停止，
而把主线程在构造函数里按 3 秒（0.0.19）时心跳能一直跑到 120 拍。
也就是说，压住我们的东西在主线程上、排在构造函数之后。

### 已排除（本轮新增）

| 手段 | 结果 |
|------|------|
| `kqueue` 外部观察退出状态 | **正常退出，退出码 1** |
| `exit` 钩子有效性自检（0.0.17） | 挂钩成功且替换函数被调用 |
| 全镜像内联 `svc` 扫描（0.0.23） | App 自身镜像零命中 |
| 进程内 Mach 异常端口 | 一条消息都没收到（与"不是异常退出"一致） |
| `signal`/`sigaction`/`task_set_exception_ports` 接管记录 | 只有 `hsbchkmobilebankingx` 的 CPU 计数器探测（`CNTPCT_EL0`/`CNTVCT_EL0`），非检测 |
| 系统崩溃报告 | 19:46–19:49 那三份全是**自己探针**卡住主线程触发的 `0x8BADF00D` 启动看门狗，与 App 无关 |

### 待验证的方向

1. 用 `task_for_pid` 之外的途径（内核层或越狱侧 hook）在**构造函数之前**介入；
2. 在 `hsbchkmobilebankingx` 里定位它自己的进程退出封装——它有 9 MB 代码且完全不 import libSystem 的退出符号。
3. 检查 `UIApplication` 的 `_terminateWithStatus:` 一类私有路径（那是另一种"看起来像 exit(1)"的退出）。



已经排除的路径：

| 手段 | 结果 |
|------|------|
| hook `exit`/`_Exit`/`_exit`/`abort`/`kill`/`pthread_kill`/`raise` | 一次都没命中 |
| hook `syscall(2)`（观察 SYS_exit / SYS_kill） | 一次都没命中 |
| `atexit` 回调 | 没触发，说明不是正常退出流程 |
| 1～31 号信号处理器 | 没收到任何信号 |
| 磁盘文件静态扫描内联 `svc` | 主二进制和 9 个重点框架都没有 exit 类 svc |
| 崩溃报告 / Jetsam 记录 | 都没有 |

**hook 本身是有效的**：探针里对 `getpid` 做了一次自检 hook，调用一次命中一次，
所以"退出函数没被调用"这个结论成立，不是 hook 失效造成的假阴性。

## 已布设但没跑通的工具

- `verify.sh`：部署探针、关掉其它 tweak、冷启动若干次、回捞日志。已经跑通。
- frida-server 在设备上能起，但 `frida.spawn` 对所有 App 都返回
  `mach task is gone`，包括能正常运行的汇丰中国。也就是说这台设备上的 frida
  只能 attach，不能 spawn，用不上"在启动前布好 hook"这条路。

## 探针版本历史

| 版本 | 内容 | 结果 |
|------|------|------|
| 0.0.1 | 退出函数 hook + 镜像/类清单 + 内联 svc 扫描 | 扫描太慢把启动拖死；类清单因抢 ObjC 运行时锁卡住 |
| 0.0.2 | 加 Swift 布尔方法 hook（`dlsym` 全部找不到）+ 心跳 | 心跳每 200ms 一次，进程在第一个心跳后消失 |
| 0.0.3 | 心跳改成 20ms 一次，加 atexit 与全信号处理器 | 只写出「心跳 0」，没有任何信号或 atexit 记录 |
| 0.0.4 | 内联 svc 扫描挪到独立线程，用 `memchr` 加速 | 扫描没跑完进程就没了 |
| 0.0.5 | 加 hook 自检（hook `getpid` 自调）与 `syscall(2)` hook | 自检通过，退出路径仍然零命中 |
| 0.0.6–0.0.12 | 改成按 `LC_SYMTAB` 解析 Swift mangled 名，hook IOSSecuritySuite 的 7 个 `amI*` 入口 | 7 个入口全部挂上（如 `amIJailbrokenSbyFZ @ 0x121afb16c`），App 行为不变 |
| 0.0.13 | 加"按住主线程"模式，把主二进制 `__TEXT` dump 到 Documents | 成功 dump 201,752,576 字节；进程随后被 `0x8BADF00D` 启动看门狗收走 |
| 0.0.14 | 改 stub 字面量接管 libc（绕开 ElleKit） | 字面量改写分支一次都没匹配上 |
| 0.0.15 | 信号处理器只记一行 | 收到 2,369,935 个 SIGUSR1，构造函数被淹没 |
| 0.0.16 | hook 去重（`__exit`/`_exit` 别名） | 构造函数能跑完，但心跳仍只到第 0 拍 |
| 0.0.17 | **只挂 `exit` 并自检** | **确认钩子有效**：`MSHookFunction` 改写了首字，`my_exit` 被调用 |
| 0.0.18 | 终止原语 + Mach 异常端口 | 异常端口零消息；心跳停在 50ms 内 |
| 0.0.19 | 主线程在构造函数里按 3 秒 | **心跳与主线程 tick 都能跑到 120 拍**，说明压制者排在构造函数之后 |
| 0.0.20 | 记录 `signal`/`sigaction`/`task_set_exception_ports` 的接管者 | 只有 `hsbchkmobilebankingx` 的 CPU 计数器探测，非检测 |
| 0.0.21 | 监控钩子是否被还原 + `syscall` | `kill`/`vm_protect` 是 `brk #1` 桩，"还原"是误读 |
| 0.0.22 | 记录 `mprotect`/`vm_protect` 覆盖到目标页的调用 | 无命中 |
| 0.0.23 | 进程内扫全部镜像的 `svc` | 932 个镜像、527 处命中，App 自身镜像为 0 |
| 0.0.24 | `atexit` + pid 对齐 | `atexit` 不触发 |

`dlsym(RTLD_DEFAULT, ...)` 找不到那些 Swift 符号，是因为它们没有被导出到动态符号表。
要 hook 得先按 `LC_SYMTAB` 把符号表映射到内存里（`__LINKEDIT.vmaddr + slide + (symoff - fileoff)`），
再按 `n_value + slide` 算运行时地址。0.0.6 之后一直用这个办法。

## 进程外工具

- `tools/procwatch`：用 `kqueue` 的 `EVFILT_PROC | NOTE_EXIT | NOTE_EXITSTATUS` 从进程外
  观察目标退出状态。**`NOTE_EXITSTATUS` 不能省**，否则 `data` 恒为 0。
  已部署到设备 `/var/jb/usr/local/bin/procwatch`。
- `task_for_pid` 在本设备返回 `kr=5`（`KERN_FAILURE`），所以没法从外部读内存或采样线程，
  进程外的观测只能用退出状态这一类间接信号。
