# hsbchkbypass 分析记录

## 目标

让汇丰香港（`hk.com.hsbc.hsbchkmobilebanking`）在越狱设备上正常运行。
当前实测版本 3.69.12（build 125629），可执行文件 `HongKong.app/HongKong`（232 MB），
bundle 路径 `/var/containers/Bundle/Application/080BB1A5-.../HongKong.app`，
数据容器 `/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29`。

**状态：排查中，没有可用版本。死因已确认为 `exit(1)`，但用户态的拦截手段已全部用尽。**

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

## Round 2（2026-10-27）：用户态拦截这条路走到尽头

这一轮把"退出到底能不能拦住"问到了底。结论是**拦不住**，而且有完整证据链。

### 先纠一个前提：pid 一直是对的

之前"心跳 50ms 就停"是别的 tweak 被禁用状态下的假象。把 pid 与时间轴对齐后：

```
我们注入的进程 pid=19142
procwatch 观察同一个 pid → 退出时刻 uptime ...670，退出码 1
最后一拍心跳             → uptime ...659（相对 386ms）
```

也就是说进程活到约 400ms，退出发生在最后一拍心跳之后 11ms，两者是同一个进程。

### 退出码 1 是真的（做了对照）

| 情形 | procwatch 读数 |
|------|----------------|
| `exit 7` | `0x700` → 退出码 7 |
| `kill -9` | `0x9` → 信号 9 |
| `kill -TERM` | `0xf` → 信号 15 |
| App 退出 | `0x100` → 正常退出，退出码 1 |

`NOTE_EXITSTATUS` 不能省：只带 `NOTE_EXIT` 时读数恒为 0，会被误读成"退出码 0"。

### 不注入我们的 tweak 也一样

移走全部 `HSBCHKBypass*` 后重新启动，仍然读 `0x100`，约 580ms 结束。
所以触发条件是**越狱环境本身**（ElleKit / systemhook 对每个进程都注入），不是本探针。

### 钩子在退出时刻仍然有效

0.0.36 在启动 386ms 时由我们自己的线程调用 `exit(99)`：

```
[386ms] === 主动调用 exit(99) ===
[386ms] !! my_exit 被调用 code=99
procwatch: 退出状态 0x6300 → 退出码 99
```

同一时刻、同一进程，我们的 `exit` 钩子命中并被 procwatch 读到。
所以"App 的 exit(1) 没走 libc `exit`"是可信的否定结论，不是钩子失效。

### 逐条堵，逐条无效

| 手段 | 结果 |
|------|------|
| `exit`/`_exit`/`abort`/`raise`/`pthread_kill`/`task_terminate` 符号入口（MSHookFunction，首字确认 `58000050`） | 零命中 |
| fishhook 重绑所有镜像的 `__got`/`__la_symbol_ptr` | 实测改到 **0 个槽**——App 的镜像里根本没有退出类槽 |
| `syscall` / `__syscall` | 零命中 |
| 把非镜像可执行内存里 `movz x16,#1; svc` 的退出桩改成 `ret`（含持续重扫） | 桩确实改掉，App 照退 |
| Mach 异常端口 | 零消息 |
| `atexit` | 不触发（说明不是 `exit()` 路径） |
| 同步采样全部线程（每 10ms） | 退出前 6ms 三个线程都不在退出路径上 |
| 广泛 hook `stat`/`open`/`fopen`/`_dyld_get_image_name` 隐藏越狱痕迹 | 直接把 App 变成 SIGSEGV（正是 lianjiabypass 记录过的坑），已回退 |

### 静态侧的关键事实

- 主二进制 `HongKong` 的 23394 个导入里**没有** `exit`/`_exit`/`abort`/`kill`/`syscall`/`dlopen`/`dlsym` 任何一个。
- `hsbchkmobilebankingx`（9 MB）只导入 `_abort`，也不导入 `exit`/`_exit`。
- 它的符号名已被剥空（字符串表只有 24 字节），只能从绑定信息取导入名。
- 退出前主线程在 `hsbchkmobilebankingx` 的**哈希循环**里（`mul` + `ror` 反复滚动，
  栈帧约 0xc00 字节），相邻还串联着 `hsbchkmobilebankingx+0x33…`/`+0x65bfa8` 等
  VM 地址——这是一个虚拟机式的内存完整性校验。
- 该框架自带的 libc 兼容层导入 `_kevent`/`_kqueue`/`_pause`/`_tcgetattr`/`_chdir`/`_getcwd`
  之类，看起来像在跑自己的运行时。

### 推论

退出既不走符号、不走 GOT、不走我们能改写的系统调用桩，而 `atexit` 不触发又排除了
`exit()`。剩下的可能只有两类：

1. **退出发生在我们的观测窗口之外**：某个更早的时刻已经决定并排好，最后由 dyld
   或内核路径收尾（例：`UIApplication` 的私有终止路径、或 `_terminateWithStatus:`）。
2. **退出由进程外的实体完成**，内核把状态报成"正常退出 1"。

再往下走，用户态的手段已经用尽。要继续只有两条路：反向分析
`hsbchkmobilebankingx` 那个虚拟机（离线工作，不碰设备），或者在越狱本体层面处理
（roothide 一类只在进程外隐藏注入的做法）。后者与「不动越狱本体」的约束冲突。

## 已布设但没跑通的工具

- `verify.sh`：部署探针、关掉其它 tweak、冷启动若干次、回捞日志。已经跑通。
- frida-server 在设备上能起，但 `frida.spawn` 对所有 App 都返回
  `mach task is gone`，包括能正常运行的汇丰中国。也就是说这台设备上的 frida
  只能 attach，不能 spawn，用不上"在启动前布好 hook"这条路。

## 探针版本历史

| 版本 | 内容 | 结果 |
|------|------|------|
| 0.0.1–0.0.5 | 终止原语 hook、镜像/类清单、内联 svc 扫描、hook 自检 | 扫描太慢把启动拖死；类清单抢 ObjC 运行时锁卡住 |
| 0.0.6–0.0.12 | 按 `LC_SYMTAB` 解析 Swift mangled 名，hook IOSSecuritySuite 的 7 个 `amI*` | 7 个入口全部挂上，App 行为不变 |
| 0.0.13 | 按住主线程，dump 主二进制 `__TEXT` | 成功 dump 201,752,576 字节 |
| 0.0.14–0.0.16 | 改 stub 字面量、信号处理器瘦身、hook 去重 | 构造函数能跑完 |
| 0.0.17 | 只挂 `exit` 并自检 | **确认钩子有效**：首字被改写，`my_exit` 被调用 |
| 0.0.18–0.0.22 | Mach 异常端口、按主线程 3 秒、接管记录、钩子还原监控 | 异常端口零消息；压住我们的东西排在构造函数之后 |
| 0.0.23 | 进程内扫 932 个镜像的 `svc` | 527 处命中，App 自身镜像为 0 |
| 0.0.24–0.0.25 | `atexit`、pid 对齐 | 同 pid 活到约 400ms 才退出 |
| 0.0.26 | 新镜像回调 | 构造函数之后没有新的 App 镜像加载 |
| 0.0.27 | fishhook 重绑退出类符号 | rc=0 |
| 0.0.28 | 主线程 PC/LR 采样 | 退出前停在 `hsbchkmobilebankingx` 的哈希循环里 |
| 0.0.29 | `syscall` / `__syscall` | 零命中 |
| 0.0.30 | 统计 fishhook 实际改到的槽 | **0 个**——App 镜像没有退出类槽 |
| 0.0.31–0.0.32 | 扫非镜像可执行内存 | 发现 syscall 桩表 |
| 0.0.33 | 把 `movz x16,#1; svc` 改成 `ret` | 桩改掉，App 照退 |
| 0.0.34 | 全线程采样 | 退出前 6ms 无线程在退出路径 |
| 0.0.35 | 广泛 hook 文件接口隐藏越狱痕迹 | App 变 SIGSEGV，已回退 |
| 0.0.36 | **在进程内调 `exit(99)` 验证钩子** | 钩子命中，procwatch 读到 99 → 钩子有效 |
| 0.0.37–0.0.38 | 持续重扫退出桩并导出全部 `svc` 站点 | 只有 7 个非镜像可执行区域，退出桩一个 |

## 进程外工具

- `tools/procwatch`：用 `kqueue` 的 `EVFILT_PROC | NOTE_EXIT | NOTE_EXITSTATUS` 从进程外
  观察目标退出状态。**`NOTE_EXITSTATUS` 不能省**，否则 `data` 恒为 0。
  已部署到设备 `/var/jb/usr/local/bin/procwatch`。
- `task_for_pid` 在本设备返回 `kr=5`（`KERN_FAILURE`），所以没法从外部读内存或采样线程，
  进程外的观测只能用退出状态这一类间接信号。
