# hsbchkbypass 分析记录

## 目标

让汇丰香港（`hk.com.hsbc.hsbchkmobilebanking`）在越狱设备上正常运行。
当前实测版本 3.69.12（build 125629），可执行文件 `HongKong.app/HongKong`（232 MB），
bundle 路径 `/var/containers/Bundle/Application/080BB1A5-.../HongKong.app`，
数据容器 `/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29`。

**状态：排查中，没有可用版本。死因已确认为 `exit(1)`；Round 5 已定位到具体的判定函数。**

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

## Round 3（2026-10-27）：再排除两个非检测假设

| 假设 | 验证方法 | 结果 |
|------|----------|------|
| 不是检测，而是"iOS 15 太旧"的门槛 | 接管 `-[NSProcessInfo operatingSystemVersion]`、`isOperatingSystemAtLeastVersion:`、`-[UIDevice systemVersion]`，一律报 17.5 | App **一次都没调用**这些接口，照退 |
| 退出由某个后台线程发起 | 启动 336ms 时 `thread_suspend` 挂起除主线程与自身外的全部线程（枚举到 3 个，挂起 1 个） | 照退，退出在主线程上 |

结合 Round 2 的全线程采样（退出前 6ms 无线程处于退出路径）与 0.0.19 里"把主线程
按在构造函数里进程能活 6 秒以上"，可以把范围收到：**决定由主线程做出，
但真正的退出动作不是我们能在用户态插入的任何一种调用**。

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

---

# Round 4（2026-10-27）：定位到盾本体，接管它的私有系统调用网关

Round 3 结束时所有用户态拦截手段都试完了，全部无效。那一轮的结论「静态侧主二进制
23394 个导入里没有任何退出原语」后来被证明是**对的**，但当时的推理有缺口：主二进制
确实不导入 `exit`，因为它根本不需要——真正的判定和执行都在 `hsbchkmobilebankingx`
里，而那个框架的导入表我一开始解析错了。

## 1. 盾的身份：Promon SHIELD 的 libshield

`hsbchkmobilebankingx` 的 `__cstring` 里有 290 条构建路径，其中 263 条落在
`/mobile/release/shield/third_party/libressl/`，另有 `shield/libshield-config.pb.cc`。
主二进制还引用了 `_OBJC_CLASS_$_PRMShieldEventManager`。`PRMShield` 是 Promon SHIELD
的类名前缀。

**决定性证据**：这些地址与 llmdoc 里汇丰中国 3.72.15（同一套 Promon 构建）的记录
**逐字节一致**：

| 项 | 地址 | 说明 |
|---|---|---|
| 系统调用网关 | `+0x78befc` | `svc #0x80; ret; brk #1` |
| 网关全局槽 | `+0x8510c8` | 存网关运行时地址，`__common` 里 |
| 网关安装点 | `+0x346c68` | `adrp/add` 算地址后 `str` 进槽 |
| mach trap 封装 | `+0x40c698` | `mov x16,#-0x1f` → 读槽 → `blr x17` |

全镜像共有 **83 个**封装用 `ldr x17,[0x8510c8]; blr x17` 走这个网关。

## 2. 为什么之前所有拦截都零命中

盾的每一次系统调用都经过它自己 `.text` 里的一条 `svc #0x80`，**不经过 libSystem
的任何具名符号**。所以 fishhook 改 GOT、`MSHookFunction` 挂 `exit`/`_exit`、hook
`syscall`、扫内联 `svc`，全部覆盖不到。

## 3. 接管手段：只改一个可写数据槽

网关槽是普通可写数据。把槽里的值换成自己的入口，83 个封装下一次调用就会走进来。
这个办法不需要改任何代码、不需要 `vm_protect`、不碰 `__TEXT`。

第一版探针（0.0.41）立刻成功：盾的每一次系统调用都可见了，调用号在 `x16`，
调用点是返回地址减镜像基址。

## 4. 网关入口必须遵守的两个约束

**（a）不能调用 libc。** 0.0.43 的崩溃报告栈是
`hsbchkmobilebankingx +0x448da0 → gw_entry → gw_log → snprintf → SIGSEGV@0x50`。
盾会在 libc 尚未就绪的线程上调用网关，处理函数里一进 `snprintf`（要读区域设置和
线程局部存储）就踩空。改成「处理函数只把寄存器写进环形缓冲、手写格式化、裸
`svc #0x80` 的 `write` 落地」之后就不再崩。

**（b）x0..x15 全部要保存。** 原网关只有 `svc; ret`，除了 `x0`/`x1` 什么都不改。
中间插一次 `bl` 会按 AAPCS64 把 `x0..x18` 全当调用者保存寄存器用；只备份 `x0..x7`
会让盾里内联在循环中的计数器悄悄变值。

顺带两个测量错误也值得记：`gw_record` 有 6 个参数，第 6 个在 **`x5`** 而不是 `x6`
（按 `x6` 取会把调用点读成垃圾）；mach 消息缓冲区在调用者的栈上，排空线程晚 1ms
再去读，内容早被覆盖，必须处理函数当场拷走。

## 5. 盾看到了什么：逐个头读取每个已加载镜像

解码 `mach_msg` 请求头后：

| 字段 | 值 | 含义 |
|---|---|---|
| `msgh_id` | 4808 | `mach_vm_read_overwrite` |
| `w3` | `0x1_0000_0000` | 目标 task（自己） |
| `w4` | 地址 | 要读的位置 |
| `w5` | 长度 | 常见 `0x20`（32 字节 Mach-O 头），以及后续节表 |

一次冷启动约 **750–1500 次**这样的读取，依次扫过进程里每一个镜像的基址。
注入库（`libellekit.dylib`、`libinjector.dylib`、tweak 自身）**确实在里面**。

## 6. 退出点

```
+0x5d842c:  sub sp,sp,#0x20 ; … ; mov x16,#1 ; mov x0,#1 ; 读网关槽 ; blr ; ret
```

一个无条件 `exit(1)` 的叶子函数，四个守卫函数调用它：
`+0x694e80`、`+0x696774`、`+0x696a08`、`+0x69765c`。崩溃报告里的
`hsbchkmobilebankingx +0x5d8484` 就是它 `blr` 之后那句。

## 7. 试过但**无效**的干预（都是有结论的负面结果）

| 干预 | 结果 |
|---|---|
| 拦退出系统调用（网关处返回） | 进程从 ~100ms 活到 15 秒以上，但停在启动图；截断状态机后主线程再也不恢复 |
| 置空盾的 71 个 `__mod_init_func` | 无效，退出点不变。盾的初始化走 ObjC `+load`，不走 C 构造函数 |
| hook `_dyld_image_count`/`_dyld_get_image_header`/`_dyld_get_image_name` | 无效。**盾根本没导入这些接口**——它一个镜像枚举符号都没有 |
| hook `dlsym` | 无效。装上了但盾一次都没调用 |
| 改写注入库的 `LC_ID_DYLIB` 路径为 `/usr/lib/libSystem.B.dylib` | 无效。改完必须把代码页恢复成 `r-x`，否则 SIGBUS（代码签名） |
| 把退出函数 `+0x5d842c` 首条指令改 `ret` | 部分：偶发能活过 8 秒，但也出现主线程 `pc/lr/sp/fp` 全零的崩溃 |
| 把注入库的 mach 读取重定向到系统 dylib（保持相对偏移） | 生效 9 次，**盾仍在同一处退出** |

重定向那版的细节值得一提：替身不能选盾自己——它是**可执行文件**，第一个 load
command 是 `LC_SEGMENT_64`，而解析器期待 `LC_ID_DYLIB`，会顺着垃圾偏移读崩。
换成 `libobjc.A.dylib` 这类真 dylib 才不崩。

## 8. 当前的核心盲点

**盾是怎么拿到"有哪些镜像、地址是多少"这份准确列表的？**

它没有导入任何 `_dyld_*` 枚举接口，没用 `dlsym`，没发 `vm_region` 类 mach 消息。
但读的地址和每个镜像基址完全吻合（不是扫描地址空间找 magic 那种做法）。
这份列表的来源还没查明，也就没法从"输入侧"切断判定。

## 9. 下一轮应该先做的事

1. **先确认盾有没有在做自身的完整性检查。** 它导入了 `_class_copyMethodList`、
   `_method_getImplementation`、`_method_getName`、`_timingsafe_bcmp`、`_dlsym`——
   这套组合与 ZDefend 的 `apptampering_hooked`（比对自己导入的函数有没有被换过）
   是同一类。0.0.55 只要挂上 `dlsym`，当次运行就在 T+2 秒死了，**很可能就是自曝**。
   所以接下来所有实验都应当只改数据、不碰任何代码，并且一次只上一个变量。
2. 想办法定位那份镜像列表的来源：可以在 `mach_vm_read_overwrite` 的地址序列上做
   文章——看第一次读之前盾刚读了什么、算过什么。
3. 若列表来源无法切断，退回到"让注入库不存在"这个方向：这需要越狱本体层面的
   per-app 黑名单，属于用户已明确排除的禁区，此路在当前约束下不通。

## 10. 回到用户目标

到现在为止，**App 仍然无法正常使用**。可以看到的全部成果是：弄清了盾的身份、
建立了唯一能观察它的手段、找到了退出点、排除了七种干预方式。
第 9 节第 2 条是当前最有希望的下一步。

---

# Round 5（2026-10-27）：看见判定本身

Round 4 留下的核心问题是"盾从哪拿到镜像列表"。这一轮把它答完了，
并且第一次直接看到了判定是怎么下的、是哪一项在报警。**App 仍然不可用**，
但排查从"猜检测面"变成了"读某一段确定的代码"。

## 1. 镜像列表的来源：dyld 的内存结构，不是任何接口

先把 Round 4 的假设逐个证伪，再给结论。证据来自网关里带真实时刻的完整调用记录。

一次冷启动里，盾在**读第一个镜像之前**只做了三件事：

| 顺序 | 调用 | 说明 |
|---|---|---|
| 1 | `syscall 294` | `shared_region_check_np`，问出共享缓存的实际映射基址 |
| 2 | `syscall 202 mib=[1,2]` | `sysctl`，结果是 `0x0100000000` / `0x4002000000` 一对数值 |
| 3 | `mach_vm_read_overwrite` 读 `缓存基址 + 0`，长度 `0x140` | 拿到共享缓存头原文 |

第 3 步读到的 320 字节开头正是 `dyld_v1  arm64e`，`+0x10` 处 `mappingOffset=0x1c8`、
`mappingCount=6`；紧接着盾按文件 `pread` 了 6 条 `0x20` 字节的映射表项，
完全对得上。**这说明它拿到共享缓存的映射范围，是为了把"住在缓存里的镜像"划出去。**

随后它逐个头读取剩下的镜像。932 个镜像里，共享缓存内 790 个**一个都没读**，
缓存外 142 个读了 141 个。把读到的地址换算成 dyld 的镜像下标，
141 个下标全部落在缓存外，且顺序递增——**它就是按 dyld 的镜像表顺序在走。**

这一步之后到开始读镜像之间**没有任何系统调用**。列表是普通内存读出来的。

## 2. 找到 dyld 的镜像数组，改了没用

在可写内存里按"24 字节记录 {Mach-O 头, 路径指针, 修改时间}"的特征扫，
能找到好几份这样的数组。其中一份长 `0x5a3` 项，末尾三项正是：

```
下标 0x5a0  .../ellekit/libinjector.dylib
下标 0x5a1  .../TweakInject/HSBCHKBypass230226.dylib
下标 0x5a2  .../libellekit.dylib
```

把所有这些数组里的注入条目整条换成一份 App 框架的记录（一次替换 67 条），
盾**照旧**读到那四个注入库的头。所以它读的**不是**这一份。

顺带确认：系统是 dyld4（崩溃栈里全是 `dyld4::`），`_dyld_get_image_header`
在 `libdyld` 里只是个转发桩，真正的实现在 dyld 自己的镜像里——
而 dyld 的进程内本体**不注册成镜像**，所以从 `_dyld_image_name` 里找不到它。

## 3. 判定的形状：一张检查表

沿着退出那一刻的帧指针往上走，退出链路是：

```
exit(+0x5d842c) ← +0x40e840 ← +0x5d908c ← +0x5d8f5c ← +0x5d8890 ← +0x713d40
```

`+0x5d8ed0` 这个函数把判定讲得很清楚：

1. 取一个单例（`+0x5d8490`，指针存在全局 `+0x8509d0`，惰性创建）；
2. **复制**它在 `+0x10` 处的那条向量（`+0x5d91d0`）；
3. 逐项调用每项的虚函数 `vtable+0x10`；
4. 只要有一项返回非零，走到 `+0x5d8f40`，最终以 `w0=5` 调 `+0x40e7e4` 退出。

在退出那一刻就地读出这张表：

```
检查项数=3
  项0  vtable=0x11442cd50  判定=+0x3a2124  结果=0
  项1  vtable=0x11443ea60  判定=+0x6f3d54  结果=1   ← 报警的是这一项
  项2  vtable=0x114425cf8  判定=+0x221514  结果=0
```

三个判定函数都是盾里的虚拟机函数，需要离线反汇编才能读懂各自在查什么。
这是当前唯一确定的检测点。

## 4. 试着让这张表失效

改的是数据，不是代码：把向量改空（终点写成起点），或者把每一项都改指到
"结果恒为 0"的第 0 项。

**结果：退出链路变了。** 从
`+0x713d40 → +0x5d8890 → +0x5d8f5c`（检查表那条）变成
`+0x43e0fc → +0x43ce78 → +0x37d4d4`（另一条，以 `w0=4` 退出）。
两条最终都落到 `+0x40e7e4`，只是原因码不同。

这条经验值得记：**判定不是一个点，是一组点；堵掉一个只是换一条路。**

但没堵住。原因有两个，都是时序：

- 单例是在检查函数**第一次运行时**才惰性创建的，在那之前轮询线程没有对象可改；
- 检查函数遍历的是那条向量的**副本**，副本在循环开始时就已经拷好，事后再改原件够不着。

尝试提前把单例建出来（直接调 `+0x5d8490`）会立刻 SIGSEGV——盾的初始化没完成时
不接受外部调用。这条路也划掉。

## 5. 排除掉的一个假设

一直怀疑它把主二进制的 load command 从磁盘读出来跟内存比。实测：

- 它确实 `open` 主二进制后按 `pread` 逐条读 load command（偏移 `0x0` 到 `0x5670`，
  先读 8 字节 `cmdsize` 再读整条命令，一共 449 次 `pread`）；
- 但把内存里同一段 24576 字节 dump 出来跟磁盘原文比对，**逐字节完全相同**。

所以这条比对是过的，不是它报警的原因。（顺带说明：这也意味着主二进制没有被人动过。）

## 6. 这一轮新增的工具

- **每条记录带真实时刻**：网关里用 `mrs x0, cntpct_el0` 取硬件计数，
  排空线程用两次采样标定每毫秒的计数再换算。寄存器读不调库，符合网关的约束。
- **帧指针回溯**：网关入口把 `x29` 存进记录，排空时沿帧链走，只保留落在
  盾镜像范围内的返回地址。退出链路和镜像读取的发起位置都是这么拿到的。
- **判定现场读检查表**：在 `emergency_line`（退出系统调用前的那一句）里
  直接读单例和容器，并逐个调用检查项，拿到 `结果`。

## 7. 未解与下一步

1. **`+0x6f3d54` 到底在查什么。** 它返回 1，是明确报警的那一项。
   它是虚拟机函数，静态读需要先摸清那套分发的形状；更快的办法是
   在它运行的那几毫秒里把它的输入（它读过的内存、它的参数对象）记下来。
2. **另一条退出路径（`+0x37d4d4`，原因码 4）的触发条件。**
   它在 92ms 到 101ms 之间发生，这段时间里**没有任何系统调用**，
   说明是纯内存判定。
3. 这两条路都不是最终答案——把检查项都改成"通过"只会在别处再冒出来。
   真正要解决的是让盾的**输入**不含注入痕迹，也就是第 2 节里没找到的那份列表。

## 8. 补充实验（同一天，接在 Round 5 之后）

| 干预 | 结果 |
|---|---|
| 把检查对象 `+0x08` 那个全 1 位掩码清零 | 无效，两条退出路径照旧 |
| 提前调 `+0x5d8490` 把单例建出来，再清空 | **SIGSEGV**——盾的初始化完成之前不接受外部调用 |
| 把报警项 `+0x6f3d54` 的头两条指令改成 `mov w0,#0; ret` | **退出点又换了**：从检查表那条变成 `+0x43a190`（初始化路径内），且两次运行中有一次 SIGSEGV |

最后一条是这一轮最有信息量的负面结果：**判定不止一处**，把检查表那一项改掉之后，
初始化路径里还有另外的判定点（`+0x43e0fc → +0x43c978 → +0x43a190`）。
单点改代码只会把退出换到另一条路上，还可能把自己打崩，所以已经全部关闭，
探针恢复到只观察（0.0.100）。

改代码那次用的页权限处理值得记：`mach_vm_protect` 改成可写、写完立刻恢复
`READ|EXECUTE`，再 `sys_icache_invalidate`。直接用 `MSHookFunction` 会 SIGBUS。

## 9. 拦截的最后一道墙：注入本身无法对单个 App 关闭

这一节是 Round 5 之后继续尝试的结果，结论是**当前约束下这条路走到头了**。

| 尝试 | 结果 |
|---|---|
| 把上报函数 `+0x40e7e4` 改成直接返回（一次覆盖所有退出路径） | 补丁装上（`ok=1`），进程 **SIGBUS**——盾的自检抓到了代码改动 |
| 就地改注入库的 `LC_ID_DYLIB` 路径（字符串在代码页里，改它等于同时改 dyld 列表与 LC_ID_DYLIB，两边永远一致） | `systemhook` 的路径太短写不下；能写的那些一写就 SIGBUS，同样卡在代码签名上 |
| 清空检查表 + 重定向注入库的镜像读取，持续高频轮询 | 重定向生效 669～1327 次，检查表在 93ms 清空，但盾在 ~98ms 仍走检查表那条退出——向量被重新填回去了，我们始终晚一步 |

**根本原因**：Round 2 就测过——把本项目的 tweak 全部移走，App **仍然** `exit(1)`。
也就是说触发条件是越狱环境本身的注入（`systemhook.dylib` / `libinjector.dylib` /
`libellekit.dylib`），不是我们的探针。而设备上的 ElleKit 没有按 App 排除的配置：
`libinjector.dylib` 里只有 `/var/jb/usr/lib/TweakInject/` 和 `.plist`，没有任何
blacklist / exclude / bundleid 一类的开关，它是无条件注入的。

于是形成一个闭环：**App 只要被注入就自杀，而注入无法对单个 App 关闭**——
除非改越狱本体，那是用户明确排除的禁区。

当前可选的只有两条，都需要用户决定：

1. **在越狱侧做 per-app 排除**（改 `libinjector` 或换支持排除列表的注入器）。
   这是唯一能让盾看到"干净进程"的路径，但违反"不动越狱本体"的约束。
2. **继续在进程内打**：需要先解决"检查表被重新填充"的时序，并且还要同时解决
   第二条退出路径（原因码 4）。工程量大，且改代码已被证明会触发自检。
