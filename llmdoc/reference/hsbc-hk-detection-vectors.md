# 汇丰香港越狱检测向量

## 目的

本文档汇总汇丰香港 App 已查明的检测组件、退出机制排查结论与当前进度。
**状态：排查中，没有可用版本。** 判定引擎已确认为 `hsbchkmobilebankingx`（Promon
SHIELD 的 libshield），退出点已定位到 `+0x5d842c`；但还没能让 App 正常使用。

> ⚠️ **2026-10-30 Round 27 更正两处旧结论**，读后文时请一并按这里重读：
>
> 1. 早期"已能接管私有网关并观察全部系统调用"只在旧版本成立。当前 3.69.12 里，
>    那 83 个「读槽再间接跳转」的调用点**一次都不执行**，网关槽是死代码。
>    把槽强行写成自己的入口之后，记录仍然是零。
> 2. **不加载本 tweak 时 App 本来就在约 570ms 退出。** 此前反复引用的
>    "挂不挂 tweak 一致"是对的，但没有量到具体数字，容易被误读成
>    "我们的改动把 900ms 变成了 900ms"——实际是 570ms 对 640–670ms。
>
> 这两条的含义见文末「Round 27」一节。

## 目标与背景

- 目标 App：`hk.com.hsbc.hsbchkmobilebanking`
- 当前版本：**`3.69.12`（build 125629）**，2026-10 实测
- 主 Binary：`HongKong.app/HongKong`（arm64, ~232 MB）
- 包含 279 个 framework，其中与设备安全相关的不超过 8 个
- 数据容器：`/var/mobile/Containers/Data/Application/A2267FB5-8887-41EE-A5B7-BE6748265D29`
- 测试设备：iPhone 13 Pro / iOS 15.4.1（22215，rootless Dopamine + ElleKit）
- 对应 tweak：项目目录 `hsbchkbypass/`，包名 `page.0x01.hsbchkbypass`

> ⚠️ **2026-10-27 更正：香港版用 Promon SHIELD。**
> `hsbchkmobilebankingx.framework`（9 MB）就是 Promon 的 libshield，
> `__cstring` 里有 263 条 `/mobile/release/shield/third_party/libressl/` 构建路径，
> 主二进制引用 `PRMShieldEventManager`。它的网关偏移、全局槽偏移、安装点、mach 封装
> 地址与本文档记录的中国版 3.72.15（Promon 时代）**逐字节一致**，是同一份构建。
>
> 两边仍然不能共用同一份 tweak：中国版 3.75.0 已经换成 ZDefend，香港版还是 Promon；
> 而且香港版的判定跑在 `hsbchkmobilebankingx` 里，中国版在 `hsbcchinax` 里。
> 中国版现状见 `llmdoc/reference/hsbc-china-detection-vectors.md`。

## 检测栈

| 组件 | 大小 | 作用 |
|---|---|---|
| **`hsbchkmobilebankingx.framework`** | **9 MB** | **Promon SHIELD 的 libshield，判定与退出都在这里** |
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

> 补充（2026-10-28 Round 22）：这个"退出码 1"**不是 libc 的 `exit`/`_exit` 发出的**。
> 在 libc 层装好钩子、完整跑一次启动，一条命中都没有；真正结束进程的是盾自己
> `+0x5d842c` 末尾那次裸系统调用。详见下面的「退出是盾自己发的」。

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

## Promon SHIELD 的私有系统调用网关（2026-10-27 Round 4）

这一节是当前最有价值的部分：它解释了为什么前十几种拦截手段全部零命中。

### 结构

| 项 | 镜像内偏移 | 说明 |
|---|---|---|
| 系统调用网关 | `+0x78befc` | `svc #0x80; ret; brk #1`，在 `__TEXT,__const` |
| 网关全局槽 | `+0x8510c8` | 存网关的运行时地址，在 `__common` |
| 网关安装点 | `+0x346c68` | `adrp/add` 算出网关地址后 `str` 进槽 |
| mach trap 封装 | `+0x40c698` | `mov x16,#-0x1f` → 读槽 → `blr x17` |
| 退出函数 | `+0x5d842c` | 无条件 `exit(1)`，四个守卫函数调用 |

全镜像共 **83 个**封装用 `ldr x17,[0x8510c8]; blr x17` 走这条网关。
`x16` 是系统调用号，`x0..x7` 是参数。

**因为这些调用一条都不经过 libSystem 的具名符号**，fishhook 改 GOT、
`MSHookFunction` 挂 `exit`/`_exit`、hook `syscall`、扫内联 `svc` 全都覆盖不到。

### 接管方式：只改一个数据槽

网关槽是普通可写数据，83 个封装每次调用都重新读它。把它换成自己的入口就完成接管，
**不需要改任何代码，不需要 `vm_protect`，不碰 `__TEXT`**。

网关入口有两条硬约束：

1. **不能调用 libc。** 盾会在 libc 尚未就绪的线程上调用网关，处理函数里一进
   `snprintf`（要读区域设置和线程局部存储）就踩空。实测崩溃栈是
   `hsbchkmobilebankingx +0x448da0 → gw_entry → gw_log → snprintf → SIGSEGV@0x50`。
   正确做法是处理函数只把寄存器写进环形缓冲，手写格式化，用裸 `svc #0x80` 的
   `write` 落地。
2. **`x0..x15` 必须全部保存。** 原网关只有 `svc; ret`，除了 `x0`/`x1` 什么都不改。
   中间插一次 `bl` 会按 AAPCS64 把 `x0..x18` 全当调用者保存寄存器用，只备份
   `x0..x7` 会让盾里内联在循环中的计数器悄悄变值。

### 观察到的判定输入

接管后解码 `mach_msg` 请求头：

| 字段 | 值 | 含义 |
|---|---|---|
| `msgh_id` | 4808 | `mach_vm_read_overwrite` |
| `w3` | `0x1_0000_0000` | 目标 task（自己） |
| `w4` | 地址 | 要读的位置 |
| `w5` | 长度 | 常见 `0x20`（32 字节 Mach-O 头）与后续节表 |

一次冷启动约 **750–1500 次**这样的读取，依次扫过进程里每个镜像的基址。
注入库（`libellekit.dylib`、`libinjector.dylib`、tweak 自身）确实在里面。

### 没有导入任何 dyld 枚举接口

`hsbchkmobilebankingx` 的导入表里**一个镜像枚举符号都没有**：没有
`_dyld_image_count`、没有 `_dyld_get_image_header`、没有 `_dyld_get_image_name`，
也没有 `dlopen`。dyld 相关只有 `__dyld_find_unwind_sections`、
`__dyld_register_func_for_remove_image`、`dyld_stub_binder` 三个。
`dlsym` 导入了，但 hook 之后观察到一个调用都没有。

**所以它那份准确的镜像列表从哪来，目前还没查明**，这是当前的核心盲点。
也就没法从输入侧切断判定。

### 已试过但无效的干预

| 干预 | 结果 |
|---|---|
| 拦退出系统调用（网关处返回） | 进程从 ~100ms 活到 15 秒以上，但停在启动图；截断状态机后主线程不再恢复 |
| 置空盾的 71 个 `__mod_init_func` | 无效。盾的初始化走 ObjC `+load`，不走 C 构造函数 |
| hook 三个 `_dyld_*` 枚举接口 | 无效，盾根本不调用它们 |
| hook `dlsym` | 无效，盾一次都没调用；而且挂上之后当次运行 2 秒内就死，疑为自曝 |
| 改写注入库的 `LC_ID_DYLIB` 路径 | 无效。改完必须把代码页恢复成 `r-x`，否则 SIGBUS（代码签名） |
| 把退出函数首条指令改 `ret` | 部分：偶发活过 8 秒，但也出现主线程 `pc/lr/sp/fp` 全零的崩溃 |
| 把注入库的 mach 读取重定向到系统 dylib | 生效 9 次，盾仍在同一处退出 |

重定向那版有个细节：替身**不能选盾自己**——它是可执行文件，第一个 load command 是
`LC_SEGMENT_64`，而解析器期待 `LC_ID_DYLIB`，会顺着垃圾偏移读崩。换成
`libobjc.A.dylib` 这类真 dylib 才不崩。

### ⚠️ 盾可能在做自身的完整性检查

它导入了 `_class_copyMethodList`、`_method_getImplementation`、`_method_getName`、
`_timingsafe_bcmp`、`_dlsym`——这套组合与 ZDefend 的 `apptampering_hooked`
（比对自己导入的函数有没有被换过）属于同一类。

**所以对盾做实验时，应当只改数据、不碰任何代码，并且一次只上一个变量。**

### 平台无关的可复用点

- 遇到「所有基于符号的 hook 零命中」，先怀疑目标有私有 syscall 网关，
  去它的 `__TEXT` 里搜 `svc` 指令和 `ldr xN,[全局槽]; blr xN` 的封装形状。
- 网关槽是可写数据，改它比改代码安全得多。
- 接管任何底层入口时，先想清楚"原实现到底改了哪些寄存器"，按调用约定完整保存。


### 判定本身：一张检查表（2026-10-27 Round 5）

Round 4 停在"盾读每个镜像的头，但不知道列表从哪来"。Round 5 把两件事都答了。

**镜像列表来自 dyld 的内存结构，不经过任何接口。** 读第一个镜像之前，
盾只做了 `shared_region_check_np`（294 号）、一次 `sysctl`（202 号，mib `[1,2]`）、
以及一次对「共享缓存基址 + 0」的 320 字节读取（内容就是 `dyld_v1  arm64e` 头，
`mappingOffset=0x1c8`、`mappingCount=6`），随后按文件读那 6 条映射表项。
用这几步拿到缓存范围，是为了把住在共享缓存里的镜像划掉：932 个镜像里
缓存内 790 个一个没读，缓存外 142 个读了 141 个，顺序与 dyld 的镜像表一致。
这段之后到开始读镜像之间**没有任何系统调用**。

> 可写内存里确实能找到 dyld 的 24 字节镜像记录数组（`{头, 路径, 时间}`），
> 末尾三项就是注入库。但把注入条目整条换掉（一次 67 条）盾照旧读到它们，
> 说明它读的不是这一份。系统是 dyld4，`_dyld_get_image_header` 在 `libdyld`
> 里只是转发桩，dyld 的进程内本体不注册成镜像。

**判定的形状**：`+0x5d8ed0` 取单例（`+0x5d8490`，指针在全局 `+0x8509d0`，惰性创建），
**复制** `+0x10` 处的向量，逐项调用 `vtable+0x10`，任一非零就以 `w0=5` 调
`+0x40e7e4` 退出。三个检查项的判定函数：

| 项 | 判定函数 | 结果 |
|---|---|---|
| 0 | `+0x3a2124` | 0 |
| 1 | `+0x6f3d54` | **1（报警）** |
| 2 | `+0x221514` | 0 |

**改动这张表会让退出链路换一条**：从 `+0x713d40 → +0x5d8890 → +0x5d8f5c` 变成
`+0x43e0fc → +0x43ce78 → +0x37d4d4`（原因码 4）。两条最终都落到 `+0x40e7e4`。

两个时序约束让事后修改无效：单例是检查函数第一次运行时才创建的；
循环遍历的是向量的**副本**，副本在循环开始时已经拷好。
提前调 `+0x5d8490` 把单例建出来会立刻 SIGSEGV。

**排除**：盾确实把主二进制的 load command 从磁盘逐条读出来（`pread` 449 次，
偏移 `0x0` 到 `0x5670`），但内存同一段 24576 字节与磁盘原文逐字节相同，
这条比对是过的。

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

## 先开火的是原因码 4，不是检查表（2026-10-28 Round 7）

把上一轮遗留的干预全部关掉、只保留网关记录之后，基线才第一次干净：

- 8 次冷启动**全部在 51-56ms 以原因码 4 退出**，调用链固定为
  `exit(1) ← +0x40e7e4(w0=4) ← +0x37d4d4 ← +0x43ce78 ← +0x43e0fc`。
- 检查表那条链（`+0x713d40 → +0x5d8890 → +0x5d8f5c → +0x5d908c`，原因码 5）
  在这 8 次里一次都没出现，单例取用 `+0x5d8490` 也从未被调用。

**所以 item1 是真判定，但不是最先开火的那一道。** 排查顺序要按时间，不按"看起来像"。

原因码 4 之前的动作（40-64ms 每 3ms 一次全线程快照，带 `x0..x8`）：

1. **逐张读镜像头。** 每个地址读 0x20 字节，再读 `base+0x20`、长度等于 `sizeofcmds`。
   一次运行读 148 个不同地址，4 个注入库里有 3 个在列。
2. **逐镜像算 xxHash64。** `+0x65bfa8` 是 4 路并行的 xxHash 主循环
   （素数 `0xC2B2AE3D27D4EB4F`、`0x9E3779B185EBCA87`），`x1` 就是当前指针。
   调用点 `+0x43cccc` 返回后立刻 `cmp x21, x20`（期望值 vs 算出的哈希），
   紧接着就是 `mov w0, #4`。

两条否证（各一次运行）：

- 把落在注入库上的读取**改指到 App 自己的一个框架**（结构完整、签名有效的 dylib 头，
  相对偏移不变）：仍然原因码 4。
- 把落在注入库上的读取**改成返回一整页零**（没有 Mach-O magic，认不出是镜像）：
  仍然原因码 4。

控制实验：`try_takeover()` 直接返回、网关槽不动，App 照样以退出码 1 结束，
时间与接管时一致。**判定与探针的接管无关。**

### 那步 xxHash 是自检，而且自检是干净的

0.2ms 采样把哈希阶段的指针抓下来，用运行时镜像表反查：`x1` 落在的全是
**盾自己**的代码页（`+0x18000`…`+0x318000`）。再直接比对：盾的 `__TEXT`
（0x80c000 字节）与磁盘文件**逐页一致，不同的页数 = 0**；App 各框架也一致；
唯一不同的是主二进制 `HongKong` 的 `+0x8000`，而它的 `__TEXT` 是 FairPlay 加密的
（`cryptid=1`），内存里是解密后的字节，差异本来就应该存在。

**所以原因码 4 不是"发现内存里的代码被改过"。** 导入表也只有 libSystem，
没有任何 Security.framework 符号，它做不了 `SecStaticCode` 那类签名校验。

### 网关看不到的一整类证据

盾从共享缓存头、dyld 结构、自己构造的清单里读数全是普通内存访问，不经过网关，
**探针完全看不见**。所以"改注入库头部读取"这类手段从原理上就只能影响走网关的那部分，
对直接内存读来的清单无效——这解释了 Round 7 两次否证为什么都没反应。

### 复用要点

- **先做"零干预"基线，再谈手段。** 上一轮的结论是在"读未映射地址"这个变量还在场时
  得出的，方向被带偏了一整轮。
- **干预开关要在一轮结束时关掉并写进记录。** 残留的破坏性实验会让后续所有结果
  无法归因，而表现是"改了但没用"。
- **一个进程里只能有一个轮询线程。** 循环体里 `pthread_create` 会造成成百上千个线程
  同时改写同一块数据、同时写日志，现象是结果时好时坏、日志行被切碎。
- **时间戳锚点要固定。** 以"标定时刻"为锚点、而标定又发生在启动末尾还带睡眠时，
  所有记录会显示同一个毫秒数，时序信息等于零。


## 拦下退出不能解决问题：App 卡在盾的检查结果上（2026-10-28 Round 12）

这一条推翻了一个持续很多轮的基本假设，后面的排查都应该先读它。

**现象。** 把盾的退出流程改成"那条线程原地停住"或"按栈帧正常返回"之后，
进程不再 50 毫秒就死，能活十几秒，但屏幕全黑，所有线程停在
`libsystem_kernel` 里等消息，盾自己的系统调用计数也随之停止增长。

**含义。** App 的启动被盾的检查结果卡住：检查不通过，盾退出、进程死；
检查被我们打断，App 就无限期等下去。**"拦住退出"这条路即使做到完美，
也只能把一次 50 毫秒的崩溃换成一个无限期的黑屏。**
要让 App 可用，唯一的方向是让盾的判定真正通过。

**随之作废的做法。** 以往所有基于"不让进程退出"的干预，其正面结果都不再算数——
包括早期"拦下退出后进程从 100 毫秒活到 15 秒"这类观察。

**顺带纠正两处旧笔记。**

- `jigsaw` 不是文件。盾里有 `no.promon.shield.ios.model.JigsawInformation` 与
  `JigsawDataBlock`，Jigsaw 是 Promon 自己的完整性清单模型。
  把"`jigsaw.txt` 打不开"当成拆包痕迹，是读错了。
- 盾确实导入了 `getenv` 与 `_uname`，"没有这两个"的旧说法是错的
  （不过实测运行期盾没用它们，只看到 Foundation 问了一次 `CFFIXED_USER_HOME`）。

**剩下唯一可用的切入点。** 检查表从建成到判定之间没有可插入的空档
（Round 6 已记录"刚重建、马上复制"）。而检查项对象如果是长期存在的，
就可以在窗口之外提前把它们的虚表指针换成一份拷贝，只改 `+0x10` 那一格。
注意 0.0.170 那几次启动里，检查表的向量**始终是空的**（采样 1212 次全为 0），
判定走的是另一条链（`+0x5d87a4 → +0x43d6fc`），这条路要先查清判定从哪来。

## 盾对自己代码段的自检是**通过**的（2026-10-28 Round 19）

这一条推翻了"盾因为自检失败才判定篡改"的假设，后续排查应先读它。

`+0x43cc08` 那段用外部线程采样抓到了现场：它对 `hsbchkmobilebankingx` 的 `__text`
整段（`0x8000` 起、`0x76c5fc` 字节）做**标准 xxHash64**，比较值是一个常量。

| 项 | 值 |
|---|---|
| 哈希函数 | `+0x65bf44`，参数 `(指针, 长度, seed)`；主循环在 `+0x65bfa8` |
| seed | `0x9fca7ba5c41b2cec`（由四个累加器反推，两次采样互相印证） |
| 覆盖区间 | 镜像 `+0x8000` 起 `0x76c5fc` 字节，正好是 `__text` 全段 |
| 期望值 | `0x8d2fe35465f18925`（四次运行完全相同） |
| 磁盘复算 | 用同一个 seed 对磁盘文件的 `__text` 算，得到 `0x8d2fe35465f18925`——**逐位相同** |

**所以内存里的 `__text` 与磁盘完全一致，这个自检每次都过。**
"改盾的代码会被抓"依然成立（改一个字节哈希就变），但"没改却判定失败"的原因在别处。

复算时两个坑：标准 xxHash64 处理剩余 4 字节加的是 `PRIME64_3`；
mergeRound 里反汇编显示的 `0xdef35b010f796ca9` 等于 `P1 × P2 (mod 2^64)`，按标准实现即可。

### 上报函数的语义：原因码不决定生死，说明文字才决定

`+0x40e7e4(reason, desc)` 是所有上报的唯一出口：

```
desc == NULL 或 desc[0] == 0  → 取 [0x848d70] 算出的函数指针并退出
desc 非空                     → 只上报一笔，正常返回，程序继续
```

所以"原因码 4"本身不是致命信号，它是**第一个没有说明文字的失败**。
`+0x43d514` 先报告过一次原因码 1（带说明、没退出），之后才走到无说明的那次。

### 观测上的两个陷阱

1. **`cntpct_el0` 会停。** 进程运行到 110ms 前后，`mrs cntpct_el0` 不再前进，
   于是所有基于它的节流与时间戳全部冻结。日志看起来"停在 110ms"，实际进程活到
   600–700ms。心跳改用 `clock_gettime(CLOCK_UPTIME_RAW)` 后日志才继续往前推。
2. **网关接管不是一个中性的观测手段。** 接管时进程能活 5.9 秒、日志写到 5734ms；
   不接管时 600–700ms 就以退出码 1 结束。早期所有"接管状态下"的时序结论都要按这个前提重读。

### 自检可以被旁路（Round 20）

自检是对盾自己 `__text` 整段做的一次 xxHash64，比较点在 `+0x43ccdc`：

```
43ccdc: cmp x21, x20      ; 期望哈希 vs 实算哈希
```

把它换成 `<subs xzr, x21, x21>`（自己减自己）之后，条件码永远相等、寄存器不被改动，
自检就形同虚设。这条补丁本身也落在被哈希的代码段里，但它 3ms 就写好，
而自检 44ms 才开始，所以来得及。

**意义**：改盾的其它代码不再被自查发现，实测两处改动都没有 SIGBUS/SIGILL。
在这之前，"不能改代码"是整条路线的硬限制。

### 在盾的函数入口装记录桩

自检旁路之后，可以在任意函数入口插桩。做法是：把函数前 16 字节写成
`ldr x16,#8; br x16; <桩地址>`，桩里先记录、再**原样重放被替换掉的那几条序言指令**、
最后跳回原函数第 5 条（续行地址放在一个全局里，运行期填好，避开 ±128MB 的分支范围）。
这样函数行为不变，只是多一条记录。

已装的两个桩：`+0x5d842c`（退出）与 `+0x40e7e4`（上报，参数 `(原因码, 说明指针)`）。

### 已定位的一个判定点

```
+0x5d8758:  ldrb w8,[x0,#0xa] ; cbnz → 返回     ; 只做一次
+0x5d87a0:  bl 0x712668                          ; 判定，结果在 w0
+0x5d87a4:  tbnz w0,#0,0x5d87e0                  ; bit0 置位 → 正常返回
+0x5d87d4:  blr x8                               ; 否则调退出(0x5d842c)
```

把 `tbnz` 换成无条件跳往 `0x5d87e0`，这一次判定就等于永远通过。

### 观测限制：40ms 之后我们自己的线程不再运行

心跳线程、定时器信号采样、排空线程在 40ms 前后一起静默，而进程要活到 500–700ms。
排除了三种解释（换时间基准、每次重新 open 文件、用预先打开的描述符），
最后确认是**线程本身被停住**：忙等线程连续跑到 976 轮就在 40ms 停住、轮次没有断档；
进程外看进程一直处于 `R` 状态、CPU 时间持续增长。

**所以 40ms 之后的一切观测只能靠"改盾的代码、让盾的线程替我们记录"。**

另外，盾会在 40ms 之前把我们的 SIGILL 处理函数换成它自己的（读回来的处置函数
低 12 位是 `0x24c`，我们的是 `0xdfc`）。这些 SIGILL/SIGSEGV 也**不产生系统崩溃报告**，
说明是盾自己处理掉的，属于"伪装成崩溃"。

### 已排除的一个假设：镜像登记名

把注入库在 dyld 里登记的名字改成普通系统库（`/usr/lib/libobjc.A.dylib` 等）之后，
原因码 4 照旧上报。所以盾读的是每个镜像**自己 LC_ID_DYLIB 里的字符串**，
不是 dyld 登记的名字——这也解释了为什么之前改 dyld 数组一直无效。

## 退出是盾自己发的，挡住之后还有第二刀（2026-10-28 Round 22）

### 结论

1. 进程的结束**不走 libc**。`exit`/`_exit` 钩子装好了、整次启动跑完，
   日志里一条退出记录都没有。真正发出结束系统调用的是 `+0x5d842c` 末尾的
   `ldr x17,[x17,#0xc8]; blr x17`。
2. 让盾不启动不行。把 `+load`（`+0x228f74` 的 `b 0x43e0ac`）改成 `ret`，
   进程 545ms 死于 SIGSEGV——App 硬依赖盾初始化时建立的对象。
3. 让盾不检查只换来时间。把两个事件管理器的 `performSecurityChecks`
   （`+0x22910c`、`+0x693f88`，都是 `mov w0,#1` 之后 `b 0x38d974`）里的 `b`
   换成 `ret`，退出时刻从 553ms 推到 910ms，仍然以退出码 1 收场。

### 两次退出调用的调用栈

在退出函数入口装"记一笔然后返回"的守护桩，顺着帧链回推，两次都抓到了：

| 次数 | 直接调用者 | 往上一层层展开 |
|---|---|---|
| 第 1 次 | `+0x40e840`（上报闸门 `+0x40e7e4` 的退出分支） | `+0x7133e8` → `+0x5d87a4` → `+0x43d6fc` → `+0x43e0fc` |
| 第 2 次 | `+0x40ffcc`（击杀帮手 `+0x40ff8c` 的 `blr`） | `+0x40fb40` → …… → `+0x7133e8` |

两条都回到虚拟机 `+0x712668`。`+0x40fb3c` 是 `ldr x8,[x0,#0x10]; blr x8`，
也就是说"杀进程"在盾里是一个**可替换的回调**，不是硬编码的调用。

### 挡住退出之后死在哪

守护桩返回之后进程不会立刻死，活到 842–910ms，改为 SIGILL。在桩里停 300ms、
每 10ms 写一条心跳，30 条全部写满——**停顿期间进程完全活着，我们的代码照常运行**。
所以致命的那一刀在退出调用**返回之后的续行路径上**，是盾发现"退不掉"再补的。

### 我们的故障处理器抓不到那一刀

在守护桩里做过两次自检，都证明处理器是活的：给自己发 `SIGUSR1` 收到了；
自己执行一条 `udf #0`，处理器记下 `pc` 并把 `pc` 往后挪一条，执行继续。
但真正致命的那次 SIGILL 一次都没进来。处理器在 26ms 装好、850ms 又重装过，
中间没有任何记录。剩下的解释是投递层被绕开：盾用裸系统调用改信号处置或线程掩码，
libc 层的 `sigaction`/`sigprocmask` 钩子看不到；同步硬件异常一旦被掩码挡住，
就不会走到用户态处理器。

### 试过但不成立的三条

| 做法 | 结果 |
|---|---|
| 拦 libc 的 `exit`/`_exit` | 无效，盾根本不走这条路 |
| 批量把 1641 条 `udf`/`hlt` 换成 nop | 它们在 53 个页面里成簇出现、紧跟 `bl` 之后，立即数呈 `0x14/0x4c/0x6c` 的序列——是数据表，不是陷阱 |
| 接管网关槽 `+0x8510c8` 记录信号处置 | 只拿到 21 条记录就断了，最后一条调用点是垃圾值，557ms SIGSEGV。接管本身会把盾弄崩 |

## 插件的能力边界（2026-10-28）

面向"能不能用插件解决"这类问题，把边界写清楚，省得反复试：

- **不能让 dyld 不加载某个框架。** 插件和盾是同批镜像，dyld 启动时按 load
  command 全部映射并跑初始化器。插件能做的只是在盾的初始化器跑之前改它的代码。
- **不能在 App 硬依赖盾的情况下摘掉盾。** `+load` 改成 `ret` 之后 545ms SIGSEGV，
  说明 App 会去用盾初始化时建好的对象。
- **不能从 libc 层隐藏越狱痕迹。** 盾的检测走自己的裸系统调用，不经过 libc。
  能碰到的只有它的网关槽，而接管网关目前不稳定（见上一节）。
- **能做的只有改判定本身**，也就是读通 `+0x712668` 这个虚拟机，
  弄清原因码 5 对应哪个环境事实。

## Round 27：所有用户态接缝都不通（2026-10-30）

这一轮没有取得让 App 可用的进展，但把两条一直默认成立的前提推翻了，
也把"为什么观测总是停在 130ms"查清楚了。**后续接手请先读这一节。**

### 基线：不加载 tweak 时 App 也是死的

| 条件 | 存活 |
|---|---|
| 完全不加载本 tweak | **575ms / 562ms** |
| 加载全部补丁（0.0.303） | 643ms |
| 加载全部补丁（0.0.305 / 0.0.307） | 670ms / 672ms |

所以此前"挂不挂 tweak 表现一致"这条观察是对的，但具体差距一直被忽略：
**所有这些工作（自检绕过、各处补丁）的净效果只有 60–100ms。**
在谈任何一个新手段之前，先想清楚它能否改变这 570ms 的基线，
否则很容易把噪声当成进展。

### 我们自己的执行通路在 52–130ms 之间全部消失

- 心跳线程的忙循环停在 1386 轮（上限 2000），最后一条记录是 123ms；
- 定时器信号 `ITIMER_REAL`（2ms 一次）停在 78ms；
- 文本日志停在 79ms；
- 主队列上 `dispatch_after` 排的 block **一条都没执行**，说明主线程在构造函数
  之后再也没有进入 runloop；
- 从进程外看，同一时刻进程状态是 `Rs`、累计 CPU 时间持续增长
  （0.14s → 0.29s → 0.35s），**不是被挂起**。

结论：进程活着并且在跑，但凡是"我们自己创建的"执行体都没了。
**40ms 之后的一切观测只能靠改盾的代码、让盾的线程替我们记录**——这条旧结论
在 Round 22 就写过，Round 27 只是把时间窗精确到了 52–130ms。

另一个细节：`task_threads` 这个枚举调用本身会让我们的线程死得更早
（0.0.298 采样到 54ms、0.0.299 到 52ms，而不采样时忙循环能写到 123ms）。
盾在监控 mach 线程枚举，这是常见的反调试做法，也解释了为什么
"从内部枚举线程"这条观测路线走不远。

### 网关槽能接管，但那 83 个调用点根本不执行

轮询来不及（槽在 39ms 之前一直是 0，而我们的线程活不到它被安装的时刻），
于是换成"废掉安装者、自己写槽"：

```
346c68  adrp x8, 0x851000
346c6c  adrp x9, 0x78b000
346c70  add  x9, x9, #0xefc     ; x9 = 0x78befc，盾的总网关
346c74  str  x9, [x8, #0xc8]    ; ← 改成 nop
```

构造函数里直接 `*g_slot = &gw_entry`。结果：槽在 39ms 确实变成我们的入口
（`0x11e30b9a4`），之后也没被盾改回去。**但 `gw.bin` 里一条 `GWREC` 都没有**，
把记录条件放宽到"前 200 次调用无条件记录"之后仍然是零。

**所以那个网关在当前版本里是死代码。** 静态上看起来是 83 个调用点，
运行期一个都不走。这个文件里 `svc #0x80` 也只出现 1 次（就是 `0x78befc` 本身），
且没有任何 `bl 0x78befc`。盾带 `__ostekake` 段、会在运行期改写自己的代码，
真正在用的 syscall 桩很可能只在内存里存在。

### 盾也不调 libc 的文件操作

盾的导入表里有 `fopen` / `opendir` / `readlink` / `realpath` / `getenv`，
这些是越狱检测最常见的入口。五个全部挂上、只记调用者落在盾里的：**零条**。
去掉过滤、记录全部调用之后，整个启动过程只有 1 条，是 ellekit 在查
`InjTest.dylib`，与盾无关。

也就是说：钩子在 32ms 装好之后，盾**再没有通过 libc 做过任何文件探测**。

### 逐个验过、全部零命中的通道

| 通道 | 结果 |
|---|---|
| 盾自己的网关槽（83 个调用点） | 能接管，零调用 |
| 上报闸门 `+0x40e7e4` | 零调用 |
| 击杀帮手 `+0x40ff8c` | 已 NOP |
| 退出函数 `+0x5d842c` | 零调用 |
| libc `exit` / `_exit` / `kill` / `raise` / `abort` | 零调用 |
| `pthread_mach_thread_np` | 零调用 |
| `mach_port_destroy`（盾唯一导入的 mach 端口函数） | 零调用 |
| libc 文件操作五件套 | 零调用 |
| 定时器信号 | 78ms 后不再投递 |
| 主队列 block | 从未执行 |

而 App **必然**在 570–670ms 之间消失，无崩溃报告。

**这已经不是"还没找到那一条路径"，而是"所有用户态的接缝都不通"。**
剩下的可能只有两种：盾用运行期生成的 syscall 桩直接和内核打交道，
或者终结由系统侧（SpringBoard / launchd）根据盾的某种外部信号完成。
两种都超出进程内 tweak 能触及的范围。

### 探针陷阱：`patch_word` 会覆盖 `MSHookFunction`

这一轮发现的一个具体错误，值得单列，因为它的表现是"钩子从来不起作用"：

`MSHookFunction` 在函数首部写一段跳转，`patch_word(addr, 0xd65f03c0)`（`ret`）
也在同一位置写 4 字节。两者同时开的时候，后写的那个把前一个覆盖掉。
0.0.287 之前上报闸门一直是这个状态——**上报钩子挂了十几版，一次都没被调用过**，
所以此前所有"上报钩子零命中"的结论都要重读。

排查方法：凡是同时用了 `MSHookFunction` 和 `patch_word` 的地址，
回读首字确认留下的是哪一个。

#### 顺带两条工具教训

- **怀疑"本库没被注入"时，先编一个只有一句 `fopen` 的最小 dylib 做对照**，
  用同样的 plist 部署。它写出文件 = 注入链正常；写不出来 = 注入链有问题。
  这一轮因为少了这个对照，误判成注入失败，还顺手重启了两次 SpringBoard，
  把设备锁屏、污染了后续几轮测量。
- **不要用重启 SpringBoard 去验证任何假设。** 它必然导致锁屏，
  而锁屏会让后续所有"存活时间"测量失去可比性。
