# 汇丰香港越狱检测向量

## 目的

本文档汇总汇丰香港 App 已查明的检测组件、退出机制排查结论与当前进度。
**状态：排查中，没有可用版本。** 判定引擎已确认为 `hsbchkmobilebankingx`（Promon
SHIELD 的 libshield），已能接管它的私有系统调用网关并观察全部系统调用，退出点已定位到
`+0x5d842c`；但还没能让 App 正常使用。

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
