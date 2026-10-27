# 汇丰香港越狱检测向量

## 目的

本文档汇总汇丰香港 App 已查明的检测组件、退出机制排查结论与当前进度。
**状态：排查中，没有可用版本。**

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

## 退出机制：尚未定位

已经排除的路径（每一条都是实测零命中）：

| 手段 | 结果 |
|---|---|
| hook `exit`/`_Exit`/`_exit`/`abort`/`kill`/`pthread_kill`/`raise` | 零命中 |
| hook `syscall(2)`（观察 SYS_exit / SYS_kill） | 零命中 |
| `atexit` 回调 | 没触发，说明不是正常退出流程 |
| 1～31 号信号处理器 | 没收到任何信号 |
| 磁盘文件静态扫描内联 `svc` | 主二进制与 9 个重点框架都没有 exit 类 svc |
| 崩溃报告 / Jetsam 记录 | 都没有 |

**这些零命中是可信的**：探针里对 `getpid` 做了一次自检 hook，调用一次命中一次，
证明 `MSHookFunction` 在这个进程里工作正常。没有自检的话，
"hook 没装上"和"hook 装上了但没人调用"看起来完全一样。

### 为什么静态扫描 svc 不成立

主二进制的 `__TEXT` 在磁盘上是**加密的**（`LC_ENCRYPTION_INFO_64` 的 `cryptid=1`）。
对着文件扫出的 svc 只能是噪声，必须在进程里扫已解密的内存。但进程注入后到消失之间
只剩不到 900ms，运行时扫描没能跑完（0.0.4 版用 `memchr` 加速后仍然不够）。

框架的情况不同：9 个重点框架的 `cryptid` 都是 0，可正常静态扫描，结果是零。

## 可继续的方向

1. 把运行时扫描拆成按镜像分片，优先只扫主二进制最大的可执行段，争取在 900ms 内完成；
2. 用更早的注入时机（`DYLD_INSERT_LIBRARIES` 或更低的 constructor 优先级）挤出时间；
3. hook `task_terminate` 一类的内核接口，看是不是外部（SpringBoard / runningboardd）
   把进程收走的——`killall` 与 Jetsam 都不留痕，这条还没排除；
4. 检查 `MobileSecurity` 里 `_abort` 的调用点。它不是检测器，但它是少数导入了终止
   原语的框架之一。

## 排查方法（可复用）

这一轮虽然没有定位到根因，但确立了三件可复用的事：

- **探针必须有自检。** 对任意无害函数（比如 `getpid`）先装一次 hook 再自己调一次，
  命中才算 hook 机制可用。否则"零命中"这个结论没有意义。
- **日志必须带时间戳。** 目标是启动不到一秒就死的进程时，没有相对时间戳的日志
  无法区分"某一步慢"和"某一步之后进程没了"。
- **磁盘上的加密段不能静态扫。** 先读 `LC_ENCRYPTION_INFO_64` 的 `cryptid`，
  为 0 才扫文件，为 1 只能在运行时扫内存。

## 环境限制

设备上的 `frida-server` 能启动，但 `frida.spawn` 对所有 App 都返回
`mach task is gone`，**包括能正常运行的汇丰中国**。也就是说这台设备上的 frida
只能 attach、不能 spawn，"启动前布好 hook"这条路用不了。attaching 到已经起来的
进程也来不及——进程在 900ms 内就没了。
