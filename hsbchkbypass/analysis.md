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

## 退出机制：尚未定位

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

主二进制的 `__TEXT` 在磁盘上是加密的（`LC_ENCRYPTION_INFO_64` 的 cryptid=1），
所以对着文件扫 svc 只能得到噪声，必须在进程里扫已解密的内存。但进程只活
不到一秒，探针注入后到进程消失之间还剩不到 900ms，运行时扫描没能跑完。

下一步可以试的方向：

1. 把扫描拆成按镜像单位的多个任务，优先只扫主二进制最大的那个可执行段；
2. 用 `DYLD_INSERT_LIBRARIES` 或 `__attribute__((constructor(101)))` 更早注入，
   挤出一部分启动时间；
3. 直接 hook `mach_vm_region` 与 `task_terminate` 一类的内核接口调用，看是不是
   外部（SpringBoard / runningboardd）把进程收走的；
4. 检查 `MobileSecurity` 里 `_abort` 的调用点，虽然它不像检测器，但它是唯一导入了
   终止原语的框架之一。

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

`dlsym(RTLD_DEFAULT, ...)` 找不到那些 Swift 符号，是因为它们没有被导出到动态符号表。
要 hook 得先按镜像基址加偏移算出地址，或者遍历 Swift 的 mangled 名段。
