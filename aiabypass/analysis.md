# 友邦友享越狱检测绕过：分析记录

目标 App：`com.aia.china.YoubangHealthRelease`（友邦友享），版本 6.9.33，build 2026102012。

两台设备上安装的主二进制 `KYHAppStore` 完全一致（md5 `b779432ab7d51192e18446ea6e166910`，70 530 224 字节），因此二进制内的文件偏移可以跨设备复用；但 App 数据容器的 UUID 和 `/private/var/containers/Bundle/Application/<UUID>/` 路径每台设备、每次重装都会变，必须重新获取。

| 设备 | 端口 | 系统 | 越狱 |
|---|---|---|---|
| iPhone 13 Pro | 22215 | iOS 15.4.1（19E258） | rootless，预启动路径 `/private/preboot/9C4B5D63.../jb-0/procursus` |
| iPhone 14 Pro Max | 22216 | iOS 16.3.1 | rootless，Dopamine + ElleKit |

## 检测组件

App 内置 `JMCodeProtectKit.framework`（`com.IPACodeProtectTwoSDk`，v3.0.0.20260903.1），混淆标记 `ipa-asm-obf`、`ijm-obf-idc`、`ijm-obf-icf`、`ijm-obf-ivmp`。这是一个 RASP（运行时应用自我保护）组件：在进程内持续检查环境，判定失败后让进程退出，表现为"打开就闪退"。

## 已确认的结论

### 1. 检测对象是越狱注入基座，与装了哪些 tweak 无关

在 22215 上依次移走 `FLEXList`、`noJailbreak`、`Shadow`、任务里 6 个 `com.apple.UIKit` 全局 tweak（`HammerIt`、`bfdecryptor`、`fixxinamine`、`iapstore`、`killads`、`leftPan`）、`Choicy`、`Crane` 之后，App 仍然崩溃。此时进程里只剩越狱基座本身：

- `/usr/lib/systemhook.dylib`（Dopamine 注入入口）
- `.../usr/lib/ellekit/libinjector.dylib`
- `.../usr/lib/libellekit.dylib`

这解释了用户观察到的"用 Choicy 禁用注入后仍然闪退"：Choicy 只能挡住 tweak，挡不住基座。

### 2. 崩溃是主动制造异常，不是普通越狱分支

系统崩溃报告里，故障线程处于伪造上下文：

```
exc  EXC_BAD_ACCESS / SIGSEGV
pc = lr = fp = 0x8    x8 = x9 = x28 = 8    sp 有效
x16 = pthread_mutex_unlock    x17 = +[NSThread isMainThread]
```

也就是说有代码执行了 `blr xN` 而 `xN = 8`。同进程里 JM 的检查线程仍在运行，栈为：

```
JM+0x122784 → JM+0x186634 → JM+0x11a77c → JM+0x16f64c
            → JM+0x164794 → JM+0x1574f4 → JM+0x152ea8 → JM+0x11c720
```

### 3. `brk #0xdead` 不是主因

主二进制里唯一的 `brk #0xdead` 位于 `KYHAppStore+0x7c55f8`（文件偏移与运行时一致），周围是 ijm 混淆器 VM 的导入绑定器：`0x7c5590 cbz x15` 在绑定失败时跳到这里。全二进制没有直接 `bl` 指向它、也没有指针引用，只在最小实验模式下被走到过一次。它不是常规崩溃路径。

### 4. 改写镜像路径无效

把 `dyld_all_image_infos.infoArray` 里 all `/var/jb`、`preboot`、`basebin`、`procursus`、`ellekit`、`TweakInject` 的 `imageFilePath` 全部改写成 `/usr/lib/lib*.dylib` 形式的合法系统路径（实测成功改写 5 个镜像，包括 `systemhook.dylib`、`libinjector.dylib`、`libellekit.dylib` 和自己的 dylib），App 仍然以同样的 `0x8` 特征崩溃。**JM 不依赖 `imageFilePath` 判定。**

### 5. `exit(1)` 来自 ellekit，不是 JM 自己

用 tweak hook `exit`/`_exit` 并记录调用者，得到：

```
EXIT(1) caller=libellekit.dylib+0x1bae8
```

反汇编 libellekit 后确认 `0x1bae8` 位于 `ellekit.hookClassPair(class:class:)`，`0x1bae0` 是 `mov w0,#1; bl exit`。即 JM 触发异常后，ellekit 的 `ExceptionHandler.portLoop` 捕获并退出进程。

### 6. 拦掉 exit 会让 App 活下来但死锁

把 `exit(1)` / `_exit(1)` 改成直接返回后，App 从"5 秒内必死"变成存活 15 秒以上，随后被系统 watchdog 杀掉：

```
FRONTBOARD code 0x8BADF00D
process-launch watchdog transgression: exhausted real time allowance of 20.00 seconds
```

卡死时的主线程栈显示它停在我们自己的 `add_image` 回调里，正在转发给 JM 的回调，而 JM 的回调在做证书链校验（`EAP8021X EAPTLSVerifyServerCertificateChain`）。同时 `ellekit_exc_port` 线程正在 dyld 的 `withLoadersReadLock` 里等待。合理解释是：ellekit 的异常线程在持有 dyld 锁的情况下被我们拦住了退出，锁没有释放，主线程再调 `_dyld_image_count` 就死锁。**所以拦 exit 不是可行方向。**

### 7. frida-server 会污染基线

`frida-server` 常驻并被 launchd 自动重启，会在没有任何注入的情况下让 App 崩溃，制造"不装 tweak 也崩"的假象。做干净实验前必须停掉并禁用它的 LaunchDaemon：

```
sudo launchctl bootout system/re.frida.server
sudo mv /var/lib/LaunchDaemons/re.frida.server.plist <备份目录>   # 实际路径 /var/jb/Library/LaunchDaemons/
```

## 当前状态

尚未达成启动成功。已排除镜像路径检测和"多一个 tweak"两条假设，确认检测对象是越狱注入基座。下一步需要在 JM 的判定点动手，或找到它判定基座是否存在的具体依据。

## 可复现的实验开关

`Tweak.x` 里的编译期开关，用 `ADDITIONAL_OBJCFLAGS` 传入：

| 开关 | 作用 |
|---|---|
| `AIA_TRULY_EMPTY=1` | 构造函数里什么都不做，只写一行日志 |
| `AIA_EMPTY=1` | 记录模块快照后直接返回，不装 hook |
| `AIA_MINIMAL=1` | 只 hook `_dyld_register_func_for_add_image` |
| `AIA_DYLD_ONLY=1` | 只装 dyld 枚举、`objc_copyImageNames`、`dladdr` 相关 hook |
| `AIA_HIDE_IMAGES=1` | 从 `_dyld_*` 枚举里过滤掉越狱相关镜像 |
| `AIA_BLOCK_ADD_IMAGE=1` | 吞掉对 `_dyld_register_func_for_add_image` 的注册 |
| `AIA_FAKE_PATH=1` | 改写 dyld 镜像表里的 `imageFilePath` |

构建（Linux + Theos）：

```
unset PERL5LIB PERL_MB_OPT PERL_MM_OPT PERL_LOCAL_LIB_ROOT
export THEOS=/home/safe/theos
cd aiabypass && make package FINALPACKAGE=1 ADDITIONAL_OBJCFLAGS="-DAIA_EMPTY=1"
```

## 观测手段

tweak 的日志写在 App 数据容器的 `Documents/aiabypass.log`，不写 `/tmp` 或 `/var/jb/tmp`。数据容器路径按 bundle id 查找：

```
sudo grep -l YoubangHealth /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist
```

崩溃的权威信息来自系统崩溃报告 `/var/mobile/Library/Logs/CrashReporter/KYHAppStore-*.ips`，其中的 `faultingThread`、`usedImages` 和 `threadState` 比自行展开栈更可靠——尤其在 ellekit 抢先把 Mach 异常处理掉的时候。

`probes/` 是早期用 Frida 写的一次性探针脚本，`crashtools/` 是配套的驱动脚本，保留下来方便后续复用。
