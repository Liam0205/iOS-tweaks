# 网商银行越狱检测分析报告

## APP 信息

- Bundle ID: `com.mybank.ios.phone`
- 当前安装版本: 4.6.4
- 主二进制: `Portal` (172MB, Mach-O arm64)

## 检测框架

APP 使用**蚂蚁集团 SecurityGuard SDK**，这是支付宝体系的通用安全框架。

### 核心安全组件

| 组件 | 功能 |
|------|------|
| `SecurityGuardRootDetect` / `ISecurityGuardRootDetect` | 越狱（Root）检测 |
| `SecurityGuardSimulatorDetect` / `ISecurityGuardOpenSimulatorDetect` | 模拟器检测 |
| `SecurityGuardFCManager` | 反欺诈/风控 |
| `SecurityGuardOpenMiddleTierGeneric` | 签名生成（WUA, x-sign） |
| `SecurityGuardDataCollection` / `ISecurityGuardDataCollection` | 设备信息采集 |
| `SecurityGuardOpenAVMPGeneric` | 反虚拟机 |

### 越狱检测方式

1. **文件路径检查**（检测以下路径是否存在）：
   - `/Applications/Cydia.app`
   - `/Library/MobileSubstrate/DynamicLibraries`
   - `/Library/MobileSubstrate/CydiaSubstrate.dylib`
   - `/Library/MobileSubstrate/MobileSubstrate.dylib`
   - `/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist`
   - `/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib`
   - `/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist`
   - `/Library/MobileSubstrate/DynamicLibraries/Veency.plist`
   - `/bin/bash`
   - `/usr/sbin/sshd`
   - `/usr/bin/ssh`
   - `/usr/lib/substrate`
   - `/usr/lib/libjailbreak.dylib`
   - `/etc/apt`
   - `/etc/apt/sources.list.d/electra.list`
   - `/etc/apt/sources.list.d/sileo.sources`
   - `/etc/apt/undecimus/undecimus.list`
   - `/private/var/lib/apt`
   - `/private/var/lib/cydia`
   - `/private/var/mobile/Library/SBSettings/Themes`
   - `/var/jb/usr/sbin/frida-server` (rootless!)
   - `/var/lib/dpkg/info/mobilesubstrate.md5sums`
   - `/var/lib/undecimus/apt`
   - `/tmp/frida-*`
   - `/jb/jailbreakd.plist`
   - `/jb/libjailbreak.dylib`
   - `/private/jailbreak.txt`
   - `/usr/share/jailbreak/injectme.plist`

2. **URL Scheme 检查**（尝试 canOpenURL）：
   - `cydia://`
   - `sileo://`
   - `filza://`
   - `undecimus://`
   - `zbra://`

3. **动态库检测**：
   - 检查 `_dyld_image_count` / `_dyld_get_image_name`
   - 检查 `CydiaSubstrate`
   - 检查 `frida-server`

4. **IOSSecuritySuite 方法**：
   - `amIJailbroken`
   - `amIJailbrokenWithFailedChecks`
   - `amIJailbrokenWithFailMessage`

5. **其他检测**：
   - `fork()` 调用
   - 文件系统可写性测试
   - 环境变量检查 (`DYLD_INSERT_LIBRARIES`)
   - `sysctl` / `ptrace` 检查

## 退出机制

检测到越狱后，APP 会在 3-5 秒后自动退出（可能通过 `exit()` / `abort()` / `_exit()` 或 terminate 相关调用）。

相关字符串：
- `is_jailbroken_kill_app_report`
- `degrade_jailbreaking_track_ph`

## 绕过策略

需要 Hook 的关键点：

### 1. 文件系统相关
- `NSFileManager` 的 `fileExistsAtPath:` — 对越狱路径返回 NO
- C 函数 `stat()`, `lstat()`, `access()`, `open()`, `fopen()` — 对越狱路径返回失败
- `realpath()` — 防止路径解析暴露 `/var/jb` 等

### 2. URL Scheme 相关
- `UIApplication` 的 `canOpenURL:` — 对越狱 URL scheme 返回 NO

### 3. 动态库相关
- `_dyld_get_image_name()` — 过滤掉越狱相关 dylib 名称
- `_dyld_image_count()` — 返回过滤后的数量
- `dlopen()` / `dlsym()` — 防止加载检测

### 4. 进程相关
- `fork()` — 返回 -1（模拟沙盒限制）
- `sysctl()` — 过滤进程信息
- `ptrace()` — 正常返回

### 5. 环境变量
- `getenv("DYLD_INSERT_LIBRARIES")` — 返回 NULL

### 6. IOSSecuritySuite
- Hook `amIJailbroken` 系列方法返回 false

### 7. SecurityGuard SDK
- Hook `ISecurityGuardRootDetect` 相关方法返回 "未越狱"

---

## 4.7.48：启动检查直接调用 `exit(0)`

### 现象

升到 4.7.48 后，App 能启动、能上下滑、能切底部 tab，但中间内容点击没有反应；
降回 4.7.47 一切正常。

### 原因

4.7.48 比 4.7.47 多出一个 `bl _exit` 调用点（48 处对 47 处）。用诊断版插件把退出钩子的
调用者记下来，得到：

```
EXIT exit main=1 st=0 ra=Portal+0x3c2ac80
```

反汇编这一段（地址相对 Mach-O 头）：

```
0x3c2ac0c  bl   <检查函数>
0x3c2ac30  cbnz w19, 0x3c2ac44    ; 非零进退出块
0x3c2ac40  ret                     ; 零则正常返回
0x3c2ac74  bl   _APLogToFile       ; 记日志
0x3c2ac7c  bl   _exit
```

4.7.47 里同样存在「检查 → 记日志 → 可能退出」的包装函数，结构一致，只是检查给出的
结论是「通过」。所以变的不是这段代码的形状，而是检查的结论。

原来的 `exit` 钩子在主线程上用死循环跑 runloop 吞掉退出。副作用是那次调用永远不返回，
调用它的启动流程停在半路，于是界面出得来、原生控件能用，而依赖后续初始化的内容区
收不到事件。

### 修复

把 `0x3c2ac30` 的 `cbnz w19` 换成 `nop`，检查结束时无论结论如何都走正常返回。

两个施工细节：

- **定位主程序不能用 `_dyld_get_image_header(0)`**。注入之后索引 0 不是主程序，
  `base + 0x3c2ac30` 会落进未映射的空洞，读它直接 `SIGSEGV`。改成按
  `[[NSBundle mainBundle] executablePath]` 与镜像路径比对。
- **打完补丁必须把页权限还原成可读可执行**。iOS 不允许一页同时可写可执行，
  请求 `rwx` 实际得到 `rw-`；不还原的话，同一页里的其它函数一执行就 `SIGBUS`
  （崩溃报告里能看到那 16KB 区域显示 `rw-/rwx`）。

### 验证

4.7.48 上冷启动后 App 正常运行，点击首页「去看看吧」「立即存入」都能正常跳转，
底部 tab 切换正常。

### 版本适用范围

补丁从 4.7.48 起生效，4.7.48 及其后的版本共用 `0x3c2ac30` 这个偏移。

动手之前会核对那里的 4 个字节必须是 `0x350000b3`（`cbnz w19, +0x14`）。新版本如果
把这段代码挪了位置，核对不上就什么也不改，只往 App 的 Caches 目录写一行
`mybankbypass.log`，记下版本号和读到的机器码。

这条兜底只保证「不乱改」，不保证新版本仍然可用。出现新版本时按上面的方法重新定位：
在 `__text` 里扫 `bl _exit` 的调用点，往前找跳过退出块的条件分支，确认前后上下文
与本文记录的一致，再把新偏移加进 `kStartupExitPatches`。

---

## 4.7.48 及以上：正常关闭 App 被 watchdog 强杀

### 现象

从切换器上滑关闭 App 时卡住几秒，随后进程消失。CrashReporter 里每次关闭都多一份
Portal 报告，终止码 `0x8BADF00D`：

```
termination: namespace=FRONTBOARD code=0x8BADF00D
  [application<com.mybank.ios.phone>:96215] failed to terminate gracefully after 5.0s
exception: EXC_CRASH / SIGKILL
```

栈（自下而上）：

```
FBSWorkspaceScenesClient  willTerminateWithTransitionContext:
UIApplication             workspaceShouldExit:withTransitionContext:
_UISceneLifecycleMultiplexer  forceExit…
UIApplication             -[UIApplication _terminateWithStatus:]
MYBankBypass.dylib        hooked_exit
Foundation                -[NSRunLoop runMode:beforeDate:]
CoreFoundation            __CFRunLoopRun → mach_msg_trap
```

### 原因

UIKit 的 `-[UIApplication _terminateWithStatus:]` 内部调用 `exit()`。我们的
`hooked_exit` 在主线程上跑 `runMode:beforeDate:[NSDate distantFuture]` 的死循环，
`distantFuture` 意味着没有超时唤醒，只要没有别的事件投递进来就一直在 `mach_msg` 上
阻塞。`exit` 永远不返回，进程也永不结束；FrontBoard 等满 5 秒发 `SIGKILL`。

这个钩子原本是为启动检查准备的。4.7.48 起退出路径已经被代码补丁改成正常返回，
走不到 `bl _exit`，钩子只剩副作用。「能进去但点不动」和这条 watchdog，其实是同一个
死循环造成的两个症状。

### 修复

1.2.4 起，只有代码补丁**没打上**时才安装 `exit` / `_exit` 钩子。判断依据是补丁函数的
返回值：核对机器码成功、写完并通过 `mach_vm_protect` 还原权限，才把
`g_startupExitPatched` 置 1。

补丁打上时两个钩子都不装，`_terminateWithStatus:` 调 `exit` 直接走 libc，进程按时退出。
补丁没打上时（版本过老，或机器码与预期不符）仍然安装，保持原来的行为。

### 验证

4.7.48 上：冷启动正常，首页「网商贷」图标进入对应页面，底部 tab 切换正常；
从切换器上滑关闭后进程立即消失，CrashReporter 里没有新增报告；再次冷启动正常。
`mybankbypass.log` 全程不存在，说明补丁每次都打上了。
