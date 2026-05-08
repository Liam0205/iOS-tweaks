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
