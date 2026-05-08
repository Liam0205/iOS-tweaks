# 检测向量参考

## 目的

本文档汇总网商银行 `4.6.4` 当前已知的越狱检测向量，说明它们来自哪些分析结论、当前 tweak 如何覆盖，以及哪些点是稳定实现中的关键经验。

## 目标与背景

- 目标 App：`com.mybank.ios.phone`
- 已验证版本：`4.6.4`
- 主进程：`Portal`
- 核心安全框架：阿里系 / 蚂蚁系 `SecurityGuard` SDK
- 其他高层检测组件：`IOSSecuritySuite`

## 检测向量总表

### 1. 文件与路径检测

App 会直接检查典型越狱路径是否存在。这是最基础、也是必须覆盖的一层。

常见检测目标包括：

- `/Applications/Cydia.app`
- `/Library/MobileSubstrate`
- `/Library/MobileSubstrate/DynamicLibraries`
- `/Library/MobileSubstrate/CydiaSubstrate.dylib`
- `/Library/MobileSubstrate/MobileSubstrate.dylib`
- `/bin/bash`
- `/bin/sh`
- `/usr/sbin/sshd`
- `/usr/bin/ssh`
- `/usr/lib/substrate`
- `/usr/lib/libjailbreak.dylib`
- `/etc/apt`
- `/private/var/lib/apt`
- `/private/var/lib/cydia`
- `/var/lib/dpkg/info/mobilesubstrate.md5sums`
- `/var/lib/undecimus/apt`
- `/usr/sbin/frida-server`
- `/tmp/frida-...`
- `/private/jailbreak.txt`
- `/private/umTest_Jailbreak.txt`
- `/usr/share/jailbreak/injectme.plist`

rootless 环境还必须特别关注：

- `/var/jb`
- `/var/jb/usr/sbin/frida-server`
- `/jb/jailbreakd.plist`
- `/jb/libjailbreak.dylib`

当前覆盖：

- ObjC：`NSFileManager` 多个文件查询接口
- C：`stat`、`lstat`、`access`、`open`、`fopen`、`realpath`、`readlink`、`creat`

稳定经验：

- 低层路径匹配必须用纯 C 逻辑，不要在 C Hook 中桥接到 ObjC。
- 目录枚举不要靠 `opendir` Hook 粗暴拦截，当前稳定方案是保留 `NSFileManager` 层过滤。

### 2. URL scheme 检测

App 可通过 `canOpenURL:` 识别常见越狱工具是否安装。

已知相关 scheme：

- `cydia://`
- `sileo://`
- `filza://`
- `undecimus://`
- `zbra://`

当前 tweak 还防御性拦截：

- `activator://`

当前覆盖：

- `UIApplication canOpenURL:`

### 3. 动态库与注入环境检测

App 可枚举已加载镜像、检查注入痕迹或通过符号/路径判断当前是否运行在越狱环境。

重点信号包括：

- `CydiaSubstrate`
- `MobileSubstrate`
- `Substitute`
- `ElleKit`
- `libhooker`
- `TweakInject`
- `frida`
- `cycript`
- `/var/jb/` 路径片段
- 当前 bypass dylib 自身名称

当前覆盖：

- `_dyld_image_count`
- `_dyld_get_image_name`
- `dlopen`
- `dladdr`

不变式：

- dyld 镜像数量与名称映射必须统一过滤语义，否则会因索引错位暴露异常。

### 4. 环境变量检测

注入型 tweak 往往会留下环境变量痕迹，常见检查点包括：

- `DYLD_INSERT_LIBRARIES`
- `DYLD_LIBRARY_PATH`
- `DYLD_FRAMEWORK_PATH`
- `_MSSafeMode`
- `_SafeMode`

当前覆盖：

- `getenv`
- `NSProcessInfo environment`

### 5. 进程、调试与沙盒检测

已知手段包括：

- `fork()`：判断是否能突破普通 iOS 沙盒限制
- `sysctl()`：查看进程调试标志，例如 `P_TRACED`
- `sysctlbyname()`：读取系统安全状态
- `ptrace` / 调试相关流程
- 向受保护路径创建文件，验证文件系统是否可写

当前覆盖：

- `fork`：固定返回失败
- `sysctl`：清理 `P_TRACED`
- `sysctlbyname`：对特定 developer mode 状态返回安全值
- `creat`：拦截典型沙盒写测试文件

说明：

- 当前源码没有单独 Hook `ptrace`，但已有覆盖足以支撑已验证版本工作。
- 若后续版本对反调试更激进，`ptrace` 可能重新成为补点。

### 6. 高层安全框架检测

#### IOSSecuritySuite

已知调用面包括：

- `amIJailbroken`
- `amIJailbrokenWithFailedChecks`
- `amIJailbrokenWithFailMessage`

当前覆盖：

- 运行时查找类并把上述接口统一改写为“未越狱”结果

#### SecurityGuard SDK

已知组件与方向：

- `SecurityGuardRootDetect`
- `SecurityGuardSimulatorDetect`
- `OpenSecurityGuardManager`
- 相关 root/jailbreak/checkEnv selector

当前覆盖：

- 运行时扫描实例方法与类方法，只要 selector 名称包含 root / jail / jailbreak / checkEnv 等语义，就按返回类型替换为 `NO` 或 `0`

说明：

- 这是“结果钳制”策略，而不是完整还原 SDK 内部协议。
- 对当前已验证版本足够有效，但 SDK 改名后应优先检查此层是否失效。

### 7. 检测后的退出链路

目标 App 在检测命中后会进入延迟退出或立即退出流程。已知相关现象与字符串包括：

- 启动后 3-5 秒退出
- `is_jailbroken_kill_app_report`
- `degrade_jailbreaking_track_ph`

当前覆盖：

- `exit`
- `_exit`
- `abort`
- `kill`
- `raise`

稳定经验：

- `exit` / `_exit` / `abort` 属于 `noreturn` 终止函数，Hook 后不能返回。
- 主线程上应维持 RunLoop，后台线程上应永久阻塞。

## 当前版本的关键修正

对本项目而言，以下三点不是“优化项”，而是让 tweak 真正稳定工作的关键修正：

1. C Hook 中改用纯 C 字符串匹配，避免 ObjC 参与低层文件 API。
2. 移除 `opendir` Hook，避免触发 watchdog 或异常目录访问行为。
3. 将退出 Hook 改成 `noreturn` 安全实现，而不是拦截后直接返回。

## 版本适配时的优先检查顺序

当网商银行升级后，建议优先检查以下几层是否发生变化：

1. SecurityGuard / IOSSecuritySuite 相关类名与 selector 是否变化
2. 新增的 rootless 路径、Frida 路径或其它文件特征
3. dyld 枚举是否改为其他镜像查询接口
4. 是否新增 `ptrace`、`posix_spawn`、更底层 syscall 或服务端联动退出
5. 检测命中后退出是否改用新的自杀链路
