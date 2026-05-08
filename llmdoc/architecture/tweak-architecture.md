# Tweak 架构

## 架构目标

`mybankbypass/Tweak.x` 的目标不是只绕过一个检测点，而是同时切断“发现越狱迹象”和“检测后自杀退出”两条链路。当前稳定版本采用“多层拦截 + 最终终止保护”的结构。

## 整体执行模型

加载顺序以 `%ctor` 为入口：

1. tweak 注入到目标进程 `Portal`
2. `%ctor` 在 dylib 加载时执行
3. 先安装退出相关 Hook，优先阻断检测命中后的 kill/exit 路径
4. 再安装文件系统、进程、环境变量、dyld 等 C 层 Hook
5. 最后执行运行时方法替换，覆盖 `IOSSecuritySuite` 与 SecurityGuard 相关 ObjC/Swift 暴露接口

这意味着当前架构同时依赖两类能力：

- Logos `%hook`：拦截高层 Objective-C 调用
- `MSHookFunction`：拦截底层 C 函数与系统接口

## 分层设计

### 1. 路径与文件可见性层

目标是让 App 读取不到典型越狱痕迹。

高层 ObjC 覆盖：

- `NSFileManager` `fileExistsAtPath:`
- `NSFileManager` `fileExistsAtPath:isDirectory:`
- `NSFileManager` `isReadableFileAtPath:`
- `NSFileManager` `isWritableFileAtPath:`
- `NSFileManager` `contentsOfDirectoryAtPath:error:`
- `NSFileManager` `attributesOfItemAtPath:error:`

底层 C 覆盖：

- `stat`
- `lstat`
- `access`
- `open`
- `fopen`
- `realpath`
- `readlink`
- `creat`

关键实现约束：

- C Hook 内统一调用 `is_jb_path_c(const char *)`，只做纯 C 字符串判断。
- 该函数既维护显式路径前缀列表，也维护越狱关键字子串列表。
- 这样可以在 `stat/open/readlink` 等低层路径上避免 ObjC 分配、消息发送和重入风险。

这是当前稳定实现的核心前提之一。

### 2. URL scheme 可见性层

App 可通过 `UIApplication canOpenURL:` 检查 Cydia、Sileo、Filza、Zebra 等工具是否存在。当前 `UIApplication` Hook 会对越狱相关 scheme 统一返回 `NO`。

### 3. 环境与进程语义层

目标是让 App 看到“更像正常沙盒 App”的进程环境：

- `NSProcessInfo environment`：删除 `DYLD_INSERT_LIBRARIES`、`DYLD_LIBRARY_PATH`、`_MSSafeMode`、`_SafeMode`
- `getenv`：对同类注入痕迹直接返回 `NULL`
- `fork`：恒定返回 `-1` 并设置 `ENOSYS`，模拟正常 iOS 沙盒限制
- `sysctl`：清除 `P_TRACED` 标志，降低调试检测可见性
- `sysctlbyname`：对 `security.mac.amfi.developer_mode_status` 返回可接受结果

### 4. 动态库隐藏层

App 可能通过 dyld 枚举或 `dladdr` 识别注入环境。当前架构使用四个点位：

- `_dyld_image_count`
- `_dyld_get_image_name`
- `dlopen`
- `dladdr`

`is_jb_dylib(const char *)` 会隐藏以下类型的名称：

- substrate / MobileSubstrate
- substitute
- ellekit
- libhooker
- frida
- cycript
- TweakInject
- 自身 tweak 名称（如 `MYBankBypass`）
- rootless 相关路径片段（如 `/var/jb/`）

这里的关键不变式是：

- `_dyld_image_count` 与 `_dyld_get_image_name` 必须保持一致的“可见镜像集合”语义，否则调用方会因索引错位看到异常行为。

### 5. 运行时安全框架覆盖层

除了通用检测，当前目标 App 还依赖更高层安全框架：

- `IOSSecuritySuite`
- Ant Group / Alibaba `SecurityGuard` 相关类

当前实现通过运行时查类和替换方法实现：

- `amIJailbroken` 返回 `NO`
- `amIJailbrokenWithFailedChecks` 返回未越狱、空失败项
- `amIJailbrokenWithFailMessage` 返回未越狱、空消息
- 对类名中与 root/jailbreak/checkEnv 相关的 SecurityGuard 方法，根据返回类型替换为 `NO` 或 `0`

这层的目标不是精确理解所有 SDK 内部逻辑，而是把其对外暴露的“越狱判断结果”统一钳制到安全值。

### 6. 终止保护层

即便检测层仍有漏网点，只要 App 走到退出链路，也可能在启动后 3-5 秒自杀。当前稳定方案先安装终止 Hook：

- `exit`
- `_exit`
- `abort`
- `kill`
- `raise`

其中 `exit` / `_exit` / `abort` 是最敏感的点，因为它们具备 `noreturn` 语义。

当前稳定做法：

- 若在主线程触发，持续运行当前 `NSRunLoop`，保持 App 主线程活着
- 若在后台线程触发，永久阻塞线程
- 绝不能从这些 Hook 中直接返回

这条约束来自已验证问题：若把 `noreturn` 终止函数简单改成“什么都不做然后返回”，会造成未定义行为甚至更快崩溃。

## 关键稳定性经验

### 纯 C 路径匹配是必须项

在 `stat/open/readlink` 等低层 Hook 中调用 ObjC 逻辑，会带来分配、消息发送、锁与重入风险。当前稳定版将低层路径判断收敛到 `is_jb_path_c`，这是已验证有效的做法。

### 不再 Hook `opendir`

早期方案曾拦截 `opendir`。实践结论是：该 Hook 会引发 watchdog 或其他不稳定行为，因此当前稳定架构明确不使用 `opendir`。目录可见性主要通过 `NSFileManager contentsOfDirectoryAtPath:error:` 结果过滤解决。

### 退出 Hook 必须满足 `noreturn`

这是绕过能稳定工作的另一个关键条件。终止函数 Hook 的目标不是“放行返回”，而是“拦住当前线程并保持调用语义不返回”。

## 依赖与边界

- 构建依赖：Theos、Substrate/ElleKit 兼容环境、UIKit/Foundation
- 打包依赖：rootless scheme
- 注入边界：由 `mybankbypass/MYBankBypass.plist` 限定，仅注入 `com.mybank.ios.phone`
- 当前文档只覆盖本地用户态 Hook 方案，不覆盖内核级、PAC 绕过或服务端风控对抗

## 主要回归风险

- 目标 App 升级后新增检测路径、类名或 selector
- SecurityGuard 内部接口命名变化，导致运行时方法替换覆盖不足
- rootless 路径出现新变体但未加入路径/子串表
- 低层 Hook 如果再次引入 ObjC 逻辑，会重新带回稳定性问题
- 终止链路若新增 `posix_spawn`、自定义 crash 或更底层 syscall 退出路径，需要补充保护
