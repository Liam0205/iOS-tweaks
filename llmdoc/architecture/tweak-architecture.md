# Tweak 架构

## 架构目标

`mybankbypass/Tweak.x` 的目标不是只绕过一个检测点，而是同时切断“发现越狱迹象”和“检测后自杀退出”两条链路。当前稳定版本采用“多层拦截 + 业务层中和 + 最终终止保护”的结构。

## 整体执行模型

加载顺序以 `%ctor` 为入口：

1. tweak 注入到目标进程 `Portal`
2. `%ctor` 在 dylib 加载时执行
3. 先安装退出相关 Hook，优先阻断检测命中后的 kill/exit 路径
4. 再安装文件系统、进程、环境变量、dyld 等 C 层 Hook
5. 最后执行运行时方法替换，覆盖 `IOSSecuritySuite`、SecurityGuard 以及 App 自身 launcher/controller 级别的越狱判断

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
- `statfs`
- `statvfs`

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
- `getppid`：返回安全父进程语义，减少越狱注入环境可见性
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
- App 自身 launcher/controller 级别的越狱决策逻辑

当前实现通过运行时查类和替换方法实现：

- `amIJailbroken` 返回 `NO`
- `amIJailbrokenWithFailedChecks` 返回未越狱、空失败项
- `amIJailbrokenWithFailMessage` 返回未越狱、空消息
- 对类名中与 root/jailbreak/checkEnv 相关的 SecurityGuard 方法，根据返回类型替换为 `NO` 或 `0`
- 直接 Hook `MYBLauncherController.checkJailbroken`，阻断 App 业务层根据越狱状态进入冻结/退出流程
- 额外中和 `MAJailbreakChecker`、`MASecurityUtil`、`RDSSecurityCheck`、`DTDeviceInfo`、`RVPBridgeExtension4Jailbroken`、`BinAOP` 等组件的越狱判断结果

这层的目标不是精确理解所有 SDK 内部逻辑，而是把其对外暴露的“越狱判断结果”统一钳制到安全值，并切断 launcher/controller 的业务分支。

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

### 业务冻结优先排查 launcher/controller

`4.7.36` 暴露出的关键问题不是简单闪退，而是“App 不退出但业务冻结”。根因是 launcher 检测到越狱后触发 exit 链路，而 tweak 的终止 Hook 把进程保活成“假活”状态：主线程 RunLoop 仍在，但业务交互已被中断。出现这一现象时，应先检查 launcher/controller 的 jailbreak check 流程，确认是否仍有上层布尔判断未被中和。

### `4.7.48`：主程序启动检查直接调用 `exit(0)`

现象与 `4.7.36` 相同（能进、能滑动、能切 tab，中间内容点击无效），但根因不同，而且不是本插件内部的 Hook 写错。

`4.7.48` 的主程序比 `4.7.47` 多出一个 `bl _exit` 调用点。形状是“检查 → 记日志 → 失败则退”：

```
0x3c2ac0c  bl   <检查函数>
0x3c2ac30  cbnz w19, <退出块>
0x3c2ac40  ret
0x3c2ac74  bl   _APLogToFile
0x3c2ac7c  bl   _exit
```

`4.7.47` 里结构相同，只是检查结论为“通过”。因此这是新版本给出的判定变了，而不是这段代码被改写。

原来只靠“终止 Hook 不返回”来挡，副作用是那次调用永远不返回，调用它的启动流程停在半路，后续初始化没有完成，于是界面结构在、事件链路不在。

现在的做法是把 `0x3c2ac30` 的 `cbnz` 换成 `nop`，让检查结束时正常返回。

**代码补丁打上之后，终止 Hook 必须撤掉**（1.2.4 起）。原来两个钩子无条件安装，挡住检测的同时也挡住了正常退出：UIKit 的 `-[UIApplication _terminateWithStatus:]` 内部调 `exit()`，钩子在主线程用 `runMode:beforeDate:[NSDate distantFuture]` 死循环跑 runloop，`exit` 永不返回，FrontBoard 等满 5 秒发 `SIGKILL`，每次关闭 App 都留一份 `0x8BADF00D` 报告，用户看到的是关 App 卡住。「能进但点不动」和这条 watchdog 是同一个死循环的两个症状。

现在的判断是：补丁函数返回成功才置 `g_startupExitPatched`；置位时不装 `exit` / `_exit` 钩子，回落到原来的行为（补丁没打上、依然依赖钩子挡退出）时照旧安装。

两条施工约束（踩过才知道）：

- **定位主程序不能用 `_dyld_get_image_header(0)`**。注入后索引 0 不是主程序，`base + 偏移` 落进未映射空洞，读取即 `SIGSEGV`。用 `[[NSBundle mainBundle] executablePath]` 与镜像路径比对。
- **改完代码页必须还原成 `R|X`**。iOS 不允许一页同时可写可执行，请求 `rwx` 得到 `rw-`，同页其它函数执行即 `SIGBUS`。

偏移按版本写死，动手前核对机器码；核对不上就不改，只写一行日志到 App 的 Caches 目录。

## 依赖与边界

- 构建依赖：Theos、Substrate/ElleKit 兼容环境、UIKit/Foundation
- 打包依赖：rootless scheme
- 注入边界：由 `mybankbypass/MYBankBypass.plist` 限定，仅注入 `com.mybank.ios.phone`
- 当前文档只覆盖本地用户态 Hook 方案，不覆盖内核级、PAC 绕过或服务端风控对抗

## 主要回归风险

- 目标 App 升级后新增检测路径、类名或 selector
- SecurityGuard 内部接口命名变化，导致运行时方法替换覆盖不足
- launcher/controller 级别的本地越狱布尔判断路径变化
- rootless 路径出现新变体但未加入路径/子串表
- 低层 Hook 如果再次引入 ObjC 逻辑，会重新带回稳定性问题
- 终止链路若新增 `posix_spawn`、自定义 crash 或更底层 syscall 退出路径，需要补充保护
