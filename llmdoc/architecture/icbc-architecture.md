# ICBC Bypass 架构

## 架构目标

`icbcbypass/Tweak.x` 同时对抗工商银行 (com.icbc.iphoneclient) 的三层防御：检测层、冻结层、弹窗退出层。与 mybankbypass 的关键区别在于：不能使用 MSHookFunction（会触发 MSHookFunctionChecker 反篡改 crash），必须使用 fishhook（GOT rebinding）替代。

## 整体执行模型

加载顺序以 `%ctor` 为入口：

1. tweak 注入到目标进程
2. `%ctor` 在 dylib 加载时执行
3. 执行 fishhook `rebind_symbols()`，覆盖所有 C 层函数（stat/access/open/fopen/opendir 等 + dispatch_semaphore_wait + CFRunLoopStop）
4. 执行 `%init`，激活 Logos hook（UIView/UIApplication/UIViewController/NSFileManager/NSProcessInfo）
5. 调用 `hookSecureUtilityPlus()` / `hookIOSSecuritySuite()` / `hookICBCJailbreakMethods()`，通过 runtime API 替换检测类的方法实现

## 核心约束：不可使用 MSHookFunction

SecureUtilityPlus 内嵌 `MSHookFunctionChecker`，检测 C 函数 prologue 前几字节的 trampoline 修改。一旦检测到：
- 设置无效回调地址 0xb5a06000
- 通过 dispatch queue 执行跳转 → crash

fishhook 修改 GOT/PLT 表指针而非函数 prologue，不被检测。这是整个 tweak 架构的前提约束。

## 分层设计

### 1. 检测绕过层

#### C 层路径隐藏（fishhook）

通过 fishhook 覆盖以下 libc 函数，对越狱路径返回"不存在"：

- `stat` / `lstat` / `access` / `open` / `fopen`
- `opendir` / `readdir`
- `realpath` / `readlink`
- `statfs` / `statvfs`
- `syscall`（拦截 SYS_stat64/SYS_access/SYS_open）
- `fork` / `getenv` / `sysctl` / `sysctlbyname`

路径判断使用纯 C 函数 `is_jb_path()`，维护显式路径列表 + 关键字子串列表。

#### ObjC 层检测覆盖（Logos %hook + runtime）

- `NSFileManager` 文件查询系列方法
- `UIApplication canOpenURL:` 过滤越狱 scheme
- `NSProcessInfo environment` 删除 DYLD_ 变量
- `_dyld_image_count` / `_dyld_get_image_name`（fishhook）隐藏注入 dylib

#### 安全框架钳制（method_setImplementation）

通过 `objc_getClass` 查找特定类并替换方法：

- `SecureUtilityPlus` 相关 Checker 类 — 所有含 jailb/check/detect/hook/debug 等 selector 返回 NO/0
- `IOSSecuritySuite` — amIJailbroken 系列返回 NO
- App 自有 jailbreak 属性方法 — 所有含 jailBreak/jailbroken 的方法返回 NO/0

### 2. 主线程冻结对抗层

APP 的冻结机制是持续运行的循环（30s 内 14,000+ 次调用），不是一次性触发。

#### dispatch_semaphore_wait 拦截（fishhook）

策略（两级区分）：
- `DISPATCH_TIME_FOREVER` 在主线程：**始终** 直接返回 0（freeze 循环永久使用此模式）
- 有限长超时 (>2s)：仅在启动前 10s 内拦截（之后放行合法同步操作）
- `DISPATCH_TIME_NOW` 或短超时：永远放行

#### UI 状态保护（Logos %hook）

所有基于时间门控（elapsed > 3s 后拦截）：

- `[UIView setAnimationsEnabled:NO]` → 直接 return
- `[UIView setUserInteractionEnabled:NO]` → 直接 return
- `[CALayer removeAllAnimations]` → 直接 return
- `[CALayer removeAnimationForKey:]` → 直接 return
- `[UIApplication beginIgnoringInteractionEvents]` → 直接 return

#### 关键不变式

- **永远不在 hook 内部进入嵌套 RunLoop**。直接返回安全值，让 UIApplicationMain 原生 RunLoop 处理事件。
- DISPATCH_TIME_FOREVER 的拦截是永久性的——冻结循环也是永久运行的。

### 3. 弹窗退出对抗层

#### UIAlertController 标记

在 `alertControllerWithTitle:message:preferredStyle:` 中，对含"安全/风险/越狱/jailbreak/root"等关键字的弹窗设置关联对象 `jb_blocked`。

#### presentViewController 拦截

对标记了 `jb_blocked` 的 UIAlertController：
- **不展示弹窗**（不调用 %orig）
- **不调用 action handler**（handler 内部包含 exit()）
- 仅调用 completion 回调
- 记录日志（debug 模式下）

两个已知弹窗：
1. "安全提示" — "您的设备环境存在隐私信息泄露..." (action: "确定" style=Cancel, handler 调 exit)
2. "风险提示" — "您的系统可能已经越狱..." (action: "确认" style=Default)

## 调试能力

通过编译开关 `#define ICBC_DEBUG_LOG 0` 控制：

- 关闭（0）：release 模式，无日志写入
- 开启（1）：写详细日志到 Documents/icbc_fishhook.log，包含 fishhook 命中、semaphore 拦截、watchdog、alert 拦截等信息

## 依赖与边界

- 构建依赖：Theos、fishhook（项目内 fishhook.c/h）、UIKit/Foundation/QuartzCore
- 打包依赖：rootless scheme
- 注入边界：`icbcbypass/ICBCBypass.plist` 限定 `com.icbc.iphoneclient`
- 不覆盖 inline SVC 检测（已确认存在但无法 GOT 级拦截；当前策略下无需覆盖，冻结已被对抗层解决）

## 与 mybankbypass 的关键差异

| 维度 | mybankbypass | icbcbypass |
|------|-------------|------------|
| Hook 机制 | MSHookFunction + Logos | fishhook + Logos（MSHookFunction 被检测） |
| 冻结对抗 | 无（退出保护即可） | 需要对抗持续运行的 freeze 循环 |
| 退出保护 | exit/abort noreturn 语义保持 | 弹窗 handler 含 exit，完全静默不调用 |
| 检测引擎 | SecurityGuard SDK | SecureUtilityPlus (IOSSecuritySuite 增强版) |
| 反 Hook 检测 | 无 | MSHookFunctionChecker（检测 prologue） |

## 主要回归风险

- App 升级后 SecureUtilityPlus 新增检测点或变更 selector
- fishhook 覆盖的 GOT 函数列表不足（新增系统调用路径）
- 冻结循环策略变更（如改用 pthread_mutex 或 mach_msg 替代 semaphore）
- 弹窗文案变更导致关键字匹配失败
- 新增第二层 anti-hook 检测（如 FishHookChecker 检测 GOT 修改）
