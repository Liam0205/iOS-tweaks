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

### 约束的本质：风险管理而非技术不可能

MSHookFunctionChecker 的 ObjC 入口已通过 `method_setImplementation` 被替换（返回 NO）。理论上若确认：
1. checker 仅在被调用时扫描（非模块加载时 static initializer）
2. 所有检测路径都经过 ObjC dispatch（无 Swift 直接调用绕过）

则 MSHookFunction 可安全使用。但当前选择 fishhook 是因为上述两项无法在不深度逆向 SecureUtilityPlus 二进制的前提下确认，且 fishhook 完全满足需求——零成本的安全决策。

### Inline SVC 对抗哲学

App 的 inline `svc #0x80` 检测（直接系统调用）在用户态完全不可拦截——不经 GOT、非独立函数入口。icbcbypass 的策略是：**接受检测命中，中和所有响应**。

这一策略成立的前提：响应层（冻结循环、弹窗退出、属性传播）全部依赖可 Hook 的高层 API（UIKit/GCD/ObjC 方法）。App 防御方面临结构性两难：底层响应（inline SVC exit）用户体验差（直接闪退），而好的 UX（弹窗、冻结）必须经过可 Hook 的 API。这个矛盾是攻击者永远可以利用的弱点。

### 假设 fishhook 也被禁

当前 FishHookChecker 的 ObjC 入口已被同样方式中和。若未来 GOT 验证做到 inline 级别：
- 自定义 trampoline（ADRP+ADD+BR 等非标模式）可绕过 prologue 模式检测
- 纯 ObjC 响应端对抗（unfreezer timer）仍然有效
- dispatch_semaphore_wait 作为 C 函数需要 ObjC 层补偿（周期性 endIgnoringInteractionEvents + setUserInteractionEnabled:YES）

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
- `DISPATCH_TIME_FOREVER` 在主线程：**始终** 直接返回 0（freeze 循环永久使用此模式），返回后调用 `sched_yield()` 让出 CPU 时间片，减少忙循环 CPU 消耗
- 有限长超时 (>2s)：仅在启动前 10s 内拦截（之后放行合法同步操作）
- `DISPATCH_TIME_NOW` 或短超时：永远放行

#### UI 状态保护（Logos %hook）

**UIView 层**（时间门控：elapsed > 3s 后拦截）：
- `[UIView setAnimationsEnabled:NO]` → 直接 return
- `[UIView setUserInteractionEnabled:NO]` → 直接 return
- `[UIApplication beginIgnoringInteractionEvents]` → 直接 return

**CALayer 层**（速率限制：区分冻结循环突发与正常 App 调用）：
- `[CALayer removeAllAnimations]` → 主线程上追踪调用间隔，连续突发调用（间隔 <50ms，冻结循环模式）被阻断，孤立调用（正常 App 动画清理）被放行
- `[CALayer removeAnimationForKey:]` → 同上速率限制策略

速率限制策略的设计依据：冻结循环以高频突发模式调用 removeAllAnimations（3.0.90 前 14s 内超过 1000 次/秒），而正常 App 动画清理是孤立的低频调用。以 50ms 间隔阈值可有效区分两者。非主线程调用始终放行。

#### 关键不变式

- **永远不在 hook 内部进入嵌套 RunLoop**。直接返回安全值，让 UIApplicationMain 原生 RunLoop 处理事件。
- DISPATCH_TIME_FOREVER 的拦截是永久性的——冻结循环也是永久运行的。
- **CALayer hook 必须区分冻结流量与正常流量**。永久全局阻断 removeAllAnimations 会导致动画对象累积、GPU 压力升高、按钮动画挂起（3.0.90 适配教训）。
- **解冻定时器必须永久运行**。冻结循环是永久的，定时器停止会导致 UI 重新冻结。30s 后降频至 5s 间隔以平衡 CPU 开销。

### 已知性能考量

**CALayer 动画累积问题**（3.0.90 发现）：当 removeAllAnimations / removeAnimationForKey: 被永久阻断（时间门控策略）时，冻结循环发起的调用和正常 App 动画清理调用被一律阻止。正常 App 的动画完成回调无法清理已结束的 CAAnimation 对象，导致：
1. 动画对象在 CALayer 上不断累积
2. Core Animation 渲染管线 GPU 压力持续升高
3. UIButton 等控件的 highlight 动画因 pending animation 堆积而无法及时完成 → 点击响应延迟

症状：登录后按钮需要 10+ 次点击才能响应。

修复：从时间门控改为速率限制（见上方 UI 状态保护）。

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

### 4. 解冻定时器（Unfreezer Timer）

`%ctor` 末尾创建一个 GCD timer，周期性恢复 UI 状态。此定时器**永久运行**（冻结循环也是永久的），但在 30s 后降频：

- 启动后 3s 开始，间隔 2s 触发（前 15 次）
- 第 15 次触发后降频至 5s 间隔（降低长期 CPU 开销）

每次触发执行：
- `endIgnoringInteractionEvents` 循环清除
- 所有 window 恢复 `userInteractionEnabled`
- 高层级覆盖窗口（非 ICBCMotionRecognizingWindow）隐藏
- `layer.speed = 1.0` 恢复动画速度
- `setAnimationsEnabled:YES`

#### 关键设计决策

定时器永久运行而非在某个时间点停止，因为冻结循环本身是永久运行的。如果定时器停止，冻结循环后续的 setAnimationsEnabled:NO / beginIgnoringInteractionEvents 调用会逐步重新冻结 UI。降频而非停止是在"持续对抗"与"CPU 开销"之间的平衡。

## 调试能力

通过编译开关 `#define ICBC_DEBUG_LOG 0` 控制：

- 关闭（0）：release 模式，无日志写入
- 开启（1）：写详细日志到 Documents/icbc_fishhook.log，包含 fishhook 命中、semaphore 拦截、watchdog、alert 拦截等信息
- debug 模式下 `%ctor` 初始化时记录 ICBC app 版本号（`CFBundleShortVersionString`），便于日志中确认目标 App 版本

注意：调试用 UIControl sendAction hook 已移除，因 Logos 预处理器与 `#if ICBC_DEBUG_LOG` 条件编译不兼容（Logos 的 `%hook` 不支持被 `#if` 包裹）。

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
