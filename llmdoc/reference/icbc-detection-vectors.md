# ICBC 检测向量参考

## 目的

本文档汇总工商银行 `3.0.80` 当前已知的越狱检测向量、冻结机制与退出链路，以及 icbcbypass tweak 的覆盖情况。

## 目标与背景

- 目标 App：`com.icbc.iphoneclient`
- 已验证版本：`3.0.80`
- 主 Binary：`ICBCBankTest`（arm64, FairPlay encrypted, ~100MB）
- 核心安全框架：SecureUtilityPlus（IOSSecuritySuite 定制增强版，静态链接到主 binary）

## 检测框架：SecureUtilityPlus

静态链接到主 binary，包含以下 Checker 类：

| 类名 | 检测内容 |
|------|----------|
| `JailbreakChecker` | 越狱检测（isJailBreak1~9，9 个子检测） |
| `IOSSecuritySuite` | 标准 amIJailbroken 系列 |
| `MSHookFunctionChecker` | 检测 MSHookFunction prologue 修改 |
| `FishHookChecker` | 检测 fishhook（**当前未生效，v7 对照实验确认**） |
| `RuntimeHookChecker` | 运行时 hook 检测 |
| `ReverseEngineeringToolsChecker` | 逆向工具检测（frida 等） |
| `DebuggerChecker` | 调试器检测 |
| `EmulatorChecker` | 模拟器检测 |
| `IntegrityChecker` | 完整性校验 |
| `FileChecker` | 文件存在性检测 |
| `ProxyChecker` | 代理检测 |
| `ModesChecker` | 模式检测 |
| `CheckAllCall` | 聚合调用入口 |

### 关键发现

- `MSHookFunctionChecker` 检测 C 函数 prologue 的 trampoline → 使用 MSHookFunction 会触发 anti-tampering（跳到 0xb5a06000 crash）
- `FishHookChecker` 存在但当前版本未有效检测 GOT rebinding（v7 对照实验确认 fishhook 安全）
- `RuntimeHookChecker` 不检测 Logos %hook / method_setImplementation（v8 确认 ObjC swizzle 安全）
- Logos %hook + fishhook 的组合不触发任何 Checker

## 检测向量

### 1. 文件路径检测

App 使用多种途径检测越狱文件：
- C 层：stat/access/open（通过 GOT 调用）
- C 层：syscall() 直接系统调用（SYS_stat64, SYS_access, SYS_open）
- Inline SVC：svc #0x80 汇编直接发起（确认存在，不可 GOT 级拦截）

已确认检测的路径类型：
- 标准越狱路径（/Applications/Cydia.app, /Library/MobileSubstrate 等）
- rootless 路径（/var/jb 及 /private/preboot/.../procursus/... 真实解析路径）
- 注入框架路径（TweakInject/*.plist 等）
- frida 相关路径

当前覆盖：fishhook stat/lstat/access/open/fopen/opendir/readdir/realpath/readlink/statfs/statvfs/syscall

### 2. 动态库枚举

通过 _dyld_image_count / _dyld_get_image_name 枚举加载的 dylib。

当前覆盖：fishhook _dyld_image_count + _dyld_get_image_name，统一过滤越狱相关 dylib 名称。

### 3. 环境变量

检测 DYLD_INSERT_LIBRARIES 等注入痕迹。

当前覆盖：
- fishhook getenv
- Logos %hook NSProcessInfo environment

### 4. URL Scheme

通过 canOpenURL: 检测 cydia:// / sileo:// 等。

当前覆盖：Logos %hook UIApplication canOpenURL:

### 5. App 内部状态传播

多个属性/方法传播越狱状态：
- isJailBreak, isJailbreak, jailbroken, jailbreaking
- phoneIsJailBreak, MaxentJailBroken
- isJailBrokenOne/Three/Four/Five
- p_isJailBreak1, p_isJailBreak2
- authorityWithJailBreakFlag:
- showJailBrokenAlertIfNeeded

当前覆盖：hookICBCJailbreakMethods() 全类遍历 + hookShowJailBrokenAlert() + hookAuthorityJailBreakFlag()

## 冻结机制

### 触发条件

Inline SVC 检测到越狱文件存在 → 触发冻结循环。由于 inline SVC 无法被 GOT rebinding 拦截，冻结循环会持续运行。

### 冻结手段（持续循环，非一次性）

30 秒内的实测数据：

| 手段 | 调用次数 | 频率 |
|------|----------|------|
| dispatch_semaphore_wait(FOREVER) | 14,083 | ~470次/秒 |
| setAnimationsEnabled:NO | 4,977 | ~166次/秒 |
| beginIgnoringInteractionEvents | 多次 | - |
| setUserInteractionEnabled:NO | 持续 | - |
| removeAllAnimations | 持续 | - |

### 当前对抗

- semaphore_wait(FOREVER) 在主线程始终返回 0
- setAnimationsEnabled:NO / setUserInteractionEnabled:NO 时间门控 3s 后拦截
- removeAllAnimations / removeAnimationForKey: 时间门控 3s 后拦截
- beginIgnoringInteractionEvents 直接 block

## 弹窗退出机制

### 已确认弹窗

1. **"安全提示"**
   - message: "您的设备环境存在隐私信息泄露和非法信息攻击等风险，为了保护您的账户及资金安全，请您在其他安全设备上使用。"
   - action: "确定" (style=Cancel)
   - handler: **调用 exit() 杀进程**

2. **"风险提示"**（登录时触发）
   - message: "您的系统可能已经越狱，可能会给您带来财产损失、隐私泄露等风险，我行建议您更换终端进行操作。"
   - action: "确认" (style=Default)

### 当前对抗

- alertControllerWithTitle 中标记含关键字的弹窗
- presentViewController 中对标记弹窗完全静默（不展示、不调用 handler）

## 反调试

- Frida attach 后 app 立即被杀（可能是 ptrace/task_threads inline SVC）
- 当前不做对抗（不影响 tweak 工作）

## 已排除的假设

- ❌ CFRunLoopStop 导致冻结
- ❌ CALayer.speed=0 导致动画冻结
- ❌ level=2000 覆盖窗口导致触摸失败
- ❌ hitTest:withEvent: 返回 nil
- ❌ sendEvent: 被自定义窗口过滤
- ❌ 主线程被 sleep/nanosleep/dispatch_group_wait 阻塞

## 版本适配优先检查

ICBC App 升级后建议检查顺序：

1. MSHookFunctionChecker 是否新增了 GOT rebinding 检测
2. 冻结循环是否改用新阻塞原语（pthread_mutex/mach_msg/__ulock_wait）
3. 弹窗文案/关键字是否变更
4. SecureUtilityPlus 新增 Checker 类或 selector 变更
5. 是否新增 inline SVC 退出路径（绕过 freeze 循环直接杀进程）
