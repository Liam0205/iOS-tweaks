# icbcbypass v1.0.0 发布反思

## 时间

2026-05-09

## 完成了什么

icbcbypass tweak 从零开始到 v1.0.0 发布，绕过工商银行 (com.icbc.iphoneclient) 3.0.80 的越狱检测+主线程冻结+退出弹窗三层防御。

## 关键教训

### 1. fishhook 替代 MSHookFunction 是 ICBC 专属约束

ICBC 使用 SecureUtilityPlus（IOSSecuritySuite 增强版），其中的 `MSHookFunctionChecker` 检测 C 函数 prologue 的 trampoline 修改。MSHookFunction 会触发反篡改（跳转到 0xb5a06000 无效地址 crash）。fishhook（GOT rebinding）修改 PLT 指针而非函数 prologue，不被检测。

**教训**: 不同 App 的反注入引擎对 hook 机制有不同检测能力。在诊断阶段必须先通过对照实验确认哪些 hook 手段安全。

### 2. 嵌套 CFRunLoopRun 是致命错误

v34-v60 长期存在"交互卡死"问题。根因是在 `dispatch_semaphore_wait` 和 `setAnimationsEnabled:` hook 内部调用 `CFRunLoopRun()`。调用者代码被悬挂在栈上，可能持有 ObjC runtime 锁或内部互斥锁，嵌套 RunLoop 再尝试获取同一把锁 → 永久死锁。

**教训**: hook 内部永远不要进入嵌套 RunLoop。如果需要让被阻塞的调用通过，直接返回一个安全值，让原生 RunLoop 自然运行。

### 3. DISPATCH_TIME_FOREVER vs 有限超时必须区分

v63 登录成功但极度卡顿，因为所有主线程 >0.5s 的 semaphore wait 都被拦截了。实际上只有 `DISPATCH_TIME_FOREVER` 是 freeze 循环专用（每秒数百次），有限超时是合法同步操作。

**教训**: 反冻结策略需要精确区分攻击流量和正常流量。基于超时类型和时间窗口的两级策略（FOREVER 始终拦截 + 有限超时仅在前 10s 拦截）是有效方案。

### 4. 弹窗 handler 可能包含 exit()

v62 尝试模拟点击弹窗确认按钮导致 APP 闪退。越狱检测弹窗的 action handler 内部直接调用 exit() 杀进程。

**教训**: 被拦截弹窗的 action handler 必须假定为有害，不能盲目调用。正确策略是完全静默（不展示、不调用 handler）。

### 5. ICBC 冻结机制极其激进

30 秒内：14,083 次 dispatch_semaphore_wait(FOREVER)、4,977 次 setAnimationsEnabled:NO、多次 beginIgnoringInteractionEvents。这不是一次性检测后冻结，而是持续运行的 freeze 循环。

**教训**: 冻结机制可以是持续运行的循环，不仅是一次性触发。对抗策略也必须是永久性的（不能用一次性修复）。

## 文档缺口（需要更新稳定 docs）

1. `project-overview.md` 缺少 icbcbypass 条目
2. 缺少 ICBC 专属的检测向量参考文档
3. 缺少 ICBC 的架构文档（与 mybankbypass 差异很大）
4. `build-deploy.md` 缺少 icbcbypass 条目

## 方法论验证

逆向分析方法论 (reverse-engineering-methodology.md) 在 icbcbypass 开发过程中被严格执行，analysis.md 记录了 32 轮实验。该方法论证明了其在复杂多层防御场景下的有效性。特别是"对照实验"原则（v7 空 tweak 实验确认 MSHookFunction 是问题）和"先确认层级再写对抗"原则多次避免了错误方向。
