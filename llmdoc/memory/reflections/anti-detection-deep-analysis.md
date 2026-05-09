# Anti-Detection Deep Analysis Reflection

## Task

对 icbcbypass 的反检测机制进行深层分析，包括 MSHookFunctionChecker 的可绕过性、inline SVC 的不可拦截性、fishhook 被禁的极端场景，以及防御方的结构性弱点。附带仓库配置修复经验。

## Expected vs Actual

- 预期：明确各层检测机制的技术边界和对抗极限。
- 实际：成功建立了完整的攻防分析模型，澄清了多个此前含混的技术判断。

## What Went Wrong

无严重错误。本次是分析型会话，核心收获是将模糊的经验判断提升为精确的技术结论。

## Root Cause

此前文档中「不可使用 MSHookFunction」的表述过于绝对化，未区分「技术不可能」与「风险管理决策」。

## Key Findings

### 1. MSHookFunctionChecker 的可绕过性澄清

icbcbypass 已通过 `method_setImplementation` 替换了 MSHookFunctionChecker 的所有 ObjC 方法入口。「不可使用 MSHookFunction」是**风险管理决策**而非技术不可能：

- **时序不确定性**：Swift 模块的 static initializer 可能比 tweak `%ctor` 更早执行，导致检测先于替换运行
- **覆盖完整性**：checker 内部可能有不经过 `objc_msgSend` 的 Swift 直接调用路径
- **成本收益**：fishhook 完全够用，无需冒险引入 MSHookFunction

结论：如果能确认 checker 只在被调用时扫描（非模块加载时），且所有入口都被 method replacement 覆盖，理论上 MSHookFunction 可用。但当前无需冒险。

### 2. Inline SVC 的用户态不可拦截性

inline `svc #0x80` 直接内联在代码段中，不经过 GOT、不是独立函数入口：

- 用户态 Hook（fishhook/MSHookFunction）**完全无效**
- 理论绕过路径：
  - Runtime 内存 patch -- 受 APRR/PPL 限制不可行
  - 二进制静态 patch -- 可行但维护成本高（每次 App 更新需重做）
  - 硬件断点 -- 理论可行但实现复杂
- **实际策略：接受检测命中，中和所有响应** -- 这是 icbcbypass 对 inline SVC 的核心哲学

### 3. fishhook 被禁的极端场景分析

如果 FishHookChecker 做到 inline 级别（GOT 验证内联，不可 Hook）：

- 自定义 trampoline（非标准 LDR+BR 模式）可绕过 prologue 检测
- 纯 ObjC 响应端对抗仍然可行（unfreezer timer + endIgnoringInteractionEvents）
- 但 `dispatch_semaphore_wait` 是 C 函数 -- 需要 ObjC 层补偿机制
- FishHookChecker 的 ObjC 入口已被 `method_setImplementation` 覆盖（与 MSHookFunctionChecker 同理）

### 4. 防御方的结构性弱点

**UX-安全性矛盾**：

- 好的用户体验（弹窗提示、冻结 UI）必须调用可 Hook 的高层 API（UIKit/GCD）
- 底层响应（inline SVC exit）闪退体验差，用户投诉风险高
- 防御方在 UX 和安全性之间无法兼得 -- 攻击者永远可以利用这个结构性弱点

### 5. 仓库配置修复经验

- `icbcbypass/control` 遗漏 `SileoDepiction` 字段导致 Sileo 不显示 depiction
- release workflow 的 release notes 应使用 `PREV_TAG..TAG` 而非 `PREV_TAG..HEAD`
- build workflow 应添加 `paths-ignore` 避免文档变更触发 macOS 构建

## Missing Docs or Signals

1. `icbc-architecture.md` 的「不可使用 MSHookFunction」表述缺乏「为何不用」的风险分析层（只说了不能用，没说清是不能还是不值得）
2. 缺少对 inline SVC 对抗哲学的显式记录（「接受命中，中和响应」）
3. 缺少极端场景（fishhook 被禁）的 fallback 策略文档
4. build/release workflow 的配置 checklist 不在任何文档中

## Promotion Candidates

| 内容 | 建议目标 |
|------|---------|
| MSHookFunction 禁用是风险决策而非技术不可能 | `architecture/icbc-architecture.md` 核心约束章节补充说明 |
| inline SVC 对抗哲学（接受命中，中和响应） | `architecture/icbc-architecture.md` 新增小节 |
| 防御方 UX-安全性结构性弱点 | `guides/reverse-engineering-methodology.md` 作为攻防分析框架 |
| workflow 配置 checklist（SileoDepiction/paths-ignore/tag range） | `guides/build-deploy.md` 补充 |

## Follow-up

1. 在 `icbc-architecture.md` 的核心约束章节增加风险决策说明段落，明确区分「技术不可能」和「风险管理」
2. 为 inline SVC 对抗哲学添加独立小节到架构文档
3. 在 `build-deploy.md` 增加 release/build workflow 配置 checklist
4. 考虑在 `reference/` 下新增 `anti-hook-detection-landscape.md`，记录各检测器的检测能力边界
