# SimTouch Phase 3 开发反思 (自定义曲线 + 键盘输入 + Pinch/Zoom)

## Task

SimTouch Phase 3 在 Phase 2 (触摸注入+录制+系统手势) 基础上实现三个功能：
1. 自定义 swipe 曲线 (cubic-bezier easing)
2. 键盘输入 (HID keyboard event + clipboard paste)
3. Pinch/zoom 多指触摸

环境：iPhone 13 Pro / iOS 15.4.1 / Dopamine (rootless)，Linux 交叉编译。

## Expected vs Actual

- 预期：基于 Phase 2 已验证的事件克隆模式，扩展 STSwipeCmd 支持曲线、注入 HID keyboard events、克隆模板扩展为双指 pinch。
- 实际：自定义曲线和键盘输入顺利完成。Pinch/zoom 首次尝试（克隆模板+append finger）失败，必须从零创建 Hand type 的 IOHIDEvent parent 才能工作。这直接反转了 Phase 2 决策 #8 的结论。

## What Went Wrong

### 1. Pinch 第一次尝试：克隆模板 + append finger（失败）

克隆 `_capturedEvent` 并修改 child[0] 为 finger1，再创建+append finger2。

问题：
- `_capturedEvent` 是从真实单指事件捕获的，已有 2 个 children。append 后变成 3 children，iOS 不识别为 pinch。
- 即使手动修正为 2 个 children，pinch 仍不生效。根因：克隆的模板 parent 是 Finger type（单指 digitizer），不是 Hand type（多指容器）。iOS 对 pinch/zoom 要求 parent type=Hand(3)，而不是 Finger(11)。

### 2. sbreload 不重启 backboardd

修改 BackboardHook.x 后执行 `sbreload`（重启 SpringBoard），发现旧 backboardd hook 逻辑仍在执行。浪费时间排查代码逻辑问题，实际是部署问题。

### 3. DIAG_NOTIFY 诊断通知从未工作

backboardd 中的 `DIAG_NOTIFY` 宏发送 Darwin notification 到 `"page.0x01.simtouch.bb.diag.<tag>"`，但 SpringBoard 端没有匹配 observer。这些诊断通知自始至终没有产生任何可观测效果，属于死代码。

## Root Cause

### 克隆失败的根因

Phase 2 建立的"克隆优于创建"规则是在单指触摸场景下得出的。单指触摸时，BKS 管道对事件附加了大量隐式属性，从零创建缺少这些属性导致被丢弃。

但多指 pinch/zoom 是完全不同的事件结构：
- Parent 必须是 `kIOHIDDigitizerTransducerTypeHand (type=3)`
- Children 必须是独立的 `kIOHIDDigitizerTransducerTypeFinger` 且 index/identity 不同
- Parent 需要 `kIOHIDEventFieldDigitizerCollection=1` 和 `kIOHIDEventFieldDigitizerIsDisplayIntegrated=1`

克隆单指模板时，parent type 是 Finger 不是 Hand，且子事件结构不可控（children 数量/identity 错误）。从零创建 Hand type parent + 正确配置的 finger children，搭配捕获的 senderID，是唯一可行路径。

### sbreload 不重启 backboardd

`sbreload` 仅重启 SpringBoard.app 进程。backboardd 是独立的 launchd 托管的系统守护进程，其生命周期独立于 SpringBoard。要更新 backboardd hook 代码，必须执行 `killall backboardd`（launchd 会自动重启它）。

## 经验/教训 -> Why -> How to Apply

### 1. Clone vs Create 不是非此即彼，取决于事件类型

**教训**：Phase 2 的"事件克隆优于从零创建"不是绝对规则。正确规则是：
- **单指触摸**：必须克隆（BKS 隐式属性依赖）
- **多指 pinch/zoom**：必须从零创建 Hand type parent（克隆单指模板的 parent type 错误，子事件结构不可控）

**Why**：BKS 的验证逻辑区分事件层级。对于单指事件，验证集中在 root event 的隐式属性（routing info、display association）。对于多指事件，验证集中在 parent-children 的结构完整性（type 必须是 Hand、children 数量正确、identity 唯一）。两种场景的约束方向不同。

**How to Apply**：
- 单指操作 (tap/swipe/longpress)：继续使用 clone 模板 + 修改坐标/phase
- 多指操作 (pinch/zoom/rotate)：从零创建 Hand parent + N 个 Finger children + 捕获的 senderID
- 遇到新的事件类型时，不要假设已有策略适用，先用最小 PoC 验证

### 2. 部署到 backboardd 必须 killall backboardd

**教训**：`sbreload` 只重启 SpringBoard，不影响 backboardd。更新 backboardd hook 后必须执行 `killall backboardd`。

**Why**：backboardd 是 launchd 直接管理的独立进程 (com.apple.backboardd.plist)，不是 SpringBoard 的子进程。它的 dylib 注入发生在自身进程启动时，与 SpringBoard 的生命周期无关。

**How to Apply**：
- 修改 BackboardHook.x 后的部署命令：`killall backboardd`（launchd 自动重启）
- 修改 Tweak.x (SpringBoard hook) 后的部署命令：`sbreload`
- 同时修改两者时：先 `sbreload`，再 `killall backboardd`（或反序均可，因为 backboardd 重启后 SpringBoard 也会重启）

### 3. 诊断基础设施必须端对端验证

**教训**：`DIAG_NOTIFY` 宏从未实际工作过。发送端（backboardd）有代码，接收端（SpringBoard）没有匹配 observer。这种半截的诊断基础设施不如不存在——它给人一种"正在被诊断"的错觉。

**Why**：开发中先写了发送端宏，计划后续补接收端 observer，但在功能调通后忘记补全或清理。

**How to Apply**：
- 诊断通知必须端对端验证：发送方和接收方同时存在且测试过
- 无用的诊断代码应清理，避免误导后续开发
- 优先使用文件日志（`/tmp/simtouch-bb.log`）作为 backboardd 的诊断手段——已证明可靠

### 4. IOHIDEventCreateCopy 是深拷贝

**教训**：`IOHIDEventCreateCopy` 复制 children 也一起深拷贝。因此克隆含 2 个 children 的模板后 append 新 child 会得到 3 个 children。

**How to Apply**：
- 克隆前确认模板的 children 数量
- 如果需要修改 children 结构，考虑从零创建而非克隆

### 5. Newton's method 求解 cubic-bezier 是可靠的

**教训**：CSS cubic-bezier 求解 (给定 t 的 x 值求对应的 y 值) 用 Newton's method 迭代 8 次 + 二分法 fallback 即可稳定工作。在 backboardd 实时注入路径中无性能问题。

**How to Apply**：
- 曲线插值代码可直接复用到其他需要 easing 的注入场景
- curve_type enum 设计（0=linear, 1-3=预设, 4=自定义 bezier）便于 CLI 传参

## Missing Docs or Signals

1. Phase 2 技术决策 #8 的表述过于绝对（"从零创建 IOHIDEvent 不产生任何可见触摸效果"），缺少作用域限定（仅验证了单指场景）。
2. 无文档记录 `sbreload` vs `killall backboardd` 的作用范围差异——部署流程文档缺失。
3. 无文档记录 IOHIDEvent parent type 对多指手势识别的影响（Hand vs Finger type 语义）。
4. DIAG_NOTIFY 基础设施在代码中存在但文档未标注其不工作状态。

## Promotion Candidates

| 内容 | 建议目标 |
|------|---------|
| Clone vs Create 规则修正（按事件类型分策略） | `reference/simtouch-technical-decisions.md` 更新决策 #8 |
| 多指 pinch 创建配方（Hand parent + Finger children + senderID） | `architecture/simtouch-architecture.md` Phase 3 节 |
| sbreload vs killall backboardd 部署边界 | `guides/build-deploy.md` 补充 SimTouch 部署小节 |
| cubic-bezier Newton's method 实现 | 仅保留 memory，实现细节不需要架构级记录 |
| HID keyboard event 注入配方 (usagePage=0x07 + Cmd+V 粘贴) | `architecture/simtouch-architecture.md` Phase 3 节 |

## Follow-up

1. 更新 `reference/simtouch-technical-decisions.md` 决策 #8：将绝对结论修正为按事件类型分策略的条件结论。
2. 在 `architecture/simtouch-architecture.md` 增加 Phase 3 架构节（曲线插值、键盘注入、pinch 创建配方）。
3. 在 `guides/build-deploy.md` 补充 SimTouch 部署命令表（哪个文件改动对应哪个 kill 命令）。
4. 清理 DIAG_NOTIFY 死代码或补全接收端 observer。
