# SimTouch Phase 2 开发反思 (v1 - v24)

## Task

SimTouch Phase 2 目标：在 Phase 1 截图 MVP 基础上实现远程触摸注入。环境为 iPhone 13 Pro / iOS 15.4.1 / Dopamine (rootless)。从 v1 到 v24，实现了基本触摸注入（tap/swipe/longpress）、事件录制基础设施、边缘手势 mask 发现，但回放功能尚未完成。

## Expected vs Actual

- 预期：基于 IOHIDEvent API 创建合成触摸事件，注入到 backboardd 的事件管道中，直接实现触摸模拟与录制回放。
- 实际：从零创建 IOHIDEvent 不产生触摸效果（BKS 附加隐式属性），必须克隆真实事件再修改字段。Darwin notification 新通道无法跨进程投递。backboardd 沙箱阻止写入 `/var/jb/` 路径。录制成功但回放无效果（待查）。

## What Went Wrong

1. **IOHIDEvent 从零创建无效**：使用 `IOHIDEventCreateDigitizerEvent` + `IOHIDEventCreateDigitizerFingerEvent` 创建完整事件并设置 senderID，调用 `orig_HandleFromSender` 后无可见触摸效果。花费多个版本排查，最终发现 BKS 内部对事件有未公开的属性依赖。
2. **Darwin notification 新通道不工作**：为录制控制注册新的 Darwin notification name（`BB_RECORD_START`/`BB_RECORD_STOP`/`BB_REPLAY_NOTIFY`），从 SpringBoard 发送到 backboardd，回调始终不触发。原因不明，调试时间浪费。
3. **backboardd 写文件到 /var/jb/ 路径失败**：尝试让 backboardd 将录制数据写入 `/var/jb/tmp/simtouch-record.bin`，文件无法创建。即使从 SpringBoard 预创建文件、设置 777 权限也无效。多个版本的调试时间。
4. **录制回放无触摸效果**：录制数据完整正确（通过 hex dump 验证），回放时用 clone 模板 + 设置所有字段 + 调用 `orig_HandleFromSender`，但不产生可见触摸。基本 `dispatchTouch` (tap) 仍然有效，说明问题出在回放逻辑而非基础架构。

## Root Cause

### 事件创建无效

BKS（BackBoardServices）在 IOHIDEvent 到达 `_BKHandleIOHIDEventFromSender` 之前，在更底层已经对事件附加了大量隐式内部属性（如 routing info、display association、policy flags）。仅设置 senderID 和标准 digitizer 字段不足以让事件通过 BKS 的验证管道。clone 真实事件保留了这些隐式属性，修改坐标/phase 后仍被 BKS 接受。

### Darwin notification 失败

可能原因：backboardd 进程启动早于 hook dylib 注册 notification observer 的时机，或 backboardd 的 CFRunLoop 运行在非默认模式下导致回调不被调度。在没有 lldb attach 到 backboardd 的情况下无法进一步确认。

### 沙箱写入限制

`/var/jb/` 在 rootless 越狱下是符号链接指向 `/private/preboot/<UUID>/procursus/`。preboot 分区有专门的沙箱保护，backboardd 作为系统守护进程不持有对该分区的写入 entitlement。`/tmp/`（→ `/private/var/tmp/`）是标准的全局临时目录，所有进程均可读写。

## 经验/教训 -> Why -> How to Apply

### 1. 事件克隆优于事件创建

**教训**：对于 iOS 内部事件系统（IOHIDEvent/BKS），不要尝试从零构造完整事件。

**Why**：Apple 的内部管道在事件上附加的隐式属性远超公开 API 可设置的范围。即使逆向出所有字段的偏移量，不同 iOS 版本间的内部布局也可能变化。

**How to Apply**：
- 先捕获一个真实事件作为模板（`IOHIDEventCreateCopy`）
- 只修改语义上需要变化的字段（坐标、phase、timestamp、mask）
- 如果 clone 后仍无效，排查是否有字段被 BKS 做了一致性校验（如 timestamp 范围检查）

### 2. 复用已验证的 IPC 通道，不轻易创建新通道

**教训**：跨进程通信（特别是到系统守护进程）时，优先复用已证明工作的通道。

**Why**：Darwin notification 看似简单（全局 name → 全局回调），但在实践中受进程启动顺序、RunLoop 模式、沙箱策略的影响。调试跨进程 IPC 故障极其困难——无法 attach debugger 到两个进程同时观察。

**How to Apply**：
- 当已有一个工作的通知通道时，通过在消息体中编码更多语义（如 phase 字段特殊值）来复用
- 仅在已验证通道无法满足需求时才引入新通道
- 引入新通道时，先在独立测试中验证双端连通，再集成到业务逻辑

### 3. backboardd 沙箱是硬约束

**教训**：不要假设 backboardd 能写入 `/var/jb/` 路径下的任何位置。

**Why**：`/var/jb/` → preboot 分区，有独立的沙箱策略。backboardd 是 launchd 管理的系统守护进程，其沙箱 profile 不包含 preboot 分区写入权限。与之对比，SpringBoard 虽然也是系统进程，但拥有更宽松的文件系统权限（或者说越狱工具专门为其 patch 了权限）。

**How to Apply**：
- backboardd 写文件统一使用 `/tmp/`（`/private/var/tmp/`）
- 如果需要持久化存储，由 SpringBoard 从 `/tmp/` 搬运到目标路径
- 对任何系统守护进程做文件操作前，先用最小 PoC 验证写入能力

### 4. 录制分析优于逆向盲猜

**教训**：对于未知的事件格式或标志位，录制真实操作并分析数据远比猜测高效。

**Why**：iOS HID 事件的 mask/flag 字段缺乏公开文档。通过 Hopper/IDA 逆向 BKS 可以找到字段偏移，但很难确定具体值的语义。录制后做 diff 分析（正常 swipe vs 边缘 swipe vs Home 手势），字段差异一目了然。

**How to Apply**：
- 在 hook 函数中实现 inline 录制（不引入额外 IPC 开销）
- 录制 binary 格式保留所有原始字段值
- 通过对比不同手势的录制数据，提取 bit 级别的语义差异
- 发现的 mask 值（如 `0x40000`=边缘、`0x1000000`=底部、`0x2000000`=顶部）应记录到参考文档

### 5. 回放 ≠ 逐字段赋值

**教训**（待验证）：clone + 设置所有录制字段 + 调用 orig 函数，不一定等于成功回放。

**Why 推测**：可能原因包括：
- 时间戳需要相对于当前系统时间而非绝对值
- BKS 有事件序列连续性检查（finger index、touch count、phase 状态机）
- 多子事件必须在单次调用中完整投递，不能逐帧调用
- 回放时的 senderID/token 必须匹配当前 HID 设备状态

**How to Apply**：
- 下一步对比成功的 `dispatchTouch` 路径与失败的回放路径的差异
- 逐步简化：先用录制数据的第一帧做 single tap 回放，排除时序问题
- 检查 BKS 是否对连续事件的 timestamp 做 monotonic 检查

## Missing Docs or Signals

1. 无文档记录 backboardd 沙箱的具体文件系统权限边界——需要试错发现。
2. 无文档记录 Darwin notification 在系统守护进程中的投递条件——失败后无法诊断。
3. 无文档记录 IOHIDEvent 的内部属性完整列表——clone 策略是经验性发现。
4. 无文档记录 BKS 事件管道的验证逻辑——回放失败无法定位具体校验点。

## Promotion Candidates

| 内容 | 建议目标 |
|------|---------|
| backboardd 文件系统权限约束（/tmp/ 可写，/var/jb/ 不可写） | `reference/simtouch-technical-decisions.md` 补充 Phase 2 节 |
| 事件克隆模式（clone + modify vs create from scratch） | `architecture/simtouch-architecture.md` Phase 2 更新 |
| 边缘手势 event_mask 位定义（0x40000/0x1000000/0x2000000） | `reference/simtouch-technical-decisions.md` 补充 |
| IPC 通道复用原则 | 仅保留 memory，过于特定 |
| 录制分析方法论 | `guides/reverse-engineering-methodology.md` 可补充 "数据驱动逆向" 小节 |

## Follow-up

1. 调查回放无效的根因：对比 `dispatchTouch` 成功路径与录制回放路径的 IOHIDEvent 内容差异（timestamp、senderID、child event count）。
2. 待回放问题解决后，更新 `architecture/simtouch-architecture.md` 增加 Phase 2 架构（backboardd hook、事件克隆管道、录制/回放数据流）。
3. 在 `reference/simtouch-technical-decisions.md` 补充 Phase 2 决策：hook 点选择、clone vs create、backboardd 沙箱约束、边缘手势 mask。
