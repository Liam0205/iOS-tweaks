# ABCBypass Rounds 10-12 Reflection (v86 - v95)

> ⚠️ **2026-08-21 更正（见 analysis.md 第 15 轮）。** 本反思中所有依赖"进程存活/
> UI 存活/弹窗消失成功"的判断都**不可信**：当时用 `grep MbapMPaaS` 判断存活，
> 实际匹配到的是后台扩展进程 `group.abc.toolExtension`，不是主 App。可信重测表明：
> 裸跑主 App ~13s 正常退出、全量 hook ~1s 崩溃、`0xb5a06000` 崩溃根因是 **libc
> 函数 inline-hook 被完整性自检发现**。
>
> **仍然成立的部分**（策略性判断，与存活信号无关）：
> - "exit 后存活是错误方向，应阻止 exit 被调用" ——方向正确。
> - "longjmp 是非结构化跳转，不执行清理" ——机制描述正确。
> - "多检测路径 / 冗余设计" ——大方向对。
>
> **已作废的部分**：v86-88 各方案"杀了 N 个定时器""23s watchdog"等具体存活数据；
> "v95 成功消除弹窗""ctor 重排序成功"等成功断言；"libdispatch 安全"类结论。

## Task

继续对农业银行 (com.bankabc.iphonerelease) v11.1.0 的越狱检测绕过开发。本阶段从 v86 到 v95，聚焦两个方向：exit() 调用后存活策略，以及 SDK 识别与检测路径分离。

## Expected vs Actual

- 预期（Round 10）：通过 exit() 后的 RunLoop 恢复实现 UI 存活。
- 预期（Round 11）：通过 longjmp 从 exit() 中直接逃逸回 RunLoop 入口。
- 预期（Round 12）：识别 SDK 后精准打击检测入口，消除 exit 调用源头。
- 实际：exit() 存活策略全部失败（栈损坏/嵌套 RunLoop/longjmp 状态损坏）；SDK 确认为 mPaaS；ctor 重排序消除了第一检测路径（文件检测弹窗），但暴露了第二检测路径（hook 完整性 → GCD exit）。

## What Went Wrong

1. **exit() 是终点，不是中间站**（Round 10）：三种 exit 存活策略都因 UIKit/CF 内部状态不可恢复而失败。v86 栈切换 + timer sweep 杀了 11 个定时器但 UIKit 状态已被栈切换破坏 → 23s watchdog kill。v87 return from exit() 直接 __stack_chk_fail。v88 嵌套 RunLoop pump 导致 outer RunLoop 永久卡住。
2. **longjmp 跳过了不可跳过的清理**（Round 11）：longjmp 机械上成功（没有 crash），但 CF RunLoop 内部 timer callback 有 cleanup 代码在 longjmp 后永远不执行，RunLoop 内部锁/状态永久损坏 → UI 冻结。
3. **pre-emptive timer defusal 覆盖不全**（Round 11-12）：CFRunLoopAddTimer hook 成功拦截了 CFRunLoop 通道的定时器，但 SDK 同时使用 GCD dispatch_after 通道，后者完全不经过 CFRunLoopAddTimer。
4. **检测路径并非单一**（Round 12）：消除文件检测后（弹窗消失），exit 仍然被调用。说明 SDK 有独立的 hook 完整性检测路径，不依赖文件扫描结果。

## Root Cause

- exit() 后存活的根本问题：UIKit/CF/GCD 的内部状态在 exit flow 中已经开始清理或标记为 invalid，无论如何"回来"都面临不一致状态。
- longjmp 的本质缺陷：它是非结构化的控制流跳转，不执行 C++ 析构、不释放锁、不恢复 RunLoop 状态机。
- 双通道冗余杀死：CFRunLoop timer + GCD dispatch_after 互为备份，只拦截一个不够。
- 多检测路径独立运行：文件检测、ObjC 方法检测、hook 完整性检测各自独立判定并触发 exit。

## Key Technical Decisions

| 决策 | 依据 |
|------|------|
| 放弃 exit 存活策略，转向消除 exit 调用源 | Round 10 三种方案 + Round 11 longjmp 全部证明 exit 后恢复不可行 |
| hook CFRunLoopAddTimer 过滤一次性 delay>5s timer | 直接在注册时阻断 kill timer 比 exit 后抢救更可靠 |
| hook CFRunLoopRunSpecific + setjmp 作为 backup | longjmp 虽然有 UI 问题但至少不 crash，作为最后防线保留 |
| fishhooks-first ctor 重排序 | SDK ObjC 扫描期间调用 stat/access/fopen，必须在扫描前完成文件 hook |
| ObjC hook 移入 ctor（不再延迟） | ObjC 检测窗口在 ctor 阶段就已开启（v93 确认） |

## Lessons Learned

1. **策略方向判断**："exit 后存活"是错误方向。正确方向是"阻止 exit 被调用"。三轮失败后转向源头拦截是关键决策点。
2. **hook 安装顺序是检测绕过的核心**：fishhook 在 ObjC swizzle 之前安装是 v95 成功消除弹窗的唯一原因。SDK 的 ObjC class scanning 触发文件检测 API 调用，如果此时 fishhook 未就位则检测结果已缓存。
3. **冗余杀死通道是常见防御设计**：CFRunLoop timer + GCD dispatch_after 双通道表明 SDK 有意设计冗余。后续需要逐一识别并阻断所有通道。
4. **SDK 识别（mPaaS）打开了新的理解维度**：知道是蚂蚁 mPaaS 后，能预判其安全模块组合（SecurityGuard + SmAntiFraud + FishHookChecker），指导后续对抗方向。

## Missing Docs or Signals

1. 无 GCD dispatch_after 拦截的通用模式文档——这是一个普遍需求。
2. FishHookChecker 的具体检测逻辑未知——需要逆向分析 GOT 比对机制。
3. mPaaS SDK 初始化序列未完全理解——何时触发哪些检测模块仍有盲区。

## Promotion Candidates

| 内容 | 建议目标 |
|------|---------|
| ctor 安装顺序决定检测绕过成败 | 已反映到 `architecture/abc-architecture.md` |
| 双通道杀死（CFRunLoop + GCD） | 已反映到 `reference/abc-detection-vectors.md` |
| SDK 识别 = mPaaS | 已反映到 reference + architecture |
| "exit 后存活不可行" 的结论 | 仅保留 memory，场景特定 |
| longjmp + CF RunLoop 状态损坏 | 仅保留 memory，场景特定 |

## Follow-up

1. 逆向 FishHookChecker 实现，确认 GOT 完整性检测具体机制。
2. 研究 GCD dispatch_after 拦截方案（可能需要 hook dispatch_source_create 或 libdispatch 内部函数）。
3. 验证 ctor 内 fishhook 的时序窗口是否足够稳定（是否存在 race condition）。
