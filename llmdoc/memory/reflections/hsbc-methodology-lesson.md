# HSBC Methodology Lesson

## Task
- 为 hsbcchinabypass 子项目记录一次方法论层面的反思，总结多轮逆向与对抗迭代后暴露出的错误假设、诊断顺序问题，以及后续文档建设方向。

## Expected vs Actual
- 预期结果：像 mybankbypass 一样，通过扩大 hook 覆盖面，逐层拦截 dyld、文件系统、GOT、退出路径，就能阻止目标 App 的越狱检测退出。
- 实际结果：经过 10+ 轮迭代后确认，HSBC China 使用的 OneSpan RASP 与 mybankbypass 面对的检测体系不同；检测引擎位于主 binary 的 C/C++ 静态库中，退出路径走 raw syscall（`svc #0x80`）或等价不可用户态拦截机制，ObjC delegate、libc exit hook、GOT rebinding、常规 dyld/文件系统隐藏都不足以阻止退出。

## What Went Wrong
- 过早把 mybankbypass 的成功经验当成通用策略，默认认为“全层 hook + 扩大拦截面”适用于所有 RASP。
- 在未先确认检测源头与退出机制前，就投入多轮对抗性 patch 与 hook 扩展，导致尝试顺序偏向“先打补丁，再理解对手”。
- 缺少显式的方法论约束，容易滑向“多试几个点看看”的无结构探索方式，用户已明确批评过这会变成“无头苍蝇一样胡乱尝试”。
- 分析记录虽然逐步积累，但没有在一开始就把每轮工作约束为“假设→验证→观察→推论”的闭环，导致部分迭代的收益主要体现在排除法，而不是快速收敛到关键诊断问题。
- 没有足够早地把“每次测试后必须更新 analysis.md，写明假设和结论”上升为硬性工作规则。

## Root Cause
- 错把“目标都是越狱检测”当成“实现层也相似”，忽略了对手能力模型的差异：mybank 主要是 ObjC 层检测与 libc 退出路径，而 OneSpan RASP 具备更低层、更内联的检测与退出能力。
- 缺少一份稳定的“逆向分析方法论”文档，导致任务执行时没有统一的诊断优先级：先确认检测在哪一层、由谁触发、通过什么机制退出，再决定应该在用户态 hook、Mach VM 层隐藏、还是直接做 binary patch。
- 现有文档更偏构建/部署与既有 tweak 架构，没有把“未知 RASP 的首轮分析流程”固化下来，导致跨任务迁移时容易默认沿用旧项目套路。

## Missing Docs or Signals
- 缺少一份面向逆向与对抗任务的指南，明确要求所有分析遵循“假设→验证→观察→推论”的结构化循环。
- 缺少一份针对未知检测引擎的首轮诊断清单，例如：
  - 先确认注入是否成功。
  - 再确认退出是否经过 crash report、signal、libc、Mach trap 或 raw syscall。
  - 再确认检测逻辑位于 ObjC/Swift 层、动态库、还是主 binary 静态库。
  - 最后才决定对抗层级与 patch 位置。
- 缺少明确文档信号提醒：每次测试结束必须立即更新 `analysis.md`，写下本轮假设、验证方法、观察结果、排除项与新的推论。
- 缺少提醒说明：成功项目（如 mybankbypass）的 hook 经验只能作为候选思路，不能直接外推到不同供应商、不同架构的 RASP。

## Promotion Candidates
- 应升级到 `guides/`：新增“逆向分析方法论”指南，固化“假设→验证→观察→推论”流程，并提供未知检测引擎的诊断优先级。
- 可升级到 `must/` 或同等级稳定规则文档：规定每次实验后必须更新 `analysis.md`，否则不能进入下一轮尝试。
- 可升级到 `reference/`：补充“常见退出机制判别表”，区分 libc exit、signal、自杀型 kill、Mach trap、raw syscall、watchdog 等现象与证据。
- 仅保留在 memory：本次具体教训是 HSBC China 的 OneSpan RASP 不走 ObjC delegate，且退出机制表现为 raw syscall/不可拦截路径，这属于当前任务的经验结论，后续若有更多样本再决定是否提升为稳定参考文档。

## Follow-up
- 在 hsbcchinabypass 后续分析中，把每一轮工作先写成可验证假设，再执行最小实验，并在 `analysis.md` 中记录观察与推论后再决定下一步。
- 后续应补写一份 `guides/` 级别的“逆向分析方法论”文档，明确先诊断检测源与退出机制，再选择 hook、隐藏、Mach VM 对抗或 binary patch 路线。
