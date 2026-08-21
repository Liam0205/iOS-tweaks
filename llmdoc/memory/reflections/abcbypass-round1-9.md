# ABCBypass Rounds 1-9 Reflection (v1 - v81)

> ✅ **2026-08-21 复核（analysis.md 第 15 轮）。** 本文最核心的教训——
> "MSHookFunction hook libc/pthread 触发 SDK 内存完整性扫描 → SIGSEGV"——已被
> 可信二分实验**再次证实且范围更广**：不止 pthread_create，`stat/open/access/
> sysctl/dlopen/_dyld_*` 等 libc 函数被 inline-hook 都会触发固定哨兵地址
> `0x00000000b5a06000` 的崩溃。**保守结论：对 ABC 任何 C 函数都不要 inline-hook。**
>
> ⚠️ 但凡本文涉及"存活/UI 存活"的具体数字或成功断言，同样受"grep 匹配到扩展进程
> `group.abc.toolExtension` 而非主 App"的方法论错误影响，需以第 15 轮可信基线为准
> （裸跑主 App ~13s 正常退出）。

## Task

对农业银行 (com.bankabc.iphonerelease, binary MbapMPaaS) v11.1.0 的越狱检测绕过开发。目标 SDK 使用 SmAntiFraud + SecurityGuard/mPaaS + SecureUtilityPlus 三层检测架构，含多重杀进程机制。经历 9 轮迭代，从 v1 到 v81。

## Expected vs Actual

- 预期：像 icbcbypass 一样，通过 fishhook + exit 拦截 + 线程冻结组合拦住检测退出。
- 实际：SDK 具备 inline SVC #0x80 直接杀进程能力，且对 libpthread 代码段做内存完整性扫描。最终方案演化为三层防御：fishhook/MSHookFunction 混合策略 + exit 路径 ARM64 栈切换 + 巡逻定时器线程挂起 + CFRunLoopPerformBlock 绕过损坏的 dispatch queue。

## What Went Wrong

1. **MSHookFunction 触发内存扫描 crash**：在 `pthread_create` 上使用 MSHookFunction 导致 SDK 的 XPC 线程用 `memmem` 扫描到 hook island 附近未映射内存 → SIGSEGV。花费多轮才通过 bisect（4/4 crash vs 0/4 clean）定位到具体原因。
2. **fishhook 覆盖率不足**：fishhook 只 hook PLT/GOT 调用，对 `dispatch_async` 只捕获 5 次重定向，而 MSHookFunction 捕获 560+ 次。检测线程创建走 shared cache 内部调用，fishhook 完全拦不住。
3. **exit() 返回后栈损坏**：`exit()` 是 `_Noreturn`，编译器不生成返回代码。直接从 exit hook 返回触发 `__stack_chk_fail` → SIGSEGV 级联崩溃。
4. **dispatch queue 不可修复**：栈切换后 main queue 处于 drain lock held + CFRunLoopSource disarmed 状态。所有修复尝试（清锁、dispatch_async 新 block、mach_msg 唤醒）均失败。
5. **延迟 fishhook 时序问题**：ctor 中调用 `rebind_symbols` 触发 BSXPCServiceConnection SIGTRAP crash，必须 dispatch_after 200ms。

## Root Cause

- SDK 对不同系统库有选择性内存扫描（libpthread 被扫，libdispatch 不被扫），导致 MSHookFunction 不能统一使用。
- inline SVC #0x80 从用户态完全不可 hook，逼迫策略从"阻止检测"转向"阻止响应 + 存活"。
- `_Noreturn` 函数的调用约定使得常规 hook return 不可行，必须用 ARM64 汇编做栈切换。
- dispatch queue 内部状态与 RunLoop source 紧耦合，外部无法安全修复中断的 drain 流程。

## Key Technical Decisions

| 决策 | 依据 |
|------|------|
| MSHookFunction 用于 dispatch_async/exit/abort，fishhook 用于 pthread_create | SDK 扫描 libpthread 不扫 libdispatch；pthread_create fishhook 足够（PLT 调用）|
| ARM64 栈切换（mov sp + ret to trampoline） | exit() _Noreturn 使正常返回不可能，栈切换避免 canary 检查 |
| CFRunLoopPerformBlock 代替 dispatch_async | main queue 被栈切换损坏后不可修复，CFRunLoop 直接绕过 |
| 0.3s 巡逻定时器持续挂起非系统线程 | fishhook 拦不住内部 pthread_create 调用，逃逸线程秒内执行 svc #0x80 |
| rebind_symbols 延迟 200ms | ctor 中调用触发 XPC SIGTRAP，文件/dyld hook 可在 ctor |

## Missing Docs or Signals

1. 无文档记录"哪些系统库会被 SDK 内存扫描"——需要逐个 bisect 验证。
2. 无文档记录 `_Noreturn` 函数 hook 的栈切换模式——这是通用技术，应作为参考文档。
3. 无文档记录 dispatch queue 内部状态模型——损坏后的行为完全靠试错发现。
4. fishhook vs MSHookFunction 的适用场景选择缺乏决策框架文档。

## Promotion Candidates

| 内容 | 建议目标 |
|------|---------|
| MSHookFunction 触发内存扫描的条件与 bisect 方法 | `reference/` 新增 abc-detection-vectors.md |
| _Noreturn 函数 hook 的 ARM64 栈切换模式 | `guides/reverse-engineering-methodology.md` 补充 |
| fishhook vs MSHookFunction 决策矩阵 | `architecture/tweak-architecture.md` 或独立参考文档 |
| "阻止检测 → 阻止响应 → 存活" 策略演进模型 | `guides/reverse-engineering-methodology.md` |
| dispatch queue 损坏后 CFRunLoopPerformBlock 绕过 | 仅保留 memory，过于特定 |

## Follow-up

1. 为 abcbypass 创建 `reference/abc-detection-vectors.md`，记录三层检测架构、各层杀进程机制、内存扫描范围。
2. 在 `reverse-engineering-methodology.md` 中补充"不可返回函数 hook"的通用模式。
3. 当前 v81 仍需验证长期稳定性（巡逻定时器误伤 GCD worker 的风险）。
