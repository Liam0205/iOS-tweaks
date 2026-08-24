# 汇丰中国 Promon SHIELD 检测定位与绕过 PoC 反思（Round 55-76）

> 本反思衔接并部分推翻 [[hsbc-methodology-lesson]]
> （`llmdoc/memory/reflections/hsbc-methodology-lesson.md`）。旧反思写在 10+ 轮时，结论是
> "检测=OneSpan RASP，退出走 raw syscall，用户态完全不可拦截"。本次会话（Round 55-76）把
> 这两条结论都更新了：**真凶是 Promon SHIELD，不是 OneSpan**；退出确实经私有 svc 网关和
> raw syscall/mach trap，但**用户态其实能拦到最终判定所依赖的那个检测点**（不是拦 syscall
> 本身，是拦目标自己的 mach 封装函数）。以下只记本次新增的发现与教训，不重复旧反思内容。

## Task

在已定位到"检测在主 binary、退出走 native 状态机"的基础上（截至 Round 54），继续对
`cn.com.hsbc.hsbcchina`（版本 3.72.15，2215 设备 / iPhone 13 Pro / iOS 15.4.1）做指令级
定位，目标是找到真正的退出触发点并做一次可验证的绕过 PoC。

## Expected vs Actual

- 预期：在 Round 52 定位的"巨型状态机 `0x75bf7c`"上继续 patch/nop 退出调用点，应该能逐步
  收敛到净启动。
- 实际：
  - `0x75bf7c` 是假线索——用 ElleKit hook + fp-chain 回溯证明它只跑 3ms 就正常返回，真正
    的 verdict 在另一处（init[42] 的 CFF 状态机 `0x43ebc4`）。此前 8 轮（Round 52-59）在
    `0x75bf7c` 上的 patch/nop 全部打在无关代码上。
  - SDK 身份被修正：strings 实锤 `no.promon.shield`/`PRMShield`，确认是 **Promon
    SHIELD**，不是旧反思认定的 OneSpan，也不是中途怀疑过的 ThreatMetrix/TuringShield。
  - 检测机制被追到最终一步：Promon 经私有数据段 svc 网关（全局槽 `0x8510c8` 存网关地址
    `0x78befc`，字节为 `svc #0x80; ret; brk`，83 个封装用
    `ldr x17,[0x8510c8]; blr x17` 陷内核，完全绕开 libSystem 具名符号）发
    `mach_msg(msgh_id=4808 = mach_vm_read_overwrite)`，在 `mach_task_self` 上逐个读
    每个已加载库的 Mach-O 头 32 字节，识别注入库。唯一触发退出的注入库是
    `systemhook.dylib`（Dopamine 注入核心）。
  - 干预确实有效但未达"净启动"：hook 目标自己的 mach 封装函数 `0x40c698`，篡改
    该库头部数据——清零 magic 能绕过 exit 但导致 100% CPU 自旋；替换路径特征字符串能把
    退出从 3s 推迟到 17s，但仍会退出。

## What Went Wrong

- **追错函数 8 轮**：在没有运行时证据的情况下，把"看起来像检测逻辑"的巨型混淆函数
  `0x75bf7c` 当成退出点，围绕它反复 patch/nop 了 8 轮（Round 52-59），直到用 ElleKit
  hook 观察到它 3ms 正常返回才发现打错了目标。
- **反复撞"中途改控制流必自旋"的铁律**：改 verdict 的 csel、拦 exit 封装、nop exit 调用、
  patch `b.ne` 分支——每一种都导致状态机自旋，重复验证了同一条约束却没能提前预判。
- **一度把别的 SDK 的行为误判成 Promon 的行为**：hook `vm_region_recurse_64` 观察到
  400+ 次遍历、能跳过 30+ 个注入 dylib 区域，一度以为找到了检测向量，但过滤后 App 仍
  退出。后来核对 `hsbcchinax` 的 bind/lazy-bind 表才发现它根本不导入任何内存枚举类
  libSystem 函数——那个 `vm_region_recurse_64` walk 来自进程里另一个并存的安全 SDK
  （疑似 TuringShield/RASPFramework），与 Promon 无关。
- **观测手段本身有代价**：想在 svc 网关处观测检测轨迹，必须 nop-store（覆盖 App 自己
  对网关的安装），但这样会破坏 `0x346c68→0x75bf7c→0x346c7c` 的安装序列导致自旋，只能
  拿到退出前约 500ms 的数据；不 nop-store 则完全观测不到（App 在微秒级同步跑完检测）。
  最终改用 ElleKit hook 目标自己的 mach 封装函数（不破坏安装序列）才干净拿到全部
  `mach_vm_read` 请求。
- **Shadow 全 hook 集对私有网关无效**：设备已装 Shadow（含全 18 项 hook，包括
  `Hook_Syscall`），照搬到 HSBC 配置后仍 3s 静默退出，无变化。
- **Frida 注入被拦**：spawn 时在注入完成前就被终止。

## Root Cause

- 8 轮追错函数的根因是"猜测驱动"而非"证据驱动"：看起来复杂、看起来是检测逻辑，就直接
  patch，而没有先用运行时回溯（fp-chain）或 hook 证明它确实在崩溃前的调用链上。
- 自旋铁律的根因是 OLLVM 控制流平坦化（CFF）dispatcher 依赖状态变量的自然取值：强改
  分支或 exit 调用会让状态变量与代码路径不一致，下游 dispatcher 找不到匹配状态就死循环。
  唯一出路是改变"进入判定前的输入"，让状态变量自然演化出未越狱的值，而不是在判定之后
  截断。
- 误判别的 SDK 行为的根因是同一进程里存在多个安全 SDK，仅凭"某个可疑 API 被频繁调用"
  不能推断调用方就是正在分析的目标二进制。
- 私有 svc 网关绕开 libSystem 的根因是 Promon 的设计本身就针对 hook 工具：把系统调用
  封装收进私有数据段/BSS 槽而非走具名符号，任何基于符号解析的 hook（fishhook、
  MSHookFunction 挂 libSystem 函数、Shadow 之类工具级 hook）天然覆盖不到。

## Missing Docs or Signals

- `guides/reverse-engineering-methodology.md` 目前有"最小改动优先"原则，但没有明确要求
  "patch 一个疑似退出点之前，先用运行时回溯/hook 证明它在退出路径上"。这次 8 轮追错函数
  正是缺了这一步验证。
- 方法论文档假定检测引擎是单一的，没有提醒"同一进程可能有多个安全 SDK 并存"，也没有给出
  用 dladdr/bind 表核对调用方身份的具体做法。这次靠核对 `hsbcchinax` 的 bind 表才排除了
  误判，属于事后才想到的排除法。
- 方法论文档现有结论"Raw syscall 退出：通常无法在普通用户态稳定拦截"不完整。本次证明：
  即使检测最终落到 raw syscall/mach trap，只要能定位到目标**自己**发起该调用的封装函数
  （而不是 libSystem 里的标准入口），用户态 hook 依然可以拦截并观察到完整参数；只是这个
  封装函数的地址是二进制特定的，需要先做定位工作。这个"私有网关"模式本身值得写成一条
  判别规则。

## Promotion Candidates

1. **新建 `reference/hsbc-china-detection-vectors.md`**：应升级。理由——本次会话把
   Promon SHIELD 身份、私有 svc 网关机制（槽 `0x8510c8`→`0x78befc`）、init[42] verdict
   位置（`0x43ebc4: cmp w9,#0x144ab99a`）、`mach_vm_read_overwrite`（msgh_id 4808）读库头
   识别 `systemhook.dylib` 的完整链路，都已跨 20+ 轮稳定下来，性质与
   `reference/lianjiabypass-detection-vectors.md`、`reference/abc-detection-vectors.md`
   一致，属于可复用的稳定参考事实。目前 `llmdoc/index.md` 的 `reference/` 列表没有 hsbc
   条目，是明显缺口。记录时需注明版本（汇丰中国 3.72.15）与设备（2215/iOS 15.4.1），
   避免像早期 abcbypass 反思一样把版本特定的地址偏移当成跨版本依据。
2. **补充到 `guides/reverse-engineering-methodology.md`**：应升级，三条通用教训——
   - patch/nop 一个"疑似退出点"函数之前，必须先用运行时手段（fp-chain 回溯、
     hook 观察调用是否真的发生在崩溃前的调用链上）证明因果，否则会像本次一样在错误
     函数上反复迭代。可作为"最小改动优先"原则下的具体子规则。
   - 观察到某个可疑 API（如内存枚举、文件检测）被频繁调用，不能直接归因于当前分析的
     目标二进制；同一进程可能有多个安全 SDK 并存。应先用 dladdr 核对调用者模块，或
     检查目标二进制自己的 bind/lazy-bind 表，确认它确实导入/调用了这个 API。
   - 若目标把系统调用封装收进私有数据段/BSS 槽（不走 libSystem 具名符号），所有基于
     符号解析的 hook（fishhook、MSHookFunction 挂 libSystem、Shadow 之类工具级 hook、
     GOT rebind）会全部失效；此时唯一可行的用户态拦截点是目标自己的封装函数入口，
     需要先靠静态分析定位该入口的地址。这应作为"确认检测逻辑位于哪一层"之后新增的
     判别分支。
3. **仅留在本反思 + `hsbcbypass/analysis.md`**：`systemhook.dylib` 是本次触发退出的
   具体元凶、"3s→17s"的干预效果曲线、方案U 的具体 hook 地址（`0x40c698` 等）——这些是
   当前版本的具体实验结果，PoC 尚未达成净启动，属于进行中的项目经验，不具备立即跨项目
   复用的价值，留在 analysis.md 即可；待方案稳定或有第二个 Promon SHIELD 目标验证后再
   考虑并入 reference 文档。

## Follow-up

- 请 `recorder` 新建 `reference/hsbc-china-detection-vectors.md`（覆盖 Promon SHIELD
  身份、svc 网关机制、init[42] verdict、`mach_vm_read_overwrite` 检测链路，标注版本与
  设备），并在 `llmdoc/index.md` 的 `reference/` 列表补一行索引。
- 请 `recorder` 在 `guides/reverse-engineering-methodology.md` 追加上述三条教训
  （patch 前先证明因果、多 SDK 并存需核对调用方身份、私有 svc 网关使符号 hook 全失效）。
- PoC 净启动未达成，GitHub issue #1（内核层隐藏越狱环境）记录了兜底方案。下一步是在
  "构造自洽的合法库镜像伪装"（让 `systemhook.dylib` 区域的读取返回一个头部、loadcmds、
  地址全部自洽的合法库镜像）与 issue #1 的内核层方案之间二选一，两者工程量都较大，
  建议下一任务开始前先读本反思与新建的 reference 文档，避免重走 Round 52-59 的弯路。
