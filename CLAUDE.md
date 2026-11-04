默认使用简体中文回复；面向用户和维护者的文档也使用简体中文。

## 语言约定

- 日常交流、`llmdoc/`、README、Issue、PR 描述和评论默认使用简体中文。API 名、命令名、文件路径和代码引用保留原文。
- 使用自然、清楚的现代汉语。句子应说明谁做什么、为什么这样做以及有什么限制，不要连续堆放缩写、名词和内部术语。
- 中文句子使用全角中文标点。代码、命令、路径、参数和原样引用中的符号保持原样，不把其中的半角符号强行改成全角。
- 不为省字把完整名词压缩成生硬的单字。例如叙述 TeX box 时写“盒子”，不要写“盒”“父盒”“盒尾”；需要区分层次时写“外层盒子”“嵌套盒子”“盒子末尾”。
- 有普通说法时，不用生硬直译或流行套话。例如写“实现、连接、检查、决定、比对测试、形式”，不写“实装、真接入、闸门、拍板、对拍、形态”；也不要用“真……”一类说法强行强调。
- 技术词确有精确定义时可以保留。内部术语或不常见的英文词第一次出现时，应顺手说明它具体指什么，不能只换一个更抽象的词。
- 代码注释和技术文档优先描述可观察的行为与因果关系，少用比喻和口号式表述。

### 不要直译

英文词先想一层再写，不要在中文里制造同音或同义的直译词。已经清理过的：

| 不写 | 改写 |
| - | - |
| 注射 | 注入 |
| 收口 | 解决、处理完 |
| 落地 | 实现、写进、最终调到 |
| 证据强度 | 这条结论是怎么来的 |
| 可观测面 | 能看到什么 |
| 收窄 | 缩小范围 |
| 口径 | 数法、统计方式 |

判断办法：把这个词讲给一个不懂逆向的人听，他停下来问「什么意思」的，就是直译。

### 不要用抽象动词代替具体动作

商业汇报里的动词会把手上的事情说糊。写文档时说出谁做了什么。

| 不写 | 改写 |
| - | - |
| 闭环 | 解决、查清 |
| 沉淀（到某处） | 写进、记进 |
| 打崩 | 弄崩、让进程崩溃 |
| 收敛（抽象义） | 定在某个结论、最后认定为 |

技术义上的「收敛」不在此列，例如数值迭代的收敛速度、状态机从循环走到终止，都是正常数学用法。区别在于它有没有一个具体对象：有对象就保留，只是「这件事情收敛了」就要换掉。

### 自造的简写不是术语

给一个现象起两三个字的名字，即便在文档里定义过，也不合适。读的人每次都要还原一次，而且换成别的项目就没人懂。

| 不写 | 改写 |
| - | - |
| 自伤 | 自己造成的崩溃、问题出在我们这边 |
| 裸跑 | 原样运行（不加载 tweak，让 App 按原样启动） |
| 跳飞 | 跳到无效地址 |
| 接缝 | 能插手的环节 |
| 二律背反 | 两难、两难处境 |

判断办法：把词素拆开念一遍，如果两个字原本不是搭配在一起的（「自」和「伤」、「跳」和「飞」），它就是自造词。真正站得住的简写（毒地址、栅栏、block）要么有公认出处，要么描述的是一个具体物体。

借来的大词同样不能用。哲学术语、军事术语、法律术语拿来描述手边的工程问题时，读者要先跨过原来的领域才能回到眼前的事。「二律背反」原指康德的两组相互矛盾的命题，用在这里只是「两个要求没法同时满足」。能用一句大白话讲清的，就不要借一个需要有来历的词。

## 工作流

Load the `llmdoc` skill before broad code exploration, planning, document updates, or non-trivial code edits.

The main assistant should align with the user before non-trivial plans or edits.

Use available `llmdoc` subagents when they fit the task. Prefer `investigator` for context exploration, current-state research, unfamiliar subsystems, and reusable scratch reports; use `recorder` for stable doc updates, `worker` for scoped implementation, and `reflector` for process lessons.

At the end of a non-trivial task, the main assistant should evaluate whether to ask the user to run `/llmdoc:update`.

Treat `.llmdoc-tmp/` as a local temporary context cache only. Validate scratch reports before reuse; tracked `llmdoc/` docs are the project knowledge source.

Keep detailed workflow rules, templates, hook behavior, and doc-structure guidance in the `llmdoc` skill.
