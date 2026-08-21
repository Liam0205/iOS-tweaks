# 逆向分析方法论

## 适用范围

本指南固化 DEV-iOS 各 bypass 子项目在面对新目标 App、RASP 或新版本升级时的通用逆向分析方法。它不是某个 tweak 的实现细节文档，而是所有反检测对抗实验都应遵循的工作流约束。

当你在做以下事情时，应优先参考本文：

- 识别未知越狱检测/反注入引擎的工作方式
- 判断 App 为何闪退、冻结、被杀或延迟退出
- 设计最小实验验证某个检测向量或退出链路
- 决定下一轮该补哪个 Hook、该继续观察哪一层

## 核心循环：假设 → 验证 → 观察 → 推论

逆向分析与反检测对抗不是“多试几个 Hook”就能推进的过程，而是持续迭代的实验循环。每一轮必须严格按以下四步执行。

### 1. 假设（Hypothesis）

基于当前已知信息，提出一个具体、可验证、可被否定的猜测。

好的假设应满足：

- 指向明确的检测面、函数、类或链路
- 可以通过最小实验被验证或排除
- 本轮只聚焦一个变量

好的假设示例：

- “RASP 通过 `_dyld_get_image_name` 枚举 loaded images 来检测注入。”
- “当前退出走的是 `abort()`，而不是业务层直接 kill。”
- “检测逻辑不在 ObjC delegate，而在独立 dylib 的 `__mod_init_func`。”

坏的假设示例：

- “试试 hook 更多函数看看。”
- “应该是某个库有问题。”
- “先把常见 jailbreak hook 全加上再说。”

### 2. 验证（Verification）

为当前假设设计最小实验，用最少改动判断它成立还是不成立。

推荐手段：

- crash tag 编码：在 `%ctor`、目标 Hook、退出 Hook 中放置不同 crash tag，定位执行进度
- 条件 Hook：只在明确条件下触发 Hook，避免一次改动覆盖多个变量
- 空 tweak 对比：确认问题来自注入本身还是某个具体 Hook
- 禁用注入对比：区分“App 自身问题”与“tweak 介入后的问题”
- 分层禁用：按 ObjC 层、libc 层、Mach VM 层逐层缩小范围

验证原则：

- 一次只测一个变量
- 能做最小补丁，就不要一次性扩大覆盖面
- 能通过对比实验回答的问题，不要靠直觉判断
- 先确认“检测是否发生”，再确认“检测后如何退出”

### 3. 观察（Observation）

如实记录实验结果，只写客观现象，不提前把猜测当成结论。

重点观察项包括：

- 是否生成 crash report
- 退出时间是立即、数秒后还是更长延迟
- PID 是否变化，是否是原进程退出后重启
- crash address、signal、exception type 的含义
- crash tag 是否命中，命中了哪个阶段
- Hook 是否触发，触发频率与时序是否符合预期
- 现象是否与预期一致，还是出现反常行为

观察记录应能回答两个问题：

- 这轮实验到底发生了什么
- 结果是否支持当前假设

### 4. 推论（Inference）

基于观察更新认知模型，明确本轮排除了什么、确认了什么，以及下一轮最值得验证的假设是什么。

推论至少要包含：

- 已排除的路径或层级
- 已确认的事实或约束
- 仍然未知的关键问题
- 下一轮实验的单一假设

如果一轮实验结束后不能清楚写出这四项，说明本轮实验设计不够好，或者观察记录不完整。

## 硬性规则：每轮实验后必须更新 analysis.md

每次实验结束后，必须立即更新对应子项目的 `analysis.md`，记录本轮的：

- 假设
- 验证方法
- 观察结果
- 推论

这是硬性规则，不是建议。

必须遵守的纪律：

- 不更新 `analysis.md`，就不能开始下一轮实验
- `analysis.md` 是累积文档，不是临时草稿
- 所有已排除与已确认的事实都要沉淀进去
- 后续轮次必须建立在前面已记录的结论上，而不是重复走旧路

`analysis.md` 的价值在于：

- 防止重复实验
- 防止“连续多轮试试看”但没有累计认知
- 让不同会话、不同阶段都能快速恢复上下文
- 把项目经验与稳定结论区分开来：方法论在 llmdoc，具体实验历史在子项目 `analysis.md`

## 未知检测引擎的诊断优先级

面对新的目标 App 或未知 RASP，不要一上来就扩 hook 面，而应按固定顺序诊断。

### 1. 先确认注入成功

首要问题不是“检测在哪”，而是“tweak 是否真的进程内执行了”。

优先方式：

- 在 `%ctor` 中设置 crash tag 或其它明确标记
- 确认标记是否稳定触发

如果连 `%ctor` 都没有命中，后面的检测分析都不成立，应先排查：

- Filter / bundle id 是否正确
- tweak 是否正确安装
- rootless 打包与注入路径是否正确
- 目标进程是否就是你以为的那个进程

### 2. 再确认退出机制类型

先识别“怎么死”，再讨论“为什么死”。

可按现象初步分类：

- 有 crash report：优先怀疑 `signal` / `abort` / 显式崩溃链路
- 无 crash report且快速退出：优先怀疑 `SIGKILL`、raw syscall、自定义更底层杀进程
- 慢退出（通常大于 5 秒）：优先怀疑 watchdog、延迟自杀逻辑或延后触发的安全分支

这个判断会直接决定后续应观察 libc、syscall 还是业务层状态机。

### 3. 确认退出是否经过标准 libc 路径

对 `exit`、`abort`、`kill` 等标准退出接口布置 crash tag 或最小 Hook，判断退出是否经过可见的 libc 路径。

如果命中：

- 说明退出仍在用户态常见链路中，可继续沿 libc / 上游调用者往回追

如果完全不命中：

- 不要继续盲目补更多 libc Hook
- 应转向更底层可能性，如 raw syscall、Mach 层、自定义汇编、或更早的检测源头

### 4. 确认检测逻辑位于哪一层

当退出机制有了初步结论后，再判断检测本体在哪一层触发。

可按以下优先级判断：

- ObjC / Swift 层：delegate callback、method hook、selector 观察有响应
- 动态库层：存在独立 dylib，且其 `__mod_init_func` 或初始化阶段行为可疑
- 主 binary 静态库层：没有独立 dylib，delegate 也不触发，检测可能已静态链接进主程序

这一步的目标不是立刻找全所有点，而是先确定主要作战层级。

### 5. 基于结论选择对抗层级

不同检测层级应匹配不同对抗策略：

- ObjC 层检测：优先 method swizzle、Logos hook、运行时替换
- libc 层退出：优先 `MSHookFunction`、GOT rebinding、标准 C 函数拦截
- Mach VM 层检测：优先观察并 Hook `vm_region` / `mach_vm_region` 等接口
- Raw syscall 退出：通常无法在普通用户态稳定拦截，应转向 binary patch 或隐藏更上游检测源头

这里的关键原则是：

- 先判断层级，再写对抗代码
- 不要把适用于上一个项目的成功策略机械复制到下一个项目

## 实验设计原则

为了让“假设 → 验证 → 观察 → 推论”循环真正有效，每轮实验还应遵守以下原则。

### 最小改动优先

一次实验最好只回答一个问题。例如：

- 只验证 `_dyld_get_image_name` 是否被调用
- 只验证退出是否经过 `abort`
- 只验证 launcher/controller 的某个布尔判断是否触发

不要把“新增 20 个 Hook”当作一轮实验，因为这种改动无法解释结果归因。

### 对照组优先

能做对照，就不要只看单一结果。常见对照包括：

- 空 tweak vs 目标 tweak
- 开启某个 Hook vs 关闭某个 Hook
- 注入 vs 不注入
- 某个版本 App vs 上一个已知可工作的版本

逆向分析最怕“现象发生了，但不知道是哪个变量造成的”。

### 观察优先于解释

例如：

- “无 crash report，启动约 1 秒后直接回到 SpringBoard”是观察
- “这是 raw syscall kill”是推论

写记录时必须把观察和推论区分开，否则后续容易把错误假设当成已证实事实。

## 反模式警告

以下做法在实战中反复证明会降低分析质量，应明确避免：

- 不要把一个项目的成功 Hook 列表直接复制到另一个项目
- 不要在未确认退出机制前就开始扩大 Hook 覆盖面
- 不要连续多轮“试试看”而不记录每轮结论
- 不要假设所有 RASP 都走 ObjC delegate 或 libc 退出路径
- 不要信任未经核实的测量工具（进程匹配、存活判断），先证明工具对，再信结果
- 崩溃时不要默认是「目标的检测」，先做裸跑对照排除「自己的 hook 自伤」

这些反模式的共同问题是：

- 它们制造改动，但不制造认知
- 它们让结果无法归因
- 它们会把项目带入“越来越多 Hook、越来越少确定性”的状态

### 先排除“自伤”，再谈“检测”

当注入后出现崩溃或提前退出，第一反应不应是“目标又加了新检测”，而是先区分是
**目标的检测**还是**自己的 hook 引入的副作用（自伤）**：

- **裸跑对照**：卸载 tweak 让目标裸跑，记录其原始行为（退出时间、是否崩溃、crash 特征）。
  若带 tweak 比裸跑**死得更早或崩溃形态不同**，问题极可能在自己的 hook。
- **二分编译开关**：用 `#if` 把 hook 分组（如 libc-hook 组、aggressive 组、ObjC-swizzle 组），
  逐组开关，定位是哪一类 hook 引入了问题。
- **固定哨兵地址的崩溃**：`EXC_BAD_ACCESS` 跳到**每次都相同**的地址，通常是目标的
  anti-tampering **主动触发**（完整性自检发现 hook 后跳垃圾指针自杀），而非随机内存错误。

abcbypass 的 `0x00000000b5a06000` 崩溃就是典型：折腾多轮当成「ABC 的时序敏感检测」，
二分后发现根因是**自己对 libc 函数 inline-hook 触发了目标的内存完整性自检**。

### 有完整性自检的目标：只用 ObjC swizzle

部分强 RASP（银行类 mPaaS 框架等）带**内存完整性自检**，会扫描并发现对函数序言的
inline-hook / GOT 改写 / `__text` patch。对这类目标：

- ❌ C 函数 inline-hook（MSHookFunction）、fishhook GOT 改写、`__text` 运行时 patch
  都会被发现并触发崩溃（范围可能覆盖 libc 广泛函数，不止某几个）。
- ✅ **ObjC 方法 swizzle 安全**——它改的是 objc 方法表，不改函数序言字节。
- **最优解常在 ObjC 层**：定位「检测判定 / 退出逻辑」所在的 ObjC 方法，整体 swizzle 短路，
  远胜于 hook `exit` 后用 longjmp/栈切换事后抢救（后者破坏 CF/GCD/UIKit 内部状态，不可恢复）。
- 靠**类名/方法名**定位的 swizzle 不依赖地址偏移，天然跨目标小版本/机型/系统版本通用。

## 实操规范

### 设备访问

- SSH 已预配置密钥登录，直接使用 `ssh root@<ip>` 访问目标设备
- 如果认证出现问题（密钥失效、Host key 变更等），提示用户检查本机 SSH 配置，不要尝试自动修复

### 资料本地化优先

远端设备通常缺少分析工具（如 strings、otool、class-dump），且每次 SSH 连接开销较高。因此：

- 总是尽可能将远端需要分析的资料下载到本地子项目目录中分析
- 推荐本地子目录结构：
  - `app-binary/` — 存放从设备拷贝的主 binary 和 framework
  - `frida/` — 存放 Frida 脚本与 trace 输出
  - `tmp/` — 临时分析文件（crash log、class dump 输出等）
- 使用 `scp` 批量拉取后，在本机使用 `strings`、`otool -L`、`nm`、`class-dump` 等工具分析
- 只在必须实时交互时（如 kill/launch app、查看进程状态、安装 deb）才 SSH 到设备执行命令

### 进程存活监控

安装 tweak 后需自行观察 app 能否持续运行，不要等用户报告。标准做法：

```bash
# 启动 app 并持续监控进程（设备上 zsh 注意不要用 [] glob）
ssh root@<ip> "uiopen --bundleid <bundle-id>"
# 分开执行检查（避免单条 SSH 命令过于复杂）
sleep 2 && ssh root@<ip> "ps -ef | grep '<ProcessName>' | grep -v grep"
sleep 5 && ssh root@<ip> "ps -ef | grep '<ProcessName>' | grep -v grep"
```

关键注意事项：

- 设备通常没有 `pgrep`，用 `ps -ef | grep ... | grep -v grep` 代替
- 设备 shell 是 zsh，方括号 `[x]` 会被当作 glob 展开，避免在 grep 模式中使用
- 启动后至少观察 10 秒再判断存活（有些检测有延迟）
- 如果进程不存在，立即检查 crash log：`ls -lt /var/mobile/Library/Logs/CrashReporter/ | head -5`
- 下载 crash log 到本地 `tmp/` 用 python 解析（JSON 格式 .ips 文件）

> ⚠️ **必须精确匹配主 App 进程，排除 App Extension（`.appex`）**。很多 App 带常驻
> 后台扩展进程（如 ABC 的 `group.abc.toolExtension`），进程名/路径包含主 binary 名。
> 用宽松的 `grep <BinaryName>` 会匹配到扩展进程，把「扩展存活」误判成「主 App 存活」，
> 从而在**假的存活信号**上反复打补丁——这在 abcbypass 上直接导致多轮结论失效。
> 正确做法是匹配主可执行文件的完整路径并排除 `PlugIns`：
>
> ```bash
> ps -eo pid,etime,args | grep -E '<BinaryName>\.app/<BinaryName>( |$)' | grep -v PlugIns | grep -v grep
> ```
>
> 把这段固化成一个可复用的测试脚本（参考 `abcbypass/tmp/abctest.sh`：逐秒探测存活 +
> 对比 CrashReporter 新增判定「崩溃」还是「正常退出」），比每次手敲 grep 可靠得多。

### Crash log 快速解析

```python
import json
with open('crash.ips') as f:
    lines = f.readlines()
    body = json.loads(''.join(lines[1:]))  # 第一行是 header JSON
    print(body['exception'])      # 异常类型
    print(body['termination'])    # 终止原因
    ft = body['faultingThread']
    for fr in body['threads'][ft]['frames'][:10]:
        print(fr.get('symbol', '?'), fr.get('imageIndex'))
```

关键判断：
- `0x8BADF00D` = watchdog 超时（app 启动太慢）
- `EXC_BAD_ACCESS` + 固定地址 = 可能是 anti-tampering 故意 crash
- `SIGKILL` 无 crash report = 系统杀进程或 raw syscall 退出

## 与其他文档的关系

本文档定位为方法论层指导，适用于所有 bypass 子项目。

相关文档分工如下：

- 各子项目自己的 `analysis.md`：记录具体实验轮次、观察和推论
- `llmdoc/reference/detection-vectors.md`：记录已确认的检测向量与稳定事实
- `llmdoc/architecture/tweak-architecture.md`：记录已稳定实现的分层架构、边界与不变式

判定标准：

- 如果内容是在说“应该如何分析”，放在本文
- 如果内容是在说“这个项目实际观察到了什么”，放在子项目 `analysis.md`
- 如果内容已经跨轮次稳定成立，且可复用于后续任务，再考虑沉淀到 reference 或 architecture
