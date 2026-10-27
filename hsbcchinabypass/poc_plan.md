# 内核 VM 过滤 PoC 计划（汇丰中国 Promon SHIELD 绕过）

## 目标
让 `cn.com.hsbc.hsbcchina` 在 Dopamine 越狱设备（2215）上不被 Promon SHIELD 检测到越狱、正常启动。

## 已确认的问题定位（Round 55-68）
- 3s 静默退出来自 native init[42] 的 OLLVM 状态机（verdict `w9==0x144ab99a → exit(1)`）。
- 中途改控制流一律 100% CPU 自旋（CFF 要求状态变量自然值）——不可行。
- 检测是**内存/环境完整性**：收集 SKS 结构 + 哈希比对（Round 67）。
- **关键新证据（Round 68）**：进程里有 **11 个来自 `/var/jb` 的注入 dylib**（injector/ellekit/Choicy/
  Crane/Cephei/其他无关 tweak + 本 bypass），而 14 个常用 libSystem 函数入口**全 clean（0 inline hook）**。
  ⇒ 检测目标更可能是**注入 dylib 的存在**（dyld image 列表异常），而非 shared cache 被改。
- 这些注入物先于 Choicy 过滤加载，任何 ElleKit 越狱进程都有 → 解释"零自研 tweak 仍退出"。

## 待验证的核心假设（PoC 第一步就要确认）
**假设 H1**：Promon 通过枚举 dyld image 列表（`dyld_all_image_infos` → `infoArray`）发现 `/var/jb`
路径的注入 dylib，从而判越狱。
- 若成立：隐藏这些 image 的 load info / 路径即可绕过。
- 验证法：PoC 探针在 China 内 hook/改 `dyld_all_image_infos.infoArray`，把注入 dylib 条目摘掉或改路径，
  看是否还退出（**纯用户态即可验证 H1，不需内核**）。

## PoC 分阶段（先易后难，每阶段都是可判定的实验）

### 阶段 A：用户态验证检测向量（不需内核，1-2 轮）
1. **A1 image 列表隐藏**：tweak 在 %ctor 早期（抢在 init[42] 前）改 `_dyld_all_image_infos` 的
   `infoArray`/`infoArrayCount`，把 11 个 `/var/jb` 注入条目从数组里摘除（或改 `imageFilePath` 指向
   `/System/...` 假路径）。观测是否还 3s 退出。
   - 成功 → H1 成立，检测=image 枚举，问题大幅简化。
   - 失败 → 检测不看 image 列表，走阶段 B 换向量。
2. **A2 若 A1 无效**：探针 dump Promon 收集 SKS 结构时读了哪些内存（在 Round67 的 0x774fec 收集器里
   看它遍历什么），确定真正的枚举源（vm_region? mach header 扫描? task_info?）。

### 阶段 B：确定内核过滤点（需要 kread/kwrite，2-3 轮）
- 用 libjailbreak 的 `proc_for_pid` + `kreadbuf`/`kwritebuf` 定位 China 进程的：
  - `proc → task → vm_map`，遍历 vm_map_entry，找注入 dylib 的映射区（vme_offset/对应 vnode 路径）。
  - 或内核里的 dyld image 记录。
- 判定 Promon 到底读哪条内核路径拿 image 信息（对照阶段 A 的用户态发现）。

### 阶段 C：内核 VM 过滤实现（核心，多轮）
按阶段 A/B 结论二选一：
- **C1（若检测=用户态 image 列表）**：其实用户态 A1 就够，不必内核。tweak 化 A1 为稳定方案：
  早期隐藏注入 image，保留自身（把自己也从列表摘掉但已加载运行）。
- **C2（若检测=内核 vm_map / 文件 vnode）**：用 kwrite 修改 China 的 vm_map_entry，
  让注入 dylib 的映射看起来像匿名/系统映射，或改其 backing vnode 路径记录。
  - 风险：改内核 vm 结构极危险，可能 panic；需在独立 daemon 里做，只对目标 pid、只改必要字段。

### 阶段 D：保活与稳定（收尾）
- 确保过滤后自身 tweak 仍能运行（先完成 bypass 逻辑再隐藏自己，或用不经 ElleKit 的加载方式）。
- 处理进程重启（SpringBoard 重拉）时的时序：过滤必须在 init[42] 跑之前完成。
  - 难点：init[42] 是 C 初始化器，在 dylib 加载后立刻跑；tweak 的 %ctor 与它竞争。
    可能需要 daemon 监听 China spawn、在其 exec 后 suspend、过滤、再 resume。

## 关键风险与未知
1. **时序**：init[42] 早于 tweak %ctor 完成检测的可能（Round 59 已见检测在主线程同步跑）。
   若如此，用户态 A1 可能来不及 → 必须走 spawn 拦截 + suspend（launchd/posix_spawn hook，pspawn.dylib 已有）。
2. **保留自身**：隐藏所有注入却留自己，需要自己不在被枚举的列表里，或最后再隐藏。
3. **多检测向量**：可能 image 列表只是其一，还有 dyld cache 哈希等；A1 验证会证伪或缩小范围。
4. **内核操作安全**：C2 若需改 vm_map，panic 风险高，先在非关键字段试，做好回滚。

## PoC 进展与最终定位（Round 68-72c）

分水岭实验结论（A1→A3）：
- **A1**（隐藏 dyld_all_image_infos.infoArray）→ 无效。检测不看 infoArray。
- **A3**（hook libSystem vm_region_recurse_64 过滤注入区域）→ 确实跳过 30+ 注入区域, 但仍退出。
- **根因**（Round 72）：hsbcchinax **不导入任何内存枚举 libSystem 函数**；vm_region_recurse_64 walk 是
  **别的并存 SDK**（TuringShield/RASP 等）做的, 与 Promon 3s 退出无关。

**最终精确定位（Round 72b/72c）**：Promon 经**私有 svc 网关**发 `mach_msg(msgh_id=4808 = mach_vm_read)`,
在 `mach_task_self`(port=0x203) 上**读各内存区域头部 32 字节**（0x20），检查 Mach-O magic/身份来识别注入 dylib。
调用点 = mach 封装 `0x40c698`（caller +0x40c738）, 读的地址正是各 PluginKit/注入 dylib 的区域基址。
完全绕开 libSystem（所以 A3 的 libSystem hook 无效）。

## 修正后的拦截方案（三选一, 按可行性排序）

### 方案 U（用户态, 优先试）: hook 0x40c698 mach 封装, 过滤 mach_vm_read 结果
- `0x40c698` 是 hsbcchinax __TEXT 内的 mach 封装函数（Round 60 已证 inline hook 不触发完整性检测）。
- hook 它: 让真实 mach_vm_read 执行, 然后**改 reply 缓冲**——若读的地址属于注入 dylib 区域,
  把返回的 32 字节 Mach-O 头改成"非 dylib"或全 0（使 Promon 认不出是注入）。
- 优点: 纯用户态, 不碰内核, 不 nop-store（不破坏安装序列, 不自旋）。
- 风险: 0x40c698 也承载其他 mach 调用（不只 4808）; 需按 msgh_id + 地址精确过滤。
  且要在 init[42] 跑之前 hook 上（%ctor 时序, Round 60 证明 MSHookFunction 能在 ctor 挂上）。

### 方案 K（内核层, 兜底 = issue #1）: 拦该进程 mach_vm_read RPC / 改 vm_map
- 若方案 U 的 hook 时序赢不了 init[42], 或 0x40c698 有反 hook, 走内核。
- libjailbreak 有 proc_for_pid + kreadbuf/kwritebuf; 可改 China 的 vm_map_entry 使注入区域
  的 backing/头部读出来是合法的; 或 hook 内核 mach_vm_read 路径。

### 方案 S（svc 网关精细化）: 只在 4808 的 reply 后改数据, 不 nop-store
- 之前 nop-store 观测会自旋是因为破坏安装序列; 若用 ElleKit 精确 hook 0x40c698 而非改网关槽, 可避免。
- 实际上方案 U 就是 S 的干净实现。

## 第一步（本次要做）
实现 **方案 U**：ElleKit hook `0x40c698`（mach 封装）, 对 `mach_vm_read`(msgh_id 4808) 读注入 dylib
区域头部的调用, 篡改 reply 使返回的 Mach-O 头看起来非注入（改 magic / 清零）。观测是否绕过 3s 退出。
这是当前最可能用纯用户态拿下的方案, 且不破坏安装序列（避免自旋）。
- 保留自身: HSBCBypass 自己的区域也要在过滤范围内（否则被 Promon 读到）。
- 判定注入区域: dladdr(address) 的 image 路径含 procursus/var jb/TweakInject/ellekit。
