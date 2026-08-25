# 汇丰中国越狱检测向量

## 目的

本文档汇总汇丰中国 App 已知的越狱检测向量、Promon SHIELD 私有系统调用网关机制、检测触发链路与当前绕过覆盖状态。

## 目标与背景

- 目标 App：`cn.com.hsbc.hsbcchina`
- 已验证版本：`3.72.15`
- 主 Binary：`China.app/Frameworks/hsbcchinax.framework/hsbcchinax`（arm64, ~6.9MB）
- 测试设备：iPhone 13 Pro / iOS 15.4.1（2215）
- SDK 识别：**Promon SHIELD**（strings 命中 `no.promon.shield` / `PRMShield`；ObjC 类
  `PRMShieldEventManager`（关键方法 `performSecurityChecks` / `setUpdateCallbacks:`）、
  `ShieldConfig`、`ShieldCallbackManager`；私有 section `__ostekake`）

> ⚠️ **SDK 身份更正**：早期分析（见 `llmdoc/memory/reflections/hsbc-methodology-lesson.md`）
> 曾认定检测引擎是 **OneSpan RASP**，中途又一度怀疑过 **ThreatMetrix**；两者均为误判。
> 第 55-76 轮用 strings + ObjC 类名彻底实锤，真正的检测引擎是 **Promon SHIELD**。历史文档
> 或反思中提到 OneSpan/ThreatMetrix 的地方均以本文档为准，详见
> `llmdoc/memory/reflections/hsbc-china-promon-poc.md`。

## 检测机制

### 1. 主 binary 内 native + OLLVM 控制流平坦化（CFF）

检测逻辑与主 binary 静态链接，无独立可疑 dylib。核心状态机使用 OLLVM 控制流平坦化
（CFF）混淆，dispatcher 依赖状态变量的自然取值决定下一跳；这意味着任何"改变已判定后的
分支/调用"的补丁都会让状态变量与代码路径不一致，导致下游 dispatcher 找不到匹配状态而
死循环（100% CPU 自旋）。

无 `__TEXT` 完整性校验：改 cstring 或做 binary patch 本身不会被发现；但改控制流（csel、
跳转目标、调用点）会触发上述自旋。

### 2. 私有 svc 网关机制（核心）

Promon 把所有系统调用/mach trap 封装收进私有数据段跳板，完全绕开 libSystem 具名符号：

- 全局槽 `0x8510c8`（`__common` BSS 段）存放网关地址 `0x78befc`
- `0x78befc`（`__TEXT __const`）处的字节内容是 `svc #0x80; ret; brk`
- 安装点 `0x346c68` 的 `str x9, [x8, #0xc8]` 在启动时把网关地址写入该槽
- 全书 83 处 syscall/mach 封装统一使用 `ldr x17, [0x8510c8]; blr x17` 跳转陷入内核

**影响**：因为所有系统调用都经这条跳板而不经 libSystem 里的具名函数入口，任何基于符号
解析的 hook（fishhook GOT rebind、`MSHookFunction` 挂 libSystem 函数、Shadow 之类工具级
hook）**全部 0 命中/无效**。这是本目标与其他已收录 App（ABC/ICBC/链家）的关键差异——
那些目标的退出仍部分经过 libc 标准入口，而汇丰中国的关键退出路径完全不经过。

### 3. 退出 / verdict 链路

- 3 秒静默退出源头：`__mod_init_func` 第 42 项（`init[42]`，函数地址 `0x43e114`）内的
  CFF 状态机
- verdict 判定分支：`0x43ebc4: cmp w9, #0x144ab99a; b.ne <继续正常流程>`，不匹配则调用
  `exit(1)`（经上述 svc 网关封装，封装地址 `0x1f05dc`）

> ⚠️ **历史误判**：第 52-59 轮曾认定退出点是巨型状态机 `0x75bf7c`，围绕它 patch/nop 了
> 8 轮。用 ElleKit hook + fp-chain 回溯证实：`0x75bf7c` 只运行约 3ms 就正常返回，与退出
> 无关，是误追的目标。

### 4. 最终检测点：读库头识别注入库

Promon 经 svc 网关发起 `mach_msg`（`msgh_id = 4808`，对应 `mach_vm_read_overwrite`），在
`mach_task_self`（port `0x203`）上逐个读取每个已加载库的 Mach-O 头前 32 字节，用于识别
注入库的身份特征。

- mach 封装函数地址：`0x40c698`（调用方 `+0x40c738`）
- 请求体字段：`body[4]` = 源地址，`body[5]` = 读取大小，`body[6]` = 输出缓冲
- **唯一触发退出的注入库**：`systemhook.dylib`（Dopamine 注入核心，路径
  `.../procursus/basebin/systemhook.dylib`）。其余已加载的越狱/tweak dylib 均未触发退出。

## 已排除的检测向量

以下向量在本轮分析中被明确排除，记录以避免后续重复验证：

| 向量 | 排除依据 |
|------|----------|
| `dyld_all_image_infos.infoArray` 枚举 | 隐藏该数组对结果无影响，退出行为不变 |
| libSystem `vm_region_recurse_64` | 观察到 400+ 次调用、能跳过 30+ 个注入区域，但核对 `hsbcchinax` 的 bind/lazy-bind 表后发现它根本不导入任何内存枚举类 libSystem 函数；该调用来自进程内**另一个并存的安全 SDK**（疑似 TuringShield / RASPFramework），与 Promon 无关 |
| ObjC 层 `performSecurityChecks`（`PRMShieldEventManager`） | 3 秒退出窗口内该方法不被调用，退出路径纯 native，不经过此 ObjC 层入口 |
| 文件系统隐藏 / Shadow 全 hook 集 | 设备已装 Shadow（含 `Hook_Syscall` 等 18 项 hook），套用后仍 3 秒静默退出，无变化 |
| Frida 注入 | spawn 时在注入完成前即被终止 |

## 当前覆盖状态

**未绕过。用户态路线已证伪（Round 77）——确认必须走内核层。**

### 用户态干预效果（Round 74-76，hook mach 封装 `0x40c698` 篡改 systemhook 头）

| 干预方式 | 效果 | 结论 |
|----------|------|------|
| 替换路径特征字符串 | 退出从 3s 推迟到 17s | 有效但不彻底，Promon 对该库存在多重/存在性校验 |
| 清零 Mach-O magic | 绕过 `exit(1)` | 但触发 100% CPU 自旋（CFF 状态变量不一致），净启动未达成 |

### ★ Round 77：Unject 实验证伪「systemhook-only」假设（决定性负面结果）

用定制 Dopamine 的 **Unject** 能力（systemhook `spawn_config_for_executable` 里按可执行名
黑名单返回 `kSpawnConfigTrust` = 只授信不注入，见
`github.com/Liam0205/Dopamine` commit `980bf0f`）对汇丰做**最干净的实验**：彻底不注入
systemhook 到 `China` 进程，连"伪装库头"都不需要。

- **配置**：`/var/mobile/zp.unject.plist` 加 `<key>China</key><true/>`（key = 可执行文件名），
  **改后必须 userspace reboot** 才生效（systemhook 是 launchd 早期常驻，运行时不重读 plist）。
- **验证 Unject 本身生效**：用微信（`WeChat`，`com.tencent.xin`）对照——加入名单 + reboot 后，
  微信 tweak（登录页 `默认/iPad登录/iPhone/iPad` 按钮条）消失，证明 systemhook 确实不再注入。
- **结果**：汇丰 **仍然闪退**，且比带注入时的 3s **更快（<1s）**，同样无 crash log（干净 exit）。

**结论**：
1. `systemhook.dylib` 的 Mach-O 头**不是**唯一判定输入。Round 68-76 的「让 Promon 读不到
   systemhook 就能过」假设被证伪。Promon 还有**独立于任何用户态注入库**的检测（很可能是环境层：
   `/var/jb` 存在、trustcache 异常、amfid/签名验证行为、内核补丁痕迹等），unject 动不了。
2. **用户态存在二律背反**：要 Promon 检测不到注入 ⇒ 不能注入 ⇒ 我们也无法用 tweak 干预；
   要用 tweak 干预 ⇒ 必须注入 systemhook ⇒ Promon 又能检测到。纯用户态无法同时满足
   "不被检测" 与 "能干预"。
3. Round 74 "改 systemhook 头能撑过 3s" 现在重新理解为：只是扰动了众多检测中某个计时/分支，
   并非命中唯一开关。

### 唯一自洽的方向：内核 / dyld 加载层（隐藏而非移除）

只有把干预下沉到 systemhook 检测看不到的层，才能同时满足"不被检测"+"能干预"。参考实现是
**roothide Dopamine**（见反思 `hsbc-china-roothide-eval.md`），它用四支柱做通用越狱隐藏：
随机 jbroot 路径、内核改写目标 task 的 `all_image_info`（让 App 枚举不到注入库）、dyld 入口/
函数 hook、per-app 黑名单（命中的 App 不注入 tweak 但内核层隐藏痕迹）。这正是本目标缺的那一层。

### ⛔ 现实约束：不能动越狱本体 ⇒ 可行域为空（2026-08-25 结论）

roothide 的隐藏机制**全部落地在越狱本体**（systemhook / launchdhook / dyldhook / jailbreakd /
内核改写）。用户明确约束**不能动越狱本体**（不改 basebin、不 rebuild、不刷定制/roothide Dopamine）。
在此约束下：

- 方案 A（换 roothide 越狱）、B（移植 roothide 到本体）均被排除。
- 方案 C（自研内核隐藏）与 B **卡在同一禁区**——隐藏必须落在本体层，而本体是禁区。C 不是工作量
  问题，是**没有可落脚的位置**。
- 唯一可动的区域只剩"注入进 App 进程的用户态 tweak"，而这正是 Round 77 证伪的二律背反：要放
  tweak 就得注入 ⇒ 被检测；不被检测就不能注入 ⇒ 没法干预。

**⇒ 在"不能动越狱本体"约束下，汇丰中国 Promon SHIELD 的可行域为空，非难度问题。** 若未来放宽
该约束（可维护定制/roothide 越狱），A/B 才是唯一有希望的方向；因我们越狱与 roothide 同源
（都是 opa334 Dopamine 的 fork），B 比从零的 C 现实得多。

详细逐轮实验记录见 `hsbcbypass/analysis.md`（第 55-77 轮）。

## 版本适配优先检查

汇丰中国 App 升级后建议检查顺序：

1. `init[42]`（`0x43e114`）与 verdict 分支（`0x43ebc4`）的地址是否随版本偏移变化
2. 私有 svc 网关槽地址（`0x8510c8` → `0x78befc`）与安装点（`0x346c68`）是否变化
3. mach 封装函数 `0x40c698` 的地址与 `mach_vm_read_overwrite` 的 `msgh_id`（4808）是否
   仍固定
4. 是否新增对其他注入特征库（不止 `systemhook.dylib`）的头部校验
5. OLLVM CFF 混淆范围是否扩大到更多函数，影响 patch 位置的选择
