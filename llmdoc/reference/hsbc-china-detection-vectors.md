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

**未绕过（PoC 阶段）**。

已验证的用户态干预效果（hook 目标自己的 mach 封装函数 `0x40c698`，篡改其读取到的
`systemhook.dylib` 头部数据）：

| 干预方式 | 效果 | 结论 |
|----------|------|------|
| 替换路径特征字符串 | 退出从 3s 推迟到 17s | 有效但不彻底，Promon 对该库存在多重/存在性校验 |
| 清零 Mach-O magic | 绕过 `exit(1)` | 但触发 100% CPU 自旋（CFF 状态变量不一致），净启动未达成 |

净启动尚未达成。候选方向二选一，两者工程量都较大：

1. 构造自洽的合法库镜像伪装，让 `systemhook.dylib` 区域的读取返回一份头部/loadcmds/
   地址全部自洽的"合法库"镜像
2. 内核层隐藏越狱环境（兜底方案，记录在 GitHub issue #1）

详细逐轮实验记录见 `hsbcbypass/analysis.md`（第 55-76 轮）。

## 版本适配优先检查

汇丰中国 App 升级后建议检查顺序：

1. `init[42]`（`0x43e114`）与 verdict 分支（`0x43ebc4`）的地址是否随版本偏移变化
2. 私有 svc 网关槽地址（`0x8510c8` → `0x78befc`）与安装点（`0x346c68`）是否变化
3. mach 封装函数 `0x40c698` 的地址与 `mach_vm_read_overwrite` 的 `msgh_id`（4808）是否
   仍固定
4. 是否新增对其他注入特征库（不止 `systemhook.dylib`）的头部校验
5. OLLVM CFF 混淆范围是否扩大到更多函数，影响 patch 位置的选择
