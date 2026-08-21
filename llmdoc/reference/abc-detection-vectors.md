# ABC 越狱检测向量

## 目的

本文档汇总农业银行已知的越狱检测向量、三层检测架构、杀死机制与当前覆盖情况。

## 目标与背景

- 目标 App：`com.bankabc.iphonerelease`
- 已验证版本：`11.1.0`
- 主 Binary：`MbapMPaaS`（arm64, ~110MB）
- SDK 识别：**MbapMPaaS = 蚂蚁金服 mPaaS 框架**（通过 callstack backtrace 确认）
- mPaaS 封装了 UIApplicationMain，控制整个 App 生命周期
- 检测框架：SecureUtilityPlus + SecurityGuard + SmAntiFraud

## 三层检测架构

### Layer 1: SecureUtilityPlus (Swift)

与 ICBC 使用相同框架。包含 13+ Checker 类：

| 类名 | 检测内容 |
|------|----------|
| JailbreakChecker | 越狱检测 |
| IOSSecuritySuite | 标准 amIJailbroken 系列 |
| MSHookFunctionChecker | MSHookFunction prologue 检测 |
| FishHookChecker | fishhook GOT 检测 |
| RuntimeHookChecker | 运行时 hook 检测 |
| ReverseEngineeringToolsChecker | 逆向工具检测 |
| DebuggerChecker | 调试器检测 |
| IntegrityChecker | 完整性校验 |
| FileChecker | 文件存在性检测 |
| ProxyChecker | 代理检测 |
| ModesChecker | 模式检测 |
| EmulatorChecker | 模拟器检测 |
| CheckAllCall | 聚合调用入口 |

当前覆盖：全部通过 `method_setImplementation` 替换为返回 NO/false。

### Layer 2: SecurityGuard (mPaaS/Alibaba)

阿里 mPaaS 安全基础设施，包含 16 个子模块：
- 加密签名
- 安全令牌
- 设备指纹
- 数据采集与上报

功能：为检测结果提供加密上报通道和设备唯一标识。本层不直接执行越狱判定，但为 Layer 3 提供基础设施支撑。

### Layer 3: SmAntiFraud (数美反欺诈)

最危险的检测层，包含系统调用级检测。

**入口**：`initWithCheckRoot:checkRiskFrame:checkFrida:`

**子模块**：
- `SmSyscallCode` / `SmSyscallUtil`：inline ARM64 `svc #0x80` 系统调用
- `checkDylibs` / `checkDylibTweak` / `checkFlexInject` / `checkInject`：注入检测
- `SmRiskApp` / `SmRiskDir`：风险应用和目录扫描

**Syscall 级检测**：直接内联 ARM64 汇编执行 stat/access/sysctl，完全绕过 GOT/PLT，用户态不可拦截。

**内存完整性扫描**（⚠️ 2026-08-21 重测更正，范围比原记录广得多）：
- 使用 `memmem` 扫描代码段，运行在 GCD worker 线程。
- **对 libc 函数的 inline hook 全部会被发现**。经二分实验证实（第 15 轮）：
  对 `stat/lstat/access/open/fopen/realpath/readlink/sysctl/getenv/fork/dlopen/dlsym`
  及 `_dyld_*` 做 MSHookFunction，会在启动 ~1s 触发后台 GCD 线程跳到**固定哨兵地址
  `0x00000000b5a06000`** 的 SIGSEGV（地址每次相同 ⇒ 主动触发，非随机内存错误）。
- **旧记录"不检测 libdispatch / MSHookFunction 对 dispatch_async 安全"未经可信验证，
  勿依赖。** 唯一可信的安全手段：**ObjC 方法 swizzle**（不改函数序言字节）。
- **⇒ 对 ABC 的硬约束：禁用一切 C 函数 inline-hook，禁止 __text patch，禁止 fishhook GOT 改写。**

## 杀死机制

### 退出行为时序

检测延迟：裸跑实测**约 13 秒**后主 App 正常退出（第 15 轮可信测量；旧记录"15 秒"为近似）。

> ⚠️ 下方"双通道杀死架构 / 退出路径 / 第二检测路径"均为 v95 及更早的**推断**，
> 且部分依赖被污染的存活判断。exit 源头的**可信**结论见文首"可信状态"与
> `MbapMPaaS+0x8db260`。以下小节仅作历史推断存档，勿直接引用为事实。

### 双通道杀死架构（v95 推断，未经可信验证）

SDK 使用两个独立的杀死通道冗余执行：

| 通道 | 机制 | 拦截方式 | 当前状态 |
|------|------|----------|----------|
| CFRunLoop 定时器 | CFRunLoopAddTimer 注册一次性定时器（delay 5-60s） → callback 调用 exit(0) | hook CFRunLoopAddTimer 过滤丢弃 | ✅ 已拦截 |
| GCD dispatch_after | dispatch_after 延迟投递 block → 调用 exit(0) | 无有效拦截方式 | ❌ 未拦截 |

**GCD 通道无法用 CFRunLoop 方式拦截**：dispatch_after 不经过 CFRunLoopAddTimer，直接走 GCD 内核队列，无公开注册拦截点。

### 退出路径（多重冗余）

| 优先级 | 路径 | 机制 | 可拦截性 |
|--------|------|------|----------|
| 主路径 A | exit(0) via CFRunLoop timer | 主线程定时器 callback 调用 | ✅ timer 被阻断 |
| 主路径 B | exit(0) via GCD dispatch_after | 主线程 dispatch block 调用 | ⚠️ exit 被 fishhook 但 block 仍执行 |
| 备选 1 | __stack_chk_fail → abort | 故意栈金丝雀损坏 | ✅ fishhook |
| 备选 2 | svc #0x80 _exit() | 后台线程直接 syscall | ❌ 不可拦截 |

### 第二检测路径（Hook 完整性检测）

v95 发现：即使越狱文件检测和 ObjC 方法检测均已成功绕过（弹窗不再出现），SDK 仍通过第二条路径调用 exit(0)。

疑似检测机制：
- FishHookChecker（SecureUtilityPlus 中的类，检测 GOT 篡改）
- 函数 prologue 完整性检查（检测 inline hook trampoline）
- 动态 GOT 比对（加载时 GOT vs 当前 GOT）

**关键区分**：第一路径（文件/ObjC）已被 ctor 重排序消除，第二路径（hook 完整性）仍然触发 exit。

**svc #0x80 特性**：
- 不产生 crash report
- 不触发 signal
- 用户态完全无法拦截
- 从后台线程执行，不经过任何可 hook 的 API

### 弹窗

- 文案："为保护您的资金安全，中国农业银行不支持越狱设备上使用。"
- 关键字匹配：农业银行/越狱/资金安全

## 当前覆盖状态

> ⚠️ **旧 v95 覆盖表（下方"作废"块）中的"✅ 已阻断/已拦截/已规避"多为误判**：
> 基于错误的存活检测（把后台扩展进程 `group.abc.toolExtension` 当成主 App），
> 且大量依赖被证明有害的 libc inline-hook / fishhook。勿引用。

### ✅ 已解决（第 16 轮，2026-08-21）——最终有效方案

**`swizzle -[DTFrameworkInterface initRiskManage]` 为空实现。**

> **跨版本/跨设备已验证**：
> - ABC **11.1.0** / iPhone 13 Pro / iOS 15.4.1（2215）：进入首页，交互正常。
> - ABC **11.2.0** / iPhone 14 Pro Max / iOS 16.3.1（2216）：能用（用户确认）。
> - 方案靠 ObjC 类名/方法名（mPaaS 稳定接口），**不依赖地址偏移**，故 ABC 小版本
>   升级、不同机型/iOS 版本均通用。上文的 `0x8db260`/`0x8dad68`/`0x8da804` 等偏移
>   仅是 11.1.0 的定位依据，swizzle 本身不用它们。

- 那条 native exit（`MbapMPaaS+0x8db260` 的 `exit(0)`，由 `[receiver action]==3`
  判定触发）所在的检测 block（invoke=`MbapMPaaS+0x8dad68`）**定义在
  `-[DTFrameworkInterface initRiskManage]` 方法内**（方法起始 `0x8da804`，block 在其 +0x564）。
- 用纯 ObjC swizzle 把 `initRiskManage` 替换成空 `void` 实现 → 风险管理不初始化
  → 检测 block 永不创建/投递 → exit 从源头消失。
- **ObjC swizzle 不改函数序言字节，不触发 ABC 完整性自检**（区别于致命的 libc inline-hook）。
- **可信实测**：`initRiskManage NEUTRALIZED`（被调 2 次），无 exit/DTRpcException/崩溃，
  主 App 存活 >90s，**完整进入农业银行首页**（我的账户/转账/明细/理财/基金 + 5 tab +
  实时资讯），用户设备实测 tab 切换/功能页/列表滚动全部正常响应。
- 定位方法：手动解析 `__objc_classlist` 方法表，找 IMP ≤ block invoke 地址且最近的方法
  即为 block 宿主方法（脚本见 `abcbypass/tmp/objcparse.py`）。

### 可信基线（第 15 轮，2026-08-21，正确进程匹配）

| 配置 | 主 App 结果 | 结论 |
|------|------|------|
| 裸跑（无 tweak） | ~13s **正常退出**（exit，无崩溃） | ABC 越狱检测原始行为 |
| 全量 hook | ~1s **崩溃** `0xb5a06000` | 净负面，libc inline-hook 触发完整性自检 |
| 仅 ObjC swizzle（未含 initRiskManage） | ~13s 正常退出，无崩溃 | = 裸跑，挡不住 native exit |
| **+ swizzle initRiskManage** | **存活，进入首页** | ✅ 成功 |

### 作废的 v95 覆盖表（仅存档，勿引用）

| 检测向量 | ~~旧状态~~ | 备注 |
|----------|------|----------|
| SecureUtilityPlus (13 classes) | ~~✅ ObjC method_setImplementation~~ | swizzle 本身安全，但"已中和"未经可信验证 |
| 文件/dyld/sysctl/env 检测 | ~~✅ fishhook/inline hook~~ | **实为有害**：触发 `0xb5a06000` 崩溃 |
| exit/abort/kill 链 | ~~✅ fishhook + 栈切换~~ | 存活判断不可信 |
| dispatch_async block 重定向 | ~~✅ 560+ redirects~~ | "560+"计数来自被污染的运行 |
| CFRunLoop / GCD / svc / 内存扫描 | ~~各种~~ | 结论不可信，见上方可信表 |
| UI 完全恢复 | ~~❌ longjmp CF 损坏~~ | UI 冻结的 longjmp 归因也未经可信验证 |

## 与 ICBC 检测的差异

| 维度 | ICBC | ABC |
|------|------|-----|
| 检测框架 | SecureUtilityPlus only | SecureUtilityPlus + SecurityGuard + SmAntiFraud |
| Syscall 检测 | 存在但响应可中和 | 存在且直接 _exit (不可中和) |
| 杀死策略 | 冻结循环 + 弹窗退出 | 多路径退出 (exit + canary + svc) |
| 内存扫描 | 无 | memmem 扫描 libpthread |
| 冻结循环 | 是（14,000+ 次/30s） | 否 |
| 对抗难度 | 高（持续冻结需持续对抗） | 极高（svc 不可拦截，仅能缓解） |

## 版本适配优先检查

ABC App 升级后建议检查顺序：

1. SmAntiFraud svc #0x80 路径是否提前执行（<200ms 窗口内）
2. 内存扫描器覆盖范围是否扩展到 libdispatch
3. 是否新增检测线程创建方式（绕过 pthread_create hook）
4. SecureUtilityPlus 是否新增 Checker 类
5. 退出时序是否变化（15s → 更早）
6. 巡逻定时器挂起的线程是否包含关键 GCD worker
7. FishHookChecker / hook 完整性检测的具体实现方式
8. GCD dispatch_after 通道是否有新的投递模式
