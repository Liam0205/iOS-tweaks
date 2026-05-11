# ABC 越狱检测向量

## 目的

本文档汇总农业银行已知的越狱检测向量、三层检测架构、杀死机制与当前覆盖情况。

## 目标与背景

- 目标 App：`com.bankabc.iphonerelease`
- 已验证版本：`11.1.0`
- 主 Binary：`MbapMPaaS`（arm64, ~110MB）
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

**内存完整性扫描**：
- 使用 `memmem` 扫描代码段
- 运行在 `com.apple.uikit.xpc-service` 线程
- 检测 libpthread 上的 inline hook（MSHookFunction trampoline）
- 不检测 libdispatch（MSHookFunction 对 dispatch_async 安全）

## 杀死机制

### 退出行为时序

检测延迟：启动后约 15 秒触发。

### 退出路径（多重冗余）

| 优先级 | 路径 | 机制 | 可拦截性 |
|--------|------|------|----------|
| 主路径 | exit(0) | 主线程 dispatch block 调用 | ✅ fishhook |
| 备选 1 | __stack_chk_fail → abort | 故意栈金丝雀损坏 | ✅ fishhook |
| 备选 2 | svc #0x80 _exit() | 后台线程直接 syscall | ❌ 不可拦截 |

**svc #0x80 特性**：
- 不产生 crash report
- 不触发 signal
- 用户态完全无法拦截
- 从后台线程执行，不经过任何可 hook 的 API

### 弹窗

- 文案："为保护您的资金安全，中国农业银行不支持越狱设备上使用。"
- 关键字匹配：农业银行/越狱/资金安全

## 当前覆盖状态

| 检测向量 | 状态 | 实现方式 |
|----------|------|----------|
| SecureUtilityPlus (13 classes) | ✅ 已中和 | ObjC method_setImplementation |
| 文件/dyld/sysctl/env 检测 | ✅ 已隐藏 | fishhook (ctor 阶段) |
| exit/abort/kill 链 | ✅ 已阻断 | fishhook + ARM64 栈切换 |
| dispatch_async 主线程 block | ✅ 已重定向 | MSHookFunction (560+ redirects) |
| pthread_create 检测线程 | ✅ 已拦截 | fishhook (非 MSHookFunction) |
| svc #0x80 后台杀死 | ⚠️ 缓解 | 线程挂起 + 巡逻定时器 |
| 内存完整性扫描 | ✅ 已规避 | 不对 libpthread 使用 inline hook |
| 弹窗 | ✅ 已抑制 | UIAlertController 关键字拦截 |
| UI 完全恢复 | ❌ 未解决 | 巡逻定时器可能过度挂起 worker |

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
