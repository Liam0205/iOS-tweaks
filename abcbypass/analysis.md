# 农业银行 (ABC) 越狱检测分析

## 环境信息

### 设备 A（Round 1 使用）
- App: 农业银行 v11.1.0 (build 11.1.3)
- Bundle ID: `com.bankabc.iphonerelease`
- Executable: `MbapMPaaS`
- Binary: 110MB, arm64 single arch, 基于蚂蚁 mPaaS 平台
- 安装路径: `/private/var/containers/Bundle/Application/772F8B77-480D-4711-A6F5-AEE1D1CE964A/MbapMPaaS.app`
- 数据容器: `/var/mobile/Containers/Data/Application/9A9D3109-D1E4-4F57-8EFA-1C265EC41095`

### 设备 B（Round 2 使用）
- iPhone 13 Pro, iOS 15.4.1, Dopamine 1.x (rootless)
- App: 农业银行 v11.1.0
- 安装路径: `/private/var/containers/Bundle/Application/FFE425EC-7B8F-4C7C-8F31-F3B6E9A88767/MbapMPaaS.app`
- 数据容器: `/private/var/mobile/Containers/Data/Application/D98B4BC7-39A9-426B-98C9-3CD16E622CA8`

## 安全框架分析

### 三层检测架构

1. **SecureUtilityPlus** — 核心越狱检测（与 ICBC 完全相同的框架）
   - 13 个已知 Checker 类 + 11 个混淆类名
   - JailbreakChecker, IOSSecuritySuite, MSHookFunctionChecker, FishHookChecker
   - RuntimeHookChecker, ReverseEngineeringToolsChecker, DebuggerChecker, IntegrityChecker, FileChecker

2. **SecurityGuard** — 阿里系 mPaaS 安全基座
   - 加密签名、安全令牌、设备指纹、数据采集等 16 个子模块

3. **SmAntiFraud** — 数美反欺诈 SDK
   - 入口: `initWithCheckRoot:checkRiskFrame:checkFrida:`
   - syscall 级能力: SmSyscallCode, SmSyscallUtil, SmSysctlByName
   - 注入检测: checkDylibs, checkDylibTweak, checkFlexInject, checkInject
   - 风险扫描: SmRiskApp, SmRiskDir

### 与 ICBC 的关键差异

| 维度 | ICBC | ABC |
|------|------|-----|
| SecureUtilityPlus | 有 | 有（相同框架） |
| 冻结机制 | semaphore_wait + 动画禁用 | 有冻结相关字符串，待验证 |
| 退出弹窗 | 有 | `showJailBrokenAlertIfNeeded` |
| SmAntiFraud | 无 | 有（syscall 级检测） |
| MSHookFunction 检测 | 有 | 有 → 必须用 fishhook |
| FishHook 检测 | 有 | 有 → 需要评估 |

### 退出行为

- 现象: 启动后 ~10s 退出
- 无 crash log（截至初始检查）
- 可能是 exit/abort 被调用，也可能是 SIGKILL 或延迟触发的安全分支

---

## 实验记录

### Round 1: 确认注入 + 识别退出机制

**假设**: tweak 能成功注入 MbapMPaaS 进程，退出走标准 libc 路径（exit/abort/kill）。

**验证方法**: 部署最小 tweak，仅包含：
- ctor 中写日志文件标记注入成功
- hook exit/_exit/abort/kill 记录退出链路
- hook signal 记录信号安装
- 记录时间戳，观察退出时间点

**观察**:
- 注入成功: ctor 在 t=0 执行，fishhook rebind_symbols 返回 0
- 无冻结: t=7s, t=12s watchdog 确认主线程响应正常，isIgnoringInteraction=0
- 退出链路 1: t=15.97s `exit(0)` 从主线程 dispatch block 调用，来源 `MbapMPaaS+0x8da264`
- exit 被拦截后进程续活: t=17s watchdog 确认主线程响应正常
- 退出链路 2: crash report 显示 `__stack_chk_fail` → `__abort` → `SIGABRT`，来源 `MbapMPaaS+0x8db268`
- `__abort` 是 libsystem_c 内部调用，不经过 GOT，fishhook 无法拦截
- 两个退出点偏移量仅差 ~0x1000，极可能是同一检测模块

**推论**:
- 已确认: 注入成功，fishhook 工作正常
- 已确认: 无 ICBC 式冻结机制（无 semaphore freeze、无动画禁用）
- 已确认: 退出走标准 libc 路径，有两条通道：exit(0) + __stack_chk_fail→abort
- 已确认: 检测有 ~16s 延迟，app 在此期间完全正常可用
- 已排除: SIGKILL、raw syscall 退出（有 crash report 且进程在 exit 被拦截后存活）
- 未知: 阻断两条退出链路后 app 是否长期稳定
- 未知: SecureUtilityPlus 的文件检测是否为主要触发源
- 未知: SmAntiFraud 是否有独立的杀进程逻辑
- 下一轮: 同时拦截 exit + __stack_chk_fail，并添加文件路径隐藏（复用 ICBC 已验证方案）

### Round 2: 全量 bypass 部署 + BoardServices 崩溃诊断（设备 B）

**假设**: 复用 ICBC 已验证方案，全量 hook（exit 链 + 文件路径 + dyld + sysctl + SecureUtilityPlus swizzle + Logos hooks）可阻止退出。

**验证方法**:
- 18 个 fishhook: exit/_exit/abort/kill/signal/__stack_chk_fail + stat/lstat/access/open/fopen/realpath/readlink + _dyld_image_count/_dyld_get_image_name/_dyld_get_image_header/_dyld_get_image_vmaddr_slide + sysctl
- 6 个 method swizzle 函数: hookSecureUtilityPlus (13 个 Swift 类) / hookIOSSecuritySuite / hookABCJailbreakMethods / hookAuthorityJailBreakFlag / hookShowJailBrokenAlert / hookSmAntiFraud
- Logos hooks: NSFileManager (4 方法) / UIApplication (3 方法) / UIAlertController / NSProcessInfo

**观察**: APP 在启动后 <1s 崩溃，crash 类型为 `EXC_BREAKPOINT (SIGTRAP)`，崩溃点固定在 `+[BSXPCServiceConnection connectionWithConnection:]` offset 1188（地址 `0x1f793c8b4`），位于 UIKit 初始化链路:
```
_UIApplicationMainPreparations → _loadInitializationContext →
  UISApplicationSupportClient _remoteTarget →
    BSServiceConnection _connectionWithEndpoint →
      BSXPCServiceConnection connectionWithConnection: → brk #0
```

**二分诊断过程**:

| 测试 | 配置 | 结果 |
|------|------|------|
| v6: 全量 18 fishhook + 全部 swizzle | 全部启用 | BSXPCServiceConnection 崩溃 |
| v7: 13 fishhook (禁用 dyld+sysctl) | exit链 + 文件hooks | BSXPCServiceConnection 崩溃 |
| v8: 6 fishhook (仅 exit 链) | 仅 exit/abort/kill/signal 等 | BSXPCServiceConnection 崩溃 |
| v9: 0 fishhook + Logos hooks only | 禁用所有 fishhook 和 swizzle | **存活到 0.66s**，弹窗被 Logos hook 拦截 |
| v10: 0 fishhook + 全部 swizzle + Logos | 恢复 6 个 swizzle 函数 | BSXPCServiceConnection 崩溃 |
| v11: 0 fishhook + 前 3 个 swizzle + Logos | SecureUtilityPlus/IOSSecuritySuite/ABCJailbreak | SSH 隧道断开，未完成 |
| v12: hookSecureUtilityPlus + 延迟 fishhook 200ms | 1 个 swizzle + 全部 18 fishhook (延迟) | **存活到 0.66s**，fishhook 生效，弹窗拦截，但 SIGABRT 杀死进程 |
| v13: 前 3 swizzle + 延迟 fishhook 200ms | 3 个 swizzle + 全部 18 fishhook (延迟) | BSXPCServiceConnection 崩溃 |

**关键发现**:

1. **Logos `// %init;` 注释无效**: Logos 预处理器生成独立的 `_logosLocalInit()` 构造函数，自动安装所有未分组的 `%hook` 块。注释掉 `%init` 不会阻止 hook 安装。
2. **v9 的「裸」tweak 实际包含所有 Logos hooks**: NSFileManager / UIApplication / UIAlertController / NSProcessInfo 的 MSHookMessageEx 始终生效。
3. **检测时间差异**: 设备 A 约 16s 触发退出，设备 B 约 0.66s 触发弹窗——同一 APP 版本在不同设备上检测速度差异巨大。
4. **弹窗文本**: 「提示 为保护您的资金安全，中国农业银行不支持越狱设备上使用。」
5. **延迟 fishhook 有效避开 BSXPCServiceConnection 崩溃**: `dispatch_after(200ms)` 后调用 `rebind_symbols` 不再触发 UIKit 初始化阶段的 XPC 崩溃（v12 验证）。
6. **hookSecureUtilityPlus 单独安全**: 仅此一个 swizzle 不触发 BSXPCServiceConnection 崩溃（v12）。hookIOSSecuritySuite 或 hookABCJailbreakMethods 之一（或两者）是崩溃元凶（v13 vs v12 的差异）。
7. **SIGABRT 新退出路径**: v12 中进程死于 `EXC_CRASH/SIGABRT`（主线程），日志中无 "EXIT blocked" 记录，说明 exit()/__stack_chk_fail 的 fishhook 未被触发。检测可能走了不经 GOT 的路径（内联调用、直接 syscall 或 SIGABRT 信号）。

**推论**:
- 已确认: Logos hooks（MSHookMessageEx）安全，不影响 UIKit 初始化
- 已确认: `rebind_symbols` 延迟 200ms 可避开 BSXPCServiceConnection 崩溃
- 已确认: `hookSecureUtilityPlus()` 在构造器阶段执行安全
- 已确认: `hookIOSSecuritySuite()` 或 `hookABCJailbreakMethods()` 触发 BSXPCServiceConnection 崩溃（需进一步隔离确认）
- 新发现: 即使所有 fishhook 生效 + 弹窗拦截，仍有未覆盖的退出路径（SIGABRT），需分析 crash report 调用栈确认来源
- **待复验**: v12/v13 的结果需要在网络稳定后重新验证，排除多次崩溃导致的 iOS 崩溃循环保护等噪声因素
- 下一步: (1) 获取 v12 SIGABRT 的 crash report 调用栈；(2) 隔离 hookIOSSecuritySuite vs hookABCJailbreakMethods；(3) 针对 SIGABRT 路径考虑 signal handler 或 MSHookFunction 方案
