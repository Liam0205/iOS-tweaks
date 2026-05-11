# 农业银行 (ABC) 越狱检测分析

## 环境信息

### 设备 A（Round 1、Round 5 使用）
- iPhone 14 Pro Max, iOS 16.3.1, Dopamine (rootless)
- SSH 端口: 2216
- App: 农业银行 v11.1.0 (build 11.1.3)
- Bundle ID: `com.bankabc.iphonerelease`
- Executable: `MbapMPaaS`
- Binary: 110MB, arm64 single arch, 基于蚂蚁 mPaaS 平台
- 安装路径: `/private/var/containers/Bundle/Application/772F8B77-480D-4711-A6F5-AEE1D1CE964A/MbapMPaaS.app`
- 数据容器: `/var/mobile/Containers/Data/Application/9A9D3109-D1E4-4F57-8EFA-1C265EC41095`

### 设备 B（Round 2–4 使用）
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

### Round 3: 退出链路攻防 + dispatch 状态破坏（设备 B，v14–v29）

**目标**: 在检测必然发现越狱的前提下，阻止 app 退出并保持 UI 可用。

**v14: UIAlertController nil → NSInvalidArgumentException**:
- 配置: 全量 hook + 越狱弹窗返回 nil
- 结果: `NSInvalidArgumentException`，app 调 `presentViewController:nil` 崩溃
- 修复: 返回带标记的空 dummy alert + hook `UIViewController presentViewController:` 拦截带标记的 alert

**v15: 0x8BADF00D watchdog kill**:
- 配置: 全量 hook，同时阻止 `exit()` 和 `_terminateWithStatus:`
- 结果: 进程无法正常退出，5s 后被 FRONTBOARD 发送 SIGKILL（`0x8BADF00D`）
- 修复: `_terminateWithStatus:` 增加时间判断——启动 120s 内阻止（检测行为），120s 后放行（生命周期行为）

**v16–v18: hookABCJailbreakMethods → BSXPCServiceConnection 崩溃**:
- 现象: v16 在后台线程 `WKMouseDeviceObserver` 上触发 `BSXPCServiceConnection SIGTRAP`
- 根因: `isRoot` 匹配过于宽泛，命中了系统类（BSXPCServiceConnection 的 `isRoot` 等）
- v18 修复: 添加系统类前缀过滤（NS/UI/BS/BK/WK/CA/AV/CT/CK/RB/_UI/__NS/OS_/CF），移除 `isRoot`/`isRooted`/`deviceisRoot` 匹配项

**v19–v20: 嵌套 CFRunLoopRun dispatch 重入 → SIGSEGV**:
- 配置: exit hook 中调用 `CFRunLoopRun()` 保活
- 现象: `SIGSEGV` at `objc_retain` (MbapMPaaS+9286272)
- 根因: exit 从 dispatch block 中调用，`CFRunLoopRun()` 嵌套运行后会重入 main dispatch queue（main queue 的特殊行为），排出了已经过时的检测 block，访问已释放对象
- 关键点: 主线程 dispatch queue 是可重入的——嵌套 CFRunLoopRun 会继续排空 main queue

**v21: dispatch_suspend 防止 SIGSEGV 但 UI 冻结**:
- 配置: exit hook 先 `dispatch_suspend(main_queue)` 再 `CFRunLoopRun()`
- 结果: 不再 SIGSEGV，但 UI 完全无响应——所有基于 dispatch_async 的 UI 更新被阻塞

**v22: 从 exit 返回 → __stack_chk_fail**:
- 配置: exit hook 直接 return（不调 CFRunLoopRun）
- 结果: 检测代码在调用 exit 前已破坏栈 canary，return 后立即触发 `__stack_chk_fail` → abort
- 结论: 检测代码故意破坏栈保护作为后备杀死机制

**v23–v24: siglongjmp 恢复 → dispatch 状态破坏**:
- 配置: exit hook 中 `dispatch_suspend` + `CFRunLoopRun`，注册 SIGSEGV handler 用 `siglongjmp` 跳出
- 结果 v24: **部分成功**——可以上下滑动、切换底部 tab，但无法点击内容
- 根因: `siglongjmp` 从 signal handler 跳出不会清理 dispatch queue 的内部状态，suspend count 累积，`dispatch_resume` 无法修复已损坏的内部引用计数

**v25–v26: dispatch_after 时序问题**:
- 发现: `dispatch_after(10ms)` 在 ctor 阶段实际到 1.16s 才执行——因为 main queue 在 `UIApplicationMain` 启动前不排空
- 影响: 检测在 0.85s 触发，但 fishhook 在 1.16s 才安装，时间窗口完全暴露

**v27: 拆分 fishhook 时序**:
- 方案: 文件/dyld/sysctl/env hook 直接放入 ctor（0.1s），仅 exit/abort hook 延迟 200ms
- 结果: 文件 hook 在 ctor 阶段安装成功，无 BSXPCServiceConnection 崩溃
- 发现: 检测仍在 0.85s 触发退出——**SmAntiFraud 使用 `svc #0x80` 内联 syscall 绕过所有 fishhook**
- 结论: fishhook 只能重绑 PLT/GOT 条目，对 `svc #0x80` 内联调用完全无效

**v28: 简化版 siglongjmp → 同样的 dispatch 损坏**:
- 配置: 去掉 dispatch_suspend，只用 siglongjmp + CFRunLoopRun
- 结果: 同 v24——可以滑动，不能点击

**v29（当前）: 彻底简化 + pthread_kill hook**:
- 方案: 去掉 siglongjmp（破坏 dispatch 状态），去掉 dispatch_suspend（冻结 UI）。只用 CFRunLoopRun + 新增 `pthread_kill` hook 阻止 SIGABRT
- 状态: 已完成代码编写，待编译部署

**关键发现汇总**:

1. **SmAntiFraud 的 `svc #0x80` 不可 hook**: SmSyscallCode/SmSyscallUtil 直接内联 ARM64 supervisor call 做 stat/access/sysctl，完全绕过 fishhook（PLT/GOT 层）。不可能通过用户态 hook 拦截。
2. **检测不可避免，只能阻止退出**: 由于 svc syscall 无法拦截，策略从「欺骗检测」转向「阻止检测后的退出动作」。
3. **exit hook 的两难**: 
   - CFRunLoopRun → dispatch 重入 → SIGSEGV（过时 block 访问已释放对象）
   - dispatch_suspend + CFRunLoopRun → UI 冻结
   - siglongjmp → dispatch 状态永久损坏（滑动正常但点击失效）
   - return → __stack_chk_fail（栈 canary 被故意破坏）
4. **ctor 阶段的 fishhook 安全性**: 文件/dyld/sysctl 类 hook 在 ctor 阶段安装安全，不触发 BSXPCServiceConnection 崩溃；exit/abort 类必须延迟 200ms。
5. **dispatch_after 在 ctor 中不可靠**: main queue 在 UIApplicationMain 之前不排空，延迟 10ms 实际变 1+ 秒。

**推论**:
- 核心未解决: 如何在 exit 被调用后保持 UI 完全可用（dispatch queue 不受损）
- 已排除: siglongjmp（破坏 dispatch）、dispatch_suspend（冻结 UI）、return from exit（stack canary fail）
- 待验证: v29 的纯 CFRunLoopRun 方案（无 dispatch_suspend/siglongjmp），搭配 pthread_kill hook 阻止 SIGABRT 路径
- 潜在方向: (1) 找到检测函数的具体偏移量做二进制 patch；(2) 替换 exit 调用的返回地址而非从 exit 返回；(3) 在检测 dispatch block 被入队前拦截

### Round 4: 信号恢复攻防 + 栈修复（设备 B，v30–v38）

**目标**: 在 exit 被拦截后，让 app 长期稳定运行，不冻结、不崩溃。

**v30: CFRunLoopRun 保活 → UI 冻结**:
- 配置: 切换到 2215 端口设备（iOS 15），exit hook 中调用 CFRunLoopRun 保活
- 结果: APP 完全冻结，无法操作——CFRunLoopRun 阻塞了 dispatch block 排空
- 结论: exit hook 中不能调用 CFRunLoopRun

**v31: exit/abort 直接 return → SIGSEGV（过时 dispatch block 崩溃）**:
- 配置: exit/__stack_chk_fail 直接 return，不做任何保活
- 结果: 检测代码在调用 exit 前故意破坏栈 canary 和 FP/LR，return 后 dispatch drain 继续执行过时 block，触发 SIGSEGV（objc_retain 访问已释放对象）
- 关键发现: 检测代码的退出序列为 **破坏栈 canary → 破坏 FP/LR → exit() → __stack_chk_fail → abort**，多重后备机制确保进程必死

**v32: SIGSEGV handler 跳过崩溃帧 → 无限循环**:
- 配置: 安装 SIGSEGV handler，将 PC 设为 LR 跳过崩溃指令
- 结果: 无限循环——handler 只设了 PC=LR 但没更新 LR 本身，下次崩溃仍跳到相同位置
- 修复: 需要同时恢复 LR 和 FP

**v33: 完整 one-frame skip → 最佳结果（交互正常数分钟后 malloc abort）**:
- 配置: SIGSEGV handler 中同时恢复 PC/LR/FP（从栈帧读取 saved_fp 和 saved_lr），x0 返回 0/nil
- 结果: **APP 完全可用数分钟**——可以正常浏览、点击、滑动
- 最终死因: `_dispatch_continuation_free_to_cache_limit` → `free()` 检测到 heap corruption → `malloc_zone_error` → abort → SIGABRT
- 关键洞察: one-frame skip 让每个崩溃的 dispatch block 提前返回 nil，dispatch drain 能正常继续处理后续 block，所以 UI 保持交互；但被跳过的 block 遗留了未释放的 dispatch continuation 对象，最终 free 时触发 heap 一致性检查

**v34: 新增 SIGABRT handler → PAC 崩溃**:
- 配置: crash_recovery_handler 同时处理 SIGSEGV 和 SIGABRT
- 结果: handler 中调用 `raise(sig)` 时崩溃——线程上下文已损坏，raise() 触发 PAC 校验失败
- 修复: 移除 raise()，添加 PAC_STRIP 宏

**v35: 累积栈损坏 → OBJC_METACLASS 无限循环（90KB crash report）**:
- 配置: PAC_STRIP 已修复，持续 one-frame skip
- 结果: 经过大量 one-frame skip 后 FP 链条被污染成 ObjC metaclass 指针链，handler 沿着 metaclass 结构无限跳转
- 根因: 每次 one-frame skip 只跳一帧，但如果 FP 已指向非栈内存（如 ObjC 元数据），saved_fp/saved_lr 的读取就会走入 ObjC 内部数据结构
- 修复方向: 当 FP 链不可信时，需要备用恢复策略

**v36: Nuclear skip（跳到 CF run loop 帧）→ APP 不再崩溃但交互死亡**:
- 配置: FP 链断裂时，扫描栈内存寻找 CoreFoundation 地址范围内的返回地址，直接跳到 CF run loop 帧
- 结果: 无崩溃（不再产生 crash report），但 dispatch queue 状态被破坏，UI 完全无响应
- 关键对比: **one-frame skip 保持 dispatch 正常但最终 malloc abort；nuclear skip 破坏 dispatch 但不崩溃——两者不可兼得**

**v37: 纯 nuclear skip + 栈扫描 → 完全卡死**:
- 配置: 对所有信号（SIGSEGV/SIGBUS/SIGABRT）统一使用 nuclear skip
- 结果: 无崩溃，但 APP 完全卡死（不能滑动也不能点击）
- 确认: nuclear skip 必然导致 dispatch queue 永久失效

**v38: 混合策略——one-frame skip + SIGABRT 抑制 + sigaction hook**:
- 策略基于 v33（最佳结果）的改进:
  - SIGSEGV/SIGBUS: 使用 one-frame skip（保持 dispatch 正常），FP 有效时恢复整个帧，FP 无效时 fallback 到栈扫描 CF 帧
  - SIGABRT: 直接从 handler return（吞掉 abort 信号），不做栈操作
  - 新增 `sigaction` fishhook: abort() 内部流程为 `raise(SIGABRT)` → handler 吞掉 → abort 调用 `sigaction(SIGABRT, SIG_DFL)` 重置 handler → 再次 `raise(SIGABRT)` → 用默认 handler 杀死进程。hook sigaction 阻止第二步的 handler 重置
- 结果: **APP 不崩溃也不退出，但完全卡死**——exit() 从未被调用
- 根因: `hookShowJailBrokenAlert()` 将 `showJailBrokenAlertIfNeeded` 变成空操作，连带跳过了后续的 exit() 调用。检测代码的状态机卡在了一个预期之外的状态（检测到越狱 → 准备退出 → 退出入口被跳过 → 主线程阻塞在某个等待逻辑中）
- 关键洞察: **v33 能工作是因为 exit() 被调用了（然后被拦截），app 在拦截后进入了正常的执行流。v38 中 exit() 根本没被触发，所以 app 永远卡在检测流程里**

**v39: 恢复 showJailBrokenAlert + v38 SIGABRT 方案**:
- 修复: 移除 `hookShowJailBrokenAlert()` 调用，让检测代码完整执行（包括 exit()）。只通过 UIAlertController/UIViewController hooks 在 UI 层面隐藏弹窗
- 结果: exit(0) 在 15.55s 被拦截，__stack_chk_fail 被拦截。**崩溃前交互正常**（与 v33 相同的行为模式）
- 最终死因: `free() → malloc_report → malloc_vreport → abort → __abort → pthread_kill → SIGABRT`，和 v33 完全相同的 malloc heap corruption 路径
- **重大发现: fishhook 对 shared cache 内部调用完全无效**:
  - 我们的 `abort` / `pthread_kill` / `sigaction` fishhook 全部没有生效
  - crash report 调用栈确认: `abort+180` → `__abort+128` → `pthread_kill+268` → `__pthread_kill+8`，全部是原始函数
  - 原因: libsystem_malloc → libsystem_c → libsystem_pthread 都在 dyld shared cache 中，shared cache 内的跨库调用使用**直接分支指令**（编译时已知相对偏移），不经过 GOT/PLT，fishhook 的 rebind_symbols 无法拦截
  - 影响范围: 所有系统库之间的互调（malloc→abort, abort→pthread_kill, abort→sigaction, abort→_exit）都不可 hook
  - fishhook 仅对 APP 二进制（MbapMPaaS）调用系统库函数有效（APP 的 GOT 不在 shared cache 中）
- **SIGABRT handler 是唯一能拦截 malloc abort 的机制**（内核级信号投递），但 abort() 在 handler return 后调用 `sigaction(SIGABRT, SIG_DFL)` 重置 handler 再 raise——这个 sigaction 调用也在 shared cache 内，我们的 hook 无效
- abort() 的完整流程:
  ```
  abort()
    → sigprocmask(SIG_SETMASK, ...) // 确保 SIGABRT 未被屏蔽
    → raise(SIGABRT)               // 我们的 handler 可以捕获
    → sigaction(SIGABRT, SIG_DFL)   // 重置 handler（shared cache 绕过我们的 hook）
    → raise(SIGABRT)               // 用 SIG_DFL 杀死进程
    → _exit(127)                    // 终极 fallback（也在 shared cache 中）
  ```

**v40（已构建，待部署）: SIGABRT handler 栈跳跃方案**:
- 方案: SIGABRT handler 不再简单 return（回到 abort 代码后会被杀），改为沿 FP 链向上走找到 CoreFoundation 帧，直接跳过整个 abort/free 调用栈
- abort 路径的栈帧是干净的（heap corruption 影响的是堆而非栈），FP chain walk 安全
- 对于 SIGABRT: 走 FP chain 20 帧内找到第一个 CoreFoundation 范围的返回地址，修改线程上下文跳转过去
- 对于 SIGSEGV/SIGBUS: 保持 one-frame skip（与 v33 相同）
- FP 链断裂时的 fallback: 调用 `install_crash_recovery()` 重新安装 handler 后 return，利用 SA_NODEFER 在 abort 第二次 raise 时再次捕获
- 状态: 已构建 v40 deb，待用户回来后部署测试

**关键发现汇总（更新）**:

1. **v33 仍然是迄今最佳方案**: one-frame skip 让 dispatch drain 正常工作，APP 完全可交互数分钟。唯一弱点是 malloc abort
2. **one-frame skip vs nuclear skip 的根本矛盾**:
   - one-frame skip: 让崩溃函数返回 nil，dispatch drain 继续 → UI 正常，但 heap 最终不一致 → malloc abort
   - nuclear skip: 跳出整个 dispatch drain 回到 CF run loop → 不崩溃，但 dispatch queue 内部状态破坏 → UI 冻结
3. **检测代码的三重杀死机制**: 破坏栈 canary + 破坏 FP/LR + exit()，确保即使 exit 被拦截，__stack_chk_fail → abort 仍会触发，即使 abort 被拦截，函数 epilogue 会跳转到垃圾地址
4. **dyld shared cache 使 fishhook 对系统库互调完全无效**: 这是最重要的发现。shared cache 内的跨库调用使用直接分支，不经过 GOT。fishhook 仅对 APP → 系统库的调用有效。这意味着:
   - abort/pthread_kill/sigaction/_exit 的 fishhook 只能拦截 APP 直接调用它们的情况
   - 系统库内部调用链（如 free→abort→pthread_kill）完全不受 fishhook 影响
   - 唯一可靠的拦截方式是内核级机制（signal handler）
5. **hookShowJailBrokenAlert 会导致检测状态机卡死**: 将 `showJailBrokenAlertIfNeeded` 变成空操作会跳过后续的 exit() 调用，导致 APP 卡在检测流程中。**必须让检测代码完整执行**，只在 UI 层面隐藏弹窗
6. **PAC (Pointer Authentication Code)**: ARM64e 设备对栈上返回地址做签名。从栈读取的指针高位含 PAC 认证位，必须用 `PAC_STRIP` 宏（`& 0x0000007FFFFFFFFF`）剥离后才能作为地址使用
7. **abort() 有完善的自保护**: 先解除 SIGABRT 屏蔽 → raise → 重置 handler 为 SIG_DFL → 再次 raise → _exit(127)。每一步都在 shared cache 内执行，只有第一次 raise 的信号投递是内核级的可拦截

**推论**:
- 已确认: one-frame skip 是唯一能保持 UI 交互的方案（v33/v39 验证）
- 已确认: fishhook 对 shared cache 内部调用链无效（abort/pthread_kill/sigaction 全部不生效）
- 已确认: hookShowJailBrokenAlert 不能使用（导致检测状态机卡死）
- 核心挑战: 拦截 abort() 的第一次 SIGABRT 后如何阻止其重置 handler 并再次杀死进程
- v40 的验证点: SIGABRT handler 中栈跳跃到 CF 帧是否能跳过 abort 的整个自保护流程
- 备选方向: (1) hook malloc_zone 的 error handler（`malloc_zone_set_introspect` 或替换 zone 的 `force_lock`/`force_unlock`）；(2) 在 SIGABRT handler 中重新安装 handler + return（利用 SA_NODEFER 反复捕获）；(3) 找到检测 dispatch block 的入队点直接阻止

### Round 5: 栈跳跃攻防 + dispatch 状态修复（设备 A，v41–v57）

**目标**: 在 exit 被拦截后，恢复 dispatch main queue 的正常排空（drain），使 UI 完全可用并长期稳定。

**v41–v50: SIGABRT 栈跳跃迭代（过渡阶段）**:
- 从 v40 的 SIGABRT handler 栈跳跃方案开始，部署到设备 C
- 反复迭代 FP chain walk 的帧查找逻辑
- 逐步发现 exit hook 和 `_terminateWithStatus` 的时序竞争问题
- 为后续 v51–v57 的精确实验奠定基础

**v51: naked 函数栈跳跃到 dispatch drain 帧 → 前几十秒丝滑后退出**:
- 配置: SIGABRT handler 使用 `jump_to_frame_regs` naked 函数跳转到 dispatch drain 的继续帧
- 结果: **APP 前几十秒完全正常可用（丝滑），然后退出**
- 关键实现: ARM64 naked 函数 `__attribute__((naked, noreturn))` + 内联汇编：
  ```c
  static void jump_to_frame_regs(uint64_t fp, uint64_t lr, uint64_t sp,
                                  uint64_t x19_val, uint64_t x20_val) {
      __asm__ volatile ("mov x19, x3\n mov x20, x4\n mov x29, x0\n mov x30, x1\n mov sp, x2\n mov x0, #0\n ret\n");
  }
  ```
- 分析: 栈跳跃方向正确，但 dispatch 内部状态在跳转后逐渐不一致

**v52: ARC 编译错误 + exit 时序竞争 → 启动即崩**:
- Bug 1: `dispatch_queue_t` 到 `uint64_t *` 的直接 cast 在 ARC 下报错:
  `cast of an Objective-C pointer to 'uint64_t *' is disallowed with ARC`
  → 修复: `(uint64_t *)(__bridge void *)mq`
- Bug 2: 检测通过 `_terminateWithStatus:0` 在 1.10s 退出，delayed block 也在 1.10s 才执行 → `rebind_symbols` 排在慢速 ObjC swizzle **之后**，exit fishhook 未及时就绪
- Bug 3: `_terminateWithStatus` Logos hook 只做了 return，未安装 crash recovery → 检测走 ObjC terminate 路径时无 SIGSEGV/SIGABRT 保护

**v52b: 修复时序 → 约十秒后卡死**:
- 修复 1: delayed block 中 `rebind_symbols` 提前到**最前面**（在所有 swizzle 之前）
- 修复 2: `_terminateWithStatus` hook 增加:
  ```objc
  g_exit_blocked = 1;
  install_crash_recovery();
  install_ui_recovery_timer();
  ```
- 结果: exit 在 15.55s 成功拦截，但约 10s 后 UI 冻结
- 发现: `dispatch_after(10ms)` 在 ctor 中实际延迟到 1.16s 才执行——main queue 在 `UIApplicationMain` 启动前不排空

**v53–v55: 栈扫描与 callee-saved 寄存器难题**:
- 问题 1 — 栈扫描误判: raw 栈内存扫描在地址 `0x16f2b66a0` 发现了看起来像 `[saved_fp, saved_lr]` 对但并非真实帧的数据。v55 增加两级 FP chain 验证（检查 saved_fp 本身是否指向有效帧），但该帧实际是真实的——问题出在 dispatch 内部复杂性
- 问题 2 — callee-saved 寄存器: dispatch drain 帧保存了 `x19=0xffffffff77ffffff`（位掩码），这是 drain 内部逻辑使用的值。即使正确恢复 x19/x20 从 drain 帧读取，dispatch 代码调用的深层函数仍在 `0x1d8de0c74` 处 SIGSEGV
- 发现 — dispatch drain lock 布局:
  - 位置: `dispatch_queue_s` 偏移 +56（`uint64_t` 字段）
  - drain 期间值: `0x001ffe9e00000100`
  - 低 32 位: drain owner TID（掩码 `& 0xFFFFFFFC`，主线程 TID=0x103）
  - 高 32 位: queue width/role/flags
- **结论: 栈跳跃方案放弃。dispatch 内部状态机的复杂度超出寄存器/栈恢复能力——即使 FP/SP/x19/x20 全部正确恢复，drain 函数调用的深层代码仍依赖无法从外部重建的上下文**

**v56: 清除 drain lock → 不崩但完全卡死**:
- 方案: 放弃栈跳跃，改为在 exit hook 中清除 dispatch drain lock（offset +56 的 TID 位清零），然后进入 `CFRunLoopRun` 保活
- 结果: 进程存活，不崩溃，但 **UI 完全无响应**
- 分析: 清除 drain lock 让进程续活，但 dispatch main queue **永远不再排空**

**v57: source0 诊断确认 run loop 活跃但 dispatch 失效**:
- 方案: 在 exit hook 中创建 `CFRunLoopSourceRef`（source0）作为诊断，同时从后台线程 `dispatch_async` 到 main queue
- 关键日志:
  ```
  [ 15.55]   recovery source0 fired — run loop IS processing sources
  [ 15.55]   bg thread: dispatching wake block to main queue
  [ 18.00]   CFRunLoopRun returned, re-entering
  ```
  **从未出现**: "dispatch block executed from source0 callback" 和 "wake block from bg thread executed on main queue"
- 结论:
  - Run loop **活跃**: source0 回调正确触发，CFRunLoopRun 反复返回（处理可用 source 后发现没有更多工作）
  - Dispatch main queue **死亡**: `dispatch_async` 入队 block 但 drain callback 永远不触发
  - **根因**: drain 函数在执行 block **之前**已经 disarm 了其 CFRunLoopSource（取消注册/标记已触发）。清除 drain lock 不会 re-arm 这个 source。这就是 dispatch_async 入队但不执行的原因

**额外发现 — exit hook 内 CFRunLoopRun 导致 v57 退化**:
- v57 比 v33 卡死**更快**的原因: exit 从 dispatch drain 的 block 中调用 → hooked_exit 进入 CFRunLoopRun → 嵌套 run loop 运行但 main dispatch source 已 disarm → drain 函数永远无法完成当前 block 并继续处理后续 block
- 对比 v33: exit hook 直接 return → 虽然触发 __stack_chk_fail → SIGSEGV 连锁，但 one-frame skip 处理每个崩溃 → drain 自然完成 → UI 完全可用数分钟

**关键发现汇总（v41–v57）**:

1. **v33 仍是全局最佳**: exit 直接 return → SIGSEGV one-frame skip → dispatch drain 自然完成 → APP 完全可用数分钟。唯一死因: 累积 heap corruption → malloc abort
2. **exit hook 绝对不能阻塞**: 在 exit hook 中调用 `CFRunLoopRun` / `dispatch_suspend` / `siglongjmp` 都会以不同方式破坏 dispatch 状态。exit 必须直接 return，让 dispatch drain 自然走完
3. **栈跳跃不可行**: dispatch 内部状态机复杂度远超寄存器/栈恢复能力。ARM64 naked 函数虽然可以精确操控寄存器，但无法重建 dispatch drain 的完整运行时上下文
4. **drain lock 可清除但不足以恢复排空**: `dispatch_queue_s` offset +56 存储 drain owner TID，清零可续活进程，但 drain 函数在处理 block 前已 disarm 其 `CFRunLoopSource`，清除 lock 不会 re-arm source
5. **CFRunLoop 与 dispatch 的桥梁机制**: main dispatch queue 通过 `_dispatch_main_queue_callback_4CF` 注册为 CFRunLoopSource1（mach port source）。drain 函数 disarm 此 source 后，即使 `dispatch_async` 入队新 block，run loop 也不触发 drain callback
6. **exit/abort fishhook 时序关键**: `rebind_symbols` 必须在 delayed block **最前面**执行（在慢速 ObjC swizzle 之前），否则检测可能在 exit fishhook 就绪前通过 `_terminateWithStatus` 退出
7. **`dispatch_after` 在 ctor 中不可靠**: main queue 在 `UIApplicationMain` 前不排空。`dispatch_after(10ms)` 实际延迟 1.16s。安全的拆分: 文件/dyld/sysctl hooks 放 ctor 直接执行，exit/abort hooks 放 `dispatch_after(200ms)`
8. **ARM64 naked 函数**: `__attribute__((naked, noreturn))` 配合内联汇编可直接操控 x29/x30/sp/x19/x20。虽然对 dispatch recovery 无效（原因见第 3 点），但技术本身是正确的
9. **`dispatch_queue_s` 布局（iOS 15–16）**: offset +56 是 drain lock（`uint64_t`，低 32 位 TID，高 32 位 flags）。主线程 TID 通过 `mach_thread_self()` 获取，匹配时用 `& 0xFFFFFFFC` 掩码

**推论**:
- 核心策略调整: 回归 v33 方案（exit return + one-frame skip），专注解决唯一弱点——malloc abort
- 已排除: 栈跳跃（dispatch 状态不可重建）、drain lock 清除（source 不会 re-arm）、exit 内 CFRunLoopRun（阻塞 drain）
- 下一步（v58）:
  - exit hook: 直接 return（不阻塞），保持 v33 的 dispatch drain 自然完成
  - SIGSEGV: 保持 one-frame skip（已验证有效）
  - SIGABRT（核心改进）: handler 沿 FP chain 跳过 abort 链（libsystem_c/malloc/pthread/kernel），落到第一个 dispatch 或 app 帧。让 drain 继续而非 nuclear skip 到 run loop
- 备选方向: (1) 定期调用 `_dispatch_main_queue_callback_4CF`（dlsym 获取）手动排空 main queue；(2) hook `dispatch_async` 将 exit 后的 main queue block 转发到 `CFRunLoopPerformBlock`；(3) 向 dispatch main queue 的 mach port（`_dispatch_get_main_queue_port_4CF`）发送 wakeup 消息 re-arm source

### Round 6: 栈切换避免级联崩溃（设备 A，v58–v61）

**目标**: 避免 exit return 后的 SIGSEGV 级联（10+ 次崩溃在垃圾内存间跳转），保持 dispatch queue 完整。

**背景回顾**: v33（Round 4 最佳）证明 exit return → one-frame skip → dispatch drain 正常 → UI 可用数分钟。但在设备 A（iOS 16.3.1）上，exit return 触发的 SIGSEGV 级联会破坏 dispatch queue 的内部链表结构。v56/v57 确认：级联后的 dispatch queue 无法通过清除 drain lock 恢复。Round 5 结论指向新方向：**既然级联后 dispatch queue 不可修复，那就避免级联发生**。

**v58: SIGABRT handler 跳到 CF 帧 → CF stack canary 失败**:
- 策略: exit 直接 return（让 __stack_chk_fail → abort 触发），SIGABRT handler 沿 FP chain 找到 CF 范围帧并跳转
- 结果: handler 成功找到 `__CFRunLoopRun` 帧并跳转，但该帧的 stack canary 已被 SIGSEGV 级联破坏
- 死因: `__stack_chk_fail` → `__abort`（shared cache 内直接调用）→ 重置 handler 为 SIG_DFL → `raise(SIGABRT)` → 进程死亡
- 关键发现: **SIGSEGV 级联不仅破坏 dispatch queue，还破坏了 CF run loop 帧的 stack canary**。任何跳回 CF 帧的方案都会在函数 epilogue 触发 __stack_chk_fail

**v59: 改用 trampoline（clean stack）→ 静默死亡**:
- 策略: SIGABRT handler 不再跳回已损坏的 CF 帧，改为跳到 `abort_recovery_trampoline`（在新的干净栈上运行）
- trampoline 功能: 清除 drain lock → 安装手动 drain timer（16ms 间隔调用 `_dispatch_main_queue_callback_4CF`）→ 进入 CFRunLoopRun 循环
- 结果: trampoline 入口日志写入，但之后**进程静默死亡**——无 crash report，无额外日志
- 推测: trampoline 的 CFRunLoopRun 可能因为 signal handler 上下文残留导致某种不一致

**v60: trampoline 增加诊断日志 → 确认 drain 函数无效**:
- 增加: drain timer 回调日志、CFRunLoopRun 返回日志
- 关键日志:
  ```
  drain timer #1 firing → drain timer #1 returned
  drain timer #2 firing → drain timer #2 returned
  (5 次 drain timer 正常触发)
  CFRunLoopRun returned (#1)
  CFRunLoopRun returned (#2)
  ```
- 结论: `_dispatch_main_queue_callback_4CF` 正常返回但**不处理任何 block**——dispatch queue 内部链表已被 SIGSEGV 级联破坏
- 最终死因: CFRunLoopRun 反复返回（无 source），while(1) 空转消耗 CPU → 可能触发 jetsam 或其他看门狗

**v61: 从 exit hook 直接栈切换到 trampoline — 彻底避免级联（突破性进展）**:
- **核心策略变更**: 不再让 exit 返回（返回必触发 __stack_chk_fail → SIGSEGV 级联），而是在 exit hook 中**直接切换栈并跳转到 trampoline**，彻底跳过级联
- ARM64 内联汇编实现:
  ```c
  uint64_t new_sp = g_main_stack_top - 256;
  __asm__ volatile (
      "mov sp, %[sp]\n"    // 切换到主线程栈顶
      "mov x29, #0\n"      // 清零 FP，终止 FP chain
      "mov x30, %[fn]\n"   // LR = trampoline 地址
      "ret\n"              // 跳转到 trampoline
      :: [sp] "r" (new_sp), [fn] "r" (tramp)
      : "memory"
  );
  ```
- 结果:
  ```
  [ 16.00] EXIT blocked: exit(0) thread=main
  [ 16.00]   2 malloc zones force-unlocked
  [ 16.00]   jumping to trampoline (avoiding cascade)
  [ 16.00] TRAMPOLINE: drain lock at +56 cleared
  [ 16.00] TRAMPOLINE: manual drain timer installed (16ms)
  [ 16.00] TRAMPOLINE: 2 zones unlocked, entering CFRunLoopRun
  [ 16.02] drain timer #1 firing → returned
  ...
  [ 16.08] drain timer #5 firing → returned
  [ 16.64] CFRunLoopRun returned (#1)
  [ 16.94] CFRunLoopRun returned (#2)
  [ 16.98] CFRunLoopRun returned (#3)
  (之后沉默约 11 秒)
  ```
- **成功: 零 SIGSEGV！** 没有触发任何 SIGSEGV 级联，这是自 Round 5 以来首次
- **进程存活约 27 秒**（launch 14:14:16 → crash 14:14:43）
- **最终死因**: crash report 显示:
  ```
  Thread 0 (main):
  __pthread_kill → pthread_kill → __abort → __stack_chk_fail
    → __CFRunLoopRun (+2756)
    → -[UIApplication _run]
    → UIApplicationMain
  ```
  `asi: {"libsystem_c.dylib": ["stack buffer overflow"]}`
- 分析:
  - crash 在 `__CFRunLoopRun` 的 stack canary 检查（函数 epilogue）
  - 调用栈显示原始 app 的 run loop 帧（`-[UIApplication _run]` → `UIApplicationMain`），不是我们 trampoline 的
  - 这说明 trampoline 的 CFRunLoopRun 最终进入了与原始 app 相同的 run loop，run loop 内部恢复了某些原始帧的上下文
  - **canary 破坏原因待定**: 可能是 drain timer 处理的 dispatch block 中包含第二轮检测代码，再次调用 exit，触发了 hooked_exit 的二次栈切换

**关键发现汇总（v58–v61）**:

1. **栈切换成功避免 SIGSEGV 级联**: v61 的 ARM64 内联汇编栈切换方案彻底消除了 exit return 后的 SIGSEGV 级联。进程从 16s 存活到 27s（11 秒无级联崩溃）
2. **`_dispatch_main_queue_callback_4CF` 对已破坏的 queue 无效**: v60 确认，即使手动定时调用 drain 函数，corrupted 的 dispatch queue 内部链表不会处理任何 block。drain 函数正常返回但什么都不做
3. **CF stack canary 也被级联破坏**: v58 证明 SIGSEGV 级联不仅破坏 dispatch queue，还破坏 CF run loop 帧的栈保护。任何跳回原始 CF 帧的方案都不可行
4. **v61 的新死因**: 不再是 SIGSEGV 级联（已消除），而是 **CFRunLoopRun 内部的 stack canary 被破坏**。crash 在进入 trampoline 约 11 秒后发生，暗示某种延迟的栈破坏——可能是 drain timer 触发了二次检测
5. **系统库地址范围确认**（iOS 16.3.1 设备 A）:
   - CF: `0x18ab63000-0x18b363000`
   - libdispatch: `0x192181000-0x192381000`
   - libc: `0x1921c8000-0x1923c8000`
   - malloc: `0x199056000-0x199156000`
   - pthread: `0x1d8de4000-0x1d8ee4000`
   - kernel: `0x1c8680000-0x1c8780000`
6. **`_dispatch_main_queue_callback_4CF` 可通过 dlsym 获取**: 地址 `0x192193418`，可用于手动调用 drain

**推论**:
- 重大进展: 栈切换方案成功消除 SIGSEGV 级联，这是之前所有方案无法做到的
- v61 比 v33 的进步: v33 需要处理 SIGSEGV 级联（one-frame skip × 10+ 次），v61 直接跳过；但 v33 的 dispatch drain 自然完成（UI 可用），v61 的 drain timer 不处理 block
- 核心矛盾仍在:
  - **exit return** → dispatch drain 自然完成 → UI 可用，但 SIGSEGV 级联破坏一切（设备 A）
  - **exit 栈切换** → 避免级联，但 dispatch queue 从未被自然 drain → UI 冻结
- 下一步方向:
  1. **调查 v61 的 canary 破坏原因**: 在 hooked_exit 中检测重入（第二次 exit 调用），记录是否有 block 触发了二次检测
  2. **在 trampoline 中安装 SIGABRT handler**: 捕获 __stack_chk_fail → __abort 的 SIGABRT，重新跳回 trampoline（循环恢复）
  3. **考虑不调用 `_dispatch_main_queue_callback_4CF`**: 如果 drain timer 触发了二次检测，禁用它可避免 canary 破坏，但 UI 仍冻结
  4. **混合方案**: 栈切换入 trampoline 后，用 `dispatch_async` 从后台线程向 main queue 提交新的 UI recovery block，同时手动 re-arm dispatch source（写入 mach port）
  5. **v33 方案在设备 A 的重新评估**: v33 在设备 B 上工作数分钟，在设备 A 上也值得重试——之前在设备 A 的测试可能因其他因素干扰
