# 农业银行 (ABC) 越狱检测分析

## 环境信息

### 设备 A（Round 1、Round 5–9 使用）
- iPhone 14 Pro Max, iOS 16.3.1, Dopamine (rootless)
- SSH 端口: 2214（原 2216）
- App: 农业银行 v11.1.0 (build 11.1.3)
- Bundle ID: `com.bankabc.iphonerelease`
- Executable: `MbapMPaaS`
- Binary: 110MB, arm64 single arch, 基于蚂蚁 mPaaS 平台
- 安装路径: `/private/var/containers/Bundle/Application/772F8B77-480D-4711-A6F5-AEE1D1CE964A/MbapMPaaS.app`
- 数据容器: `/var/mobile/Containers/Data/Application/9A9D3109-D1E4-4F57-8EFA-1C265EC41095`

### 设备 B（Round 2–4、Round 8 使用）
- iPhone 13 Pro, iOS 15.4.1, Dopamine 1.x (rootless)
- SSH 端口: 2213（原 2215）
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

### Round 7: 后台线程 syscall exit 发现 + 线程挂起方案（设备 A，v62–v66）

**目标**: 理解 v61 trampoline 中进程静默死亡的原因，找到并阻止杀进程的机制。

**v62: 增加诊断日志 + 信号掩码恢复 → 静默死亡**:
- 改进: trampoline 增加信号掩码恢复（`sigprocmask` 清零），SIGABRT handler 增加 SP 日志，hooked_exit 增加调用计数
- 结果: 与 v61 相同——trampoline 正常运行，drain timer 触发，CFRunLoopRun 返回 3 次，然后**进程静默死亡，无 crash report，无 SIGABRT handler 日志**
- 关键发现: **静默死亡（无 crash report）只可能是直接 `svc #0x80` syscall 调用 `_exit()` 或 `kill(SIGKILL)`**。用户态 signal handler 和 fishhook 均不可拦截

**v63: 挂起所有后台线程 → 进程无限存活（确认后台线程是杀手）**:
- 策略: exit hook 跳转 trampoline 后，用 Mach API `task_threads()` + `thread_suspend()` 挂起所有非主线程
- 结果: **进程无限存活**（heartbeat 持续到 48+ 秒，用户手动杀死才停止）
- 挂起了 29/30 线程
- UI 完全冻结（动画仍在播放因为 Core Animation 在独立系统进程中运行）
- **这是决定性实验**: 证实了 v62 的静默死亡是由后台线程通过 `svc #0x80` 直接 syscall 杀死进程

**v64: 选择性线程挂起 → 部分 UI 交互恢复**:
- 策略: 只挂起未命名线程和 SmAntiFraud 已知线程（`ant_bifrost.anr`、`LagMonitor*`），保留有名的系统线程
- 线程分类:
  - 挂起（19/28）: 所有未命名线程 + `ant_bifrost.anr`
  - 保留（9/28）: `com.apple.uikit.xpc-service`, `APFileLog`, `com.apple.uikit.eventfetch-thread`, `PowerGetThread`, `longLinkThread`, `MASS_Net`, `com.apple.NSURLConnectionLoader`, `com.apple.CFSocket.private`, 1个未命名
- 结果: **进程存活 55 秒，底部 tab 可以切换！** 这是首次在 exit 拦截后实现用户交互
- 死因: `0x8BADF00D` watchdog kill——用户将 APP 切到后台，`_terminateWithStatus` hook 拦截了优雅退出，5秒后 FRONTBOARD 发 SIGKILL
- **关键**: 进程不是被检测杀死的，而是被 iOS 生命周期管理杀死的

**v65: 修复 _terminateWithStatus 阈值 → 静默死亡（新线程逃逸）**:
- 改进: `_terminateWithStatus` 阈值从 120s 降到 30s（检测在 ~16s 触发，30s 后允许 iOS 生命周期退出）
- 结果: 进程存活约 25 秒后**静默死亡（无 crash report）**——与 v62 相同的死因
- 根因: 线程挂起是一次性的。检测代码在被挂起后**创建了新线程**（如 `LagMonitorThread` 在 v64 crash report 中出现但不在初始线程列表中），新线程未被挂起，可以调用 `svc #0x80 _exit()`
- 底 tab 这次无法切换——可能因为某些需要的 dispatch worker 线程被误挂起

**v66（已编码，未部署）: 持续线程巡逻**:
- 策略: 改为「挂起所有 → 恢复已知安全线程」模式（反转 v64 的逻辑），并安装 2 秒间隔的 patrol timer 持续扫描和挂起新创建的线程
- 安全线程白名单: `com.apple.*`, `APFileLog`, `PowerGetThread`, `longLinkThread`, `MASS_Net`
- 每次 patrol: `task_threads()` 枚举所有线程，挂起不在白名单中的，resume 白名单中的
- 状态: 代码已完成，待部署测试

**关键发现汇总（v62–v66）**:

1. **后台线程通过 `svc #0x80` 直接 syscall 杀死进程**: v63 的全量挂起 → 无限存活 vs v62 的不挂起 → 静默死亡，决定性证明
2. **SmAntiFraud 动态创建线程**: 线程挂起必须是持续的（patrol 模式），一次性挂起不够——检测代码会创建新线程绕过
3. **选择性挂起可恢复部分 UI**: v64 证明只要保留 `eventfetch-thread` 和 `uikit.xpc-service`，底 tab 可以切换。完整 UI 还需要解决 dispatch queue drain 问题
4. **`0x8BADF00D` watchdog kill 必须处理**: `_terminateWithStatus` 阈值 120s 太长，APP 切后台时被 FRONTBOARD 杀死。改为 30s 后放行
5. **Mach 线程 API 可用**: `task_threads()` + `thread_suspend()` + `thread_resume()` + `pthread_from_mach_thread_np()` + `pthread_getname_np()` 组合可以精确控制线程生命周期

**推论**:
- 进程存活问题已解决: 栈切换 + 持续线程挂起 = 无限存活
- UI 部分可用: tab 切换已实现，完整 UI 需要 dispatch queue recovery
- 核心矛盾从「进程存活」转向「dispatch queue 恢复」:
  - 栈切换放弃了正在进行的 dispatch drain
  - drain lock 可清除但 CFRunLoopSource 未 re-arm
  - 手动调用 `_dispatch_main_queue_callback_4CF` 返回但不处理 block（queue 内部状态不一致）
- 下一步方向:
  1. 部署 v66 验证持续 patrol 是否能保持进程无限存活
  2. 研究 dispatch main queue 的 CFRunLoopSource re-arm 方法（`_dispatch_get_main_queue_port_4CF` 获取 mach port → `mach_msg` 发送唤醒消息）
  3. 或者: 不修复 dispatch queue，而是用 `CFRunLoopPerformBlock` / `performSelector:onThread:` / `NSRunLoop` 调度替代 dispatch_async，重新驱动 UI 更新

---

### Round 8: 线程管理精细化 + Dispatch Queue 恢复攻坚（v67–v75）

**测试设备**: Device B (2215→2213, iPhone 13 Pro, iOS 15.4.1)

**v67: patrol timer 0.5s + 全量挂起模式**:
- 策略: 延续 v66 的 patrol 模式，间隔从 2s 缩短到 0.5s
- 结果: 进程在 trampoline 中存活约 17 秒后静默死亡（无 crash report = svc #0x80 新线程逃逸）
- 新线程创建速度超过 0.5s 的 patrol 间隔

**v68: 新增 pthread_create hook + patrol timer 0.5s**:
- 新增: `hooked_pthread_create` 函数 + fishhook 绑定。`g_exit_blocked` 后阻止所有 PLT 层面的 pthread_create 调用
- 结果: **进程存活 71+ 秒**（heartbeat #60），但 **UI 逐渐冻结**
- 0 个 `pthread_create BLOCKED` 日志——检测线程在 pthread_create 之前就被初始挂起冻住了
- **UI 表现**: 一开始 tab 切换和部分滑动正常工作，逐渐变卡（"有明显的逐渐变卡的过程"），最终完全冻结；顶部搜索框轮播动画始终正常
- **分析**: patrol timer 每 0.5s 挂起所有 unnamed 线程。GCD worker 线程（libdispatch 按需创建）和 CA 渲染线程都是 unnamed 的。随着系统创建新 worker → 被 patrol 挂起 → 系统再创建 → 再被挂起……逐步耗尽并发处理能力

**v69: 移除 patrol timer，仅保留 pthread_create hook**:
- 策略: 验证 pthread_create hook 单独是否足以保护进程
- 结果: **CFRunLoop 完全阻塞**——进入 CFRunLoopRunInMode 后无 heartbeat 输出
- 原因: drain timer 的 `_dispatch_main_queue_callback_4CF(NULL)` 调用阻塞在 dispatch 内部锁上
- 进程活着（ps 可见）但 CFRunLoop 被 drain timer 回调卡死

**v70: 移除 patrol timer + 移除 drain timer**:
- 策略: 去掉所有可能导致阻塞的 timer，只保留 pthread_create hook
- 结果: heartbeat 恢复正常！但 **进程在 ~18 秒死亡**（同 v67）
- **关键结论**: pthread_create hook **不足以阻止进程被杀**。SmAntiFraud 的线程创建绕过了 PLT hook（通过共享缓存内部调用或直接 syscall 创建线程）
- patrol timer 是进程存活的必要条件

**v71: 智能 patrol（PC 判断）+ pthread_create hook**:
- 新增: `is_system_thread_pc()` 函数——用 `thread_get_state(ARM_THREAD_STATE64)` 读取线程 PC 寄存器，`dladdr()` 判断所在库
- patrol 改进:
  - 跳过 suspend_count > 0 的线程（已挂起）
  - 跳过 named safe 线程
  - 未挂起的 unnamed 线程: PC 在系统库 → 跳过（系统线程），PC 在非系统库 → 挂起（检测线程）
- patrol 间隔: 0.2s
- 结果: 进程存活 80+ 秒，heartbeat 正常。**0 个 PATROL 日志**（smart patrol 没挂起任何新线程）
- **UI 仍冻结**，但表现不同: "逐渐变卡的过程变得不明显，像是突变"
- 分析: 不是 patrol 误杀线程导致的。系统线程被保护了，但 dispatch queue 本身的损坏（stack switch 导致）才是 UI 冻结根因

**v72: 不做 stack switch，直接 return**:
- 策略: 从 hooked_exit 直接 return，不做栈切换，保留 dispatch drain 完整性
- 结果: return 后触发 `__stack_chk_fail`（exit 是 `_Noreturn`，编译器不生成返回路径有效代码） → 10 次 SIGSEGV 级联 → FP=0x0 → crash recovery 进入 trampoline
- **结论**: 编译器在 `_Noreturn` 调用后不生成有效代码，直接 return 不可行
- 用户反馈: "部分操作可响应（底 tab 切换），部分不行（上下滑列表），但部分场景又可以"——首次精确描述了部分 UI 可用/不可用的边界

**v73: stack switch + dispatch_async 恢复尝试**:
- 策略: 恢复 stack switch。清除 drain lock 后 `dispatch_async(main_queue, ^{})` 一个空 block 尝试 re-arm CFRunLoopSource
- 结果: 进程存活 70+ 秒，但 `DISPATCH RECOVERED` block **从未执行**
- 分析: dispatch_async 内部检查 queue 状态，发现"正在 drain"则跳过 source signal（因为正常情况下 drain 循环会处理新 block）。但 drain 已被放弃，无人处理

**v74: Phase 1 全量挂起 + Phase 2 智能恢复**:
- 新策略:
  1. Phase 1: 激进挂起所有 unnamed 线程（确保捕获检测线程）
  2. Phase 2: 立即扫描被挂起线程，恢复 PC 在系统库的（GCD workers、CA 渲染等）
- 结果: **21 挂起 → 19 恢复**，仅 2 线程保持挂起
- `DISPATCH RECOVERED` 仍未执行——恢复 GCD workers 并不能修复 dispatch queue 内部状态
- 进程被 `_terminateWithStatus` 在 41.71s 正常终止（>30s 阈值，用户切后台）
- **重要发现**: SmAntiFraud 线程在 PC 检查时大多在系统 syscall 中（sleep/nanosleep），被误判为系统线程并恢复。PC 判断对检测线程有假阳性
- 仅 2 个线程保持挂起，但进程在 41s 内未被 svc #0x80 杀死——要么这 2 个是关键检测线程，要么检测线程被恢复但未来得及执行

**v75: 诊断版 + mach_msg 直接唤醒**:
- 新增: dump main dispatch queue 结构（16 * 8 bytes）
- 发现:
  - `mq[4] (+32) = 0x2a07` — mach port handle
  - `mq[7] (+56) = 0x1ffe9e00000100` — drain lock（低 32 位 0x100，与 main thread TID 0x103 通过 `& 0xFFFFFFFC` 匹配）
  - `mq[10] (+80) = 0x6ff00140001` — 可能是 dq_atomic_flags（含 draining 状态位）
- 尝试: `_dispatch_get_main_queue_handle_4CF` 获取 port → `mach_msg` 发送唤醒
- 结果: `mach_msg` 返回 `MACH_SEND_TIMED_OUT` (0x10000004)——port 消息队列已满（dispatch_async 已发过唤醒但未被消费）
- `DISPATCH RECOVERED` 仍未执行

**关键发现汇总（v67–v75）**:

1. **进程存活 vs UI 可用是两个独立问题**:
   - 存活: patrol timer + pthread_create hook 组合可保证进程不被 svc #0x80 杀死
   - UI: dispatch queue 在 stack switch 后损坏，是独立于线程管理的问题

2. **Patrol timer 对 UI 的影响**:
   - 全量 patrol（v68）: UI 渐进冻结——误杀 GCD workers
   - 智能 patrol（v71）: UI 突然冻结——不误杀，但 dispatch queue 仍损坏
   - 无 patrol（v70）: 进程在 ~18s 死亡——patrol 是存活必需的

3. **Dispatch queue 损坏的根因**: stack switch 放弃了 dispatch drain 的执行上下文。以下修复尝试均失败:
   - 清除 drain lock at +56 ✗
   - dispatch_async 新 block ✗（内部"正在 drain"状态阻止 source signal）
   - mach_msg 直接唤醒 port ✗（port 已满，且 drain callback 执行后不处理 block）
   - 直接 return 避免 stack switch ✗（_Noreturn 函数无有效返回代码）

4. **Smart resume 的局限**: PC 判断对 SmAntiFraud 线程有假阳性——检测线程大部分时间在 syscall（系统库 PC），被误判为系统线程。21 挂起 → 19 恢复，几乎全部放行

5. **Main dispatch queue 结构**（iOS 15.4.1, ARM64）:
   - +32: mach port handle（与 `_dispatch_get_main_queue_handle_4CF` 一致）
   - +56: drain owner TID（低 32 位，按 `& 0xFFFFFFFC` 对齐）
   - +80: atomic flags（含 draining 状态位，`0x6ff00140001`）

**推论与下一步方向**:
- Stack switch 不可避免（return 不可行），dispatch queue 损坏不可避免
- 需要绕过损坏的 dispatch queue 而非修复它
- **最有前景的方向**: Hook `dispatch_async`，当 `g_exit_blocked` 且目标为 main queue 时，通过 `CFRunLoopPerformBlock` 重定向到 CFRunLoop 执行。这只能截获 PLT 级别的调用（app 代码），系统库内部调用仍走损坏的 dispatch queue
- 另一方向: 研究 `mq[10] (+80)` 的 flags 含义，尝试清除 "draining" 状态位使 dispatch 自然恢复

### Round 9: MSHookFunction 与 SDK 内存扫描冲突 + dispatch_async 重定向（设备 A，v76–v81）

**测试设备**: Device A (2214, iPhone 14 Pro Max, iOS 16.3.1)

**目标**: 实现 Round 8 确定的最有前景方向——MSHookFunction inline hook `dispatch_async` 重定向到 CFRunLoop + MSHookFunction `pthread_create` 替代 patrol timer。

**v76: ARC bridging error + CFRunLoop 阻塞**:
- 新增: `hooked_dispatch_async` 和 `hooked_dispatch_async_f`，MSHookFunction inline hook
- Bug 1: `Block_copy(block)` 在 ARC 下报错 `cast of block pointer type 'dispatch_block_t' to C pointer type 'const void *' requires a bridged cast`
- 修复: 移除 Block_copy/Block_release，ARC 自动管理 block 的 copy
- Bug 2: v75 的 mach_msg 诊断代码仍在 trampoline 中，导致主线程阻塞
- 结果: "卡住了，动画效果也卡住了"——连 Core Animation 都不动了

**v77: 移除 mach_msg 诊断 → fishhook 只捕获 5 次 redirect**:
- 修改: 移除 trampoline 中所有 mach_msg 和 queue dump 诊断代码
- 结果: 仍然卡死
- 关键日志: `dispatch_async REDIRECT #1~#5 to CFRunLoop`，之后无新 redirect
- **分析**: fishhook 只 hook PLT/GOT 调用。APP 内部通过 GOT 调用 dispatch_async 的只有 5 次。系统库（UIKit、CF 等）的 dispatch_async 调用走共享缓存内部直接分支，不经过 GOT。5 次 redirect 不足以恢复 UI

**v78: 改用 MSHookFunction inline hook dispatch_async**:
- 策略: 从 fishhook 改为 MSHookFunction（修改函数入口字节的 inline hook），可捕获所有调用者（包括共享缓存内部调用）
- 结果: hook 成功安装（日志确认 `MSHookFunction armed`），但仍卡死
- 分析: MSHookFunction 安装成功但 redirect 效果与 v77 类似——v78 可能有其他问题

**v79: MSHookFunction dispatch + pthread_create（线程名过滤）**:
- 新增: MSHookFunction hook `pthread_create`，post-exit 后阻止所有新线程创建
- 结果: **部分 UI 恢复！** "没有完全卡死，可以切换底 tab，部分可以上下滑。但多数无法点击。"
- 后续: "完全卡死了，有一个明显的渐进的过程" → 最终被 watchdog 重启
- 分析: pthread_create 全量阻止过于激进——阻止了 GCD worker 线程和 CA 渲染线程的创建，导致并发能力逐渐耗尽

**v80（构建失败 → 修复后 4/4 闪退）: pthread_create dladdr 过滤 + 无 patrol**:
- 改进: `hooked_pthread_create` 使用 `dladdr(start_routine)` 判断线程所属库——允许系统库线程（GCD workers、CA 等），阻止 APP/SDK 线程（SmAntiFraud）
- 构建问题: forward declaration 的 counter 变量与后续 `static volatile int` 定义冲突，修复为只保留 forward decl
- **测试结果: 4 次启动均在 ~6.7 秒闪退（SIGSEGV）**
- crash report:
  - Thread 4 `com.apple.uikit.xpc-service` 崩溃
  - `memmem` 读取无效地址 `0x1ddd73040`（共享缓存中 32MB 未映射区域）
  - 调用栈: `memmem → app code (offset ~76M) × 4 → _dispatch_call_block_and_release`
  - ellekit exception handler 线程循环 5 次

**关键二分实验: 定位 MSHookFunction 崩溃源**:

| 测试 | MSHookFunction 目标 | pthread_create | 结果 |
|------|---------------------|----------------|------|
| bisect-1 | 全部禁用 | fishhook | **存活** — exit 在 15.74s 拦截，trampoline heartbeat 正常 |
| bisect-2 | dispatch_async + dispatch_async_f | fishhook | **存活** — 560+ redirect，heartbeat 正常 |
| (推断) | pthread_create | — | **闪退** |

**结论: MSHookFunction 对 `pthread_create` 导致 SDK 内存完整性扫描崩溃**

- SDK 的 `com.apple.uikit.xpc-service` 线程使用 `memmem` 扫描内存区域检测代码篡改
- MSHookFunction 修改 `pthread_create`（libpthread）的函数入口字节 → SDK 扫描到修改后的字节 → 跟踪跳转到 hook island → 扫描附近内存 → 命中未映射区域 → SIGSEGV
- MSHookFunction 对 `dispatch_async`（libdispatch）不触发此问题——可能是 SDK 只扫描特定系统库

**v81（当前版本）: MSHookFunction dispatch + fishhook pthread + patrol timer**:
- 最终策略:
  1. `dispatch_async` / `dispatch_async_f` → **MSHookFunction**（inline hook，捕获所有调用者，560+ redirect）
  2. `pthread_create` → **fishhook**（仅 PLT/GOT，避免触发 SDK 扫描崩溃）
  3. **patrol timer 0.3s** → 持续扫描并挂起新检测线程（弥补 fishhook 无法捕获内部调用的不足）
- bisect 测试确认: MSHookFunction dispatch_async 不导致崩溃，560 次 redirect 工作正常
- 状态: 已构建部署，待用户测试 UI 表现

**关键发现汇总（v76–v81）**:

1. **MSHookFunction 对 libpthread 不安全**: SDK 的内存完整性扫描检测到 `pthread_create` 入口被修改，扫描过程中命中未映射区域导致 SIGSEGV。100% 复现
2. **MSHookFunction 对 libdispatch 安全**: `dispatch_async` 的 inline hook 不触发 SDK 扫描崩溃。可能是 SDK 只扫描特定关键库（libpthread、libsystem_kernel 等）
3. **MSHookFunction vs fishhook 效果对比**:
   - `dispatch_async` fishhook: 5 次 redirect（仅 PLT/GOT 调用）
   - `dispatch_async` MSHookFunction: 560+ 次 redirect（所有调用者包括共享缓存内部）
   - 效果提升 100 倍以上
4. **fishhook 的 pthread_create 无法捕获 post-exit 线程创建**: bisect 测试中 `pt_block=0, pt_allow=0`——检测线程在 exit 前已创建，或使用内部直接调用绕过 PLT
5. **Patrol timer 仍然是线程管理的必要组件**: fishhook pthread_create 不足以阻止 svc #0x80 杀进程线程，patrol timer 负责持续挂起新出现的检测线程

**推论**:
- dispatch 重定向问题已解决: MSHookFunction 捕获 560+ 次 dispatch_async，全部重定向到 CFRunLoopPerformBlock
- 线程管理采用双层方案: fishhook pthread_create（安全但不完整）+ patrol timer 0.3s（补充扫描挂起）
- 待验证: v81 的 UI 表现——MSHookFunction dispatch redirect + patrol timer 组合能否实现稳定交互
- 已知风险: patrol timer 可能误挂 GCD workers（v68 问题）。v81 的 `suspend_and_log_threads` 使用 `is_system_thread_pc()` 判断，对检测线程有假阳性（Round 8 发现）。可能需要进一步优化 patrol 逻辑

---

## Round 10: 主线程死锁与 svc exit 对策（v82–v85）

**测试环境**: Device A (iPhone 14 Pro Max, iOS 16.3.1, Dopamine 2.x), 端口 2216

### 问题发现

v81 部署后，APP 启动 ~10 秒后 UI 冻结（heartbeat 停在 #10，26.53s）。进程最终被 watchdog 杀死。

**根因分析: CFRunLoopRunInMode 死锁**

1. trampoline 挂起 19 个线程（防止 svc exit），保留 8 个系统线程
2. dispatch_async 重定向到 CFRunLoopPerformBlock（保持 UI 响应）
3. 其中某个 block 内部调用 `dispatch_sync(someBackgroundQueue, ...)`
4. 该 queue 的 worker 线程已被挂起 → 永远等不到 → RunLoop 死锁
5. 日志特征: heartbeat 计数停止，无崩溃日志

### v82: hook dispatch_sync 内联执行

**策略**: hook `dispatch_sync`/`dispatch_sync_f`（MSHookFunction），当主线程处于 exit-blocked 状态且目标不是 main queue 时，直接在主线程内联执行 block。

**结果**: heartbeat 持续 2.68s（比 v81 的 9.88s 更短），66 次 sync inline。进程无崩溃日志直接退出。

**分析**: dispatch_sync 内联执行解决了死锁，但同时执行了 SDK 的 svc #0x80 exit 代码。SDK 将 exit 调用包装在 dispatch_sync block 中投递到 background queue，内联执行等于在主线程运行了杀进程代码。

### v83: shared cache 地址过滤 dispatch_sync

**策略**: 区分系统框架 block 和 SDK block。Block 的 invoke 函数指针在 shared cache（≥0x180000000）则内联执行，否则丢弃。

**结果**: heartbeat 持续 6.9s。sync_inline=16（系统 block），sync_drop=8（SDK block 丢弃）。进程仍死亡。

**分析**: 进步明显，sync_drop=8 说明拦截了 8 个 SDK sync block。但杀手不是 dispatch_sync——redir 计数在死亡前已停止增长，说明进程被 CFRunLoop timer 回调或其他非 dispatch 机制杀死。

### v84: 扩展过滤到 dispatch_async

**策略**: 同样的 shared cache 地址过滤应用到 dispatch_async/dispatch_async_f 重定向。SDK async block 直接丢弃。

**结果**: heartbeat 持续 8.34s。redir=350（vs v83 的 644），async_drop=4，sync_drop=8。进程仍死亡，无崩溃日志。

**分析**: async_drop=4 说明拦截了 4 个 SDK async block。redir 减少到 350。但进程仍在 ~25s 后死亡。redir 在 heartbeat #9 和 #10 之间没有变化——杀手不是 dispatch block，而是 **CFRunLoop 定时器回调**。SDK 在 exit 之前（启动阶段 16s 内）注册了定时器到主 RunLoop，该定时器在 ~25s 触发，执行 svc #0x80。

### v85: svc 二进制补丁（失败）

**策略**: 扫描 APP/SDK 的 `__TEXT,__text` 段，找到 `mov x16, #1; svc #0x80`（exit syscall）模式，用 NOP 替换。使用 `vm_protect(VM_PROT_COPY)` 修改代码页。

**结果**: 找到并补丁了 1 条指令。但 APP 启动后立即闪退（0.82s）。

**分析**: 两种可能原因:
1. SDK 有代码完整性校验（tamper detection），检测到自身指令被修改后触发保护机制
2. rootless 越狱（Dopamine）的代码签名验证仍对主二进制有效，修改 __TEXT 页触发 CS 验证失败

**结论**: 二进制补丁方案在当前环境不可行。已回退。

### 当前稳定代码: v85（回退 svc patch，保留 dispatch 过滤）

保留的改进:
- dispatch_sync/sync_f: hook + shared cache 过滤（inline 系统 block，drop SDK block）
- dispatch_async/async_f: shared cache 过滤（redirect 系统 block，drop SDK block）
- heartbeat 日志包含 redir / async_drop / sync_inline / sync_drop 计数

### 待解决: CFRunLoop 定时器退出炸弹

已确认杀手是 SDK 在启动阶段注册的 CFRunLoop 定时器/NSTimer，在 ~25s 后触发 svc #0x80。

**候选方案**:
1. **hook CFRunLoopAddTimer**: 记录所有添加到主 RunLoop 的定时器，trampoline 时 invalidate 所有 pre-exit 定时器
2. **hook NSTimer scheduledTimer...**: 拦截并阻止 SDK 的 NSTimer 创建
3. **独立 patrol 线程 + watchdog**: 将 patrol 从 CFRunLoop timer 移到独立线程，增加 watchdog 检测主线程死亡并恢复
4. **自定义 RunLoop mode**: 只运行我们注册的 timer/source，不执行 SDK 的

**推荐**: 方案 1（hook CFRunLoopAddTimer），最精准且对 UIKit 影响最小

---

## Round 10: CFRunLoopAddTimer hook + exit() 存活策略 (v86-v88)

核心思路：从 Round 9 的推荐方案出发，hook CFRunLoopAddTimer 跟踪所有注册到主 RunLoop 的定时器，在 exit() 被调用时批量 invalidate。

### v86: 栈切换 + 定时器清扫

**策略**: 
1. MSHookFunction hook CFRunLoopAddTimer（ctor 阶段立即安装，先于 SDK 注册定时器）
2. hooked_exit 中: suspend 非关键线程 → invalidate 所有 pre-exit 定时器 → 栈切换到 mmap 分配的 1MB 栈 → 在新栈上泵 CFRunLoopRunInMode

**结果**: 定时器清扫成功——invalidated 11 个 pre-exit 定时器，进程存活超过 25s（bypass 了 svc #0x80 定时器杀死）。但 UI 从未出现——watchdog 在 ~23s 杀死进程。

**分析**: 栈切换破坏了 UIKit 的启动栈状态。UIKit 依赖主线程原始栈上的上下文（CATransaction、UIApplication 初始化状态等），切换到新栈后这些上下文丢失。

### v87: 从 exit() 直接 return

**策略**: 不切换栈，直接从 hooked_exit return，让调用链回到 SDK → RunLoop。

**结果**: return 触发 `__stack_chk_fail` → 10 次 SIGSEGV → 跌入 crash recovery trampoline。UI 短暂出现但冻结，~12s 后进程死亡。

**分析**: `exit()` 是 `__attribute__((noreturn))`，编译器不保留 return 路径的栈状态。SDK 的调用方在 call exit() 后的栈帧已被优化掉，return 跳入垃圾指令。

### v88: RunLoop in-place pump

**策略**: 在 hooked_exit 内部直接泵 CFRunLoopRunInMode——不 return、不切换栈，让 exit() 永不返回同时继续处理 RunLoop 事件。

**结果**: 
- exit(0) 在 t=15.69s 被拦截 ✅
- 11 个定时器 invalidated ✅
- heartbeat 达到 #10（t=27.70s），进程存活 28s ✅
- 所有 dispatch/pthread 计数器 = 0（SDK 在 exit 后无活动）
- UI 从未渲染 ❌
- 进程在 ~28s 被杀（watchdog）

**分析**: 在 exit() 内部泵 RunLoop 创建了**嵌套 RunLoop**。外层 RunLoop（UIKit 的 RunLoop，从 UIApplicationMain 启动的）仍然卡在 `SDK code → exit() → hooked_exit()` 的调用链上。嵌套的 RunLoop 可以处理事件，但 UIKit 的渲染管线依赖外层 RunLoop 的正常迭代，嵌套调用无法触发渲染。

**Round 10 结论**: 三种 exit() 存活策略全部失败:
- 栈切换: 破坏 UIKit 状态
- 直接 return: noreturn 导致栈损坏
- 嵌套 RunLoop: UI 无法渲染

---

## Round 11: longjmp 逃逸 (v89-v92)

核心突破：不在 exit() 内部存活，而是用 setjmp/longjmp 跳回 exit() 调用之前的 RunLoop 入口点。

### v89: longjmp 基础实现

**策略**:
1. MSHookFunction hook CFRunLoopRunSpecific（CF RunLoop 的底层入口）
2. hooked_CFRunLoopRunSpecific: 在主线程首次调用时 setjmp → 调用 orig
3. hooked_exit: longjmp 回到 setjmp 点 → invalidate 定时器 → 重新调用 orig_CFRunLoopRunSpecific
4. RunLoop 从"干净"的入口重新进入，SDK 的调用栈被完全丢弃

**结果**:
- exit(0) 在 t=15.55s 被拦截 ✅
- longjmp 成功回到 RunLoop recovery point ✅
- 64 tracked timers 中 5 个 invalidated ✅
- 进程在 ~20s 死亡（watchdog），UI 冻结

**分析**: longjmp 本身成功了，但 UI 仍然冻结。可能原因: (1) longjmp 后 dispatch hook 的 g_exit_blocked 被后续 exit 调用设为 1，冻结了 dispatch 通道; (2) CF RunLoop 内部状态在 longjmp 跨越定时器回调时被破坏。

### v90: 移除 g_exit_blocked + 线程状态诊断

**策略**: hooked_exit 中不设置 g_exit_blocked（避免误触发 dispatch 阻断），recovery 后扫描并恢复所有线程状态。

**结果**:
- exit(0) 在 t=10.69s 被拦截
- **29 threads total, 0 suspended, 29 running** — 所有线程正常
- 进程仍死亡，UI 冻结

### v91: 已知参数恢复

**策略**: longjmp 后 ARM64 参数寄存器(x0-x7)被破坏（setjmp 不保存非 callee-saved 寄存器），原始 CFRunLoopRunSpecific 参数丢失。recovery 后使用已知参数 `orig_CFRunLoopRunSpecific(CFRunLoopGetMain(), kCFRunLoopDefaultMode, 1e10, false)` 重新进入。

**结果**: 同 v90——recovery 成功但 UI 冻结，进程被杀。

**分析**: 参数损坏可能不是主因。更根本的问题是 longjmp 跨越了 CoreFoundation RunLoop 的内部状态边界:
- `__CFRunLoopDoTimers` → `timer_callback` → `exit()` 路径中，CF 内部维护了"正在触发的定时器"等状态
- longjmp 跳过了这些状态的清理，RunLoop 重入后可能处于不一致状态
- 表现为：RunLoop 在跑但无法正常处理 UI 事件

### v92: 预防性定时器拦截

**策略**: 在 hooked_CFRunLoopAddTimer 中检查定时器属性，拦截可疑的 SDK 杀死定时器:
- interval == 0（一次性）
- 延迟 > 5s 且 < 60s
- 直接不调用 orig（定时器不注册到 RunLoop）

**结果**:
- t=0.13: 拦截 one-shot delay=35.0s ✅
- t=3.42: 拦截 one-shot delay=15.0s ✅
- **exit(0) 仍在 t=15.64 被调用** ❌

**分析**: SDK 使用**两种**延时机制:
1. CFRunLoopTimer → 我们可以拦截 ✅
2. GCD dispatch timer (dispatch_after) → 不经过 CFRunLoopAddTimer，我们无法拦截 ❌

exit() 在 15.64s 来自 dispatch_after 投递的 block。

**Round 11 结论**: longjmp 机制可靠地捕获 exit()，但 CF RunLoop 内部状态被 longjmp 打断，UI 无法恢复。预防性定时器拦截有效但不完整（只能拦截 CFRunLoop 路径，不能拦截 GCD 路径）。

---

## Round 12: 检测绕过优化 + SDK 识别 (v93-v95)

核心转变：从"如何在 exit() 后存活"转向"如何让检测本身失败，使 exit() 不被调用"。

### SDK 识别: MbapMPaaS (蚂蚁金服 mPaaS)

v94 在 UIAlertController hook 中添加了调用栈日志，关键发现:

```
BT[1]  MbapMPaaS + 9292048    ← 创建越狱 alert 的函数
BT[13] MbapMPaaS + 2911556    ← SDK 包装了 UIApplicationMain
BT[14] dyld start + 2528
```

**MbapMPaaS 是蚂蚁金服的 mPaaS（Mobile Platform as a Service）框架**，完整包装了 APP 生命周期:
- SDK 的代码调用 UIApplicationMain（不是 APP 的 main()）
- SDK 控制何时/是否加载主 UI
- 检测失败 → 不加载主 UI + 显示 alert + 延时 exit()

### v93: ObjC hooks 移到 ctor

**策略**: 将 hookIOSSecuritySuite / hookABCJailbreakMethods / hookAuthorityJailBreakFlag / hookShowJailBrokenAlert 从延迟块移到 ctor，在 SDK 检测之前就 hook 掉 isJailbroken 等方法。

**结果**: Alert **仍然出现**在 t=0.82。所有 ObjC hooks 在 t=0.07-0.38 安装，但检测仍成功。

**分析**: ObjC 方法 hook 生效了（t=0.07-0.38），但 fishhooks（stat/access 等）在 t=0.62 才安装。**ObjC 扫描（0.3s+）期间文件检测 hooks 未就位**，SDK 趁此窗口完成了文件检测。

### v94: 调用栈诊断

**策略**: 在 UIAlertController hook 中用 `[NSThread callStackSymbols]` 打印完整调用栈。

**结果**: 成功获取调用栈（见上方 SDK 识别部分）。确认 alert 由 MbapMPaaS 框架通过 dispatch_async 投递到主队列。

### v95: fishhooks-first 排序

**策略**: 将 build_dyld_map + rebind_symbols（文件/dyld/sysctl hooks）移到 ctor 最前面，在 ObjC 类扫描之前安装。

**结果**:
- fishhooks 在 t=0.02 安装 ✅
- ObjC hooks 在 t=0.08-0.38 安装
- **没有越狱 alert!** ✅（文件检测被拦截）
- 但 exit(0) **仍在 t=10.90 被调用** ❌
- 11 个定时器 invalidated
- 进程死亡，UI 冻结

**分析**: 文件检测成功绕过（无 alert），但 SDK 仍然调用了 exit()。这表明存在**第二条检测路径**:
- 可能是 **hook 完整性检查**（FishHookChecker 检测 GOT 修改）
- 可能是 **环境检测**（检测 DYLD_INSERT_LIBRARIES 或其他越狱痕迹）
- 可能是 **内存扫描**（检测 MSHookFunction 的 trampoline 指令）
- 这条路径通过 GCD dispatch_after（非 CFRunLoopTimer）触发 exit()，无 alert

**Round 12 结论**: 
1. SDK 确认为 MbapMPaaS（蚂蚁金服 mPaaS），控制整个 APP 生命周期
2. fishhooks-first 排序成功绕过了文件检测层（无 alert）
3. 第二条检测路径独立于文件检测，可能是 hook/内存完整性检查
4. 两个独立杀死通道: CFRunLoopTimer（可拦截）和 GCD dispatch timer（未拦截）

---

## 当前状态: v95

### 已解决
- 文件系统检测绕过 ✅（fishhooks-first 排序）
- ObjC 方法检测绕过 ✅（10+ classes hooked）
- CFRunLoopTimer 杀死定时器拦截 ✅（hooked_CFRunLoopAddTimer 过滤 one-shot delay>5s）
- exit() 捕获 ✅（longjmp 回到 CFRunLoopRunSpecific）

### 未解决
1. **第二条检测路径**: SDK 在文件检测通过后仍触发 exit()，可能是 hook 完整性检查
2. **GCD dispatch timer 杀死**: exit() 通过 dispatch_after 触发，不走 CFRunLoopAddTimer
3. **longjmp 后 UI 恢复**: CF RunLoop 内部状态被 longjmp 打断，UI 无法正常渲染
4. **SDK 生命周期控制**: MbapMPaaS 包装 UIApplicationMain，检测成功后不启动主 UI

### 候选方案

1. **绕过 hook 检测**: 用 MSHookFunction（内联 hook，不修改 GOT）替代部分 fishhook 调用，使 FishHookChecker 检测不到
2. **hook dispatch_after**: 拦截 SDK 通过 GCD 投递的延时 exit() block
3. **直接 hook MbapMPaaS 检测函数**: 根据 backtrace 偏移量找到检测入口，MSHookFunction 使其返回 "clean"
4. **hook SDK 的 ctor**: 使用 `_dyld_register_func_for_add_image` 在 SDK dylib 加载时立即 hook 其 ctor 内的检测逻辑

---

## 第 13 轮（续）: 2215 设备实测 —— 定位退出源头 + 源头 patch 失败于完整性校验（2026-08-20）

### 基线复现（v0.1.0-116, drain-level longjmp 版）
- 设备: iPhone 13 Pro / iOS 15.4.1 / 端口 2215。工具: simtouch 自动化截图 + tap。
- ABC 11.1.0 **存活 >3 分钟**、UI 完整渲染（登录页/首页动画在跑），DIAG 显示 drains 稳定 ~62 次/秒、无 exit 复发、无 "逐渐降级"。
- **但触摸不可交互**（用户实测: 点登录页返回键后整个 App 不再响应点击，动画仍在）。
- 根因: T+16.13s 主线程 `exit(0)` 被 drain-level longjmp 中和，但 longjmp 从 `_dispatch_main_queue_callback_4CF` 中途跳出，破坏了主 RunLoop 的事件投递结构 —— drain pump 能让定时器/动画类 block 继续跑（drains 在涨），但新触摸事件无法通过被破坏的 RunLoop 投递。**证实文档记载的 v89-92 "longjmp 后 UI 冻结" 教训: drain-level 只是把破坏点下移，未根治。**

### 退出源头精确定位（backtrace + capstone）
- 给 `hooked_exit` 加主线程完整 backtrace。抓到那次致命 exit 的调用链:
  ```
  dyld start → main → UIApplicationMain → GSEventRunModal → CFRunLoopRunSpecific
    → _dispatch_main_queue_callback_4CF → libdispatch → MbapMPaaS+0x8db264 → hooked_exit
  ```
  即 **SDK 通过 dispatch_async 往主队列投递的检测 block，命中越狱后直接 exit(0)**（不是定时器，走 GCD 主队列）。
- 反汇编 `MbapMPaaS+0x8db254` 附近，判定结构:
  ```
  0x8db254: cmp  w24, #3        ; 检测状态 == 3 (风险/越狱)
  0x8db258: b.ne #0x8db1bc      ; 否 → 正常路径 (原始 21fbff54 = b.ne)
  0x8db25c: mov  w0, #0
  0x8db260: bl   _exit          ; 是 → exit(0)  ← 破坏 RunLoop 的源头
  0x8db264: bl   ___stack_chk_fail
  ```
  经 LIEF 解析 GOT 确认: `0x1049f9234`→`_exit`，`0x1049f84cc`→`___stack_chk_fail`，`0x1049fa248`→`_objc_release`。`0x8db1bc`（b.ne 目标）是无 exit 的正常继续路径。

### 源头 patch 尝试与失败（关键负面结果）
- 方案: 运行时把 `0x8db258` 的 `b.ne #0x8db1bc` patch 成无条件 `b #0x8db1bc`（`21fbff54`→`d9ffff17`），标准 W^X 流程（vm_protect RW+COPY → 写 → 恢复 RX → sys_icache_invalidate），带原始指令校验。
- 结果: patch **写入成功**（日志确认 `b.ne -> b`），且**这次启动全程无 EXIT blocked、无 DRAIN ESCAPE**（exit 确实没被调用，源头阻断机制上有效）。
- **但进程约 T+0.58s 崩溃**: crash log = **SIGILL (Illegal instruction: 4)**，faulting thread 0 = `libobjc lookUpImpOrForward` ← `_objc_msgSend_uncached` ← `MbapMPaaS+0x2fd9570`，经 `dispatch_once_callout` 初始化路径。崩溃点是正常 objc_msgSend（与 patch 的 0x8db258 无直接控制流关联）。
- **定性: ABC SDK 存在 `__text` 段代码完整性校验**。对主 binary 任何运行时代码修改都会被发现，触发 objc 层 SIGILL。与 **round 13 (v85) patch svc 失败 0.82s 崩溃同源**（时间量级一致）。
- **对比 lianjiabypass**: JGBSDK 无此完整性校验，`__text` patch（29 处 svc→ret）成功。**ABC 不适用 __text patch 路线**。已禁用 `patch_detection_exit_branch()`，保留代码供参考。

### 新的确定结论
- 破坏 UI 交互的**唯一源头**已精确定位: `MbapMPaaS+0x8db260` 的 `exit(0)`，由主队列 dispatch block 中 `cmp w24,#3` 判定触发。
- 源头阻断的正确方向不是改主 binary 代码，而是: **(a) 让 w24 != 3**（hook 计算 w24 的上游检测函数，使其返回非风险值）；或 **(b) 拦截该 dispatch block 本身不让它上主队列执行**（backtrace frame 有 block 函数地址，可在 dispatch_async hook 里按 caller 过滤）；或 **(c) hook 那个包含 0x8db254 判定的函数入口整体 return**（需先定位函数入口，非返回地址）。
- 完整性校验的存在意味着: 所有绕过必须靠**函数级 hook（MSHookFunction trampoline 在函数入口，改的是执行流不是校验覆盖的指令字节）或数据/状态干预**，不能改 `__text` 指令。

### 下一步
- 优先方案 (b): 该 exit block 的函数入口地址在 backtrace 里（`MbapMPaaS` frame，dispatch 投递的 block）。在已有的 `dispatch_after`/`dispatch_async` hook 基础上，按 block 函数所属地址范围过滤掉这个检测 block，使其根本不上主队列。风险: 需确认丢弃该 block 不影响正常初始化。
- 备选 (a): 反汇编 `0x8db254` 所在函数入口，回溯 w24 的来源（哪个检测函数的返回值），MSHookFunction 该函数使其返回 clean。


