# ICBC Bypass 分析记录

## 目标

绕过工商银行 (com.icbc.iphoneclient) 的越狱检测，使 app 在越狱设备上正常运行。

## 环境

- 设备: iPhone (Dopamine, rootless, ElleKit)
- App 版本: 3.0.80
- Bundle ID: com.icbc.iphoneclient
- 主 Binary: ICBCBankTest (arm64, FairPlay encrypted, ~100MB)
- App 路径: /private/var/containers/Bundle/Application/0DA210C4-B60C-4E3A-983E-26FF249B23E2/ICBCBankTest.app

## 已确认的事实

### 1. 检测行为特征
- 启动后弹窗提示检测到越狱，要求退出
- 通过 UI 层响应（非 raw syscall），说明是 ObjC/Swift 层检测+响应
- 存在 `showJailBrokenAlertIfNeeded` 方法作为弹窗入口
- 存在 `kUPWHomePageJailBrokenToastNotAgainKey`，暗示有"不再提示"逻辑

### 2. 检测框架：SecureUtilityPlus
- 静态链接到主 binary 中（不是独立 framework）
- 是 IOSSecuritySuite 的定制/增强版本
- 包含以下检测器类：
  - `JailbreakChecker` — 越狱检测（9 个子检测 isJailBreak1~9）
  - `IOSSecuritySuite` — 标准 amIJailbroken 系列
  - `MSHookFunctionChecker` — 检测 MSHookFunction
  - `FishHookChecker` — 检测 fishhook
  - `RuntimeHookChecker` — 运行时 hook 检测
  - `ReverseEngineeringToolsChecker` — 逆向工具检测(frida 等)
  - `DebuggerChecker` — 调试器检测
  - `EmulatorChecker` — 模拟器检测
  - `IntegrityChecker` — 完整性校验
  - `FileChecker` — 文件存在性检测
  - `ProxyChecker` — 代理检测
  - `ModesChecker` — 模式检测
  - `CheckAllCall` — 聚合调用入口

### 3. 已知检测点（从 strings 提取）
- 标准越狱文件路径：/Applications/Cydia.app, /Library/MobileSubstrate, /var/lib/cydia 等
- URL scheme: cydia://
- frida: /usr/sbin/frida-server, com.apple.uikit.viewservice.frida
- substrate: /usr/lib/libsubstrate.dylib, /Library/MobileSubstrate/DynamicLibraries
- dpkg: /var/lib/dpkg/info/mobilesubstrate.md5sums

### 4. App 内部 jailbreak 状态传播
- 多个属性：isJailBreak, isJailbreak, jailbroken, jailbreaking
- 方法：phoneIsJailBreak, MaxentJailBroken, isJailBrokenOne/Three/Four/Five
- p_isJailBreak1, p_isJailBreak2
- authorityWithJailBreakFlag:
- carrier 上报字段包含 os.jailbreak=%d

### 5. Frameworks（非检测相关）
- AVProVideo, DeepNetV2, FinApplet, IMSecurity(证书相关), STDigitalHumanPlayer, WClientSDK, ZegoLiveRoom, ZegoQueue

---

## 初步假设（轮次 1）

**假设**: ICBC 使用 SecureUtilityPlus（IOSSecuritySuite 增强版）进行越狱检测，检测结果通过 ObjC/Swift 属性传播，最终由 `showJailBrokenAlertIfNeeded` 显示弹窗。通过 hook 检测器返回值 + 阻止弹窗显示，可以绕过检测。

**验证方法**: 编写 tweak 覆盖以下层面：
1. Hook SecureUtilityPlus 的所有 Checker 类，使检测结果返回"安全"
2. Hook `showJailBrokenAlertIfNeeded` 为 no-op
3. Hook 标准文件路径/dyld/环境变量检测
4. 如果有 anti-hook 检测（MSHookFunctionChecker, FishHookChecker），需要让它们也返回"未检测到 hook"

**预期结果**: 弹窗不再出现，App 正常启动

---

## 与 HSBC 的关键区别

| 对比项 | HSBC (OneSpan) | ICBC (SecureUtilityPlus) |
|--------|---------------|------------------------|
| 检测引擎 | 主 binary 内 C/C++ 静态库 | Swift 类，ObjC 可 hook |
| 退出机制 | raw syscall (不可拦截) | UI 弹窗 + 可能的 exit |
| 检测层级 | 极低层(内存直读) | ObjC/Swift 层 |
| 对抗难度 | 极高 | 中等（与 mybankbypass 类似） |
| delegate | 不触发 | 通过属性/方法传播 |

---

## 尝试记录

### 尝试 1: 全层 hook (v1, 0.1.0-1)
- **假设**: hook SecureUtilityPlus 全部 Checker + 弹窗方法 + 文件/dyld/exit 全覆盖可绕过
- **验证方法**: 完整 tweak 安装后启动 app
- **观察**: 
  - Watchdog 超时 (0x8BADF00D)，app 20 秒后被系统杀死
  - Crash stack: `hookShowJailBrokenAlert` → `class_getInstanceMethod` → `WAITING_FOR_ANOTHER_THREAD_TO_FINISH_CALLING_+initialize`
  - 原因：`%ctor` 中 `objc_copyClassList` 遍历所有类并调用 `class_getInstanceMethod`，触发了 ObjC 运行时死锁
- **推论**: 
  - ❌ 不能在 constructor 阶段遍历全部类列表调用 runtime API
  - ✅ tweak 确认注入成功
  - 需要把全类遍历 hook 延迟到 main queue

### 尝试 2: 延迟全类 hook 到 dispatch_async (v2, 0.1.0-2)
- **假设**: 将 `hookICBCJailbreakMethods`/`hookShowJailBrokenAlert`/`hookAuthorityJailBreakFlag` 延迟到 `dispatch_async(main_queue)` 可避免死锁
- **验证方法**: 安装后启动
- **观察**: 
  - 弹窗消失了！ ✅
  - 但 app 在 ~1 秒后闪退
  - Crash: SIGSEGV, `KERN_INVALID_ADDRESS at 0xb5a06000`
  - Crash stack: `_platform_strstr` → `is_jb_dylib` → `hooked_dyld_get_image_name` → app 代码
  - `orig_dyld_get_image_name()` 对某些 index 返回了 0xb5a06000（32 位无效指针）
- **推论**: 
  - ✅ SecureUtilityPlus hook 有效——弹窗不再出现
  - ❌ dyld hook 实现不安全：每次调用重新遍历，且不处理无效指针
  - 需要改用预构建 map + 指针有效性校验

### 尝试 3: Map 式 dyld hook + 指针校验 (v3-v4, 0.1.0-3~4)
- **假设**: 用 dispatch_once 预构建索引 map + 跳过 <4GB 的指针可修复 dyld crash
- **验证方法**: 安装后启动
- **观察**: 
  - 仍然瞬间死亡（进程 t=0s 后即不存在）
  - Crash: 同一地址 0xb5a06000, 但这次 faulting thread 是 dispatch worker（不是 dyld hook 线程）
  - Stack: `[image15] +0xb5a06000` → `_dispatch_client_callout` → 普通 dispatch 流程
  - 这意味着有代码在 dispatch queue 中试图 JUMP 到 0xb5a06000
- **推论**: 
  - 0xb5a06000 很可能是 SecureUtilityPlus 的 anti-tampering 机制
  - 当 MSHookFunctionChecker/IntegrityChecker 检测到方法被替换后，故意设置一个无效回调地址
  - 后续 dispatch block 执行时跳到该地址导致 crash
  - 我们在 v1-v4 中 `hookSecureUtilityPlusClass` 替换了所有 BOOL 返回的方法（太激进）
  - 可能破坏了非安全相关的方法，或者触发了完整性校验
  - **下一步**: 只替换名字中明确包含安全语义的方法，减少对 checker 类内部非检测方法的干扰

### 尝试 4: 精确匹配 selector 名 + dispatch_once map (v5, 0.1.0-5)
- **假设**: 只替换 selector 名包含 jailb/check/detect/hook/debug/inject/tamper/root/emulat/reverse/frida/proxy/integrity 的方法，不动其他内部方法，可避免触发完整性校验
- **验证方法**: 安装后启动，观察进程存活
- **观察**: 同一 crash (0xb5a06000, dispatch worker thread)
- **推论**: 问题不在 method_setImplementation 的激进程度

### 尝试 5: 纯 C 层 hook，完全不修改 SecureUtilityPlus 方法 (v6, 0.1.0-6)
- **假设**: 如果不动 SecureUtilityPlus 任何方法实现，只靠 C 层 hook 隐藏越狱痕迹使检测自然返回"安全"
- **验证方法**: 移除所有 hookSecureUtilityPlus/hookIOSSecuritySuite/hookICBCJailbreakMethods 调用，只保留 MSHookFunction + Logos %hook
- **观察**: 
  - 仍然 crash，同一地址 0xb5a06000
  - 同样是 dispatch worker thread 跳转到无效地址
  - crash 与是否修改 SecureUtilityPlus 方法无关
- **推论**: 
  - ⚠️ **关键发现**: `MSHookFunctionChecker` 检测的是 C 函数 prologue 的 trampoline（MSHookFunction 覆盖函数前几字节），而非 ObjC method 替换
  - 即使不碰 SecureUtilityPlus 方法，只要用 MSHookFunction hook 了 stat/access/open 等系统函数，MSHookFunctionChecker 就检测到 hook 存在
  - 检测后设置无效回调 0xb5a06000，通过 dispatch queue 触发 crash
  - **下一步**: 测试完全不用 MSHookFunction（空 tweak，只有 %ctor+%init），确认是 MSHookFunction trampoline 触发检测

---

## 已确认的关键约束

1. ✅ SecureUtilityPlus 方法 hook（method_setImplementation）可消除弹窗
2. ❌ MSHookFunction 对 C 函数的 hook 会被 MSHookFunctionChecker 检测到
3. ❌ 检测后 app 通过 dispatch queue 执行跳到 0xb5a06000 的无效 block 来 crash（非 exit/abort 路径）
4. 需要找到一种不被 MSHookFunctionChecker 检测到的 hook 方式

### 尝试 6: 空 tweak 对照实验 (v7, 0.1.0-7)
- **假设**: 只有 %ctor+%init（Logos swizzle NSFileManager/UIApplication/NSProcessInfo），无任何 MSHookFunction 调用，app 不会 crash，正常显示弹窗
- **验证方法**: 移除所有 MSHookFunction 调用，只保留 Logos %hook
- **观察**: 
  - ✅ 进程持续存活！t=3s ALIVE, t=10s ALIVE
  - App 应显示越狱弹窗（Logos swizzle 的 NSFileManager/UIApplication/NSProcessInfo 仍在，但不触发 MSHookFunctionChecker）
- **推论**: 
  - ✅ **确认**: MSHookFunction 是触发 MSHookFunctionChecker 的原因
  - ✅ Logos %hook（method swizzle）不被检测
  - ✅ ObjC runtime API (method_setImplementation) 也不被检测（v2 弹窗消失说明 SecureUtilityPlus 方法替换生效过）
  - **结论**: 可以安全使用 Logos %hook + method_setImplementation，但不能使用 MSHookFunction
  - **下一步**: 重新启用 SecureUtilityPlus 方法替换（消除弹窗），但完全不使用 MSHookFunction。C 层检测通过纯 ObjC 层结果钳制来应对。

### 尝试 7: 纯 ObjC hook — Logos + method_setImplementation (v8, 0.1.0-8)
- **假设**: 只用 dispatch_async 延迟执行 hookSecureUtilityPlus/hookIOSSecuritySuite/hookICBCJailbreakMethods/hookShowJailBrokenAlert/hookAuthorityJailBreakFlag，完全不用 MSHookFunction，可以同时消除弹窗且不触发 anti-tampering
- **验证方法**: 安装后启动，观察进程存活 + 弹窗状态
- **观察**: 
  - ✅ 进程持续存活！t=4s ALIVE, t=15s ALIVE
  - 无 crash
  - 弹窗状态：待用户确认
- **推论**: 待补充（等用户确认 UI 状态）

### 尝试 8: 早期 SecureUtilityPlus hook + UIAlertController present 拦截 (v9-v10, 0.1.0-9~10)
- **假设**: 
  - 在 %ctor 直接执行 hookSecureUtilityPlus()（只 objc_getClass 查特定类，不遍历全类列表，不会死锁）
  - 用 Logos %hook UIAlertController 标记越狱相关弹窗，在 presentViewController 时拦截
  - 不使用 MSHookFunction
- **验证方法**: 安装后启动，观察进程存活 + 弹窗
- **观察**: 
  - v9: SIGABRT crash — 从 alertControllerWithTitle 返回 nil 导致后续代码 unhandled exception
  - v10: 改为标记+拦截 present 方式，进程 t=5s ALIVE, t=20s ALIVE ✅
  - 弹窗状态：待用户确认
- **推论**: 
  - ✅ hookSecureUtilityPlus() 在 %ctor 中直接执行是安全的（不涉及全类遍历）
  - ✅ 拦截 presentViewController 比返回 nil 更安全
  - 如果弹窗消失且 app 可交互 → 基本绕过成功
  - 如果弹窗消失但 app 不可交互 → 可能有额外的业务层冻结逻辑

### 尝试 9: 全部 ObjC hook 同步放入 ctor + method-list 枚举 (v11, 0.1.0-11)
- **假设**: 将 hookICBCJailbreakMethods/hookShowJailBrokenAlert/hookAuthorityJailBreakFlag 从 dispatch_async 提前到 %ctor 同步执行（改用 class_copyMethodList 枚举避免死锁），可以在业务状态机启动前完成状态钳制，解决"卡开屏页"问题
- **验证方法**: 安装后启动，观察能否过开屏页进入功能页
- **观察**: 
  - ✅ 进程持续存活（5s, 15s, 长时间无 crash）
  - ✅ 过了开屏页（之前 v10 卡在这里）
  - ❌ 卡死在 welcome 页（APP 更新后介绍新功能的引导页），无法继续
  - 无弹窗出现
- **推论**: 
  - ✅ 把 hook 提前到 ctor 确实解决了"卡开屏页"问题（说明之前是 hook 太晚，业务状态已被冻结）
  - ❌ welcome 页卡死是新问题
  - 可能原因：UIAlertController hook 中 "安全" 关键字过于宽泛，误拦截了 welcome 页需要的合法弹窗（如隐私政策/权限请求/用户协议确认），导致流程无法推进
  - **下一步**: 缩窄 UIAlertController 拦截关键字——只拦截明确的越狱弹窗（"越狱"/"jailbreak"），移除 "安全" 这个过宽的匹配

### 尝试 10: 移除 "安全" 关键字，只保留 "越狱/jailbreak" (v12, 0.1.0-12)
- **假设**: "安全" 关键字太宽泛，误拦了 welcome 页的合法弹窗。只保留 "越狱"/"jailbreak" 可以让合法弹窗通过
- **验证方法**: 安装后启动，观察弹窗是否回来、welcome 页是否可交互
- **观察**: 
  - ✅ 进程存活
  - ❌ 越狱弹窗重新出现
- **推论**: 
  - 越狱检测弹窗的 title/message 不包含 "越狱"/"jailbreak" 字样，而是用了 "安全" 相关措辞
  - welcome 页问题与 alert 过滤无关——弹窗回来了但用户能看到 welcome 页本身
  - 需要找到更精确的关键字组合来区分越狱弹窗和合法弹窗

### 尝试 11: 组合条件拦截（"安全" + 风险/检测/设备等）(v13, 0.1.0-13)
- **假设**: 越狱弹窗用 "安全" 做标题，message 含 "风险"/"检测"/"设备" 等词；合法弹窗 message 含 "隐私"/"协议" 等不同内容。组合判断可区分两者
- **验证方法**: 安装后启动，观察越狱弹窗是否消失、welcome 页是否可交互
- **观察**: 
  - ✅ 进程存活（4s, 16s 确认）
  - ✅ 越狱弹窗没有出现
  - ❌ 依然卡死在 welcome 页
- **推论**: 
  - ⚠️ **关键发现**: welcome 页卡死与 UIAlertController 过滤无关
  - v12 弹窗回来时也卡 welcome 页；v13 弹窗被拦时也卡 welcome 页
  - 说明 welcome 页的卡死是独立问题——不是因为某个弹窗被误拦
  - 可能原因：
    1. welcome 页自身有越狱状态检查，阻止了按钮交互
    2. 某个被我们 no-op 的方法（如 authorityWithJailBreakFlag:）的回调本来会推进状态机
    3. App 向服务器上报了越狱状态，服务器端阻止了后续流程
    4. welcome 页需要加载网络内容，但安全相关请求失败
  - **下一步**: 先诊断 welcome 页的 VC 结构和状态

### 尝试 12: 自动触发 alert action handler (v14, 0.1.0-14)
- **假设**: 弹窗被阻断后 app 状态机等待 action 回调。触发 handler 可模拟用户确认并推进流程
- **验证方法**: 在 presentViewController 拦截时用 KVC 取 handler 并调用
- **观察**: 
  - ❌ 进程瞬间死亡（<2s）
  - Crash: EXC_BREAKPOINT/SIGTRAP
  - 无新 crash log（可能是 handler 调了 exit() 导致未生成 report）
- **推论**: 
  - ✅ **确认**: 越狱弹窗的 action handler 内部调用 exit()/abort() 杀进程
  - ❌ 不能触发 handler
  - 由于没有 MSHookFunction（会触发 anti-tampering），无法 hook C 层 exit()
  - **下一步**: 回退 handler 触发。用 VC 层级 dump 诊断 welcome 页卡死的具体原因

### 尝试 13: present-then-dismiss 策略 (v17-v18, 0.1.0-17~18)
- **假设**: 主线程阻塞是因为代码在等 alert 被 dismiss 后才恢复交互。如果先 present 再立刻程序化 dismiss（不触发 action），等待条件就满足了
- **验证方法**: UIViewController presentViewController hook 中，对 jb_blocked alert 执行 %orig(vc, NO, completion) 然后 dispatch_async dismiss
- **观察**: 
  - ✅ 进程存活
  - ❌ welcome 页仍然在动画几秒后冻结
  - 用户描述："欢迎页动画正常动态，没看到弹窗，界面整个卡住"
  - 尝试用 dispatch_after 到 global queue 写诊断文件——文件也没生成
- **推论**: 
  - ❌ 冻结不是在等 alert dismiss
  - ⚠️ dispatch_after 到 global queue 也不触发，说明进程可能有更深层的阻塞（不仅是主线程）
  - welcome 页冻结是独立于 UIAlertController 的问题

### 尝试 14: authorityWithJailBreakFlag: 改为 pass-through (v19, 0.1.0-19)
- **假设**: `authorityWithJailBreakFlag:` 被 no-op 后，原本应执行的"安全通过"回调/状态切换没有发生。改为调用原始实现但 flag=NO 可恢复状态推进
- **验证方法**: 保存原始 IMP，hook 中调用 origIMP(self, sel, NO)
- **观察**: 
  - ✅ 进程存活
  - ❌ welcome 页仍冻结，与之前完全相同
- **推论**: 
  - ❌ 冻结与 `authorityWithJailBreakFlag:` 无关
  - 需要重新思考冻结的根因

### 尝试 15: 移除全类遍历 hook (v20, 0.1.0-20)
- **假设**: hookICBCJailbreakMethods/hookShowJailBrokenAlert 的全类遍历导致延迟死锁
- **验证方法**: 从 ctor 中移除这两个函数，只保留 SecureUtilityPlus + IOSSecuritySuite + authorityWithJailBreakFlag
- **观察**: ❌ welcome 页仍冻结，现象不变
- **推论**: 全类遍历不是冻结原因

### 尝试 16: 完全移除所有 runtime hook (v21, 0.1.0-21)
- **假设**: SecureUtilityPlus/IOSSecuritySuite 的 method_setImplementation 触发了某种完整性保护导致冻结
- **验证方法**: ctor 中只保留 %init + UserDefaults，不调用任何 hookXxx() 函数。仅有 Logos %hook（NSFileManager/UIApplication/UIAlertController/UIViewController/NSProcessInfo）
- **观察**: ❌ welcome 页仍冻结，与之前完全相同
- **推论**: 
  - ❌ 冻结与 SecureUtilityPlus hook 无关
  - 冻结是 app 自身的行为，不是我们的 hook 引起的

### 尝试 17: 移除 UIAlertController/UIViewController hook (v22, 0.1.0-22)
- **假设**: alert 的 present-then-dismiss 操作导致了冻结
- **验证方法**: 完全移除 UIAlertController 和 UIViewController 的 hook。只保留 NSFileManager/UIApplication/NSProcessInfo + UserDefaults
- **观察**: 
  - ✅ 弹窗正常弹出（越狱检测弹窗）
  - 弹窗是模态的，不点击不能操作后面的内容
  - ⚠️ **关键发现**: 即使不点击弹窗，保持等待，几秒后背景动画也冻住了
  - 用户之前的观察"动画正常然后冻住"与 alert hook 无关
- **推论**: 
  - ✅ **确认**: 主线程冻结是 APP 自身的第二道防线——独立于弹窗
  - 即使弹窗正常显示、没有被我们干扰，app 仍会在检测后主动冻结主线程
  - 这解释了为什么之前所有 alert 相关的修改都无法解决冻结问题
  - 冻结的触发源不是 ObjC 层——我们的 NSFileManager hook 没有覆盖 C 层
  - SecureUtilityPlus 内部用 C 函数（stat/access/open/lstat）直接检测越狱文件
  - C 层检测仍然返回"文件存在" → 触发主线程冻结
  - **根因**: 需要 hook C 层文件检测函数，但 MSHookFunction 会触发 anti-tampering
  - **解决方案**: 用 fishhook（GOT/PLT rebinding）代替 MSHookFunction。fishhook 不修改函数 prologue（只改 GOT 表指针），MSHookFunctionChecker 检测不到

---

## 当前状态

- 进程稳定 ✅
- 过了开屏页 ✅
- 弹窗已拦截 ✅（present-then-dismiss + handler 替换）
- **主线程冻结** ❌ — fishhook 拦截生效但冻结依旧

## 已确认的两道防线

1. **弹窗**：ObjC 层检测 → 显示 UIAlertController（action handler 调 exit）— 已解决
2. **主线程冻结**：检测仍触发，尽管 C 层 fishhook 在拦截 — 需要进一步诊断

---

## 尝试记录（续）

### 尝试 18: fishhook 覆盖全部 C 层函数 (v23, 0.1.0-23)
- **假设**: 用 fishhook（GOT rebinding）hook stat/lstat/access/open/fopen/realpath/readlink/statfs/statvfs/fork/getenv/sysctl/sysctlbyname/dlopen/dladdr/_dyld_* 系列，可隐藏越狱文件使 C 层检测返回安全
- **验证方法**: 安装后启动观察冻结是否消除
- **观察**: 
  - ✅ 进程存活（5s, 15s 确认）
  - ✅ 无 crash（MSHookFunctionChecker 未触发 — 确认 fishhook 不被检测）
  - ❌ 欢迎页动画仍然冻死，跳过按钮不可点击
  - 弹窗一闪而过（UIAlertController hook 生效）
- **推论**: 
  - ✅ fishhook 不触发 MSHookFunctionChecker（GOT rebinding 安全）
  - ❌ 冻结与 C 层文件 hook 覆盖面无关（或者检测用了 hook 无法覆盖的方式）
  - **下一步**: 对照实验——卸载 tweak，确认冻结是 app 原生行为

### 尝试 19: 对照实验——无 tweak (v23 卸载)
- **假设**: 卸载 tweak 后 app 正常显示弹窗但不冻结（即冻结是我们的 hook 引入的副作用）
- **验证方法**: dpkg -r 卸载后启动 app
- **观察**: 
  - ✅ 弹窗正常显示（标题"安全提示"，内容警告风险/隐私泄露，一个"确定"按钮点击退出）
  - ❌ 欢迎页同样冻死——即使没有 tweak 注入，动画也会在几秒后停止
- **推论**: 
  - ✅ **确认**: 冻结是 app 在越狱设备上的原生行为，不是 tweak 副作用
  - 弹窗 action handler 确认调用 exit（点击"确定"退出 app）
  - 冻结独立于 tweak 存在——在越狱设备上 app 自身就会冻住主线程

### 尝试 20: fishhook 诊断 + syscall hook (v24-v25, 0.1.0-24~25)
- **假设**: fishhook 回调可能没有被真正调用（GOT rebinding 失败或检测用了 inline SVC），需要日志确认；同时添加 syscall() hook 拦截直接系统调用
- **验证方法**: 在 hooked_stat/access 中写日志到沙箱 Documents/，添加 syscall hook 拦截 SYS_stat64/SYS_access/SYS_open
- **观察**: 
  - v24: 日志写 /tmp 失败（沙箱限制）
  - v25: 改用 NSHomeDirectory()/Documents/，日志成功生成
  - 日志内容关键发现：
    - `[INIT]` 确认 ctor 执行
    - 大量 `[HIT] access: /var/jb/usr/lib/TweakInject/*.plist` — ElleKit 注入框架自身的文件访问
    - `[HIT] stat: /private/preboot/.../dopamine-lsRKzc/procursus/usr/bin/ssh` — **检测代码使用真实路径**
    - `[HIT] syscall_access: /private/preboot/.../procursus/usr/bin/ssh` — **确认 app 使用 syscall() 调用**
    - `[HIT] stat: /private/preboot/.../procursus/private/var/lib/apt`
  - ❌ 冻结依旧发生
- **推论**: 
  - ✅ **fishhook 确实在工作**：stat/access/syscall hook 全部触发
  - ✅ **syscall() 被拦截**：app 确实调用 syscall(SYS_access, ...) 且被我们捕获
  - ✅ **路径被正确阻断**：is_jb_path 匹配 "procursus"/"dopamine" 子串
  - ❌ 尽管所有可 hook 路径被阻断，冻结仍然发生
  - 可能原因：
    1. 有更多检测路径超过日志限制（50条）未被记录
    2. opendir/readdir 目录枚举未被 hook
    3. 内联 `svc #0x80` 汇编直接发起系统调用，完全绕过 libc 和 syscall()
    4. 检测向量不是文件系统（如端口扫描、Mach 端口、vm_region 等）
  - **下一步**: 增加日志上限到 200，添加 opendir/readdir hook，添加 PASS-SUSPICIOUS 日志（记录通过但含可疑关键字的路径），确认是否还有遗漏路径

---

## 已确认的关键事实（更新）

1. ✅ fishhook（GOT rebinding）不触发 MSHookFunctionChecker
2. ✅ fishhook 成功拦截 stat/lstat/access/open/syscall/opendir 等 C 函数调用
3. ✅ app 确实使用 syscall() C 函数进行部分检测（非全部 inline asm）
4. ✅ 冻结是 app 原生越狱检测行为（无 tweak 也冻）
5. ✅ app 检测使用 Dopamine rootless 的真实解析路径（/private/preboot/.../procursus/...）
6. ✅ 所有 hookable 的文件系统调用均被拦截（零 PASS-SUSPICIOUS），但冻结仍触发
7. ✅ **确认 inline SVC** — 所有 GOT 级别的检测路径已被阻断，冻结必定来自 inline svc #0x80
8. ✅ **冻结机制已确认**: 三重攻击
   - `dispatch_semaphore_wait(DISPATCH_TIME_FOREVER)` 阻塞主线程
   - `[UIView setAnimationsEnabled:NO]` 循环调用禁用动画
   - `beginIgnoringInteractionEvents` 禁用触摸
9. ✅ 冻结代码从 `dispatch_once` 启动（crash stack 确认）
10. ✅ 阻断 semaphore/animation/interaction 三者后，主线程仍在紧密循环中消耗 100% CPU
11. ✅ dispatch_async 到 main queue 可以执行（watchdog 证明 main_responsive=1），但 runloop 不正常迭代
12. ❌ CFRunLoopRunInMode 从循环内部调用会导致黑屏或 watchdog 超时

## 冻结机制详细分析

从 crash log (v32) 和诊断日志确认的执行流：

```
dispatch_once (ICBCBankTest+79621056)
  → freeze_setup (ICBCBankTest+79621268)
    → freeze_loop (ICBCBankTest+79621952)
      → disable_func (ICBCBankTest+80153464)
        → dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER)  ← 永久阻塞主线程
```

同时循环调用：
- `[UIView setAnimationsEnabled:NO]` — 持续禁用动画
- `beginIgnoringInteractionEvents` — 持续禁用触摸

## 已尝试的冻结对抗策略

| 版本 | 策略 | 结果 |
|------|------|------|
| v28 | semaphore 直接返回 0 | 主线程响应但 UI 冻结（紧密循环吃 CPU） |
| v29 | + block setAnimationsEnabled:NO + beginIgnoring + unfreezer timer | 同上 |
| v30 | setAnimationsEnabled 内 runMode yield | 黑屏 |
| v31 | setAnimationsEnabled 内 CFRunLoopRunInMode + re-entrancy guard | 仍冻 |
| v32 | semaphore 内 CFRunLoopRunInMode(100ms) | watchdog kill (0x8BADF00D) |
| v33 | semaphore 内 CFRunLoopRunInMode(1ms, 每5次) | 黑屏 |

## 当前策略 (v34, 已测试 — 失败)

**思路转变**: 不再试图在循环内 yield 给 runloop。改为：
- 当检测到 freeze 模式（setAnimationsEnabled:NO 被调用 >50 次）后
- 在 dispatch_semaphore_wait 中用 `CFRunLoopRun()` **接管主线程**
- 先恢复 UI 状态（re-enable animations/interaction）
- 然后进入正常 runloop 运行，**永不返回**给 freeze 代码

### 尝试 21: CFRunLoopRun 接管（v34, 0.1.0-34）
- **假设**: freeze 循环在 dispatch_once 中用 semaphore_wait(FOREVER) 阻塞主线程，用 CFRunLoopRun() 替代可让主线程正常运行
- **验证方法**: g_freeze_indicator > 50 时触发 CFRunLoopRun()
- **观察**: 
  - 卡在启动页，然后 crash 退出
  - 日志: `[TAKEOVER] Freeze detected (indicator=52), entering CFRunLoopRun`
  - `[WATCHDOG] t=5s main_responsive=0`, `t=10s main_responsive=0`
  - 推测为 frontboard watchdog kill (0x8BADF00D)
- **推论**: 
  - ❌ CFRunLoopRun() 在启动初期（indicator 刚到 52 时）就触发了
  - 此时 app UI 初始化可能还未完成
  - CFRunLoopRun 进入后主线程无法完成后续初始化代码 → watchdog 超时
  - 需要用时间门控而非 indicator 计数

### 尝试 22: 时间门控的 CFRunLoopRun 接管 + 诊断 (v35-v36, 0.1.0-35~36)
- **假设**: 用 elapsed > 5.0 秒 + g_freeze_indicator > 5 作为 takeover 条件，确保 app 初始化完成后再接管
- **验证方法**: 安装后启动，添加 UI 状态 dump 诊断
- **观察**: 
  - ✅ 进程稳定存活
  - ✅ main_responsive=1（主线程响应）
  - ❌ 动画卡住，按钮不可用
  - ⚠️ **TAKEOVER 未触发** — dispatch_semaphore_wait(FOREVER) 在主线程上根本没被调用！
  - `freeze_indicator=292`（setAnimationsEnabled:NO 被调 292 次）
  - unfreezer 成功恢复了 `isIgnoring=0 animEnabled=1`
  - `beginIgnoringInteractionEvents` 只被调了 1 次
  - 存在两个 Window:
    - `ICBCMotionRecognizingWindow` level=0（主内容窗口，自定义类名）
    - `UIWindow` level=2000（alert 级别窗口，有 rootVC + 全屏 UITransitionView）
- **推论**: 
  - ❌ **之前对冻结机制的理解需要修正**
  - 冻结**不是**通过 `dispatch_semaphore_wait(FOREVER)` 阻塞主线程实现的
  - 主线程是活的（responsive=1），但 UI 不可交互
  - `setAnimationsEnabled:NO` 被调了 292 次，但我们的 hook 成功阻止了（animEnabled=1 in dump），动画仍然冻结说明动画冻结可能是 CALayer/CAAnimation 层面直接操作
  - **level=2000 的 UIWindow 是关键线索** — 可能是透明覆盖窗口拦截触摸
  - `ICBCMotionRecognizingWindow` 自定义类也可能在事件链中做过滤
  - 冻结可能是多层面的：
    1. 触摸不可用 → level=2000 的窗口拦截
    2. 动画冻结 → 直接 CALayer 暂停（speed=0）或移除 animation
  - **下一步**: 
    1. 隐藏/移除 level=2000 的窗口
    2. 检查 CALayer speed 是否被设为 0
    3. Hook `ICBCMotionRecognizingWindow` 的事件方法

---

## 已确认的关键事实（更新 2）

1. ✅ fishhook（GOT rebinding）不触发 MSHookFunctionChecker
2. ✅ 冻结是 app 原生越狱检测行为（无 tweak 也冻）
3. ✅ app 检测使用 Dopamine rootless 的真实解析路径
4. ✅ 所有 hookable 的文件系统调用均被拦截（零 PASS-SUSPICIOUS），但冻结仍触发
5. ✅ **确认 inline SVC** — 所有 GOT 级别的检测路径已被阻断，冻结必定来自 inline svc #0x80
6. ✅ **冻结机制修正**: 
   - 主线程 **不被阻塞**（main_responsive=1）
   - `setAnimationsEnabled:NO` 被反复调用（295 次/7 秒），但被 hook 拦截
   - `beginIgnoringInteractionEvents` 只被调 1 次，被 hook 拦截
   - level=2000 的覆盖窗口已被 hidden → 仍冻
   - layer.speed 全部 = 1.0 → 不是 CALayer 暂停
   - 动画冻结原因仍未确认
7. ❌ 之前假设的"dispatch_semaphore_wait 紧密循环"不成立——TAKEOVER 条件满足但 semaphore_wait(FOREVER) 在主线程上未被调用
8. ❌ 业务层 jailbreak 属性 hook（hookICBCJailbreakMethods + hookAuthorityJailBreakFlag + hookShowJailBrokenAlert）不改变冻结行为
9. ⚠️ 全类遍历 hook 存在间歇性 crash 风险（`[NSDictionary allKeys]` SIGSEGV）——可能是 checker 完整性校验
10. ⚠️ `backtrace()` 调用会触发 dyld image 查询（已 hook），可能导致 checker 校验失败 crash

## 已尝试的冻结对抗策略（更新）

| 版本 | 策略 | 结果 |
|------|------|------|
| v28 | semaphore 直接返回 0 | 主线程响应但 UI 冻结 |
| v29 | + block setAnimationsEnabled:NO + beginIgnoring + unfreezer timer | 同上 |
| v30 | setAnimationsEnabled 内 runMode yield | 黑屏 |
| v31 | setAnimationsEnabled 内 CFRunLoopRunInMode + re-entrancy guard | 仍冻 |
| v32 | semaphore 内 CFRunLoopRunInMode(100ms) | watchdog kill |
| v33 | semaphore 内 CFRunLoopRunInMode(1ms, 每5次) | 黑屏 |
| v34 | indicator>50 时 CFRunLoopRun 接管 | 启动页卡死→crash |
| v35-36 | 时间门控 takeover + 诊断 | 进程活，主线程响应，但 UI 仍冻 |
| v37 | + CALayer setSpeed: hook | crash (SIGSEGV in NSDictionary) |
| v38 | 回退 CALayer hook，保留诊断 | 稳定，UI 仍冻 |
| v39 | + 恢复业务层 hook | 稳定，UI 仍冻 |
| v40 | + backtrace() 诊断 | crash (backtrace 触发 dyld 查询→checker crash) |

## 当前认知总结

**动画冻结的根因仍未确定**。已排除：
- ❌ 不是 setAnimationsEnabled:NO 导致（已 block，animEnabled=1）
- ❌ 不是 beginIgnoringInteractionEvents 导致（已 block，isIgnoring=0）
- ❌ 不是 level=2000 覆盖窗口导致（已 hidden）
- ❌ 不是 layer.speed=0 导致（全部 1.0）
- ❌ 不是主线程阻塞导致（main_responsive=1）
- ❌ 不是业务层 jailbreak 属性导致（全部返回 NO）

**仍可能的原因**：
1. `ICBCMotionRecognizingWindow` 自定义 `sendEvent:` / `hitTest:withEvent:` 过滤事件
2. freeze 循环除了 setAnimationsEnabled:NO 还做了其他操作（移除 animation、禁用 timer、invalidate displayLink）
3. freeze 代码直接操作 CALayer.timeOffset 或 removeAllAnimations
4. welcome 页 VC 内部读取某个非 ObjC 的全局标志（C 变量）来决定交互
5. 主线程 dispatch queue 被密集 block 占满，runloop 有响应但无法持续处理 CA rendering

## 下一步方案

### 方案 A: Frida 辅助诊断 — 已测试，不可行
- Frida attach 后 app 立即被杀（反调试检测，可能是 ptrace/task_threads inline SVC）
- 端口 27042 被检测不是唯一问题——附加本身触发了退出

### 尝试 23: 深度 UI dump + 恢复全类业务层 hook (v39-v42)
- **假设**: 业务层 jailbreak 属性（isJailBreak/jailbroken 等）未被 hook 导致 VC 内部禁用交互
- **验证方法**: 恢复 hookICBCJailbreakMethods/hookAuthorityJailBreakFlag/hookShowJailBrokenAlert + 深度 view 层级 dump
- **观察**:
  - 进程稳定
  - 深度 dump 显示：
    - topVC = `ICBCGuideViewController`
    - nav stack: [ICBCLoadingViewController, ICBCGuideViewController]
    - 所有 subview: userInteraction=1, alpha=1.0, hidden=0, layer.speed=1.0
    - UIButton enabled=1（但 title=nil，可能用 image）
    - freeze_indicator=295（setAnimationsEnabled:NO 仍在被循环调用）
  - 没有任何 view 级别的异常
- **推论**:
  - ❌ 冻结不是 view 属性层面的问题
  - 所有 userInteraction/hidden/alpha/layer.speed 全正常
  - 冻结可能发生在事件传递路径（sendEvent）或动画移除（removeAllAnimations）

### 尝试 24: 绕过 ICBCMotionRecognizingWindow + 阻止 CALayer 动画移除 (v43-v44)
- **假设**: 
  1. `ICBCMotionRecognizingWindow` 重写 sendEvent: 在检测到越狱时丢弃事件
  2. freeze 循环调用 `removeAllAnimations` 导致动画停止
- **验证方法**: sendEvent 直接调 UIWindow 原始实现；CALayer removeAllAnimations 在 freeze 期间 no-op
- **观察**: UI 仍冻结，无变化
- **推论**: ❌ 事件传递和动画移除都不是冻结原因

### 尝试 25: 从 setAnimationsEnabled:NO 内部执行 CFRunLoopRun (v47)
- **假设**: freeze 循环是主线程 while 循环，从内部调 CFRunLoopRun() 可永久接管
- **验证方法**: indicator > 200 且 elapsed > 6s 时触发 CFRunLoopRun()
- **观察**: 
  - ✅ **成功！** UI 短暂恢复——用户可以左右滑动欢迎页
  - ✅ 跳过按钮也能点击
  - ❌ 约 3-5 秒后再度冻死
  - 日志: main_responsive=0 at t=10s
- **推论**: 
  - ✅ **CFRunLoopRun 方案正确** — 第一波 freeze 完全被打破
  - ❌ 存在第二波 freeze 机制，在 takeover 后几秒内重新阻塞主线程
  - 第二波不通过 setAnimationsEnabled:NO（indicator reset 后未再达到 200）
  - 第二波直接阻塞了主线程（main_responsive=0）

### 尝试 26: 多波嵌套 CFRunLoopRun (v48)
- **假设**: 允许多次 CFRunLoopRun 嵌套调用对抗后续 freeze 波
- **观察**: 只触发了 1 次 takeover——第二波不调 setAnimationsEnabled:NO
- **推论**: ❌ 第二波 freeze 用完全不同的方法

### 尝试 27: 降低 sleep/usleep 阈值 + 扩大 semaphore 拦截 (v50)
- **假设**: 第二波可能用短时 sleep 循环或长超时 semaphore_wait
- **观察**: 
  - v50: crash (SIGSEGV in setValuesForKeysWithDictionary:) — 长超时 semaphore 拦截太激进，破坏了正常异步等待
- **推论**: ❌ 不能拦截非 FOREVER 的 semaphore_wait

### 尝试 28: 只保留 sleep 降低阈值 (v51)
- **假设**: 第二波通过 usleep/nanosleep 实现
- **观察**: 
  - 进程存活
  - main_responsive=0 at t=10s（仍被阻塞）
  - **无 sleep/usleep 拦截日志** — 第二波不用 sleep
- **推论**: 
  - ❌ 第二波 freeze 不使用 sleep/usleep/nanosleep/dispatch_semaphore_wait
  - 必须是其他阻塞原语：pthread_mutex_lock / mach_msg / select / poll / __psynch_mutexwait / dispatch_group_wait

### 尝试 29: 添加 dispatch_group_wait hook (v52)
- **假设**: 第二波 freeze 使用 dispatch_group_wait(FOREVER) 阻塞主线程
- **验证方法**: fishhook dispatch_group_wait，主线程 + elapsed>8s + 超时>2s 时拦截并记录 [FREEZE2]
- **观察**: 
  - 第一次运行: APP 闪退（fraudmetrix SDK crash，与 v50 相同，间歇性）
  - 第二次运行（v53）: APP 卡死
    - `[TAKEOVER-ANIM] #1 elapsed=5.3` — 第一波成功打破
    - `[WATCHDOG] t=5s main_responsive=1` — 主线程响应
    - `[TAKEOVER] elapsed=7.1 indicator=7` — semaphore 接管触发
    - `[WATCHDOG] t=10s main_responsive=0` — **第二波在 7~10s 之间重新阻塞了主线程**
    - **无 [FREEZE2] 日志** — dispatch_group_wait 未在主线程被调用
- **推论**: 
  - ❌ **dispatch_group_wait 已排除** — 不是第二波冻结原语
  - 第二波在 TAKEOVER(7.1s) 之后、t=10s 之前触发（约 3s 窗口）
  - 排除列表更新：sleep, usleep, nanosleep, dispatch_semaphore_wait(FOREVER), dispatch_group_wait

### 尝试 30: semaphore 诊断 + 长 watchdog (v54)
- **假设**: 第二波可能使用 dispatch_semaphore_wait(非 FOREVER 长超时)
- **验证方法**: 不拦截，只记录 [SEMA-DIAG]；增加 t=14s watchdog
- **观察**: 
  - APP 卡死（用户报告）
  - 但日志显示**重大突破**：
    - `[TAKEOVER] elapsed=5.0 indicator=1385` — 第一波打破
    - `[TAKEOVER-ANIM] #1 elapsed=5.0` — 动画接管
    - `[POST-TAKEOVER] topVC: UITabBarController` — **成功跳过 guide，进入主界面！**
    - `[POST-TAKEOVER] ICBCVoiceTabbar` — 自定义 tab bar 可见
    - `[WATCHDOG] t=5s main_responsive=1`
    - `[WATCHDOG] t=10s main_responsive=1` — **首次在 10s 仍响应！**
    - `[WATCHDOG] t=14s main_responsive=1 sema_diag=0 freeze_indicator=2` — **14s 仍响应！**
    - **无 SEMA-DIAG** — 主线程上没有长超时 semaphore 等待
    - **无 FREEZE2** — dispatch_group_wait 未被调用
  - UIWindow level=2000 已被 hidden
  - freeze_indicator 在 takeover 后只增加了 2（无循环）
- **推论**: 
  - ✅ **APP 成功达到主界面状态** — UITabBarController + ICBCVoiceTabbar
  - ✅ **主线程在 14s 仍响应** — 第二波冻结在此路径下未在 14s 内触发
  - ❌ 用户仍报告 "卡死" — 冻结可能发生在 14s 之后
  - 与 v53 对比（t=10s main_responsive=0），v54 显著改善
  - 可能原因：
    1. 冻结发生在 >14s（延迟的第三波/定时检测）
    2. 触摸事件在 UI 层面被拦截（尽管主线程活跃）
    3. 渲染/视觉冻结但主线程实际在运行
  - **下一步**: 添加更长的 watchdog（20s, 30s），确认冻结何时发生

### 已排除的阻塞原语
- ❌ sleep / usleep / nanosleep（无日志）
- ❌ dispatch_semaphore_wait(DISPATCH_TIME_FOREVER)（会触发 TAKEOVER）
- ❌ dispatch_group_wait（无 FREEZE2 日志）
- ❌ setAnimationsEnabled:NO 循环（indicator 未达 200）

### 剩余候选
1. `dispatch_semaphore_wait(dispatch_time(NOW, large_value))` — 非 FOREVER 的长超时（v50 尝试拦截导致 crash）
2. `pthread_mutex_lock` — 死锁（某 mutex 被锁住不释放）
3. `mach_msg_trap` — 等待 Mach 端口消息（无限期）
4. `__psynch_mutexwait` — 内核级互斥锁等待
5. `__ulock_wait` — 用户态锁等待
6. `objc_sync_enter` — @synchronized 争用

### 策略思考
两种方向：
- **方向 A**: 继续诊断——添加 dispatch_semaphore_wait 的诊断日志（记录所有主线程调用，不拦截），确认是否有长超时 semaphore
- **方向 B**: 战术绕过——利用第一波打破后的 2-3s 可交互窗口，自动化完成关键 UI 操作（跳过 guide + 确认弹窗），使 app 进入正常状态后第二波可能不再触发

### 尝试 31: 扩展 watchdog 至 30s (v55)
- **假设**: 冻结发生在 14s 之后（主线程后来被阻塞）
- **验证方法**: 增加 t=20s, t=30s watchdog
- **观察**: 
  - 用户报告：几秒后(<10s) APP 卡死
  - 日志：
    - `[TAKEOVER] elapsed=7.5 indicator=1384` — 第一波打破
    - `[TAKEOVER-ANIM] #1 elapsed=9.4` — 动画接管
    - `[POST-TAKEOVER] topVC: UITabBarController` — **成功进入主界面**
    - `[WATCHDOG] t=5s main_responsive=1` ✅
    - `[WATCHDOG] t=10s main_responsive=1` ✅
    - `[WATCHDOG] t=14s main_responsive=1 sema_diag=0 freeze_indicator=0` ✅
    - `[WATCHDOG] t=20s main_responsive=1 sema_diag=0 freeze_indicator=0` ✅
    - `[WATCHDOG] t=30s main_responsive=1 sema_diag=0 freeze_indicator=0` ✅
    - **主线程从未被阻塞！5s-30s 全程响应！**
- **推论**: 
  - ⚠️ **范式转换！"卡死"不是主线程阻塞！**
  - 主线程活跃运行（runloop 正常迭代），freeze_indicator=0，sema_diag=0
  - 用户看到的"卡死"是 **触摸事件传递失败**，不是线程冻结
  - APP 到达了 UITabBarController（主界面），但触摸无法到达 UI 元素

---

## 范式转换：问题是触摸事件传递，不是线程阻塞

### 已完全排除
- ❌ 主线程阻塞（所有 watchdog 从 5s-30s 全部 responsive=1）
- ❌ dispatch_semaphore_wait（无论 FOREVER 还是长超时，sema_diag=0）
- ❌ dispatch_group_wait
- ❌ sleep/usleep/nanosleep
- ❌ setAnimationsEnabled:NO 循环（indicator=0 在 takeover 后）
- ❌ beginIgnoringInteractionEvents（已 block + isIgnoring=0）

### 触摸无法传递 + 动画冻结的可能原因
> 用户确认：不仅触摸不可用，动画也确实被冻结。两者同时发生。

1. **CALayer removeAllAnimations 持续被调用**：takeover 后 g_freeze_indicator 重置为 0，我们的 hook 条件 `if (indicator > 10)` 不再拦截，后台持续清除动画的代码恢复生效
2. 某个透明全屏 view 覆盖在内容之上，拦截了 hitTest
3. `ICBCMotionRecognizingWindow` 的 `hitTest:withEvent:` 返回 nil
4. 某个全屏手势识别器（UIGestureRecognizer）吞掉所有触摸
5. app 内部状态机判定为越狱设备，持续执行 "soft freeze"（不阻塞主线程但禁用 UI）
6. `CATransaction.setDisableActions(YES)` 持续被调用
7. 有第二个后台线程在循环设置 `userInteractionEnabled=NO`

### 尝试 32: hitTest 绕过 + removeAllAnimations 3s 门控 (v57)
- **假设**: 
  1. ICBCMotionRecognizingWindow 的 hitTest 返回 nil 导致触摸丢失
  2. removeAllAnimations 在前 5s 执行导致动画被清除
- **验证方法**: hitTest 也调用 UIWindow 原始实现；removeAllAnimations 门控从 5s 降到 3s
- **观察**: 
  - APP 卡死（触摸不可用）
  - ✅ **但动画恢复了！** 用户确认能看到动画
  - 主线程全程 responsive（5s-30s）
  - freeze_indicator 增长缓慢（4→9→10→12）
  - POST-TAKEOVER: topVC=UITabBarController, 所有 interaction=1
- **推论**: 
  - ✅ **动画问题已解决** — removeAllAnimations 3s 门控有效
  - ❌ **触摸问题与 hitTest 无关** — 绕过自定义 hitTest 未解决
  - 触摸冻结是独立问题，不依赖于：
    - hitTest:withEvent: 返回值
    - sendEvent: 自定义实现
    - userInteractionEnabled 状态
    - beginIgnoringInteractionEvents
  - 剩余可能：
    1. 事件根本没到达 ICBCMotionRecognizingWindow（被 UIApplication 或更上游拦截）
    2. 某个透明 window/view 在 hitTest 中先匹配
    3. 手势识别器冲突
  - **下一步**: 在 sendEvent: 中加计数器，确认事件是否到达 window
freeze 检测代码可能不仅在第一波循环中执行——可能有**独立的后台定时器**或 **dispatch_source** 持续：
- 调用 `removeAllAnimations`
- 设置 `userInteractionEnabled=NO`
- 或通过其他机制禁用 UI

我们的 unfreezer timer 每 2s 恢复一次 `userInteractionEnabled=YES`，但如果对方代码每帧或每秒多次重新设回 NO，用户仍然无法操作。

### 下一步
1. **改变 CALayer hook 策略**: 不再基于 freeze_indicator 判断，改为基于时间（elapsed > 5s 后永久拦截 removeAllAnimations）
2. **增加 hitTest 诊断**: 记录 hitTest 返回值
3. **增加 userInteractionEnabled 保护**: hook `UIView setUserInteractionEnabled:NO` 在 takeover 后拦截
4. **考虑 hook sendEvent 日志**: 确认事件是否到达 window 级别

---

## ✅ 里程碑: 卡死问题彻底解决 (v61)

### 根因确认

**嵌套 CFRunLoopRun() 导致死锁** 是 v52-v60 所有版本"交互卡死"的根本原因。

之前的 TAKEOVER 策略：
1. hook `dispatch_semaphore_wait(FOREVER)` → 进入 `CFRunLoopRun()` 保持主线程"活着"
2. hook `setAnimationsEnabled:NO` (indicator>200) → 进入嵌套 `CFRunLoopRun()`

**为什么这会死锁**：
- `CFRunLoopRun()` 从 hook 内部调用，意味着调用者代码被悬挂在栈上
- 调用者可能持有 ObjC runtime 锁、@synchronized 锁、或内部互斥锁
- 嵌套 RunLoop 中的代码尝试获取同一把锁 → 永久死锁
- 结果：主线程在 5-10s 后变为 `main_responsive=0`

### v61 解决方案

**核心原则**: 不要在 hook 内部进入嵌套 RunLoop。让阻塞调用直接返回，让 UIApplicationMain 的原生 RunLoop 自然处理事件。

变更：
1. `dispatch_semaphore_wait`: 主线程上 >0.5s 的等待直接返回 0（不进入 RunLoop）
2. `setAnimationsEnabled:NO`: elapsed>3s 后直接 return（不累计计数后进入 RunLoop）
3. `setUserInteractionEnabled:NO`: 时间门控 3s
4. `removeAllAnimations/removeAnimationForKey`: 时间门控 3s
5. `beginIgnoringInteractionEvents`: 直接 block
6. `CFRunLoopStop`: pass-through（不再阻止）

### v61 观察结果

```
[WATCHDOG] t=5s  main_responsive=1
[WATCHDOG] t=10s main_responsive=1
[WATCHDOG] t=14s main_responsive=1 sema_blocked=27115 freeze_indicator=5508 sendEvent=109 appEvent=109
[WATCHDOG] t=20s main_responsive=1 sema_blocked=28178 freeze_indicator=6026 sendEvent=144 appEvent=144 isIgnoring=0
[WATCHDOG] t=30s main_responsive=1 sema_blocked=28242 freeze_indicator=6048 sendEvent=146 appEvent=146 isIgnoring=0
```

- ✅ **主线程全程响应**（5s-30s 全部 responsive=1）
- ✅ **触摸事件正常传递**（sendEvent=146）
- ✅ **动画正常**
- ✅ **交互可用** — 用户确认可以点击、滑动
- 拦截了 28,242 次 semaphore_wait 和 6,048 次 setAnimationsEnabled:NO

### APP 冻结尝试的规模

APP 的"冻结"机制极其激进：
- **28,242 次** dispatch_semaphore_wait(FOREVER) 在主线程
- **6,048 次** setAnimationsEnabled:NO
- **多次** beginIgnoringInteractionEvents
- 所有在 30 秒内发生

这不是一次性检测后冻结，而是**持续循环**的主动 freeze 策略。

---

## 当前阶段: 登录成功，但性能问题

### v62 闪退分析
- 弹窗被拦截并记录：title="安全提示"，msg="您的设备环境存在隐私信息泄露..."
- 唯一 action "确定" style=1 (Cancel) → handler 内部调用了 exit()
- v62 错误地调用了该 handler → APP 自杀

### ✅ v63: 登录成功！

**修复**: 完全静默弹窗（不展示、不调用 handler、直接 return）

**被拦截的弹窗**:
1. "安全提示" — "您的设备环境存在隐私信息泄露和非法信息攻击等风险，为了保护您的账户及资金安全，请您在其他安全设备上使用。" (action: "确定" style=Cancel)
2. "风险提示" — "您的系统可能已经越狱，可能会给您带来财产损失、隐私泄露等风险，我行建议您更换终端进行操作。" (action: "确认" style=Default)

**观察结果**:
```
[WATCHDOG] t=14s main_responsive=1 sema_blocked=6538 freeze_indicator=3205 sendEvent=84
[WATCHDOG] t=20s main_responsive=1 sema_blocked=8497 freeze_indicator=3486 sendEvent=88
[WATCHDOG] t=30s main_responsive=1 sema_blocked=10486 freeze_indicator=4098 sendEvent=128
```

### ⚠️ 性能问题: APP 极其卡顿

**现象**: 每次点击/操作需要 3-4 秒才有响应（如勾选协议 checkbox、按钮点击等）

**原因分析**: `dispatch_semaphore_wait` hook 过于激进
- 我们拦截了主线程上所有 >0.5s 的 semaphore wait（共 10,486 次 in 30s）
- 但很多是**合法的同步操作**（等网络响应、等数据加载）
- 返回 0 后，调用方以为操作完成但实际数据未就绪 → 状态不一致/重试/延迟

**freeze 循环 vs 合法等待的区别**:
- freeze 循环: 启动后前 3-5 秒内密集调用（每秒数千次），timeout=FOREVER
- 合法等待: 用户操作后偶尔调用（一次操作一次等待）

### 下一步优化方向

**方案: 时间窗口策略**
- 只在 freeze 窗口期（前 8-10 秒）拦截有限超时的 semaphore_wait
- DISPATCH_TIME_FOREVER 始终拦截（freeze 机制专用）
- 之后放行所有有限超时的 semaphore_wait（合法同步操作）

### ✅ v64: 完全正常！发布版本 1.0.0

**最终策略**:
- `DISPATCH_TIME_FOREVER` 在主线程: **始终** return 0（freeze 机制永久使用此模式）
- 有限长超时 (>2s): 仅在前 10s 内拦截（之后放行合法同步操作）

**最终观测数据**:
```
[WATCHDOG] t=5s  main_responsive=1
[WATCHDOG] t=10s main_responsive=1
[WATCHDOG] t=14s main_responsive=1 sema_blocked=10216 freeze_indicator=3981 sendEvent=33
[WATCHDOG] t=20s main_responsive=1 sema_blocked=12861 freeze_indicator=4633 sendEvent=59
[WATCHDOG] t=30s main_responsive=1 sema_blocked=14083 freeze_indicator=4977 sendEvent=69
```

**最终状态**:
- ✅ 主线程全程响应
- ✅ 动画正常
- ✅ 交互流畅（无卡顿）
- ✅ 登录成功
- ✅ 越狱弹窗静默
- ✅ APP 正常使用

---

## 总结

### 技术方案

ICBC APP 的越狱检测+冻结机制分为三层：

**第一层: 检测** (SecureUtilityPlus + IOSSecuritySuite + 自有方法)
- 路径检测 → fishhook 拦截 stat/access/open/fopen/opendir 等
- Runtime 检测 → hook isJailBreak*/amIJailbroken 等方法返回 NO
- 环境变量检测 → hook NSProcessInfo.environment 过滤 DYLD_ 变量
- dylib 枚举检测 → hook _dyld_image_count/_dyld_get_image_name
- URL Scheme 检测 → hook canOpenURL: 过滤 cydia/sileo 等

**第二层: 冻结** (持续运行的 freeze 循环)
- dispatch_semaphore_wait(FOREVER) 在主线程: ~200 次/秒，永久运行
- setAnimationsEnabled:NO: ~50 次/秒，永久运行
- beginIgnoringInteractionEvents: 多次
- setUserInteractionEnabled:NO: 持续调用
- removeAllAnimations: 持续调用

**第三层: 弹窗+退出** (检测到越狱时)
- "安全提示" 弹窗，"确定"按钮 handler 调用 exit()
- "风险提示" 弹窗，登录时触发

### 绕过方案

| 层 | 方法 | 效果 |
|----|------|------|
| 检测 | fishhook + ObjC runtime swizzle | 所有检测返回"安全" |
| 冻结 | semaphore_wait(FOREVER) 始终返回 0 | 主线程不被阻塞 |
| 冻结 | setAnimationsEnabled/setUserInteraction 时间门控 | 动画+交互正常 |
| 冻结 | removeAllAnimations 时间门控 | 动画不被清除 |
| 弹窗 | presentViewController 拦截 + 静默 | 弹窗不展示不退出 |

### 关键教训

1. **不要在 hook 内部进入嵌套 RunLoop** — 会导致调用者栈上的锁永远不释放 → 死锁
2. **DISPATCH_TIME_FOREVER vs 有限超时区分对待** — 前者是 freeze 专用，后者可能是合法操作
3. **弹窗 handler 可能包含 exit()** — 不能盲目调用被拦截弹窗的 action handler

---

## ICBC 3.0.90 版本适配 (2026-05-10)

### 环境

- ICBCBypass: v1.0.0（发布版）
- ICBC App: 3.0.90（从 3.0.80 升级）
- 用户反馈：登录界面 FaceID 自动触发（正常），登录后各按钮卡顿，需点击 10+ 次才能响应

### 诊断日志分析

**检测向量**：与 3.0.80 完全一致，未观察到新增检测路径
- TweakInject plist 枚举（46 条 access 命中）
- Dopamine preboot 路径检测（stat/opendir/syscall_access 三件套，28 条路径）
- 标准越狱路径双查（rootless 真实路径 + 传统路径各一遍）
- 所有路径均被 fishhook 成功拦截

**弹窗**：与 3.0.80 一致
1. "安全提示" — "您的设备环境存在隐私信息泄露..." (action: "确定" style=Cancel) → 已静默
2. "风险提示" — "您的系统可能已经越狱..." (action: "确认" style=Default) → 已静默（登录后触发）

**冻结机制对比**：

| 指标 | 3.0.80 v64 (30s) | 3.0.90 v1.0.0 (30s) | 变化 |
|------|-------------------|----------------------|------|
| sema_blocked | 14,083 | 14,935 | +6% |
| freeze_indicator | 4,977 | 4,272 | -14% |
| sendEvent | 69 | 141 | +104% |
| main_responsive | 全程 1 | 全程 1 | 不变 |
| isIgnoring | 0 | 0 | 不变 |

**冻结时序模式变化**：

3.0.80 的 semaphore 阻塞**匀速分布**：
- t=3~14s: 10,216 次 (~929/s)
- t=14~30s: +3,867 次 (~242/s)

3.0.90 的 semaphore 阻塞**前置集中**：
- t=3~14s: 14,058 次 (~1,278/s) — 初始爆发强度 +37%
- t=14~20s: +14 次 (~2.3/s) — 近乎停止
- t=20~30s: +863 次 (~86/s) — 小规模第二波

### 性能问题根因分析

主线程全程响应（main_responsive=1），sendEvent 正常传递（141 次），触摸事件到达 app。问题不在事件传递链，而在 **hook 副作用导致的 UI 渲染/响应延迟**。

#### 问题 1: CALayer 动画清理被永久阻断

```objc
// Tweak.x:882-897 — 当前实现
- (void)removeAllAnimations {
    CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
    if (elapsed > 3.0) { return; } // ← 3 秒后 ALL 动画移除被永久阻断
    %orig;
}
```

这个 hook 在 ctor 后 3 秒起永久阻断 **所有** CALayer 的 `removeAllAnimations` 和 `removeAnimationForKey:` 调用——不区分是 freeze 循环的恶意调用还是 app 正常 UI 的合法调用。

后果：
- 已完成的动画永远不被清理 → CALayer 树中动画对象堆积
- 按钮按下/抬起的过渡动画挂起 → 视觉上按钮「没反应」
- GPU 渲染压力随时间线性增长
- 在 3.0.90 中影响更明显（可能因为 app 新增了 UI 动画/效果）

#### 问题 2: semaphore 忙循环消耗 CPU

freeze 循环中 `dispatch_semaphore_wait(FOREVER)` 被直接返回 0，将原本的阻塞等待变为忙循环：
- 前 14 秒以 ~1,278 次/秒的速度空转
- 每次调用包含 `pthread_main_np()` + `CFAbsoluteTimeGetCurrent()` + 条件判断
- 忙循环占据主线程 CPU 时间片，挤压 UI 事件处理窗口

3.0.90 的初始爆发强度比 3.0.80 高 37%（1,278 vs 929/s），恰好覆盖了登录和 FaceID 触发的关键窗口。

#### 问题 3: setUserInteractionEnabled:NO 全局阻断

```objc
// Tweak.x:871-879
- (void)setUserInteractionEnabled:(BOOL)enabled {
    if (!enabled) {
        if (elapsed > 3.0) { return; }
    }
    %orig;
}
```

阻断了所有 `setUserInteractionEnabled:NO` 调用。正常 app 逻辑中，按钮在网络请求期间会被 disable 后 enable——阻断 disable 但不阻断 enable 可能导致状态不一致。

### 待修复项

1. **CALayer hook 策略优化**：不应永久阻断，应改为：
   - 仅在 freeze 活跃期（前 10-15s）阻断
   - 或计数阻断（前 N 次后放行）
   - 或仅阻断 freeze 循环线程的调用（识别调用栈特征）

2. **semaphore 忙循环缓解**：在直接返回 0 时插入 `usleep()` 降低空转频率，释放 CPU 给 UI 处理

3. **setUserInteractionEnabled hook 收窄**：仅在 freeze 窗口期内阻断，之后放行

4. **添加 ICBC 版本号日志**：在 `[INIT]` 日志中记录 `CFBundleShortVersionString`，方便用户反馈版本信息

### 版本信息缺失

用户反馈无法确认 ICBC APP 版本。当前 `[INIT]` 仅记录 tweak 版本。需在 ctor 中添加：
```objc
NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
fprintf(f, "[INIT] ICBCBypass v1.0.0 / ICBC %s ctor started\n", appVer.UTF8String);
```
