# 链家越狱检测绕过 — 实验记录

目标 App：链家 iOS，bundle id `com.exmart.HomeLink`，版本 9.86.91（CFBundleVersion 9.86.91.0）
设备：iPhone 14 Pro Max / iOS 16.3.1 / Dopamine 2.x（SSH 隧道端口 2216，mobile@localhost）
本地分析目录：`lianjiabypass/`（app-binary/ tmp/ frida/）
越狱表现：启动秒退

链家与贝壳找房同属贝壳集团，URL scheme 含 `lianjia` / `lianjiabeikeft` / `beikejinggong`，共用同一套安全 SDK（JGBSDK）。摸清链家后方案可复用到贝壳。

---

## 第 0 轮：静态侦察（2026-08-20）

### 假设
链家秒退由某个第三方安全/风控 SDK 的越狱检测触发，检测面和退出链路可通过静态分析定位。

### 验证方法
从设备拉取主 binary（222MB）+ 可疑框架（`a` / `du` / `JGBSDK`）到本地，用 `file` / `strings` / `nm` 分析身份、检测特征、退出符号、ObjC 方法结构。

### 观察结果

**框架身份：**
- `du.framework`（676KB）= 数盟（Shuzilm / 数字联盟）设备指纹 SDK。路径 `/Users/shuzilm/.../dna_iOS/du/`，类 `DUNetwork`。含 `/Applications/Cydia.app`、`MobileSubstrate.dylib`、`sysctl` 特征——采集设备指纹（含越狱信号），但通常只采集上报，不直接杀进程。
- `a.framework`（90KB）= 无明显检测特征的小工具/加密库，暂不重点。
- `JGBSDK.framework`（3MB）= **越狱检测核心引擎**。@rpath `JGBSDK.framework/JGBSDK`，动态库，非静态链入主程序。疑似贝壳自研“精工”安全 SDK（URL scheme `beikejinggong`）。

**JGBSDK 检测清单（XxxCheck selector）：**
`JailbrokenCheck`、`DylibCheck` / `checkDylib`、`detectDebugger`、`ProxyCheck`、`VPNCheck` / `shareJGBVPNCheck`、`AppInfoCheck`、`ScreenRecordCheck`、`ScreenShotCheck`、`AirPlayCheck`、`VirtualPositionCheck`、`TextIntegrityCheck`。

**JGBSDK 越狱检测特征串：**
`/Applications/Cydia.app`、`CydiaSubstrate.framework`、`/Library/MobileSubstrate/DynamicLibraries/`、`.../xCon.dylib`、`/Library/MobileSubstrate/MobileSubstrate.dylib`、`/private/detect_log.txt`、`/private/var/tmp/cydia.log`、`your app hooked by Frida`。

**用户可见提示串：**
"Your application is running under a jailbreak environment. We recommend that you exit the operation or operate in a non-jailbreak environment."（另有网络代理风险提示）。

**关键类与回调：**
- `LJBRProtectManager`（链家/贝壳统一保护管理器，主 binary 也引用它）
- `JGBProtect` / `JGBIntercept`
- 回调 `receiveProtectEventWithCode:reason:`——JGBSDK 把检测结果报给业务层。
- 弹窗逻辑：UIAlertView / UIAlertController（`alertControllerWithTitle:message:preferredStyle:`）。

**退出/自保护相关导入符号：**
- `_exit`（JGBSDK 直接导入）
- `_vm_protect`（可能有代码段完整性自保护）
- `CFRunLoopObserverCreateWithHandler` / `CFRunLoopPerformBlock` / `dispatch_source_set_event_handler`——检测可能延迟或周期性触发，不止启动一次。

### 推论

**已确认：**
- 越狱检测本体在独立动态库 `JGBSDK.framework`，未静态链入主 binary，对抗面清晰。
- 检测项目众多，其中 `JailbrokenCheck` + `DylibCheck` + `detectDebugger` 是越狱环境直接命中项。
- 存在业务层回调 `receiveProtectEventWithCode:reason:` 给 `LJBRProtectManager`。

**仍未知（下一轮要回答）：**
- 秒退到底是 JGBSDK 内部直接 `_exit()`，还是回调 `LJBRProtectManager` 后由业务层退出？（决定 hook 点选在 SDK 检测函数、回调、还是 `_exit`）
- 退出前是否弹窗？秒退时序（立即 / 数秒）？有无 crash log、什么信号？
- `_vm_protect` 是否意味着 SDK 有代码完整性自校验（影响能否用 MSHookFunction）？

**下一轮单一假设（待验证）：**
装空 tweak（仅 `%ctor` crash tag）确认能注入 `com.exmart.HomeLink`；再对 `_exit` / `abort` 布最小 hook + 打点，判断秒退是否经过标准 libc `_exit` 路径，以及是否由 JGBSDK 触发。

---

## 第 1 轮：确认注入 + 观察退出机制（2026-08-20）

### 假设
链家能被 ElleKit 注入；秒退经过标准 libc `_exit` 路径，可用 fishhook 观察到调用点。

### 验证方法
探测版 tweak：`%ctor` 打点确认注入；fishhook rebind `exit`/`_exit`/`abort`/`kill`（observe-only，打回溯栈）；记录 JGBSDK/du/a/senseid 模块加载、`LJBRProtectManager`/`JGBProtect` 类是否存在。

**踩坑（已沉淀记忆 [[feedback_tweak_log_path]]）：** 日志先写 `/var/jb/tmp/` 再写 `/tmp/` 都失败——普通 App 沙箱两者都无写权限，日志静默为空，误判为“没注入”。改用 `NSTemporaryDirectory()`（沙箱内 Data 容器 tmp/）后正常。链家 Data 容器：`/var/mobile/Containers/Data/Application/FF131465-0653-49BB-AAC5-AE54C31453D0/`。

### 观察结果
- **注入成功**：`%ctor` 在 0.00s 执行，日志正常写入沙箱内。
- 0.08s 时 `JGBSDK` / `a` / `du` / `senseid_ids` 四框架均已加载。
- `LJBRProtectManager` 类 **PRESENT**；`JGBProtect` 类 **absent**。
- `receiveProtectEventWithCode:reason:` **不是 LJBRProtectManager 的实例方法**（selector not found）——可能是类方法或在其他类上。
- 日志停在 `ctor done`，**exit/_exit/abort/kill 四个 fishhook 全部未命中**。
- App 在启动后约 5-6 秒退出。
- **无 crash report**（CrashReporter 目录无 LianJiaShell 相关条目）。

### 推论

**已确认：**
- ElleKit 能注入链家，tweak 在 `%ctor` 阶段稳定执行。
- 检测框架（JGBSDK + 数盟 du + senseid）在启动早期即加载。
- 秒退 **不经过 fishhook 拦截的 libc 退出符号**，且 **不产生 crash report**。

**已排除：**
- “秒退走可被 fishhook 拦截的 exit/_exit/abort/kill 导入” —— 否定。fishhook 只改本 tweak 之外调用方的导入绑定；JGBSDK 内部那唯一一处 `bl _exit`（静态分析 @0xbc4c）走的是自身已解析 stub，fishhook 拦不到其他镜像的内部调用。

**仍未知（下一轮要回答）：**
- 退出到底是：(a) JGBSDK 内部 `_exit` 直接调用（需 MSHookFunction 直接 hook 函数地址，而非 fishhook 导入表）；(b) raw syscall `svc` 退出；(c) 别的干净退出路径。
- `receiveProtectEventWithCode:reason:` 真正宿主类是谁？检测结果回调链路。
- 退出前是否弹越狱提示窗（观察期没截到 UI）。

**下一轮单一假设（待验证）：**
用 MSHookFunction 直接 hook `_exit`/`exit` 的函数实现地址（而非 fishhook 导入表），确认 JGBSDK 内部 `_exit` 调用是否命中；同时 hook `LJBRProtectManager` 全部方法（用 runtime 遍历 method list 打点），定位检测判定与退出触发的确切调用链。

---

## 第 2 轮：Frida 动态 trace 尝试（2026-08-20，attempt 1-7）

### 假设
用 Frida spawn + Interceptor hook 全部退出原语 + JGBSDK 检测函数，一轮抓全退出机制与检测链。

### 验证方法
frida-server 17.9.8（设备）+ client（本机 venv，经 SSH 隧道转发 27042）。probe.js：hook exit/_exit/_Exit/abort/pthread_exit/raise/kill/pthread_kill/thread_terminate/task_terminate/libsystem_kernel!syscall/objc_exception_throw + JGB 内部 exit-site @0xbc4c；probe_min.js：hook open/openat/stat/access/objc_msgSend 验证 Interceptor 是否生效。日志带 attempt 编号写入 `frida/logs/attempt-NNN.log`。

### 观察结果
- **attempt 1-3（spawn）**：脚本能加载（打印 hooked 日志），但 App **+0.7~0.9s 退出，所有退出/终止 hook 零命中**。
- **attempt 4-5（attach 运行中进程）**：session 能建立，但 `create_script` 报 `ProtocolError`（先疑版本，client 17.17→降到 17.9.8 匹配 server 仍失败）。
- **attempt 6-7（spawn，重启 server + 新隧道后）**：`script.load()` 报 `TransportError: connection closed`。
- **对照（spawn 系统 App com.apple.Preferences）**：spawn→attach→load→脚本正常执行打印，**完全正常**。
- 环境插曲：frida-server 跑了半个月状态漂移 + SSH 隧道死连接，重启 server（launchctl bootout/bootstrap）+ 重建隧道后 `frida-ps`/spawn 系统 App 恢复正常。设备本地 `python3 socket` 测 27042 一直 OPEN，故障在隧道与会话层。

### 推论

**已确认：**
- Frida spawn + 脚本注入机制本身可用（Preferences 对照通过）。
- 对链家：spawn 时 `script.load()` 连接被关闭、attach 时 `create_script` 失败、spawn 能加载时也在 <1s 零命中退出——**三种表现都指向 JGBSDK 的 anti-frida**（binary 内有 `your app hooked by Frida` 字符串佐证）。JGBSDK 检测到 frida 后主动破坏 frida 会话/提前退出，走的路径绕过所有已 hook 的退出原语（疑似内联 `svc`，与 abcbypass 的 `svc #0x80 不可拦截` 同类）。

**已排除：**
- “用 Frida 动态 trace 链家退出链路” —— 被 anti-frida 挡住，本路线不可行（至少裸 frida 不行）。

**仍未知：**
- 反 frida 与无 frida 时的真实秒退（5-6s）是否同一退出路径。
- 检测判定链、退出原语具体是什么。

**下一轮单一假设（待验证）：**
放弃裸 Frida，回到 **tweak 注入路线**（attempt 已证明 ElleKit 能进且 `%ctor` 稳定执行、未被立即杀）。用 MSHookFunction 直接 hook `_exit`/`exit`/`abort` 函数实现地址 + 遍历 `LJBRProtectManager` 方法打点（日志写沙箱内 `NSTemporaryDirectory()`），定位真实退出机制。若 tweak 也零命中，则确认退出走内联 `svc`，转向 binary patch 或更上游隐藏检测源。

---

## 第 3 轮：JGBSDK 静态反汇编（2026-08-20，LIEF + capstone）

### 假设
JGBSDK @0xbc4c 的 `_exit` 是越狱检测命中后的退出点，hook 它或其调用者可阻断秒退。

### 验证方法
用 LIEF 解析绑定表 + capstone 反汇编。定位 `_exit`（唯一调用点 @0xbc4c）所属函数，解析其调用的 stub（普通 stub + `__objc_stubs` selector），dump `containsString:` 比对的 CFString 常量。

### 观察结果
- **`_exit` @0xbc4c 是 `___stack_chk_fail` 的死角**：`0xbc48: bl ___stack_chk_fail`（stub 0x27d3ec 已确认）紧接 `0xbc4c: bl _exit`，是编译器栈保护失败处理块，**正常执行永不到达**。这解释了第 1、2 轮 hook @0xbc4c 零命中。
- 含 `_exit` 的函数（入口约 0xafe8 附近，尾在 0xbc4c）是一个**文件系统扫描检测函数**，返回布尔 `w20`（0=干净 / 1=命中，`0xbc04: mov w20,#1`）：
  - `[NSFileManager defaultManager]` + `contentsOfDirectoryAtPath:error:` 枚举目录
  - `countByEnumeratingWithState:objects:count:` 两层嵌套 for-in 遍历目录及子目录
  - 对每项 `containsString:` 匹配常量
- **比对常量（@0x28b1xx CFString）**：`'%@%@/DynamicLibraries'`、`'.dylib'`、`'.plist'`、`'lnk'`。
- stub 身份确认：0x27d3ec=`___stack_chk_fail`、0x27d56c=`_exit`、0x27d7a0=`_objc_release`、0x27d74c=`_objc_enumerationMutation`。

### 推论

**已确认：**
- JGBSDK 有一个 **MobileSubstrate `DynamicLibraries` 目录扫描检测**：枚举 `.../DynamicLibraries` 目录，对文件名匹配 `.dylib`/`.plist` 判定越狱注入。
- **这个检测直接命中我们自己的 tweak**：`LianJiaBypass.dylib` + `LianJiaBypass.plist` 就在 `/var/jb/Library/MobileSubstrate/DynamicLibraries/`。装 tweak 反而给检测送把柄。
- JGBSDK 唯一的 `_exit` 与检测退出无关（是 stack_chk 死角）——**真实秒退不在 JGBSDK 的 `_exit`**，在别处（调用者据 `w20` 决策，或其他检测项/框架）。

**已排除：**
- “hook JGBSDK @0xbc4c 能阻断退出” —— 否定，那是 stack_chk_fail 死角。

**仍未知：**
- 这个扫描函数的调用者是谁、`w20=1` 后如何触发退出。
- 真实秒退的退出原语（仍未定位）。
- 其他检测项（`JailbrokenCheck` 等）各自的实现。

**下一轮单一假设（待验证）：**
两条并行：(1) 对抗侧——用 tweak hook `contentsOfDirectoryAtPath:error:` / `NSDirectoryEnumerator`，过滤掉含我方 dylib/plist 的结果（参考 mybankbypass 的“保留 NSFileManager 目录结果过滤”成功经验），看能否消除这一检测；(2) 定位侧——找该扫描函数入口 + 调用者，追 `w20=1` 到退出决策，确认真实退出原语。

**决策（用户拍板）：先做 A = 闭环验证。** 针对已确认的 `DynamicLibraries` 目录扫描检测写对抗（过滤 `contentsOfDirectoryAtPath:error:` 结果，隐藏我方 dylib/plist 及常见越狱文件），装机跑一次，观察秒退时间是否变化/消除，以此判断该扫描是否秒退主因。若有效则继续逐项；若无效说明秒退主因在别的检测，再回到定位侧。逐项静态摸清（B）暂缓。

---

## 第 4 轮：A 闭环验证 — tweak 对抗（2026-08-20）

### 假设
过滤 `contentsOfDirectoryAtPath:` 目录枚举结果隐藏 tweak，能消除/推迟秒退。

### 验证方法
v0.0.2：`%hook NSFileManager contentsOfDirectoryAtPath:error:` 过滤越狱项 + fishhook `opendir`/`stat` 打点。v0.0.3：扩展 C 层 hook 到 opendir/stat/lstat/access/open/fopen（命中越狱路径打日志 + 返回 ENOENT）。日志写沙箱 `NSTemporaryDirectory()`，用底层 open/write 避免与 fopen hook 递归。

### 观察结果
- **v0.0.2**：注入成功，但 `DIR FILTER` **从未打印**——`contentsOfDirectoryAtPath:` 未被调用。秒退依旧（~5-6s）。fishhook `stat` 命中 **1 条：`stat: /Applications/Cydia.app`**（在 1.15s），之后无更多打点，进程 5-6s 退出。
- **v0.0.3（首版）**：hook `fopen` 与日志函数 `lj_log`（用 fopen）递归 → 进程 ~3s 秒崩，日志只有 INIT 行。改 lj_log 用底层 open/write + 重入保护后修复。
- **v0.0.3（修复递归后）**：进程恢复 5-6s 退出，但日志仍只有 INIT + `[dbg] before rebind`，**`[dbg] after rebind` 未打印 → `rebind_symbols` 卡住/崩溃**（进程其余线程仍活，仅 ctor 线程卡）。

### 推论

**已确认：**
- 检测**不走** `NSFileManager contentsOfDirectoryAtPath:`（ObjC 目录枚举）——第 3 轮反汇编看到的那个目录扫描函数本轮未执行，或走了别的路径。
- 检测**确实做 `stat` 扫描已知越狱路径**（至少 `stat /Applications/Cydia.app`），但仅 1 条命中——fishhook 对 `stat` 的导入表改绑只覆盖了部分调用方（那条可能来自主程序/数盟，JGBSDK 内部 stat 走已解析地址，fishhook 拦不到）。
- **fishhook 同时 rebind opendir/stat/lstat/access/open/fopen 6 个符号会卡死 ctor 线程**（iOS 16.3.1 / ElleKit 环境）。v0.0.2 只 rebind opendir+stat 能跑，加 open/fopen 后卡——疑似 fishhook 对 variadic `open` 或与 ElleKit 交互的问题（呼应 abcbypass 的 fishhook 约束教训 [[abcbypass-round1-9]]）。

**已排除：**
- “目录枚举 ObjC hook 能覆盖检测” —— 否定，检测不走该 ObjC 方法。

**仍未知：**
- 秒退主因检测项 + 真实退出原语（仍未定位）。
- fishhook 卡死的确切触发符号（open? fopen? 数量?）。

**下一轮单一假设（待验证）：**
最小变量法：C 层只 rebind `stat`+`lstat`+`access`（去掉 open/fopen 排除 fishhook 卡死），扩大 `stat` 打点为**全路径记录**（不止越狱路径），看检测在 Cydia.app 之后还 stat 了哪些路径、退出前最后一个文件检测是什么。据此定位秒退主因。若 fishhook 仍不稳，改用 MSHookFunction 直接 hook `stat` 函数地址。

---

## 第 5 轮：秒退绕过成功 → 暴露第二层“主线程冻结”（2026-08-20）

### 假设
最小 hook 集（stat/lstat/access/opendir，去掉 open/fopen）能稳定 rebind；补 dyld 镜像枚举对抗（隐藏越狱 dylib）可覆盖 DylibCheck。

### 验证方法
v0.0.4：最小 4 hook + 全路径 stat 打点。v0.0.5：+ `_dyld_image_count`/`_dyld_get_image_name`/`dlopen`/`dladdr`（过滤越狱镜像）。装机观察存活 + simtouch 截图看界面。

### 观察结果
- **v0.0.4**：`rebind_symbols` 返回 **rr=0**（成功）——确认 open/fopen 是第 4 轮卡死元凶。`access` **大量命中**：检测通过 `access()` 遍历 `/var/jb/usr/lib/TweakInject/*.plist`（一份已知 tweak plist 黑名单，~38 项），逐个探测。`stat /Applications/Cydia.app` 命中。全部 BLOCK 后仍秒退（日志止于 1.18s 的 `/var/mobile/Containers` 正常 stat）。
- **v0.0.5（加 dyld 对抗）**：**秒退消除！进程存活 >30s**。确认 **DylibCheck（遍历 `_dyld_get_image_name` 找越狱 dylib）是秒退主因之一**——之前一直扫到我方 `LianJiaBypass.dylib` 和 ElleKit。
- **但**：simtouch 截图显示 App **卡在启动闪屏页**（绿色 logo + “连接每个家的故事”），间隔 40s 两张截图画面无变化，**CPU 0.0%** → **主线程被挂起阻塞**，不是加载慢，进不去主界面。

### 推论

**已确认（秒退层，已解决）：**
- 链家启动秒退由多路文件/镜像检测叠加触发，对抗组合拳（缺一仍退）：
  1. `access` 拦截 `/var/jb/usr/lib/TweakInject/*.plist` 黑名单扫描
  2. `stat` 拦截 `/Applications/Cydia.app` 等越狱路径
  3. **`_dyld_get_image_name`/`_dyld_image_count` 隐藏越狱 dylib（DylibCheck，决定性）**
- fishhook 在本环境可稳定 rebind stat/lstat/access/opendir/dyld*/dlopen/dladdr（8 符号 rr=0）；**open/fopen 不可加入**（卡死 ctor）。

**新问题（第二层）：**
- 秒退绕过后，App 卡在闪屏、主线程挂起（CPU 0%）。类似 icbcbypass 的“主线程冻结”防御，或我方 hook 副作用（dyld 隐藏改变镜像索引可能扰乱 App 自身逻辑）。

**仍未知：**
- 冻结是检测触发的惩罚，还是 hook 副作用？
- 主线程阻塞在哪个调用（等锁/等信号/等网络/死循环 sleep）？

**下一轮单一假设（待验证）：**
先区分冻结成因：(a) 用 simtouch 确认是否任何检测项残留触发；(b) 抓主线程调用栈（lldb/frida 受 anti-frida 限制，可用 tweak 装 SIGSTOP 观察 or 定时 dump 主线程 backtrace）定位阻塞点；(c) 对照实验——临时收窄 dyld 隐藏范围（只藏自己 dylib 不藏 ellekit），排除 hook 副作用导致镜像索引错乱。
