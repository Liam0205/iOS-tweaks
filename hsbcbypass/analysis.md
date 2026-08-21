# hsbcbypass 分析记录

## 目标

让**汇丰银行（= 汇丰中国 HSBC China）**与**汇丰香港（HSBC HK）**两个 App 在越狱设备
（2215，iPhone 13 Pro / iOS 15.4.1）上正常运行，绕过其越狱检测与退出机制。

## 环境信息

- 设备：2215（反向隧道，`ssh -p 2215 mobile@localhost`）
- App Store 参考（bundle id 需在设备上实测确认，勿凭此猜测）：
  - HSBC China：App Store id `1217785007`，开发者 HSBC Bank (China) Company Limited
  - HSBC HK Mobile Banking：App Store id `1164066737`
- 已确认（第 0 轮，2026-08-21，设备 22215）：

| App | bundle id | binary | 版本 | 扩展(.appex) | binary 大小 |
|---|---|---|---|---|---|
| 汇丰中国 | `cn.com.hsbc.hsbcchina` | `China.app/China` | 3.72.15 | 无 | 6.9MB |
| 汇丰香港 | `hk.com.hsbc.hsbchkmobilebanking` | `HongKong.app/HongKong` | 3.69.12 | `HSBC_HongKong.appex` + `PushServiceExtension.appex` | 232MB |

  - Team ID: `VWDSW3WE4N`（汇丰中国），签名与 entitlements 正常。
  - **⚠️ 汇丰香港有 2 个扩展进程，存活检测必须排除 `.appex`/PlugIns**（test 脚本已处理，
    参考 abcbypass 把扩展误当主 App 的教训）。
  - 测试工具：`hsbcbypass/tmp/hsbctest.sh`（精确匹配主 App 路径、排除 appex、崩溃判定）。

## ⚠️ 关键历史情报（来自 llmdoc/memory/reflections/hsbc-methodology-lesson.md）

之前做过 **hsbcchinabypass（汇丰中国，即本次的"汇丰银行"）**，10+ 轮未拿下，教训：

- 汇丰中国用的是 **OneSpan RASP**（非 ICBC/ABC 的 SecureUtilityPlus/mPaaS 体系）。
- **检测引擎在主 binary 的 C/C++ 静态库里**，不走 ObjC delegate。
- **退出走 raw syscall（`svc #0x80`）或等价的不可用户态拦截机制**。
- 结论：ObjC delegate hook、libc exit hook、GOT rebinding、常规 dyld/文件系统隐藏
  **都不足以阻止退出**。照搬 mybankbypass 的"全层 hook 扩大拦截面"是错误方向。

⇒ 本次不可重蹈覆辙。必须严格按 RE 方法论 guide：先确认检测源与退出机制，再选对抗层级。
   OneSpan RASP + raw syscall 若确认，则常规 hook 无解，需考虑 binary patch / 更上游
   检测源隐藏 / Mach 层手段。同时参考 abcbypass 的成功经验：**有完整性自检的目标，
   ObjC swizzle 可能是唯一安全手段；binary patch 可能被完整性校验发现**（需实测确认
   OneSpan 是否有完整性自检）。

## 分析计划（假设 → 验证 → 观察 → 推论）

### 第 0 轮：情报收集（上设备后）
1. 确认两个 App 的 bundle id、binary 名、是否有 .appex。
2. 裸跑对照：不装任何 tweak，观察两个 App 的原始行为——
   - 启动后多久退出？退回桌面还是崩溃？
   - 有无 crash report？crash 特征（signal / raw syscall / watchdog 0x8BADF00D）？
   - 有无越狱提示弹窗？文案？
3. 拉取主 binary 到本地 `app-binary/` 静态分析（strings / otool / 找 OneSpan 特征、
   svc #0x80 内联点、检测字符串）。
4. 判断：HSBC HK 与 HSBC China 是否同一套 RASP（OneSpan）？还是不同供应商？

### 后续轮次
- 依据第 0 轮结论，按 RE 方法论诊断优先级推进，每轮更新本文件。

## 实验记录

### 第 0 轮（2026-08-21）：情报收集 + 裸跑对照（部分完成）

- 设备通过 **22215** 端口访问（2215 端口的旧 sshd 隧道僵死占用，改用 22215，同一台
  iPhone 13 Pro / iOS 15.4.1）。
- 两个 App 的 bundle id / binary / 版本 / 扩展已确认（见上表）。
- **裸跑对照遇阻**：`uiopen cn.com.hsbc.hsbcchina` 返回 0，但主 App 进程**从未出现**
  （每 0.2s 高频抓取 5s 内 0 命中），无 crash log。汇丰香港同样起不来。
  - 已排除：uiopen 本身失效（能正常拉起设置 App `com.apple.Preferences`）；签名问题
    （entitlements 正常）；bundle id 错误（已用 ldid/strings 核准）。
  - **最可能原因：设备锁屏**。银行 App 常因数据保护（NSFileProtection）/前台策略，在
    锁屏状态下不启动到前台，而系统 App 不受此限。需用户解锁并点亮屏幕后重测。

### 第 0 轮静态分析（汇丰中国 3.72.15 主 binary + framework）

**🔑 重大发现：检测体系已升级，历史"纯 OneSpan + raw syscall 无解"结论对 3.72.15 不成立。**

主 binary 符号（Swift demangle 可见）：
- `RASPFramework`（汇丰自封装 RASP：`SecureAppModel`/`RASPAppController`/`AppSecurityEvent`/
  `RASPTrackManager`）
- **两套可切换 RASP 供应商**：`ActiveOneSpanRASPProvider`（OneSpan/VASCO，`VascoDPSDK`）+
  `ZimperiumRASPProvider`（Zimperium），经 `RASPCreatorStrategy` 策略模式选择。有
  `InactiveZimperiumRASPProvider` ⇒ 当前可能只启用 OneSpan。
- Swift 层越狱判定：`isJailbroken`、`jailbreak6status`、
  `XChinaJourney.DeviceInfoConfiguration(deviceUUID, isJailbroken, isRooted)`。

RASP 是**独立 framework**（非静态链入主 binary）：`China.app/Frameworks/` 下有
`RASPFramework.framework`、`VASCODSK.framework`、`MobileSecurity.framework`、
`UserSecurity*PluginKit.framework`（共 150 个 framework）。

RASPFramework 揭示的检测→响应模型（strings）：
- 策略类：`JailbrokenStrategy`、`ExitOnStrategy`、`acceptJailbroken`
- **有越狱弹窗**：`jailbroken_title_stop_ios`、`jailbroken_cta_stop_close`（停止/关闭）、
  `jailbroken_cta_advised_continue`（建议但可继续）、`rasp_exit_on_body_1/2`、
  `rooted device detected`、`developer mode detection`、`emulatorDetection`、`debugger`
- 退出可能走 **`_abort`**（framework 里有 `_abort` 符号），而非纯 raw syscall svc。

⇒ **新假设**：3.72.15 的越狱响应是"检测 → JailbrokenStrategy/ExitOnStrategy → 弹窗 →
  abort/退出"，且检测判定在 Swift/ObjC 层（`isJailbroken`、`RASPFramework` 类）。
  若成立，则可在 Swift/ObjC 层 hook 判定或策略类短路（类似 abcbypass 的 initRiskManage
  思路），比历史的 raw-syscall 悲观结论好办得多。**待裸跑对照验证真实退出方式。**

## 当前阻塞

### 观测工具不可靠（已定位，2026-08-21）

设备锁屏假设已被用户否定（"一直解锁呢"）。重新诊断发现**是观测手段坏了，不是 App 起不来**：

- `ps -eo pid,args`（mobile 用户）**看不到任何 Bundle/Application 下的 App 进程**——
  不只汇丰，所有 App 都抓不到 args。此前多轮"进程从未出现"的结论都建立在这个坏观测上，作废。
- `log stream` 在本越狱环境对 SpringBoard/launchd 谓词**零输出**（无权限或被裁剪）。
- 从 SSH 发起的 `uiopen <bundle>` 返回 0，但只是"请求已投递给 SpringBoard"，不代表拉起。

**可靠信号**：汇丰中国数据容器
`…/Data/Application/67AD6C38…/` 内有 **13:50 的新写入**
（AppDynamics、高德 SDK 日志），证明它**近期确实运行过**；但通过 SSH `uiopen` 后容器
**mtime 零变化**，说明 SSH 侧拉起没生效。

**其他已确认事实**：
- 主二进制 `China` 为 App Store 加密（`LC_ENCRYPTION_INFO_64 cryptid 1`），静态分析需先脱壳。
- 设备装了大量全局注入 tweak：`Shadow`（filter=UIKit，注入所有 App）、`noJailbreak` 等。
- mobile 用户**无权限**改 `/var/jb/Library/MobileSubstrate/DynamicLibraries/`（`mv` 被拒）。
- **Choicy 里汇丰中国和汇丰香港均已设 `tweakInjectionDisabled=true`**——当前完全禁止任何
  tweak 注入这两个 App（推测上一轮排查时手动设的）。这既意味着裸跑环境更干净，也意味着
  **将来 hsbcbypass 要能注入，必须先在 Choicy 放开或加白名单**。

## Round 0 结论（2026-08-21，探针版实测）

用户在 Choicy 中把汇丰的 `tweakInjectionDisabled` 关掉（放开注入）后，亲手点图标启动汇丰
中国：**确认闪退**（不是弹窗、不是卡住）。据此布设探针版 tweak 实测：

### 探针 tweak（纯观测，已部署到设备）

- 包名 `page.0x01.hsbcbypass` 0.0.1，filter 两个汇丰 bundle id。
- hook 五条退出路径 `exit`/`_exit`/`abort`/`kill`/`pthread_kill`，命中即把调用栈写入
  App 沙盒 `NSTemporaryDirectory()/hsbc_probe.log`（本设备无 `log`/syslog 工具，靠文件回捞）。

### 实测结果 —— 退出机制确认

探针日志只有注入成功记录，**五条 libc 退出路径一条都没命中**：
```
探针注入成功: pid=17707 bundle=cn.com.hsbc.hsbcchina
退出路径探针已布设 (exit/_exit/abort/kill/pthread_kill)
探针注入成功: pid=17708 bundle=cn.com.hsbc.hsbcchina   ← 启动了两次/有子进程
```
⇒ **退出不走 libc**，印证历史结论：OneSpan 用 **raw syscall（`svc #0x80` 直接
`SYS_exit`/`exit_group`）** 结束进程，用户态 hook libc 抓不到退出动作，也不产生 crash log。

⇒ 但注入本身成功了（Choicy 放开后通道通），且**注入没能阻止闪退**——说明单纯注入不触发
额外自检崩溃，闪退纯粹是越狱检测判定为真后的响应。

### 关键情报 —— hook 候选层（从 RASPFramework 符号提取）

退出动作（raw syscall）无法 hook，但触发它的**决策点在 Swift 层**。`RASPFramework` 是
HSBC 自研 Swift 包装（VIPER 架构），符号里锁定两类可下手点：

**源头层（让检测返回 false）**：
- `jailbreak6statusySb_tF` —— 返回 `Bool` 的越狱状态方法
- `isJailbroken`
- `XChinaJourney.DeviceInfoConfiguration(deviceUUID:isJailbroken:isRooted:)`

**决策层（让响应流程走"接受"分支）**：
- `RASPFramework.acceptJailbroken(track:)` —— 接受越狱的容忍入口
- `UntrustedDeviceInteractor`/`Presenter`/`Router`/`ViewController` —— 整套"不受信设备"
  响应流程；`SetupSecureModelStrategy`

## Round 1（2026-08-21，探针 v3~v6 运行时观测）

### 能自助启动了（不再依赖用户点图标）

- 从 SSH 拉起必须带 `--bundle`：`uiopen --bundle cn.com.hsbc.hsbcchina` 才生效；
  不带参数的 `uiopen cn.com.hsbc.hsbcchina` 返回 0 但不拉起（之前误判为"起不来"的根源）。
- 用探针日志文件 `…/67AD6C38…/tmp/hsbc_probe.log` 作为"是否真启动"的可靠信号。
- Choicy 已对汇丰放开注入，dpkg 用 `sudo -n` 可无密码安装。

### 退出时机与检测层级（关键）

探针加了**时间戳 + 心跳线程(每 50ms 落一条) + RASPFramework Swift 入口 hook**，实测：

- App 注入后**存活约 440~450ms**，然后进程被杀，心跳戛然而止（很规律，像定时检查点）。
- `RASPAppController.init`（off 0x6508）**从未进入**。
- `RASPAppInteractor.setupSecureModel`（off 0x6a70）**从未进入**。

⇒ **检测与退出发生在 RASPFramework 的 Swift 入口之前**。RASPFramework 只是 UI 响应层
（弹窗/拦截界面），检测源在更底层。

### 检测源锁定 —— VASCODSK.framework

探针启动瞬间 dump 全部 955 个 image，安全相关的只有四个（都在 App 自带 Frameworks）：

| image | 角色 |
|---|---|
| **`VASCODSK.framework`** [106] | **OneSpan/VASCO DSK，RASP 检测核心（首要嫌疑）** |
| `MobileSecurity.framework` [85] | HSBC 自研安全层 |
| `RASPFramework.framework` [95] | HSBC 的 RASP UI 包装（VIPER，仅响应层） |
| `UserSecurity*PluginKit` ×N | 认证 / 业务层，非越狱检测 |

⇒ 约 450ms 的检测 + raw syscall 退出，最可能由 **VASCODSK** 在自己的初始化线程 / 定时器里
完成，绕过 libc 和 RASPFramework Swift 层。这与历史"纯 OneSpan + raw syscall"结论一致，
但现在**精确定位到了 image**。

## Round 2（2026-08-21，VASCODSK 静态分析 + 策略转向）

### VASCODSK 分析结果

- **未加密**（`cryptid 0`，cryptsize 2.24MB），797 个符号，`llvm-nm` 可读。
- Swift 层 `VascoDPSDK` 类全是 **Digipass OTP / 签名 API**（`GenerateSignature`、
  `ChangePassword`、`GetDigipassProperty`、`ActivateOnlineWithFingerprint`…）——
  这是 OneSpan 的**令牌功能，不是越狱检测**。
- 越狱检测在 **C 层，混淆命名，无明文导出符号**；只 import 了 `_abort`。

### 关键推论 —— 强硬模式，纯 C 检测 → raw syscall 直杀

综合 Round 1+2：
- 检测走**纯 C 路径**：检测到越狱 → 直接 `svc` 退出，**不经过 RASPFramework 的
  UntrustedDevice/弹窗 UI 流程**（那些 Swift UI 类是"温和模式"给弹窗用的，此处未触发）。
- 因此 hook RASPFramework Swift 层无意义（根本没走到）。退出动作是 raw syscall，也 hook 不了。

### 策略转向 —— hook 检测「输入」而非「输出」

历史教训：纯 C + 自检 + raw syscall，patch text / hook 退出都不行。但**检测函数必须先读
环境**才能判定越狱：`stat`/`lstat`/`access`/`open`/`fopen` 探越狱路径、`sysctl`
(`kinfo_proc`) 查被调试、`fork`/`getppid`、`dlopen`/`dladdr` 查注入、`readlink`、
`_dyld_*` 枚举镜像找 tweak。**这些底层输入函数是可 hook 的 libc/dyld 符号**。
abcbypass 的成功也是靠改检测输入，不是拦退出。

## Round 3（2026-08-21，输入观测 + 调用栈定位 —— 排除误判）

### 教训:libc 文件查询全是注入器噪声，不是汇丰检测

探针 v7/v8 hook 了 `stat/lstat/access/open/fopen/dlopen/sysctl/fork` 并对命中越狱特征路径
的调用加 `backtrace + dladdr` 回溯。结果那些看似"检测"的查询
（`/var/jb/usr/lib/TweakInject/*.plist`、`Choicy.dylib`、`/private/preboot`）
**调用栈来源全是越狱自身组件**：

```
access("…/TweakInject/HammerIt.plist") ← #1 HSBCBypass.dylib #2 libinjector.dylib
lstat("/private/preboot")              ← … systemhook.dylib … libinjector.dylib
open("…/TweakInject/HammerIt.plist")   ← … Choicy.dylib … libinjector.dylib
```

⇒ 这些是 **ElleKit/Choicy 注入器加载 tweak 列表的正常行为**，被 `hsbc_is_jb_query`
误当成检测。**汇丰的检测根本不经过 libc 文件符号。**（另外那 1w+ 条 `stat(framework)`
是 dyld 正常加载。）

### 修正后的判断 —— VASCODSK 内联 syscall 检测

- 检测在 **VASCODSK 的 `__text` 内，用内联 `svc` 直接发 syscall**（`open`/`stat`/`csops`/
  `sysctl`/`ptrace` 等），不调用 libc 导出符号，所以 hook libc 完全抓不到。这是 OneSpan
  的强混淆反 hook 手法，与历史"raw syscall 退出"一脉相承。
- RASPFramework Swift 层（`RASPAppController.init`/`setupSecureModel`）确认**从未进入**，
  是温和模式 UI，此处未走。

### Frida 可用但被反调试秒杀

- 设备装了 `re.frida.server` 17.17.0（LaunchDaemon，root，默认监听 127.0.0.1:27042）。
- 本地已装 frida-tools 17.17.0（`~/.frida-venv`），经
  `ssh -N -L 27042:127.0.0.1:27042 -p 22215` 端口转发可 `frida-ps -H 127.0.0.1:27042`
  正常列进程。
- 但 `frida -f cn.com.hsbc.hsbcchina`（spawn）**`Failed to attach: unexpected early
  end-of-stream`** —— VASCODSK 在 frida 完成注入前就检测到并杀进程。**汇丰也检测 Frida。**

## Round 4（2026-08-21，脱壳 + 退出机制精确观测）

### 内存脱壳成功

- China 只有 **1 页加密**（`cryptoff=0x8000 cryptsize=0x1000 cryptid=1`）。
- tweak 在 %ctor 里遍历 `MH_EXECUTE` 定位主二进制，dump `header+cryptoff` 处 4096 字节
  解密内存 → `app-binary/China.decrypted`（拼回 offset 0x8000）。反汇编验证解密页是有效
  arm64 指令。**离线可反汇编全二进制。**
- 已交由子代理反汇编分析越狱检测调用链与退出机制。

### 关键 ObjC selector（可 swizzle 的希望）

脱壳后 strings 发现主二进制里有带冒号的 ObjC selector：**`jailbreakStatus:`、
`debuggerStatus:`**，以及 Swift `jailbreak6statusySb_tF`(返回 Bool)、`isJailbroken`、
`XChinaJourney.DeviceInfoConfiguration(...isJailbroken:isRooted:)`。带冒号 selector 若是
可 swizzle 的 ObjC 方法，就是最理想 hook 点（abcbypass 成功靠 ObjC swizzle）。

### 退出机制 —— 约 635ms「无声死亡」，双进程

探针 v11/v12 加了：更多退出变体(`_Exit`/`std::terminate`)、**信号 handler**
(ABRT/SEGV/BUS/ILL/TRAP/SYS/FPE/PIPE)、心跳按 pid 分文件、记录 pid/ppid/argv0。实测：

- 每次启动**稳定出现两个 China 主进程**（pid 不同，**ppid 都是 1=launchd**，argv0 都是主
  `China.app/China`，非 extension）——是两次独立 spawn，不是父子。
- 两个进程心跳都在 **约 635ms（#50）戛然而止**，采集 15s 也无更多心跳 → 进程确实在
  ~635ms 死亡。
- 死亡时：**无信号捕获、无 libc 退出函数命中、无 mach terminate**。

⇒ 能这样"无声"杀掉进程的只有 **SIGKILL（不可捕获，无记录）** 或 **`exit_group` 内联
syscall**。两个进程几乎同时死，略偏向"外部统一 kill / 看门狗"，但 ppid=1 看不出发起者。
（注：主二进制 China 反汇编中 svc 指令数为 0，说明若是内联 syscall，可能在别的模块或用了
非常规编码；待子代理反汇编确认。）

## Round 5（2026-08-21，崩溃日志决定性突破 —— 退出机制确认）

### 拿到 China 崩溃日志（root 可读，mobile 读不到）

`sudo cat /var/mobile/Library/Logs/CrashReporter/China-2026-08-21-143428.ips`
（已存 `tmp/China-crash-143428.ips`）。决定性字段：

```
exception : {type:EXC_BAD_ACCESS, signal:SIGBUS,
             subtype:"UNKNOWN_0x32 at 0x1162f4000"}
termination: {code:10, namespace:SIGNAL, indicator:"Bus error: 10",
              byProc:"exc handler", byPid:19156}
faultingThread 触发帧: pc=0x1162f4000, imageIndex=1(全 0 的伪 image),
   esr="(Instruction Abort) Translation fault"
vmRegionInfo: 0x1162f4000-0x1162f8000 [16K] r-x/rwx SM=PRV  "Memory Tag 255"
另有崩溃线程栈: dyld4::RuntimeState::notifyObjCInit
   → runAllInitializersForMain → start
```

### 退出机制 = 故意跳 RWX stub 触发指令中止

- OneSpan 检测到越狱后，**把 PC 跳到一块动态分配的 RWX 私有内存
  (`Memory Tag 255`, 16K, r-x/rwx)去执行**，那里是未正确映射的地址，产生
  **Instruction Abort（Translation fault）→ SIGBUS/EXC_BAD_ACCESS**。
  这是**故意的崩溃式退出**，不是 exit/abort，所以 libc 退出 hook 全部落空。
- `byProc:"exc handler"` 说明有自定义 **mach 异常处理**，可能抢在 BSD signal 之前，
  这也解释了为什么我们的 `signal()` handler 没抓到（且该崩溃发生在装 handler 之前的早期）。
- 崩溃在 **dyld `runAllInitializersForMain` / `notifyObjCInit` 阶段**——即某 framework 的
  **initializer/构造器**里就完成检测并触发跳转，非常早（与"Swift RASPAppController 入口
  从未进入""约 635ms"一致）。RWX stub 地址每次 mmap 随机，**无法静态 patch**。

### 结论：必须在「检测判定」处下手，不能拦退出

退出是随机地址的故意 fault，拦不住。可行方向回到**检测判定的源头/上层**：
- ObjC selector `jailbreakStatus:`/`debuggerStatus:`（可 swizzle？待子代理确认类归属）
- Swift `jailbreak6status`→Bool、`isJailbroken`
- 检测跑在某 framework 的 initializer 里；候选发起者：`MobileSecurity`、`VASCODSK`、或主
  二进制自身的 C 检测。等子代理反汇编报告定位判定函数地址与调用链。

## Round 6（2026-08-21，穷尽退出拦截 —— 确认退出路径不可拦）

依次尝试并全部落空（进程仍在 ~635~760ms 死亡）：

| 手段 | 结果 |
|---|---|
| `sigaction(SA_SIGINFO)` 抓 ABRT/SEGV/BUS/ILL/TRAP/SYS/FPE | **未触发**（BSD signal 层收不到） |
| `task_set_exception_ports` 抢 EXC_BAD_ACCESS/BAD_INSTRUCTION（kr=0 成功） | **未触发** |
| 扩大到 EXC_MASK 全类型（ARITHMETIC/SOFTWARE/BREAKPOINT/CRASH/GUARD） | **未触发** |
| hook `task_set_exception_ports`/`thread_set_exception_ports` 看 OneSpan 是否重设 | **无任何第三方调用** |
| hook mach `task_terminate` | **未触发** |
| hook libc `exit/_exit/_Exit/abort/kill/pthread_kill/terminate` | **未触发** |

**关键推论**：
- 有 tweak 注入时的退出，**不产生崩溃日志、不触发 mach 异常、不调用任何可 hook 的终止/
  信号函数**。（14:34 那份 SIGBUS 崩溃日志是**无 tweak 时**的行为；有 tweak 时走了更彻底的
  静默路径。）
- 唯一符合的机制：**内联 `svc #0x80` 直接调 `SYS_exit`/`exit_group`**，位于运行时动态生成
  的 RWX stub（崩溃日志里的 `Memory Tag 255` r-x/rwx 区域）内，纯汇编，**无法 hook**。
- ⇒ **退出路径彻底放弃拦截**。必须且只能在「检测判定」处下手，让检测认为"未越狱"，使其
  根本不跳 stub。

### 待办（聚焦检测判定）
1. **等子代理反汇编报告**（正在跑）→ 确定 `jailbreakStatus:`/`debuggerStatus:` 类归属、
   `jailbreak6status`/`isJailbroken` 的判定函数地址和调用链。
2. 定位后优先 **ObjC swizzle / 高层 Swift hook** 让判定返回"未越狱/未调试"，避开完整性自检
   （abcbypass 经验：C 函数 inline-hook 会触发自检，只有 ObjC/高层入口安全）。
3. 若判定在纯 C 且有自检：考虑在**检测输入**层伪造（但 Round 3 已知它不走 libc 文件符号，
   可能用内联 svc 直接 syscall 读环境，那样输入也 hook 不了 → 最后手段是 patch 判定函数
   返回值，需先确认无自检或自检可绕）。
4. 汇丰香港（含 `.appex`）稍后单独验证是否同一套机制。

## 汇丰香港 —— 同源确认（2026-08-21）

汇丰香港 `hk.com.hsbc.hsbchkmobilebanking` 用几乎相同的安全栈：
`LegacyVASCODSK.framework`（Legacy 版，同源稍旧）、`MobileSecurity.framework`、
`RASPFramework.framework`、同样的 `UserSecurity*PluginKit`。主二进制加密参数也相同
（`cryptoff=0x8000 cryptsize=0x1000 cryptid=1`）。

⇒ **两个 App 同一套 OneSpan RASP 机制**。攻破汇丰中国的检测判定后，香港大概率同法可解，
一份 tweak（两个 bundle filter）有望覆盖两者。香港主二进制同样只 1 页加密，可用相同的
tweak 内存脱壳法离线分析。

## Round 7（2026-08-21，定位检测判定类 —— 决定性突破）

### 手工解析 ObjC 元数据（lief 社区版不带 objc，自写 Python 解析）

- `tmp/nlcls.py`：解析 `__objc_classlist`/`__objc_nlclslist`，处理 iOS15 chained-fixup
  指针（真实 VA = 低32位 + 0x100000000）。
- `tmp/cls_methods.py`：解析类的 baseMethods，列方法名+imp 地址。

### 检测核心类 = `AppSecurityMonitor`（模块 `WithOneSpanRASP`）

`__objc_classlist` 里找到 OneSpan RASP 的 Swift 类，**检测方法全是 ObjC 方法（可 swizzle！）**：

| 方法 | imp 地址 | 说明 |
|---|---|---|
| `-[AppSecurityMonitor jailbreakStatus:]` | 0x100017d68 | 越狱检测（event码 2） |
| `-[AppSecurityMonitor repackagingStatus:]` | 0x100017da8 | 重打包检测 |
| `-[AppSecurityMonitor debuggerStatus:]` | 0x100017de8 | 调试器检测 |
| `-[AppSecurityMonitor screenshotDetected]` | 0x100017e20 | 截屏 |
| `-[AppSecurityMonitor libraryInjectionDetected]` | 0x100017e50 | **库注入检测（event码 5）** |
| `-[AppSecurityMonitor hookingFrameworksDetected]` | 0x100017e80 | **hook框架检测（event码 6）** |
| `-[AppSecurityMonitor developerModeStatus:]` | 0x100017eb8 | 开发者模式 |
| `-[AppSecurityMonitor emulatorDetected]` | 0x100017ef0 | 模拟器 |

- 相关类：`ActiveOneSpanRASPProvider`（无 baseMethods，纯 Swift）、`AppSecurityMonitor`。
- 杀我们的大概率是 `jailbreakStatus:` + `libraryInjectionDetected` + `hookingFrameworksDetected`
  （我们注入 tweak 必然触发后两者）。
- 有 `+load` 的 non-lazy 类只有 2 个 ADEum（AppDynamics），**排除 `+load` 是检测点**。
- `jailbreakStatus:`/`debuggerStatus:` 之前误以为是 AppDynamics（周围字符串是 ADEum），
  实际是 `AppSecurityMonitor` 的方法（方法名区按字母排序才与 ADEum 相邻）。

### 意义：回到 abcbypass 的成功路径

这些是**标准 ObjC 方法**，可用 Logos `%hook AppSecurityMonitor` 覆盖，让检测返回"安全"值，
无需碰底层 C / 内联 svc / RWX stub。下一步：
1. 观测版 hook 这 8 个方法，记录调用顺序 + 返回值类型/值（带冒号的收 x2 参数，返回对象；
   无参的返回状态）。
2. 据观测确定"安全"返回值，改为始终返回未检测到。
3. 注意 OneSpan 可能有完整性自检——ObjC swizzle 通常安全（abcbypass 验证），但需实测。

## Round 8（2026-08-21，AppSecurityMonitor ObjC 方法观测 —— 未命中）

观测版 tweak（重写，聚焦）：`NSClassFromString(@"_TtC15WithOneSpanRASP18AppSecurityMonitor")`
成功找到类并 `method_setImplementation` hook 了全部 8 个检测方法（日志确认 8 个都 hook 上）。

**结果：8 个方法一次都没被调用**（`→` 计数为 0），进程仍退出。

⇒ 这些 ObjC 方法是 OneSpan 暴露的**被动查询接口**（供 App 主动查状态），**实际的越狱拦截
不经过它们**——OneSpan 在自己的 C 层后台自动检测并触发退出（内联 svc）。

### 下一步（更接近根源的观测）

- hook `pthread_create`，记录所有新线程的**入口函数地址 + 所属模块**——检测后台线程的入口
  会直接暴露检测代码在哪个模块（大概率 VASCODSK / MobileSecurity 的 C 层）。
- hook `AppSecurityMonitor` 的 `init`/`alloc` 及 `ActiveOneSpanRASPProvider` 的方法，确认
  检测启动链（是谁 new 了 monitor、调了什么启动检测）。
- 等子代理反汇编报告（分析 China.decrypted 的检测→退出调用链）。
- 若确认检测纯在 VASCODSK C 层且用内联 svc 读环境 + 触发退出：最后手段是运行时 patch
  VASCODSK 的检测函数（需定位）或在其依赖的 syscall 封装处拦截（若有）。

## Round 9（2026-08-21，并行静态分析 —— 缩小检测源）

与子代理并行,排除了若干路径:

- **pthread_create 未被调用**:检测后台线程不用 libc `pthread_create`(疑用
  `bsdthread_create` syscall 或 mach `thread_create` 直建),又一处绕开可 hook 层。
- **MobileSecurity 不是 RASP 检测层**:`otool -L` 显示它不依赖 VASCODSK,只做加密
  (SymmetricCryptor)、生物识别、屏幕捕获。
- **China 直接链接 VASCODSK**(`@rpath/VASCODSK.framework`),`AppSecurityMonitor`
  (在主二进制 China 的 `WithOneSpanRASP` 模块)是调 VASCODSK 的层。China 用 iOS15
  chained-fixups,`--bind`/`--lazy-bind` 解析不出 VASCODSK 符号引用(需 chained imports 解析)。
- **VASCODSK C 层全混淆**:导出函数名全随机(`_ACdvYdwnXvIsmklLDhnw` 类),检测字符串
  加密隐藏;发现 `__swift56_hooks`/`__s_async_hook` 段名(疑检测 Swift/async hook)。
- **RaspAdapterPlugin-Policy.json**(DataProvider.framework)只是插件消息路由声明
  (fraud feed 查询),**不是检测行为开关**。RASP 检测行为编译进 OneSpan 库,无外部配置可改。
- **8 个 AppSecurityMonitor ObjC 检测方法确认是被动查询接口**,拦截不经过它们。

⇒ 检测确定在 **VASCODSK C 层**(混淆),由 China 的 `AppSecurityMonitor`/
`ActiveOneSpanRASPProvider` 初始化时启动后台检测,内联 syscall 读环境 + 触发退出。
静态定位混淆检测函数是当前唯一出路(子代理进行中)。

## Round 10（2026-08-21，子代理反汇编报告 + 核对）

子代理反汇编 China.decrypted 完成,关键结论 + 我的核对:

### 确认:AppSecurityMonitor 是"状态汇报"接口,判定不在其中
- 9 个方法(init + 8 检测)只是把外部传入的 Bool 参数转成整数状态码返回
  (`jailbreakStatus:` 返 0/2,`debuggerStatus:` 返 0/1...),判定值从 x2/x3 参数传入。
- 通过 `RASPFramework.SecureAppModel.init(appSecurityMonitor:)`(China 内 GOT
  `0x1004cec38`,构造点约 0x100016b60/0x100016bbc)接入:SecureAppModel 持有满足
  `AppMonitorDelegate` 协议的 AppSecurityMonitor。
- 印证我 Round 8 实测:这些 ObjC 方法闪退前从未被调用。

### 核对:`_matrix_die` 不是越狱退出路径（子代理误判,已排除）
- 子代理发现 VASCODSK `0xfb38`(它猜名 `_matrix_die`)封装调 `abort`(经 stub 0x26824),
  被 0xfdc0/0xfe10/0xfed4 调用。
- **但反汇编显示这些是内部错误处理**(0xfddc 分配内存→0xfde4 cbz 查空指针→die),
  是"malloc 失败就 abort"的标准模式,不是越狱检测。
- 且崩溃日志明确是 **SIGBUS(跳 RWX stub)不是 SIGABRT**,`abort` 产生 SIGABRT,
  时间线不符。→ `_matrix_die` 不是越狱退出点,排除。
- VASCODSK 不含 `brk`/`udf`/`svc`;China 里的 `brk #1` 是 Swift 标准 fatalError trap,非检测专用。

### 子代理最有价值的洞察:hook 时机可能太晚
- 检测可能在 **tweak 的 hook 完成之前的极早期**(dyld 静态初始化器 / Swift 全局初始化器 /
  `+load` 阶段)就跑完并触发退出。这能统一解释"所有 hook(libc/信号/mach/pthread/ObjC)
  都没命中"——不是拦不到,是**太晚**。
- 观测显示 tweak 在 `+7~12ms` 才布设完 hook;若检测在 0~7ms 跑完,全错过。

### 下一步:验证并解决 hook 时机
1. 确认检测相对 tweak `%ctor` 的时序:tweak 是否晚于 OneSpan 的初始化器。
2. 若太晚:设法让 tweak 更早注入(ElleKit 加载顺序 / DYLD_INSERT / `+load` 里抢先 /
   构造器优先级),赶在 OneSpan 检测初始化器之前 hook。
3. 时机解决后,重新用 mach 异常端口 / RWX mmap hook 抓 SIGBUS stub 的真实来源。

## Round 11（2026-08-21，RWX 监控零命中 —— 确认 hook 时机太晚）

给 tweak 加 hook `mmap`(PROT_EXEC)/`mprotect`(+EXEC)——生成 RWX stub 的必经路径,带调用栈回溯。

**结果:零命中**(0 次 PROT_EXEC 分配被捕获),进程仍闪退。

崩溃日志证明 RWX stub 内存确实被分配(Memory Tag 255 r-x/rwx),但我们的 mmap/mprotect
hook 没抓到 → **该分配发生在 tweak 的 MSHookFunction 生效之前**。

**决定性结论:hook 时机太晚。** OneSpan 的检测+退出发生在 tweak `%ctor` 里布设 hook
(约 +7ms)之前的极早期。综合此前所有"零命中"(libc 退出/信号/mach/pthread/mmap/ObjC
方法),统一解释就是时机——不是拦不到,是**所有 hook 都晚于检测**。

推论:OneSpan 检测在**某个先于我们 tweak 初始化的 framework 的初始化器**里跑完
(dyld `runAllInitializersForMain`/`notifyObjCInit` 早期)。tweak 虽在主 App 前注入,
但 OneSpan 的检测 framework 可能排在我们 tweak 构造器之前执行。

### 下一步:解决注入时机(核心突破口)
1. 确认 tweak dylib 相对 OneSpan framework(VASCODSK/RASPFramework)的初始化顺序。
2. 让 tweak 抢最早:
   - `%ctor` 用 `__attribute__((constructor(101)))` 提最高优先级;
   - 或 hook dyld 的镜像加载早期回调,在 OneSpan 初始化器执行前布设 hook;
   - 或研究 ElleKit 注入顺序,让 HSBCBypass.dylib 排在最前(文件名/依赖控制)。
3. 时机赶上后,mmap/mprotect hook 应能抓到 RWX stub 生成的调用栈 → 定位检测退出模块。

## Round 12（2026-08-21,mach VM 层 hook —— 仍零命中,确认裸 syscall）

### 澄清注入时机(查证 dyld 行为)

查 dyld 加载顺序(leptos-null/LoadOrder):inserted dylib(tweak)的构造器**先于**依赖
framework 的初始化器**先于**主程序。所以 tweak `%ctor` **理论上早于** VASCODSK 初始化器。
tweak `%ctor` 里能 `NSClassFromString(AppSecurityMonitor)` 是因为 ObjC 类注册(map_images)
早于所有初始化器,但≠初始化器已执行。→ 时机本身 tweak 不算晚。

### mach VM 层 hook 仍抓不到 OneSpan 的 RWX 分配

hook `mach_vm_protect`/`vm_protect`(dlsym 取址,mach_vm.h 在 SDK 不可用)。生效
(抓到 ellekit 自己 hook 时的 +EXEC 副作用),但 **OneSpan 的 RWX stub 分配依然零命中**。

⇒ **OneSpan 用内联 `svc` 直接发 `mach_vm_*` syscall,连 mach 用户态封装都绕过。**
这是最底层的裸 syscall,用户态**任何** hook(libc/mach 封装/ObjC/信号/异常端口)都拦不到。

### 已穷尽的 hook(全部零命中,统一原因=内联裸 syscall + 混淆)

libc: exit/_exit/_Exit/abort/kill/pthread_kill/terminate/stat/open/access/fopen/dlopen/
sysctl/fork/mmap/mprotect/pthread_create;
mach: task_set_exception_ports/thread_set_exception_ports/task_terminate/mach_vm_protect/vm_protect;
signal: sigaction 全致命信号;ObjC: AppSecurityMonitor 8 方法。

### 最终技术判断

汇丰 OneSpan RASP 在**纯裸 syscall 层**完成检测(读环境)、后台线程、内存分配、退出,
全程不碰任何用户态可 hook 符号,且检测代码在 VASCODSK 内混淆。**用户态 tweak（MSHookFunction/
fishhook/ObjC swizzle）无法拦截。** 这与历史 hsbcchina 10+ 轮失败一致,是目前遇到的最强 RASP。

剩余理论路径(都超出常规 tweak,成本/风险高):
1. **内核态**:KPP/PPL 之外的内核 hook 拦 syscall(需 kernel patch,当前越狱未必支持,风险高)。
2. **patch VASCODSK 磁盘二进制**:定位混淆检测函数改其返回/跳转,但有完整性自检 + 签名,
   且函数混淆难定位、跨版本不稳。
3. **syscall 层拦截**:hook `svc` 不可能(用户态);唯一是内核 sysent 或 dyld 的 syscall shim。

## Round 13（2026-08-21，内核态 / 二进制 patch 可行性评估）

设备 = iPhone 13 Pro / iOS 15.4.1 / **Dopamine 2**（KFD + PPL bypass）/ ElleKit / rootless。

### 路径 A：内核态拦截 syscall —— 理论可能但高风险，不优先

- 设备有 **libkrw0 + libkrw0-dopamine**（内核读写 API）。
- Dopamine 的 libkrw **包含写 PPL 保护内存 + kcall 原语**（官方 README 确认），
  理论上能改内核代码页 / sysent。
- 但拦截"应用内联 svc 发的裸 syscall"需在 syscall 入口/sysent 插 hook：
  - 高难内核工程；改错直接 boot loop；semi-untethered 每次重启要重做。
  - 会影响全系统所有进程的 syscall，副作用大。
- 结论：**理论可行但风险/成本过高，作为最后手段**。

### 路径 B：二进制 patch VASCODSK —— 更实际，优先 ✅

关键前提已具备：
- VASCODSK **未加密**（cryptid=0），可完整反汇编。检测的**判断/分支逻辑是普通 arm64 代码**，
  改指令即可绕过（不受"裸 syscall 免疫 hook"影响——patch 改的是代码本身，不是 hook）。
- 设备装 **AppSyncUnified**（接受 unsigned/fakesigned）+ **ldid**（重签名）→ patch 后能重签、系统能接受。
- 方案：patch VASCODSK 检测函数（改判定分支/直接返回未越狱）→ ldid -S 重签 → 替换
  `China.app/Frameworks/VASCODSK.framework/VASCODSK`（需 root 写 Bundle，sudo 可）。

**唯一未知障碍 = 完整性自检**：
- VASCODSK 是否自校验 __TEXT？主二进制是否校验 VASCODSK 的 hash/签名？
- 若有自检：要么一并 patch 掉自检，要么自检也走裸 syscall 读文件（那 patch 磁盘文件会被发现）。
- **子代理正在反汇编 VASCODSK 查：检测判定地址、退出触发、完整性自检、最小 patch 方案。**

### 下一步
1. 等子代理 VASCODSK 反汇编报告（patch 点 + 自检情况）。
2. 若无自检或自检可一并 patch：做 patch → ldid 重签 → 替换 → 测试。
3. patch 前备份原 VASCODSK。改 Bundle 内文件是中等风险（可逆，先备份）。

## Round 14（2026-08-21，patch 工具链验证 —— 撞上代码签名墙）

验证 patch→重签→替换链路(用**原样重签**的 VASCODSK,零逻辑改动):

- 备份原库到 `/tmp/VASCODSK.orig`(2409312 字节),root 可写 Bundle。
- `ldid -S` 重签成功(→2350064 字节)。
- 替换后启动 → **App 崩溃 `SIGKILL - CODESIGNING`**(namespace CODESIGNING),
  崩在 dyld `makeJustInTimeLoaderDisk`/`compatibleSlice`(加载 VASCODSK 时签名校验失败)。
- 已恢复原库(App 恢复正常)。

### 关键结论:主障碍是 iOS 代码签名,不是 OneSpan 自检

- App Store App 的 nested framework 被 ldid adhoc 重签后,**dyld 拒绝加载**(SIGKILL-CODESIGNING)。
- AppSyncUnified 放行主可执行的伪签名,但**这里 nested framework 的 adhoc 签名仍不被接受**。
- 这比 OneSpan 自检更早触发(探针都没注入就崩)。

### 待解决:如何让 patch 后的 VASCODSK 通过签名
候选(待验证):
1. **重签整个 App**(主二进制+全部 framework 用同一 adhoc,保持一致),而非只单个 framework。
2. **正确的 adhoc/fakesign**:ldid -S 可能没生成 AMFI 认的 CDHash;试 `ldid -S` 带
   entitlements、或用 `jtool2`/`ldid` 不同参数,或 `codesign` (若有)。
3. 确认 AppSync 是否需要 App 的 cdhash 进 trustcache(改了 cdhash 就要重新 trust)。
4. 若签名这关过不去 → 二进制 patch 路径受阻,回到内核态(路径 A)或放弃。

### 现状:等子代理 VASCODSK 反汇编(patch 点),并行解签名问题

## Round 15（2026-08-21，签名障碍突破 —— patch 工具链打通 ✅）

Dopamine 用 **jailbreakd + trustcache**(不是证书链)信任 adhoc 签名的二进制。
`/var/jb/basebin/jbctl rebuild_trustcache` 会重建 trustcache 信任已签名文件。

**验证成功**:adhoc 重签的 VASCODSK 放进 Bundle → `jbctl rebuild_trustcache` → 启动,
**探针成功注入(pid=20387),无 CODESIGNING 崩溃**。Round 14 的签名墙被绕过。

### 完整可行的二进制 patch 工具链(已验证)
1. patch `VASCODSK` 二进制指令（绕过检测判定）
2. `ldid -S <file>` adhoc 重签
3. `sudo cp` 替换进 `China.app/Frameworks/VASCODSK.framework/VASCODSK`（chown _installd）
4. `sudo /var/jb/basebin/jbctl rebuild_trustcache` 信任新 cdhash
5. `uiopen --bundle` 启动 → 加载成功

备份在 `/tmp/VASCODSK.orig`。改 Bundle 可逆（cp 回原库 + rebuild_trustcache）。

### 剩余:定位 patch 点 + 完整性自检
- 子代理正在反汇编 VASCODSK 找：越狱检测判定地址、退出触发、完整性自检。
- 若 VASCODSK 自校验 __TEXT（patch 后 hash 变会被发现）→ 需一并 patch 掉自检，或
  改成"不改磁盘、只在运行时用 tweak patch 内存"（但那又回到 hook 时机问题）。
- 若主二进制/RASPFramework 校验 VASCODSK 的 hash → 也要处理。
- **关键有利点**：检测的判定/分支是普通 arm64 代码，patch 改指令直接生效，不受裸 syscall 影响。

## Round 16（2026-08-21,验证主二进制不校验 VASCODSK hash）

用 adhoc 重签版(逻辑未改、仅 hash/签名变)启动:App 行为**与原版完全一致**
(存活 ~300ms 后检测退出),没有因 hash 不符提前崩。

⇒ 证明两点:
1. **主二进制 / RASPFramework 不校验 VASCODSK 的文件 hash**——patch VASCODSK 不会被上层发现。
2. patch VASCODSK 的逻辑改动会真正加载执行。

**二进制 patch 路径的前置条件全部验证通过**:
- ✅ VASCODSK 未加密可反汇编
- ✅ adhoc 重签 + jbctl rebuild_trustcache 能让改动的库被 dyld 接受(Round 15)
- ✅ 上层不校验 VASCODSK hash(Round 16)
- ✅ Bundle 可写、可逆(备份 /tmp/VASCODSK.orig)

**唯一剩余未知 = VASCODSK 是否自校验自己的 __TEXT**（子代理正在查）。若无自检,patch 检测
判定点即可成功;若有自检,需一并 patch 自检。

现在等子代理定位:检测判定指令地址 + 退出触发 + 自检。拿到后即可实施 patch。

## Round 17（2026-08-21,重大转折 —— 检测源不是 OneSpan!）

子代理彻底核实 **VASCODSK 里没有任何越狱检测**(0 svc、无检测字符串、import 表无
sysctl/csops/ptrace/mmap/mprotect,纯 Digipass OTP 库)。RASPFramework/MobileSecurity 同样无。
**之前所有"检测在 OneSpan/VASCODSK C 层内联 svc"的假设被证伪。** China 主二进制自身也
0 svc、无 mmap/sysctl import、无实际越狱路径字符串。

### 扫描全部 framework 的 import,找到真正的检测源

扫 China.app 所有 framework 的 `nm -u`,找 import mmap/mprotect/sysctl/csops/ptrace 的:

| framework | 可疑 import | 性质 |
|---|---|---|
| **TuringShieldPluginKit** | _mmap _sysctl | **腾讯 Turing 盾风控** |
| **TransmitSDK3** | (Swift) | **Transmit Security,含 libDeviceSecurityAssessment** |
| **TMXProfiling** | _mmap _sysctl _sysctlbyname | **ThreatMetrix(12 处 svc!)** |
| RemoteSale | _mmap _mprotect _sysctl | 有 mprotect(能生成 RWX) |
| BioCatchSDK/TransmitSDK3/TuringShield/... | _sysctl 等 | 各类风控/生物识别 |

### 三个明确的检测源(都未加密、明文可分析)

1. **TuringShieldPluginKit**(腾讯 Turing 盾,744KB,0 svc):**明文越狱路径字符串全在**
   (`/var/jb/Applications/Sileo.app`、`/Library/MobileSubstrate/...`、Cydia、apt),
   且有 ObjC 方法 **`isJailbrokenEnvironment:`** ← 最理想,可 hook 也可 patch。
2. **TransmitSDK3**(Transmit Security,4MB,0 svc):`libDeviceSecurityAssessment.JailbreakCheck`
   枚举列出全部检测手段:urlSchemes/symbolicLinks/existenceOfSuspiciousFiles/
   suspiciousFilesCanBeOpened/restrictedDirectoriesWriteable/dyld/fork,`isJailbroken`(Swift)。
3. **TMXProfiling**(ThreatMetrix,479KB,**12 处 svc**):可能是用内联 svc 的那个。

### 意义
- 之前"用户态 hook 全零命中"可能是因为 hook 错了对象(盯 OneSpan)。真正检测在这些 SDK。
- TuringShield 的 `isJailbrokenEnvironment:` 是 ObjC 方法,能 swizzle(abcbypass 路径可用)。
- 二进制 patch 工具链(Round 15-16)已就绪,可直接用于这些 framework。

### 下一步
1. 优先分析 TuringShieldPluginKit（明文 + ObjC 方法,最好下手）:定位 `isJailbrokenEnvironment:`
   调用链,先试运行时 hook 观测它是否被调用、何时。
2. 分析 TransmitSDK3 的 JailbreakCheck、TMXProfiling 的 12 处 svc。
3. 判断哪个 SDK 的检测触发了退出（可能多个并存,需逐个验证）。

## Round 18（2026-08-21,真凶锁定 = ThreatMetrix (TMXProfiling)★）

TMXProfiling(ThreatMetrix,LexisNexis 反欺诈/RASP SDK,479KB,未加密)**含 12 处内联
`svc #0x80`**,是唯一用内联 syscall 的 framework。这就是"检测源"。

### 它自己实现 syscall wrapper 绕开 libc(所以我们 hook libc 全零命中)

反汇编 0x4a38 是个 `access` 的裸 syscall wrapper:
```
0x4a38: stp x29,x30,[sp,#-0x20]!
0x4a3c: stp x16,x17,[sp,#0x10]
0x4a40: mov x16, #0x21      ; 33 = SYS_access
0x4a44: svc #0x80           ; 直接 syscall,不调 libc access()
0x4a48: ldp x16,x17,[sp,#0x10]
0x4a50: ret
```
syscall 号:`0x21`(33=access,查越狱文件存在)、`0x9d`(157)、`0xca`(202=sysctl,查被调试)。

⇒ **这解释了之前所有零命中**:ThreatMetrix 用自实现的 svc wrapper 调 access/sysctl,
完全绕开 libc 符号,MSHookFunction hook libc 的 access/sysctl/stat 当然抓不到。
检测和退出都在 TMXProfiling 内。

### 从 OneSpan 死胡同中走出

- 之前 10+ 轮 + 本 session 前半都盯错了对象(OneSpan/VASCODSK)。真凶是 ThreatMetrix。
- ThreatMetrix **未加密、可反汇编、可 patch**,patch 工具链(Round 15-16)已就绪。
- 可能还有其他检测源(TransmitSDK3 的 libDeviceSecurityAssessment、TuringShield),
  但 ThreatMetrix 的内联 svc 最符合观测到的"绕开所有 hook + 静默退出"。

### 下一步:分析并 patch TMXProfiling
1. 反汇编 TMXProfiling,定位:哪些函数调这些 svc wrapper 做越狱判定;判定结果如何流向退出;
   是否有完整性自检。
2. 找退出触发点(它有 mmap import,RWX stub 可能它生成)。
3. patch 检测判定(改分支/返回未越狱)或退出触发 → ldid 重签 → 替换 → rebuild_trustcache → 测试。
4. 委托子代理做 TMXProfiling 深度反汇编。

## Round 19（2026-08-21,首次 patch 实验 —— Transmit 非真凶）

### 子代理 TMXProfiling 报告修正
- TMXProfiling 12 处 svc:mprotect(74)/getpid(20)×2/bind(104)/close(6)/socket(97)/
  setsockopt(105)/access(33)×2/statfs(157)/sysctl(202)/stat(188)。**没有 exit/kill/ptrace**,
  这 12 处 svc 里没有直接终止进程的。
- 检测函数 0x15090:遍历加密路径字符串,调 stat/fstatat 查存在性,结果只是把标记 "C" 塞进
  profile 上报数据(0x282ac 调用点),**未见它自己调 exit/abort**。
- TMXProfiling 有**控制流扁平化**(0x7b5c 分发器被 984 处调用)+ 字符串混淆,静态难还原。
- CC_SHA256/CCHmac 疑似校验配置文件非自身 __TEXT,自检未确证。

### patch 工具链验证成功(重要)
- **TransmitSDK3 用开源 IOSSecuritySuite**:`amIJailbroken`(0x12b16c)、`amIReverseEngineered`。
- patch `amIJailbroken` → `mov w0,#0; ret`（`00008052 c0035fd6`,VA==fileoff）。
- 部署踩坑:首次 ldid -S 后 dyld 报 `code signature invalid errno=1`;重做一遍
  (ldid -S 生成 CandidateCDHash → cp → rebuild_trustcache)**成功加载**,探针注入(pid 变化)。
  → **patch+重签+trustcache 工具链对 4MB framework 也可行**(注意 ldid 要确认生成了 CDHash)。

### 实验结果:patch Transmit amIJailbroken 后 App 仍退出(~300-400ms,行为不变)
⇒ **TransmitSDK3 不是触发退出的检测源**(其越狱检测可能只用于风险上报,不杀进程)。
真凶仍未定位。多个风控 SDK 并存,需继续。

### 下一步
- 候选剩:TMXProfiling(0x15090 检测/上报)、TuringShieldPluginKit(isJailbrokenEnvironment:)、
  BioCatchSDK、RemoteSale(有 mprotect,能生成 RWX!)、ChinaFacialRecognition 等。
- 更高效:用 tweak(能注入)hook TMXProfiling 的 svc wrapper 地址 + 各 SDK 检测入口,
  运行时记录谁被调用、时序,而非逐个 patch 盲试。
- 或抓一份无 tweak 的完整裸崩溃日志(线程更全)看哪个 framework 在退出线程栈上。

## Round 20（2026-08-21,关键发现:SDK 有反 inline-hook 自检）

动态插桩实验(hook TMX 的 access/stat wrapper + Transmit amIJailbroken)发现:

| tweak 配置 | 存活 |
|---|---|
| 纯心跳,不 hook 任何 SDK 函数 | ~374ms(#30,基线) |
| MSHookFunction hook Transmit amIJailbroken(0x12b16c) | **立即退出(心跳 #0 都没输出)** |
| MSHookFunction hook TMX access/stat wrapper | **立即退出** |

⇒ **这些 SDK 有反 inline-hook 自检**:MSHookFunction 改函数头字节(插跳转)会被检测到,
触发即时退出(比正常越狱检测的 ~374ms 快得多)。

### 重大结论:必须二进制 patch,运行时 hook 必被反制
- 运行时 `MSHookFunction`/fishhook 改内存指令 → SDK 自检发现 → 秒杀。这解释了本 session
  以及历史所有"hook 尝试"失败的另一层原因(不只是时机,还有反 hook 自检)。
- **二进制 patch(改磁盘 + 重签 + trustcache)是正确路径**:patch 后内存里是完整正常指令,
  无 hook 跳转痕迹,不触发反 hook 自检。裸崩不产生 crash log 也符合(自检退出走 svc)。
- patch Transmit amIJailbroken 时 App 仍存活到 ~300ms(Round 19)→ 说明 patch 本身不触发
  反制(对的),只是 Transmit 非触发退出的检测源。

### 下一步:策略3 批量二进制 patch
逐个/批量 patch 各 SDK 的越狱判定函数(改返回未越狱),用二进制 patch(非 hook)避开自检:
1. 已 patch:Transmit amIJailbroken(无效,非真凶)。
2. 待 patch:TMXProfiling 0x15090(检测函数)、TuringShield isJailbrokenEnvironment:、
   BioCatchSDK、RemoteSale、ChinaFacialRecognition 等。
3. 一次 patch 多个 → App 若存活 → 二分定位真凶。
4. 注意:patch 要避开各 SDK 可能的完整性自检(改磁盘 hash 变);但 Round 16 已证上层不校验
   framework hash,SDK 自身若校验 __TEXT 需一并处理。

## Round 21（2026-08-21,逐个 patch 排除 + 定位剩余 SDK）

二进制 patch(不被反制)逐个测试判定函数:
- **Transmit amIJailbroken(0x12b16c)** patch 返回0 → App 仍 ~376ms 退出。**排除**。
- **TMX 检测函数 0x15090** patch 返回0 → App 仍 ~376ms 退出。**排除**(或 0x15090 非关键点)。

基线存活稳定 ~376ms(#30)。已确认 patch 机制对 TMX/Transmit/VASCODSK 都能重签加载成功。

### 重要线索:RWX stub 生成者 = 有 mprotect 的模块
崩溃日志退出机制是"跳动态 mmap 的 RWX stub"。生成 RWX 需 mprotect(+EXEC)。
import `_mprotect` 的只有 **RemoteSale**(29MB)和 TMX(内联 svc mprotect@wrapper 0x41ec)。
→ **RemoteSale 是重点嫌疑**(它能生成 RWX stub)。

### 进行中
- 子代理批量定位 TuringShieldPluginKit(`isJailbrokenEnvironment:`)和 BioCatchSDK
  (`JailbreakModelEx`)的判定函数地址 + patch 方案。
- 待查:RemoteSale 的 mprotect 用途(是否生成退出 stub)。
- 候选真凶优先级:Turing(明文越狱路径,最像专门检测)> RemoteSale(能生成RWX)> BioCatch。

## Round 22（2026-08-21,继续排除:Turing/BioCatch 也非真凶）

子代理给出精确 patch 点:
- Turing `+[...isJailbrokenEnvironment:]` @0x5ba10(位掩码访问器,`ubfx x0,x2,#27,#1`)
  → patch `mov w0,#0;ret`。
- BioCatch isRooted 落地点 @0xa9ba0(`and w8,w23,#0x1`)→ patch `and w8,wzr,#0x1`。

patch 两个 + 重签(注意:ldid -S 要验证生成 CandidateCDHash,否则加载失败 Library not loaded)
+ rebuild_trustcache,加载成功,但 **App 仍 ~379ms 退出**(基线不变)。

### 已排除的检测源(patch 判定函数后 App 仍退出)
Transmit(amIJailbroken)、TMX(0x15090)、Turing(isJailbrokenEnvironment:)、BioCatch(isRooted)。

⇒ 这些 SDK 都是"检测→存结果→上报服务端"模式,**不直接触发退出**。真凶不在这批风控 SDK 的
越狱判定函数。

### 重新聚焦:主 App China 自己的越狱判定+退出
- 崩溃在 `notifyObjCInit`(初始化阶段),主二进制 China 有 `isJailbroken`/`jailbreak6status`
  /`XChinaJourney.DeviceInfoConfiguration(isJailbroken:isRooted:)` 符号。
- 最可能:**China 主 App 自己检测越狱(或读取某 SDK 结果),然后自己决定退出**。
- 之前 hook China 的 AppSecurityMonitor ObjC 方法没被调用——但那是 OneSpan 的;China 自己的
  Swift 越狱判定(jailbreak6status)可能才是。
- 也可能是某个没排查的 framework(RemoteSale 有 mprotect 能生成 RWX stub;
  ChinaFacialRecognition/HKEApi/Sensors/Tealium 等)。

### 签名工具链注意(重要)
`ldid -S` 偶发不生成有效签名 → dyld `Library not loaded`(签名无效)。**必须验证
`ldid -h <file>` 输出含 `CandidateCDHash` 再部署**,然后 `jbctl rebuild_trustcache`。

## Round 23（2026-08-21,退出机制深挖 + fishhook 可用性）

### fishhook(GOT hook)不被反制 —— 重要的可用手段
用 fishhook 改 GOT hook mmap/mprotect(不动函数头),App 存活基线 384ms **没被秒杀**。
⇒ **fishhook/GOT hook 不触发反 inline-hook 自检**(区别于 MSHookFunction 改函数头被秒杀)。
这为"tweak 方案"保留了一条路:能 hook 的是 libc 导入符号(GOT),但 SDK 用内联 svc 的调用抓不到。

但 fishhook mmap/mprotect **零命中 PROT_EXEC** → RWX stub 不走 libc mmap/mprotect 的 GOT,
用内联 svc(TMX 式)或 mach vm_protect 生成。

### ★崩溃日志关键指纹:LR=0xcafebabe
重新深挖唯一完整崩溃日志(143428,无 tweak):触发线程
- PC=0x1162f4000(RWX stub),**LR=0xcafebabe**,x20=0x1162f8000(stub 尾)
- usedImages 只有 dyld + 一个 base=0 伪 image → 崩溃在 dyld 初始化**极早期**
- `0xcafebabe` 是故意设的魔术值(也是 Mach-O FAT magic),典型反篡改自毁标记
- 静态搜所有 SDK 无 `0xcafebabe` 字节 → 运行时用 mov 构造,静态抓不到

### 已排除检测源(patch 判定后仍退出)
Transmit/TMX/Turing/BioCatch 的越狱判定函数。它们是"检测→上报"型,不触发退出。

### 现状判断
- 触发退出的是**运行时动态生成的自毁 stub**,生成方式绕开静态/GOT-hook 点(内联 svc/vm)。
- 由某模块检测越狱后触发,该"检测→自毁"链未定位(可能在主 App China 或 RemoteSale)。
- 子代理正在查 RemoteSale(有 mprotect,RWX 生成嫌疑)。

### 交付形态判断(回答"能否用 tweak")
- inline-hook tweak:❌ 被反制秒杀。
- fishhook/GOT tweak:✅ 不被反制,但只能 hook libc 导入,抓不到内联 svc,对本检测可能不够。
- binary patch:✅ 前置条件全通,但要先定位"检测→自毁"链的 patch 点。
- **tweak 内存 patch(不 hook,直接改目标模块指令)**:理论可行且不被 inline-hook 自检发现
  (改的是别的模块的指令,不是自己 hook),但需先定位 patch 点 + 确认无周期性 __TEXT 自检。

## Round 24（2026-08-21,动态定位真凶的多种尝试）

为定位"检测→退出"触发点,试了多种不被反制的动态观测,均未直接命中:
- **fishhook mmap/mprotect**(GOT,不被反制):零命中 PROT_EXEC → RWX 不走 libc GOT。
- **mach 异常端口抢 EXC_BAD_ACCESS**:有 tweak 时不触发异常(退出走静默 svc exit,非 stub 崩溃)。
- **task_threads 枚举 + thread_get_state 采样所有线程 PC**(300us 间隔):零命中 App 模块
  → 检测线程执行极快,采样错过;或不在预期模块。

### 关键区分:有无 tweak,退出路径不同
- **无 tweak**:曾产生 SIGBUS 崩溃日志(143428,PC=RWX stub,LR=0xcafebabe)。但现在裸跑
  (无 tweak)也**不再产生崩溃日志**,说明常态退出是**静默 svc exit**,那次 SIGBUS 是特例。
- **有 tweak**:一律静默 svc exit(~380-460ms),无异常、无崩溃日志、无 libc 退出调用。

### 已确认的可用/不可用手段(交付形态依据)
- MSHookFunction(改函数头):❌ 被反 inline-hook 自检秒杀。
- fishhook(改 GOT):✅ 不被反制,但只能 hook libc 导入,抓不到内联 svc。
- mach 异常端口 / task_threads 采样:✅ 不被反制(不 hook),但抓不到极快的内联 svc 检测。
- binary patch:✅ 不被反制,但逐个 patch SDK 判定函数(Transmit/TMX/Turing/BioCatch)均无效。

### 困境
真凶是"检测越狱→内联 svc 退出"的链,执行极快、用 svc 绕开所有可观测点,且不在已排除的
4 个 SDK 的判定函数里。候选剩:主 App China 自身逻辑、RemoteSale(子代理分析中)、
或其他未排查 framework。静态因 Swift 符号剥离/混淆难定位,动态因 svc 极快难捕获。

## Round 25（2026-08-21,全 framework svc 扫描 + 退出机制再定性）

字节级扫描 App 全部 framework 的 `svc #0x80`(011000d4,仅 4 字节对齐的才是代码):
- 有 svc 的:TMXProfiling(access/statfs/sysctl)、TMXBehavioSec(同)、TMXProfilingConnections、
  RemoteSale(OpenSSL 内)。**syscall 号全是 access(33)/statfs(157)/sysctl(202),无 exit(1)/ptrace(26)。**
- XChinaJourney/hsbcchinax 的 "svc" 未对齐 → 是数据里的巧合字节,非代码。
- **China 主二进制:0 处 svc**(字节级确认)。China initializer(0x1000196f4)是全局对象构造,非检测。

### 退出机制的逻辑矛盾(重新定性)
进程退出:❌ 不走 libc exit/abort/kill(hook 零命中);❌ 无内联 svc exit(全扫无 exit syscall);
❌ 常态不产生崩溃日志(那次 SIGBUS 143428 是特例)。那进程如何消失?

**新假设:被外部 SIGKILL(不可捕获,无记录)。** 佐证:每次启动稳定出现**两个 China 进程**
(ppid 都=1)。可能是:看门狗进程检测越狱后 kill 主进程,或子进程 kill 父进程。
SIGKILL 不可捕获、不产生 crash log、不触发信号/mach handler —— 完美符合所有观测。

### 下一步(全新方向)
1. 验证"双进程 + 外部 kill"假设:root 高频监控两个 China 进程的生死顺序,看谁先死、
   是否一个 kill 另一个(hook kill 零命中是因为 kill 调用在**另一个进程**里,我们只注入了被杀的那个)。
2. 若确认是伴生进程 kill:需在**发起 kill 的进程**里注入/拦截,或阻止伴生进程启动。
3. 若是同进程内:重新审视 China Swift 代码里调用 exit 的高层封装。

### 已彻底排除
所有第三方风控 SDK(Transmit/TMX系列/Turing/BioCatch/RemoteSale/OneSpan)的检测→退出;
China 内联 svc;China initializer。

## Round 26（2026-08-21,MAX effort — _exit import 收敛到 XChinaJourney ★）

### 决定性收敛:主 App China 无任何退出能力,只 4 个 framework import _exit
- **China 主二进制 import 表:无 exit/abort/kill/terminate/syscall,0 svc** → China 不亲自退出。
- ThreatMetrix 三兄弟(TMXProfiling/BehavioSec/Connections)的 svc 网关只有
  access/statfs/sysctl/mprotect/getpid/socket,**无 exit/ptrace/kill stub** → 检测不退出,排除。
- 全 framework 扫 import `_exit`(直接终止 syscall 封装),只有 4 个:
  - **XChinaJourney**(汇丰核心 journey 模块,38MB,启动即加载,含
    `DeviceInfoConfiguration(isJailbroken:isRooted:)`)← ★头号嫌疑
  - ChinaFacialRecognitionJourneyPluginKit(人脸,启动未必跑)
  - DidvJourneyPluginKit(DIDV,启动未必跑)
  - RemoteSale(已排除)

⇒ **退出动作最可能是 XChinaJourney 调 `_exit`**。之前 hook libc _exit 零命中的原因待查
(可能:被反制/调用的是自身 GOT 未走 libc 本体/时机)。

### 退出机制再定性(排除法收敛)
进程 `(China)` zombie 态自己退出 + 无 mach 异常(BAD_ACCESS/BREAKPOINT/BAD_INSTRUCTION/
ARITHMETIC/GUARD/SOFTWARE 全抓零命中)+ 无 libc exit hook 命中 → 是 `_exit`/`exit_group`
syscall(正常退出,非崩溃、非信号)。由 import _exit 的 framework 执行。

### 下一步(聚焦 XChinaJourney)
1. 定位 XChinaJourney 里 `_exit` 的 GOT stub 及所有调用点,反汇编调用链,找"检测越狱→_exit"。
2. patch 那个调用点(把 bl _exit 改 nop,或把检测判定分支反转)。
3. 验证:patch XChinaJourney 后 App 是否存活。
