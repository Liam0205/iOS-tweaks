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

## Round 27（2026-08-21,MAX — 定位 XChinaJourney 唯一 _exit 调用点 ★★）

用 chained-fixups 脚本(tmp/xchina_chained.py)解析 XChinaJourney GOT:
- `_exit` GOT VA=0x2041af8,`_mmap`=0x2042088,`_sysctl`=0x2042700,`_abort`=0x20418a8。
- XChinaJourney **同时具备 _sysctl(检测)+ _mmap(RWX)+ _exit(退出)** 能力,真凶画像完整。

追踪调用链:
- 引用 _exit GOT 的代码只有 __stubs 里的 `_exit` stub @ **0x1b91594**(adrp+ldr 0xaf8+br)。
- `bl 0x1b91594`(调 _exit)全 framework **只有 1 处:0x180abc0**。
- 0x180abc0 上下文:
  ```
  180abb8: bl 0x1809138        ; 前置(打印/上报?)
  180abbc: orr w0, wzr, #0x1   ; w0=1 (退出码)
  180abc0: bl 0x1b91594        ; _exit(1)  ★唯一退出点
  ```
- 该退出函数(入口 0x180ab98)无直接 bl 调用者,通过对象 vtable(0x180ab40 处构造,存函数
  指针 slot)间接 blr 调用 → 混淆的间接派发,所以之前静态难追。

### ★ patch 方案(最接近成功)
- 目标:XChinaJourney 文件偏移 **0x180abc0**(VA==fileoff,__TEXT vmaddr=0)
- 原字节:`bl 0x1b91594` = `75 1a 0e 94`
- patch 为:`nop` = `1f 20 03 d5`
- 效果:唯一的 _exit(1) 调用变 nop,检测触发到这里也不退出。
- 风险:若此 _exit 有正常业务用途会有副作用;但它是全 framework 唯一 _exit + 退出码1,
  高度像"检测→异常退出"。先实验验证。

## Round 28（2026-08-21,MAX — 确证退出=内联 svc,非任何函数封装）

hook 全套底层退出封装(dlsym 取真实地址 + MSHookFunction):
exit@0x1ca8336dc、_exit/__exit@0x1f721cf34(libsystem_kernel 同一 syscall 封装)、
abort、pthread_kill、abort_with_reason、abort_with_payload。**全部 hook 成功,全部零命中。**
(exit_group 在 iOS 不存在)。进程 ~261ms 静默退出。

⇒ **退出不经过任何 libc/libsystem 退出函数,确证是内联 svc(mov x16,#1/#59; svc #0x80)。**
- patch XChinaJourney 的 _exit stub + _abort stub 为 ret → App 仍退出(排除 XChinaJourney)。
- 全 framework 扫 `mov x16,#1/#59` → China 0 处;各 framework 也无明文 exit stub。
- 唯一可能:**ThreatMetrix 通用 svc 网关**(TMXProfiling/BehavioSec/Connections 的 0x4010/
  0x4068,`ldr x16,[sp,#0x10]; svc`,syscall 号从栈传入)被传入 exit(1)。静态看不到栈值。

### 关键疑点:ThreatMetrix 通用 syscall 网关
- 0x4010: `svc; ldp x16,x17,[sp,#0x10]; ...` — x16 之前由 `ldr x16,[sp,#0x10]` 从栈加载
- 这种"通用 syscall 分发器"能调**任意** syscall 号,包括 exit(1)/exit_group(59)。
- 之前判断"TMX 检测不退出"是基于它没有 `mov x16,#1` 的明文 exit stub,但**网关+栈传号可绕过**。

### 下一步(不惜代价)
1. 动态抓网关的 syscall 号:MSHookFunction hook 网关地址记录 x16(可能被反制,试)。
2. 或 patch 网关:x16==1/59 时跳过 svc(拦 exit 不影响其他 syscall)→ 看 App 是否存活。
3. 若 TMX 网关确实调 exit → 找调用网关传 exit 的上游(检测判定)→ patch 判定或拦 exit。

## Round 29（2026-08-21,MAX — 重大方法论疑点:退出可能是 SSH uiopen 假象 ★★★）

### 退出机制在技术上"无处可寻"
穷尽确认,退出**不经过**:
- 任何 libc/libsystem 退出封装(exit/_exit/__exit/abort/pthread_kill/abort_with_reason/payload
  全 hook 零命中)
- 内联 svc exit:全 App(China + 150+ framework)**无任何 `mov x16,#1; svc` 或 `#59`**
  (hsbcchinax/TechnicalPlatform 的 mov x16,#1 后不接 svc,是普通代码/数据)
- XChinaJourney 的 _exit/_abort stub(patch 成 ret 后仍退出)
- 无崩溃日志、无 mach 异常(全掩码零命中)、无信号

### ⇒ 退出极可能不是 App 自己发起,而是外部 SIGKILL
SIGKILL:不可捕获、无 crash log、无 svc、无异常 —— **完美符合所有观测**。

### ★核心疑点:我一直用 SSH `uiopen --bundle` 启动,可能是假象
- SSH uiopen 拉起的 App **不是正常用户前台启动**,可能因 FrontBoard 场景未正确建立/
  非前台/看门狗,被 SpringBoard 用 SIGKILL 回收(~260-500ms 很像场景建立超时)。
- 双进程先后启动、(China) zombie 态、存活时间随机波动 260~500ms —— 都更像**系统回收**
  而非越狱检测的确定性退出。
- **我可能追了 29 轮一个非越狱检测的现象!** 之前 4 个 SDK/XChinaJourney patch"无效",
  可能因为它们本来就不是退出原因——退出是 uiopen 启动方式导致的系统回收。

### 必须验证(用户设备端)
请用户**亲手点图标**启动汇丰中国,肉眼看:是立即闪退(越狱检测)?还是能进入界面/停留更久?
对比 SSH uiopen 的 260ms 退出。若点图标能正常/久留 → 之前的"退出"是 uiopen 假象,
真正的越狱检测行为需要重新用点图标观测。

## Round 30（2026-08-21,MAX — 定位退出模块=hsbcchinax OLLVM 混淆状态机 ★★★）

### 主线程 PC 采样(环形缓冲抓退出瞬间)决定性定位
高频采样主线程 PC(环形缓冲留最后60条),退出前主线程执行点:
- **438/450+ 采样在 `hsbcchinax`**(其他模块个位数噪声)→ 退出代码在 hsbcchinax。
- 退出瞬间最后热点:`hsbcchinax+0x630430`(状态机节点)、`+0x65bfa8`(hash 循环)。
- 调用来源 LR:hsbcchinax+0x43ccd0 / 0x3802b0 / 0x713ec8 等(多入口调同一逻辑)。

### hsbcchinax = 汇丰核心扩展,退出逻辑用 OLLVM 控制流扁平化混淆
- hsbcchinax **import 无 exit/abort、svc=0**(llvm-objdump)——自己不直接退出,间接调用。
- 0x630430 反汇编:大量 `cmp w17,wN; b.eq/b.ne` + magic 常量(0xcd1/0x5393、0x1a26/0x1d34)
  = 典型 **OLLVM 控制流扁平化 dispatcher**。0x65bfa8 是 madd/ror/mul 的 hash 循环。
- 检测+退出决策都在这段混淆代码里。这是最后的硬骨头。

### 确认的完整定位链(30轮收敛)
真凶 = **主二进制 China + hsbcchinax**(汇丰自研)的越狱检测,不是任何第三方风控 SDK。
- 检测逻辑:hsbcchinax 的 OLLVM 混淆状态机(0x630430 区 / 0x65bfa8 hash)。
- 退出:间接调用(具体退出 syscall 点仍被混淆隐藏,无 svc/exit import 说明可能跳转到
  其他模块的退出封装,或运行时解密的 stub)。
- 主线程绝大部分时间在此执行直到 ~500ms 退出。

### patch 策略候选
1. 反混淆 hsbcchinax 的 OLLVM dispatcher,定位"越狱判定→退出"分支,patch 分支。工作量大。
2. 找 hsbcchinax 如何间接调用退出(它无 exit import,但主线程从这里退出)——追 0x630430
   状态机的出口跳转,可能跳到某 framework 的退出封装或函数指针表。
3. 二分:patch hsbcchinax 的 0x65bfa8 hash 循环 / 0x630430 状态机入口,看能否阻断。

## Round 31（2026-08-21,MAX — 检测入口=hsbcchinax +load,patch 0x43c118 暴露调用栈 ★★★）

patch hsbcchinax 0x43c118(采样最热调用者)入口为 ret → App 存活延长(376→501ms)且
**退出变成 SIGSEGV 崩溃**(原本静默),崩溃栈完整暴露检测入口链:
```
dyld runInitializersBottomUp → notifyObjCInit → libobjc load_images
  → hsbcchinax+0x43e104 (+load 里的调用)
  → hsbcchinax+0x43e0fc
  → hsbcchinax+0x93924 → 0x93964 → 0x939b8 → 0x939ec → 0x93ab0 → 0x93b64 (崩)
```

### 决定性:检测在 hsbcchinax 的 ObjC `+load`(启动最早期)
- **`load_images → hsbcchinax+0x43e104`**:hsbcchinax 有 `+load` 方法,启动最早期(dyld
  notifyObjCInit 阶段,正是崩溃日志一直显示的阶段)就跑检测。
- 检测核心函数链:`+load`(0x43e0fc/0x43e104)→ 0x43c118(检测,OLLVM 混淆)→ 0x93xxx 区。
- 0x93924-0x93b64 是检测的子逻辑(之前采样热点 0x93a10/0x93c30 也在此)。
- patch 0x43c118 整体 ret 太粗暴(破坏返回值→野指针 SIGSEGV),但**证明这条链就是检测**。

### 下一步(精确 patch)
1. 反汇编 hsbcchinax `+load` 链:0x43e0fc(load 方法)、0x93924 区(检测子函数),
   找"判定越狱→退出"的精确分支,精细 patch(不破坏返回值)。
2. 或:找 hsbcchinax 的 `__objc_nlclslist`(+load 类)确认 load 方法,从源头让 load 不检测。
3. 子代理正在反混淆 0x630430/0x65bfa8 区,结合这条 +load 链定位判定分支。

## Round 32（2026-08-21,★★★ 决定性转折:JB 退出已绕过,现卡在 +load 自旋 → 启动看门狗）

### 实测证据(自取设备日志)
用户点图标启动,截图见汇丰启动页(红白 logo + 支持IPv6 + 备案)停留 ~20s 后消失。拉日志:
- 探针 pid 27769 心跳一直跳到 +19306ms(#1550)才停(此前基线只有 374ms/#30)。
- 崩溃日志 China-2026-08-21-195054.ips(root 可读):
  - EXC_CRASH / SIGKILL,namespace FRONTBOARD,code 0x8BADF00D
  - "process-launch watchdog transgression: ...:27769 exhausted real (wall clock)
    time allowance of 20.00 seconds",ProcessVisibility: Foreground
  - CPU:20s 窗口烧了 16.8s app CPU(~30% CPU)= 忙自旋,不是等网络。
- 线程0(主线程,triggered)调用栈仍在 hsbcchinax 的 +load 里:
  dyld notifyObjCInit → libobjc load_images → hsbcchinax+0x43e0fc → 0x43d6fc →
  0x5d87a4 → hsbcchinax+0x7128c0(PC 卡在此)。

### 关键重定性:不再是越狱检测!
- 越狱"检测→退出"已被绕过(不再 374ms 秒退)。现在死因是 iOS 启动看门狗:
  主线程 20s 没从 +load 返回 → main() 从未执行 → 看门狗 0x8BADF00D 杀进程。
- 用户看到的"启动页"是 LaunchScreen 启动图(main 没跑),不是真 UI。
- 双进程:27743/27765(89B)仍 374ms 死(旧路径/prewarm);27769 加载 patch 版
  hsbcchinax,在 +load 自旋 20s。

### 根因 = 上一次(Round 31 后,未记录)的 patch
diff app-binary/hsbcchinax(pristine,md5==设备 /tmp/hsbcchinax.orig)vs 设备部署版:
- 唯一代码改动:文件偏移 0x22910c 一条指令(其余 8B 头部 + 68920B 是 ldid 重签 __LINKEDIT)。
- 原始:mov w0,#1 (0x22910c) ; b 0x38d974 (0x229110,尾调用独立函数 0x38d974,
  该函数内 0x38d9c4 调 0x93900——正是 +load 链上的函数)。
- 我改成了:ret (d65f03c0)——粗暴早返回,跳过尾调用 0x38d974 的后续初始化。
- 效果:从"374ms 秒退"→"+load 自旋 20s 被看门狗杀"。⇒ 0x22910c 确在 +load 检测路径上,
  ret 绕过退出但破坏初始化流,使 OLLVM dispatcher(入口 0x712668,热点 0x7128c0,
  由 0x5d87a0 bl 0x712668 调用返回 bool)陷入非终止自旋。

### 假设 H1(领先)vs H2
- H1(patch 破坏控制流):ret 丢返回值/跳过 0x38d974,dispatcher 0x712668 输入被破坏,
  状态机走不到终止态 → 死循环。领先:此前对其它 framework 的 binary patch(Round 19-22)
  都能加载运行到 ~376ms 无即时反制,无"改磁盘即自旋"的完整性反制。
- H2(反篡改故意自旋):可能性低,理由同上。

### 下一步(委托子代理深挖 static RE)
目标:让 +load 正常完成并返回(不退出、不自旋)。候选:
1. 0x22910c 从 ret 改回不破坏流的形式(如 mov w0,#0; b 0x38d974 中和标志但保留尾调用),
   实测 +load 是否跑完。
2. 定位 dispatcher 0x712668 的真实"越狱判定分支"与终止条件,做最小 patch。
3. 备份齐全(/tmp/*.orig + 本地 app-binary/),改动可逆。

## Round 33（2026-08-21,landing-pad patch 变体实验 + 工具链修正）

### 工具链修正:必须用设备原生 ldid 签名
- linuxbrew ldid 生成 sha1+sha256 双 hash → dyld 拒绝加载(SIGKILL CODESIGNING)。
- 设备 /var/jb/usr/bin/ldid 生成 sha256-only → 被 trustcache 接受,可加载。
- 新流程(patchtest.sh):本地 patch → scp 未签名到设备 → 设备 ldid -S → cp 进 Bundle →
  chown _installd → jbctl rebuild_trustcache → uiopen 观测。已跑通。

### 实验:0x22910c 三种取值
| 0x22910c | 行为 | 解读 |
|---|---|---|
| mov w0,#1(pristine) | 374ms 静默退出 | 原始越狱退出 |
| ret(Round 31/32) | +load 自旋 20s → 看门狗 0x8BADF00D | 跳过 0x38d974,破坏 dispatcher 流 |
| mov w0,#0(本轮) | +504ms(#40)后 SIGSEGV,KERN_INVALID_ADDRESS@0x0,栈损坏 | w0 非布尔门,0x38d974 用它做地址/索引计算,置0→野指针 |

⇒ **0x38d974 不是简单的 exit(flag) 门**:它拿 x0 参与(混淆的 computed blr)地址计算。
landing-pad 层的三种改法(退出/ret/flag=0)都不对。**必须在上游"越狱判定"处 patch**,
让根本不抛异常/不进这个 landing pad。等 RE 子代理定位判定分支。

### 现状
- 设备已回滚 pristine(md5 == orig),干净基线。
- patchtest.sh 就绪:`./patchtest.sh <off> <bytes> [秒]`,自动从 pristine 干净 patch+部署+测。

## Round 34（2026-08-21,★ 关键收敛:自旋在 dispatcher 0x712668 内部,非 flow 损坏)

### 高层 gate 分析(0x5d8758,+load 子树,调用者 0x43c690/0x43d6f8)
```
5d8778 ldrb w8,[x0,#0xa]; cbnz → 已跑过则跳过(run-once 标志)
5d878c bl 0x712664        ; init 状态对象(sp+0x18)
5d87a0 bl 0x712668        ; ★ dispatcher 状态机, 返回 w0
5d87a4 tbnz w0,#0,0x5d87e0 ; if(w0&1) 跳过被保护 body → 干净返回
5d87b4 bl 0xe4634 ...      ; 否则执行被保护工作(混淆 blr @5d87d4)
```

### 实验:强制 gate 跳过 body(0x5d87a4 tbnz → 无条件 b 0x5d87e0, 字节 0f000014)
- 结果:仍 20s 看门狗 0x8BADF00D。probe 到 +19141ms(#1510)。
- 崩溃栈 PC = **hsbcchinax+0x7126e4(dispatcher 循环头 cmp w8,w25)**,返回地址仍 0x5d87a4。
- ⇒ **自旋发生在 `bl 0x712668`(0x5d87a0)内部, dispatcher 从未返回**。我的 gate patch
  (0x5d87a4)根本没执行到。

### 决定性结论
- 自旋**不是**我之前 patch 破坏控制流导致(本 patch 是干净分支,未corrupt)。
- **dispatcher 0x712668(OLLVM 扁平化状态机)本身在越狱-且-未退出时不终止**:
  正常(pristine)路径它检测到越狱后走"退出"case(374ms 死);一旦退出被绕过/上游改变,
  状态机进入一个等待某永不满足条件的 case → 死循环在 0x7126e4 分发头。
- landing pad(0x22910c)、gate(0x5d87a4)都是 dispatcher 之外的表皮,patch 它们无效。

### 真正需要:反混淆 dispatcher 0x712668
必须定位状态机里:(a)"检测到越狱"置哪个 state 值;(b)该 state 通向 exit case 的分支;
(c)把"越狱 state"改写成"正常 state",让状态机走完正常初始化并返回 w0=1(跳过 body 且不死)。
或找到检测输入(state 变量的赋值处),从源头让它取"未越狱"值。
- hsbcchinax **无 CC_SHA/CCHmac/csops/amfi import** → 大概率无 __TEXT 自检, 磁盘 patch 可行。
- 已委托 RE 子代理反汇编此 dispatcher(进行中)。

## Round 35（2026-08-21,运行时状态机采样 —— 探针扰动目标,需降低侵入性）

### 尝试:探针 tweak 采样主线程 PC + x8/x9(状态机变量)
- dispatcher 静态区间 [0x712118,0x713400),状态变量 = w8/w9(0x712174 初始化为
  0x257df12c,与各 case 的 32-bit magic 比较选择跳转)。
- 探针每 0.5ms suspend 主线程 → thread_get_state 读 PC/x8/x9 → 命中区间记 state 值。
- 部署到 gate-skip patch(0x5d87a4=0f000014,Round34 确认能自旋到 20s)+ 探针一起跑。

### 结果:探针把结果改变了(致命扰动)
- 装了采样探针后,App 不再自旋到 20s,而是 ~460ms(#40)就退出(接近 pristine 退出时机)。
- 采样器 0 命中 dispatcher 区间(`disp pc` 一条没记)。
- 原因:每 0.5ms suspend 主线程 = 高频打断状态机;且 mach_thread_self() 每次泄漏 port。
  suspend/resume 扰动了时序,可能让 app 走了不同分支或被自身逻辑判定异常退出。

### 教训 + 下一步
- 侵入式采样(高频 suspend 主线程)不可用于这种紧循环状态机观测。
- 备选:(a)极低频采样(20ms/次,减少扰动,20s 仍能抓上千样本);(b)放弃运行时,
  依赖静态 RE(agent 已生成 87MB 全反汇编,分析中);(c)只读不 suspend(用
  thread_get_state 不 suspend,精度差但零扰动——但 Apple 要求 suspend 才能稳定读)。
- 决定:优先静态 RE(agent);运行时改用极低频采样作为交叉验证。
- 工具链提醒:替换 framework 后首次启动偶发 CODESIGNING(forEachDependentDylib),
  重建 trustcache 后重启即好(同 Round 19/22 现象)。

## Round 36（2026-08-21,RE 子代理报告 —— 重大修正 + 新方向）

### ★ SDK 身份修正:hsbcchinax = Promon SHIELD(不是 OneSpan/ThreatMetrix/自研)
strings 实锤:`no.promon.shield`、`PRMShield`、`ShieldSDK:`、gitlab `.../release/shield/...`。
之前 32 轮对"OneSpan/VASCODSK/ThreatMetrix"的归因,对 hsbcchinax 这个模块是错的——
真正跑退出的是 **Promon SHIELD**(嵌在 hsbcchinax)。

### ★ 0x22910c 修正:是 -[PRMShieldEventManager performSecurityChecks],不在 +load 静态链上
- `--objc-meta-data` 确认:类 `PRMShieldEventManager`,方法 `performSecurityChecks` imp=0x22910c。
- 全文件 0x22910c 只出现 1 次(method_t 的 imp 槽 @0x836528)。
- 我把它 patch 成 `ret` = 把这个 ObjC 方法变成返回垃圾的空 stub,**没碰真正的检测/退出逻辑**。
- 该方法静态只被 addObserver:/removeObserver: 引用,**agent 找不到它到 +load 的静态调用边**。
  ⇒ 但我的**实测**:patch 0x22910c 确实把行为从"374ms 死"变成"20s 自旋"——有可复现因果。
  reconcile:performSecurityChecks 极可能是**通过 observer/通知机制动态派发调用**的周期性/
  事件安全检查(所以没有静态 bl 边,objc_msgSend 动态分发看不到)。我 nop 它 → 检测不出
  越狱裁决(不 374ms 死)但也没完成 event bookkeeping → +load 等待检查完成的 dispatcher
  永久自旋。**即"patch 对了函数,但改法错了"(粗暴 ret 而非"返回干净裁决 + 完成记账")。**

### ★ 0x38d974 修正:不是异常 landing pad,是"调用回调+销毁"辅助函数
agent 反汇编:独立函数(自有序言),取 x0(BOOL flag)→ 经 objc_getAssociatedObject 键控的
computed blr 调用存储的回调 → 调析构 0x93900 → __stack_chk 返回。**不 throw、不 exit。**
纠正我 Round 32-33 的"异常 landing pad / __cxa_throw"假设(那是 __unwind_info LSDA 把相邻
两函数合并造成的错觉)。这解释了为何我 `mov w0,#0` 得到 SIGSEGV:破坏了回调调用的参数。

### +load 真实链路(修正)
- +load IMP=0x228f74 → 尾调 0x43e0ac(在巨型 OLLVM 扁平化函数 0x439f68-0x443a7c 内)。
- 0x43e0f8 有 `blr x8`,x8 = 运行时解析(x19 从 dyld-rebase 指针槽 0x849000 + objc 关联对象
  键控 hash 算出)——**静态无法确定跳转目标**。
- 0x5d8758 检查 [x0+0xa] 标志 → `bl 0x712664`(1 条 thunk→0x712118 dispatcher A)→
  `bl 0x712668`(**独立函数 dispatcher B**,agent 纠正早前误并)。**自旋点 0x7128c0 在 0x712668 内。**
- 两个都是 OLLVM 状态机(w9 状态寄存器 vs 一堆混淆 32-bit 常量比较)。

### 检测判定:未静态定位(但有强线索)
- 全文件**无** jailbreak/Cydia/substrate/frida 字符串;**无** ptrace/sysctl/csops/fork import。
- ⇒ Promon SHIELD 的越狱检测**极可能走 Foundation `fileExistsAtPath:` 文件探测**,路径串
  运行时用 `mov/movk` 逐字节拼装(混淆),静态 grep 不到。
- **无 __TEXT 自检**(无大范围读 __TEXT 的 hash 循环、无未导入 hash syscall)——磁盘 patch
  本身不会被自检发现。**但** +load 控制流依赖运行时 dyld-bind/关联对象值 ⇒ patch dispatcher
  的混淆常量有"磁盘值≠运行时值"风险。

### agent 结论 + 我的下一步(input 层,绕开混淆)
- agent 明确:静态已到瓶颈,不愿瞎猜 patch 点;建议**动态 trace**(断点 performSecurityChecks
  / fileExistsAtPath: / 监视 [x0+0xa] 标志)确认真实数据流。
- 我的方向(与历史 abcbypass 成功路径一致 = ObjC/高层而非字节 patch):
  **探针 hook `fileExistsAtPath:`(ObjC swizzle)+ `stat/lstat/access/open/fopen`(fishhook GOT,
  Round 23 证 GOT hook 不触发反 inline-hook 自检),按 caller 模块(dladdr)过滤只留 hsbcchinax
  发起的调用** → 观测 Promon SHIELD 到底探哪些路径。若确认走文件探测 → 对越狱路径返回
  "不存在",在**输入层**绕过,完全不碰混淆的 dispatcher/字节 patch。
- 探针已在本地写好并编译(见 Tweak.x),等设备可用一条命令部署。

### 交付形态再评估
- 之前认为 hsbcchinax 走 raw syscall 不可 hook —— 对 Promon SHIELD **可能不成立**(无 syscall
  import,走 Foundation)。若检测确在 fileExistsAtPath:/stat 层 → **ObjC swizzle / fishhook
  tweak 可能直接可行**,不必二进制 patch。这是本 session 相对历史结论的又一利好。

## Round 38（2026-08-21,RE 子代理 —— 检测判定定位到"加密 stub 表",判定不可静态 patch）

### dispatcher 0x712668 机制(agent 精确反汇编)
- 函数体 0x712668-0x71371c,**仅一个出口**。w9 状态寄存器在 0x7126d8 被**固定常量 0x54d8b0c8**
  播种(非参数派生,每次运行起点相同)。主循环头 0x7126e4(cmp/b.le/b.gt/b.eq vs ~40 个 magic)。
- 第一次迭代落到 0x712de0:把 caller 数据写入 x24 状态对象(x24 = 0x5d8758 帧的 sp+0x18,
  贯穿 0x712664→0x712668 的持久状态缓冲),写常量 0xa7418482 到 x24+0x88,然后
  **`bl 0x713720`(x1=x24+0x8c)= 检测调用**。
- 0x713720 = 第二个小状态机,出口 0x713930 `w0 = w23 & 1`。w23 由三个分支置 0/1,取决于
  两个调用的结果:**`bl 0x7748d8`(×3: 0x7137cc/0x713810/0x713870)+ `bl 0x775034`
  (×1, 内部 0x7138f8, x0=handle x1=x24+0x8c x2=4, 比较 x0==4)**。
- 0x713720 返回 0/1 回流到 0x712dfc(`cmp w0,#0`)→ csel 选下一个状态常量 → `b 0x7126e4`。
  **这里就是"越狱(w23=1 / count==4)vs 干净(w23=0)"分叉点。** 干净分支最终到真正终止 case
  0x7136f8(`w0=[sp,#0x8c]&1; ret`@0x71371c);越狱分支走别的 case,一旦上游退出被堵→自旋。

### ★ 判定不可静态 patch 的根因:加密 lazy-stub 表
- `0x7748d8`、`0x775034` 是 `__stubs` 跳板(adrp x16,0x84c000; ldr x16,[x16,#off]; br x16),
  但目标槽(0x7748d8→**0x84c000**;0x775034→**0x84c020**)**不在 dyld bind/lazy-bind 表里**。
- agent dump 该页原始字节(0x84c000-0x84c128,~38 槽):每个非零槽是远超二进制地址范围的
  64 位值(如 0x687fc6c16e5511b4)= **密文**。0x84c130 起全 0。
- ⇒ **Promon SHIELD 运行时把这些槽解密成真实函数指针**(疑似 dispatch_once 守卫的 init,
  在 0x6bdc48-0x6bdc90,与 +load 自身 cache-check 同一 idiom)。这是保护检测原语的**反静态
  分析机制**——不是 __TEXT hash/CRC 自检(再次确认无),而是**惰性指针解密表**。

### 再次确认:无全局完整性自检
无 CC_SHA/CCHmac/csops/amfi import(查全 bind+lazy-bind);__text 无 svc;无读大范围
__TEXT 的循环。**改别处明文指令不会被 hash 检查抓**——风险仅限这个加密 stub 表(局部)。

### agent 给的候选(明文可 patch,但未验证):
- 0x713908 `f100101f cmp x0,#0x4` → `f100001f cmp x0,#0x0`(或改分支),强制"未越狱"比较结果。
  **agent 明确不愿作为"第五次盲猜",建议先 live trace。**

### 下一步:runtime 读解密后的 stub 槽(我的 tweak,非 frida)
agent 核心建议 = 先动态确认 0x7748d8/0x775034 解密后指向什么真实函数(极可能
fileExistsAtPath:/stat/access,因为全二进制无 ptrace/sysctl/csops raw import/svc)。
我的做法(可靠注入,无需 frida-server):
- 探针 poll 槽 0x84c000/0x84c020(+slide),一旦变成合法进程内指针 → dladdr 出真实符号+模块。
- 同时保留 fileExistsAtPath: swizzle + fishhook(stat/lstat/access/open/fopen)做兜底。
- 若解密指针指向导出符号(如 stat)→ Shield 直接调它可能**绕过 GOT**,fishhook 抓不到,
  但 dladdr 读槽能识别;若走 ObjC(fileExistsAtPath:)→ swizzle 能抓+能改。据此决定绕过点。
- 并行:已请 agent 静态反解密例程(若能离线解密 stub 表,直接静态定位真实函数,免上设备)。

## Round 39（2026-08-21,RC4 引擎定位 + 静态撞墙 + 转向动态/反编译器）

### agent 发现:解密引擎 = RC4(确认逐字节匹配)
- 0x6df1cc = RC4 PRGA 核心(标准 i/j swap + keystream XOR 循环,x8=256项 uint32 加宽 S-box,
  x2=输入 x3=输出 x0=状态)。**但**只有 3 个真实调用者(0x3c151c/0x485e2c/0x485f5c),
  操作的是另一个结构(config/telemetry blob 解密),**没有静态边指向 stub 表槽 0x84c000/0x84c020**。

### 关键情报:加密 stub 表是"全二进制系统级"机制,非专门保护 JB 检测
- 345 个 __stubs 里 **243 个(70%)** 指向未解析区间 0x84BF58-0x84CB60(~250 槽)。
- dyld fixup 空洞:rebase 表在 0x84BF30 断,0x84D298 续,中间(含两个目标槽)完全在
  dyld bind/rebase/lazy-bind 之外。二进制用 legacy LC_DYLD_INFO_ONLY(非 chained fixups)。
- ⇒ Promon 编译工具对**数百处内部调用**做了 stub 表混淆,由一个**运行时 unpacker 极早期**
  填充(agent 静态找不到 writer,疑在 +load/构造器早期,可能非简单 adrp+str)。
- **推论(利好)**:writer 必须在检测运行前把整表解密好 → 那一刻起,内存里槽全是明文指针。
  探针只要在检测发生时读槽(Round 38 已实现)就能拿到真实函数;不必静态解密。

### agent 自我纠错:0x713908 `cmp x0,#0x4` 不是干净 patch 点
- 完整 trace 两分支:x0==4→w23=1(越狱);x0!=4→w23=0(干净)。**但两分支都无条件调
  encrypted stub 0x7748d8**,越狱分支还多调 0x774f68(又一加密槽 0x84c580)。
- ⇒ patch 这个 cmp 只是改走哪个"仍依赖加密调用"的分支,**不隔离加密表**,不是干净点。
  agent 明确收回上轮的这个建议(诚实)。
- 干净分支状态流 0x7480f1e→0x366c8782(清 w19)向终止 case(0x713120 `w9==0x4624b8ac`→
  [sp,#0x8c]→ret@0x71371c)收敛更快;越狱分支 3+ 跳仍未收敛(与 pristine 374ms 越狱快退一致?
  待证:未确认每 case 最终 [sp,#0x8c]&1 返回值)。

### 静态结论:撞墙(非努力不足,是加密表覆盖 70% 调用 + writer 不在磁盘可见处)
agent 建议:(a)用真正的反编译器(Ghidra/IDA CFG 恢复)离线破;(b)上设备 live trace
0x775034/0x7748d8/0x774f68 解密后目标 + 参数/返回值,一步绕开静态解密难题。

### 我的行动(离线优先,设备兜底)
1. 环境无 Ghidra/IDA/r2,但有 Java26 + pip + brew + 网络。**后台装 angr**(/tmp/angr_install.log):
   angr 的 CFGEmulated 能跟间接调用,且可**符号执行/模拟 RC4 例程直接离线解密两个槽**,
   甚至定位 writer。这是最有希望"不上设备就破"的路径。
2. 设备兜底:Round 38 探针(stub 槽轮询 + fileExistsAtPath:/libc swizzle)已编译就绪,
   一条命令部署,读解密后真实目标。
3. 一旦知道真实检测函数:优先 tweak 级 hook(swizzle/fishhook 目标函数)绕过,避开加密表 +
   避开脆弱字节 patch。这与 abcbypass 成功路径一致。

## Round 40（2026-08-21,★★★ angr 离线 CFG 恢复 —— 定位检测判定消费点,得干净 patch）

### 工具:本地装 angr 9.3.3(pip,~/.re-venv),CFGFast 成功恢复 dispatcher CFG
环境无 Ghidra/IDA,但 pip+网络可用。angr CFGFast(限定 0x712668-0x714000)恢复 333 节点,
稳定解出状态机结构(纯静态 CFG,不依赖运行时值——正好补上 agent 手工 trace 的缺口)。

### 决定性:dispatcher 只在唯一状态值时终止,检测判定在唯一 csel 消费
- 终止条件(0x7136e4):`cmp w9,#0x4624b8ac; b.ne 0x7126e4`(不等就跳回循环头=自旋);
  等则 `ldr w8,[sp,#0x8c]; ret`(0x7136f8/0x71371c)。
- 唯一产生终止态 0x4624b8ac 的块 = 0x7130fc(需先到达中间态 0x17c6c0cf)。
- **检测结果分叉(唯一)@0x712dfc-0x712e14**:
  ```
  712dfc cmp w0,#0            ; w0 = 检测结果(0=干净, 1=越狱)
  712e00 w8 = 0x07480f1e      ; "干净"下一状态
  712e08 w9 = 0x564fec1b      ; "越狱"下一状态
  712e10 csel w8,w9,w8,ne     ; w0!=0(越狱)→0x564fec1b, 否则→0x07480f1e
  712e14 b 0x7126e4
  ```
- 干净态 0x7480f1e 收敛到终止(agent 已 trace + angr CFG 佐证);越狱态 0x564fec1b 走深链,
  上游退出被绕过时不收敛 → 自旋。**这解释了全部现象**:pristine 越狱→走越狱态→(原本有退出)
  374ms 死;我之前 patch 绕过退出但没改 verdict→越狱态自旋。

### ★ 干净 patch(第 4 candidate,机理正确,非盲猜)
- **文件偏移 0x712e10**:`csel w8,w9,w8,ne`(`2811881a`)→ `nop`(`1f2003d5`)。
- 效果:nop 后 w8 保持 0x712e00 载入的**干净态 0x7480f1e**,无视 w0(检测结果)。
  状态机随后完全按"非越狱设备"正常跑完初始化 → +load 返回 → 无看门狗。
- **为何优于前 3 次失败**:前 3 次(landing-pad ret / flag=0 / gate skip)是跳过/破坏代码,
  把状态机留在 limbo。本 patch **让所有 encrypted-stub 副作用照常执行**(两分支都调 0x7748d8),
  只在最终 verdict 消费点翻转成"干净",精确模拟正常设备。不碰加密表、不碰退出、不破坏流。
- 备选(冗余):0x712dfc `cmp w0,#0`→恒等,或直接让 0x712e10 选 w8。首选 nop 最干净。

### 待设备验证(一条命令)
`./patchtest.sh 712e10 1f2003d5 25` —— 从 pristine 干净 patch + 设备签 + trustcache + 启动观测。
预期:+load 跑完,存活 >20s 不被看门狗杀,进入真实 UI(而非停在 LaunchScreen)。
若成功:香港 App 同法(同 Promon SHIELD 栈)。若仍自旋:说明干净态也依赖某未满足的运行时
副作用,需回到 live trace 0x7748d8/0x775034 解密目标。

### 交付形态
若 0x712e10 patch 成功 → **二进制 patch 方案成立**(改 1 条指令 + ldid 重签 + trustcache)。
无 __TEXT 自检(已多轮确认),patch 稳定。仍可探索 tweak 级(hook 检测函数)作为免改 Bundle 的
交付,但 1 指令 patch 已是最小可用方案。

## Round 41（2026-08-21,patch 离线验证 —— 安全性确认 + 收敛性无法离线证明)

### angr 模拟收敛性:无法离线证明(三方一致的结论)
- 试从 clean 态 0x7480f1e 符号/具体执行 dispatcher → 立即 deadend。原因同 agent 手工 trace:
  状态机含 computed blr + 读 x24 缓冲/加密 stub 返回值,**转移依赖运行时解密值**,
  纯静态/模拟无真实值就跑飞。三个角度(agent 手工、angr 符号、angr 具体)一致:
  **收敛性只能上设备证。**

### patch 安全性:已离线确认单一用途(重要,降低翻车风险)
- 含 0x712e10 的块 = 0x712dfc(`cmp w0,#0`,检测结果判定),**唯一前驱** 0x712de0
  (`add x1,x24,#0x8c; bl 0x713720` = 检测调用)。
- 全二进制**无任何指令直接跳到 0x712e10**。⇒ 该 csel 只处理 0x713720 的检测 verdict,
  nop 它不影响其他逻辑。**patch 外科级隔离,无副作用风险。**

### 结论:离线能做的都做完了,剩下必须设备验证
- patch 点机理正确(唯一 verdict 消费点)+ 安全(单一用途)已确认。
- 能否让状态机收敛到终止 = 设备实测(一条命令 `./patchtest.sh 712e10 1f2003d5 25`)。
- 若成功:HK 同法。若失败(仍自旋):证明 clean 态也需某运行时副作用,回到 live trace
  0x7748d8/0x775034 解密目标(探针已就绪,含 stub 槽轮询)。

## Round 42（2026-08-21,clean 路径依赖交叉核查 —— 混合依赖,Plan B 备料中）

### angr 派发模拟器交叉核查(与 agent 并行,互验)
自写二分派发模拟器(处理 b.le/b.gt/b.eq + mov/movk 状态组装),跑 clean 态 0x7480f1e:
- clean case body 的 next-state 由 **csel** 决定(w8 vs w9 二选一),即转移可能条件依赖。
- block 0x71302c(clean 链上一环)= **纯寄存器/立即数**转移:`cmp w9,#const; csel` 产生
  终止喂给态 0x17c6c0cf,不读内存。**最后一跳到终止是寄存器逻辑,利好。**
- 但中段区间 0x712e44-0x713008 有大量 `ldr [sp,#0x60/0x98/0xa0/0x78...]` 载入——这些
  是检测子机(0x713720)早先写入栈槽的值。⇒ **clean 路径是混合依赖**:部分转移纯寄存器,
  部分读栈槽(可能由 encrypted-stub 结果填充)。

### 含义(对 0x712e10 patch 的预测)
- 若 clean 路径读的栈槽在"正常设备"上本就是确定值(与越狱无关的初始化数据)→ patch 成立。
- 若某栈槽的值依赖 encrypted-stub 检测结果 → 即使强制 clean 态,该槽仍是"越狱"值,
  中段某 csel 可能拐回自旋。→ 那就是 Plan B 靶点(需 hook/patch 那个 stub 或槽)。
- **结论**:patch 有实打实的成立可能(终止段纯寄存器),但中段栈依赖需 agent 精确列出才能
  100% 预判。agent 正在做(Round 41 委派的 clean 路径依赖枚举)。

### 状态:离线已到"需 agent 精确 trace + 设备实测"的边界
- 主攻 patch(0x712e10 nop)机理正确 + 单一用途安全,已提交。
- HK 侧:本地无 HK 二进制(232MB 需上设备拉),HK 离线预研受阻,待设备。
- 不再重复 trace(避免与 agent 撞车/盲猜);等 agent 依赖枚举 + 设备一条命令验证。

## Round 43（2026-08-21,★★ 独立二次验证 —— clean 路径纯寄存器,patch 对 dispatcher 成立）

### RE 子代理独立方法验证(非复述我的数,是第二套工具重现)
子代理自写确定性 tracer(从 loop head 播种 w8=w9=0x7480f1e,机械解析每条
mov/movk/cmp/csel/branch,操作数是具体整数就解析分支,遇未知就停并报依赖)。
产物 /tmp/hsbc_clean_path_trace.txt,脚本 /tmp/trace_clean_path.py。

### clean 路径状态序列(确认,4 跳到终止)
```
0x7480f1e  (patch 强制的 clean 态)
0x366c8782 (block 0x712c80: cmp w9,0x7480f1e eq → csel 选 0x366c8782, 同时 w19 清零)
0x366c8782 (原地一次 pass-through 块, 状态不变)
0x17c6c0cf (block 0x712720: b.le → 0x7130fc)
0x4624b8ac (终止! block 0x7130fc 内 0x71311c: cmp w9,0x17c6c0cf eq → csel w8=0x4624b8ac)
→ 0x7136e4 cmp w9,0x4624b8ac eq → 0x7136f8 ldr w8,[sp,#0x8c]; ret@0x71371c
```

### 三个关键结论(独立验证)
1. **内存依赖:仅 1 处,且不影响状态转移。** 0x71312c `ldr w9,[sp,#0x8c]` 在终止块内、
   状态决策(0x713128 已定 w8=0x4624b8ac)之后执行;其结果喂 csel→str 回返回值槽,
   但下条 `b 0x7126e4`→`mov x9,x8` 无条件用 w8 重导 w9,**该 ldr/csel 对循环是死的**。
   查全 dispatcher 20 处 w19 触点,只 0x713130 在路径上,即这个死写。
2. **[sp,#0x8c] = 返回值 w0 来源**(0x7136f8 `ldr w8; and w0,w8,#1; ret`)。clean 路径
   w19=0(0x712ca4 具体清零,非内存读)→ 返回 w0=0,纯寄存器常量,**无 encrypted-stub 依赖**。
3. **判决:纯寄存器/立即数路径,patch 对 dispatcher 独立成立。** 0x7480f1e→...→0x4624b8ac
   到终止 ret 全程只用编译期常量 + 寄存器算术,**0 次加密 stub 调用(0x7748d8/775034/774f68),
   0 处 gate 分支的内存读**。每个分支都以具体整数比较解析成功(有未知会停,未停)。

### 唯一未验证环节(agent 明确标注,非 patch 缺陷)
分析是 dispatcher 0x712668 独立层面。**caller 0x5d8758**(`bl 0x712664` init→`bl 0x712668`
→`tbnz w0,#0` @0x5d87a4)需接受 w0=0 为"未越狱"信号——与原始崩溃栈语义一致
(tbnz w0,#0 在低位=0 即 clean 时跳过 guarded body)。首份报告已刻画,本 trace 无矛盾。

### 置信度提升
0x712e10 nop patch 从"机理正确候选"升级为"**对 dispatcher 离线双重验证成立**"。
剩余唯一不确定 = 设备实测整条 +load 是否真跑完(dispatcher 只是其一环)。
一条命令待验:`./patchtest.sh 712e10 1f2003d5 25`。

## Round 44（2026-08-21,caller 层分析 —— clean 使 caller 执行 guarded body,非跳过)

### 关键语义澄清:clean(w0=0)让 caller 跑"更多"代码,不是更少
caller 0x5d8758:`bl 0x712668`(dispatcher)→ `tbnz w0,#0,0x5d87e0`(0x5d87a4):
- **w0=1(越狱)→ 跳到 0x5d87e0**,跳过 guarded body,直接 stack-check + ret。
- **w0=0(clean,我 patch 后)→ 不跳, 落入 guarded body 0x5d87a8-0x5d87dc**:
  - 0x5d87ac ldr x19=[0x849000+0x3b0];0x5d87b4 `bl 0xe4634`;0x5d87d4 `blr x8`
    (x8=x19-[0x838138], associated-object 键控 computed call, 同 +load 早期模式);
    0x5d87dc `bl 0x93900`(析构)。
⇒ guarded body 是**正常设备执行的真实初始化**(越狱时被跳过)。我的 patch 让 app 做
  "正常设备该做的事",语义正确。

### guarded body 无自旋风险(静态可判部分)
- 0xe4634 = 正常返回函数(0xe46dc 明确 ret,无自循环),构造对象 + 记账后返回。
- ⇒ guarded body 本身不是 spin 源(至少 0xe4634 这条不是)。

### 残余不确定(仅设备可判)
- 0x5d87d4 的 `blr x8` 是 associated-object 键控间接调用,**静态解析不出目标**(同加密表家族)。
  正常设备上它正常返回;我们环境下是否一致 = 设备实测。
- 且 dispatcher 只是 +load 巨型函数(0x439f68-0x443a7c)中一环;整条 +load 跑完与否仍需实测。

### 净结论(诚实)
- Round43 已证:dispatcher 层 clean 路径纯寄存器到达 ret,patch 对 dispatcher 成立。
- Round44 补充:clean 让 caller 执行 guarded body(正常 init),0xe4634 会返回不自旋;
  但 body 内 computed blr + 整条 +load 的收敛只能设备验。
- **静态分析到此完备**。patch 机理正确、单一用途、dispatcher 层双验证、caller 语义正确。
  唯一验证手段 = `./patchtest.sh 712e10 1f2003d5 25`(设备)。

## Round 45（2026-08-24,★ 首次设备实测 0x712e10 patch —— 越过自旋,暴露 guarded body 崩溃)

### 设备重连
隧道端口变更 22215→22315(设备/服务器几天间隔重连)。已更新 patchtest.sh。
设备重启导致 /tmp/*.orig 备份丢失,已从本地 pristine(app-binary/hsbcchinax, md5 91d77d..)恢复。

### 实测结果:patch 生效(越过自旋),但 clean 路径的 guarded body 崩溃
`./patchtest.sh 712e10 1f2003d5 28`:
- **不再 20s 自旋看门狗**(dispatcher patch 按 Round43 预测生效,走了 clean 态)——这是进步。
- 但 **~2s 内 SIGSEGV**(China-2026-08-24-110020.ips):
  - EXC_BAD_ACCESS / SIGSEGV / KERN_INVALID_ADDRESS at 0x0(空指针)
  - isCorpse=1, triggered thread **0 帧, PC/LR=None, 寄存器几乎全 0**(x0=0,x1=0,x8=3)
  - 栈损坏无回溯 = 跳到 NULL/野地址执行(computed blr 目标坏)。

### 印证 Round 44 的残余风险
- clean(w0=0)让 caller 0x5d8758 **不跳过** guarded body,执行 0x5d87b4-0x5d87dc:
  - 0x5d87d4 `blr x8`(x8 = x19 - [0x838138], x19=[0x849000+0x3b0], associated-object 键控)。
- 这个 computed blr 在我们环境下算出坏地址 → 崩。**dispatcher 层已解决,问题下移到 caller
  的 guarded body computed call。**

### 与历史对照
- Round 33 `mov w0,#0`(也强制 clean 语义)→ +504ms SIGSEGV 栈损坏,**同一现象**。
- ⇒ 强制 clean 会触发 guarded body 的坏 computed call。这不是 dispatcher 的问题,是
  "正常设备该跑的 init"在被 patch 的越狱环境下缺了某前置状态。

### 下一步(两条路)
A. **观测 guarded body 的 blr**:探针 hook 0x5d87d4 前读 x8/x19/[0x838138]/[0x849000+0x3b0],
   看 x8 算成什么、正常应指向哪。Round38 探针(stub 槽轮询)已编译,加 caller 观测点。
B. **换 patch 层级**:不强制 clean 走 guarded body,而是找"让 caller 认为 clean 但跳过
   guarded body"或"让 dispatcher 返回 clean 且 guarded body 前置条件满足"的点。
   但 Round44 已知 guarded body 是正常 init(不能简单跳过,跳过可能缺初始化)。
- 关键新认知:**光 patch 检测 verdict 不够**;guarded body 的 computed call 依赖某个
  只有"真正没被 patch/正常启动"时才建立的运行时状态(associated object / 解密指针)。
  可能需要回到"不改 verdict 而是让检测输入为 clean"(即检测函数真的判定未越狱),
  这样 guarded body 的前置状态由正常流程建立。

## Round 46（2026-08-24,★★ 探针实测 —— 检测不走 libc + 崩溃根因=Promon 自定位锚点 0x838138)

### 探针实测结论1:Promon 检测完全不走 libc 文件层(彻底排除文件 hook 路线)
观测探针(fishhook stat/lstat/access/open/fopen + swizzle fileExistsAtPath:)实测:
- 所有 jb 路径命中的 caller **全是注入器**:libinjector(52)/systemhook(23)/Choicy(18)/libsandy(1)。
- **hsbcchinax 发起的文件查询:0 条。** ⇒ Promon 检测不调 libc 文件 API(印证 Round3)。
  hook 文件探测/fileExistsAtPath: 对绕过无用。

### 探针实测结论2:★加密 stub 槽解密后指向 hsbcchinax 内部函数(非系统 API)
- slot 0x84c000(0x7748d8) → **hsbcchinax+0x3bbef4**
- slot 0x84c020(0x775034) → **hsbcchinax+0x4365d4**
⇒ Promon 把内部调用也加密成 stub 表(多层)。0x3bbef4 又是薄封装:
  `mov x16,#6; blr [0x8510c8]`(再经 0x851000 页的加密 stub),继续套娃。纯静态无限层。

### ★★ 崩溃根因锁定:Promon 自定位锚点 0x838138 未初始化
guarded body 崩溃点 0x5d87d4 `blr x8` 的 x8 计算:
```
0x5d87ac ldr x19,[0x8493b0]      ; x19 = 0x3aeb1ff8 (存储的偏移)
0x5d87c8 strb wzr,[0x838138]     ; (某分支)清零锚点
0x5d87cc ldr x8,[0x838138]       ; x8 = *(0x838138)
0x5d87d0 sub x8,x19,x8           ; x8 = 0x3aeb1ff8 - [0x838138]
0x5d87d4 blr x8                  ; 崩:[0x838138]=0 → x8=0x3aeb1ff8 裸偏移(无slide)→野地址
```
- **0x838138 是 Promon 全局自定位锚点**(0x838000 页被引用 1434 次)。惯用法
  `真实地址 = 存储值 - [0x838138]`(见 0x79c88 同款代码)。正常时它存某修正值(约 -slide),
  让 sub 得到正确运行时地址;崩溃时=0 → 裸偏移 → 野指针。
- ⇒ **我在 0x712e10 强制 clean,跳过了 Promon 初始化锚点 0x838138 的那一步**,导致 guarded
  body 的自定位计算失败。**问题不是检测,是绕过方式破坏了 Promon 初始化时序。**

### 策略(下一步)
- 纯静态解多层自定位混淆=无限套娃,放弃。
- 运行时观测:pristine 正常启动(探针只读),dump 0x838138 正常被写成什么值/何时写,
  以及 0x8493b0/两个检测函数的真实行为。有正确锚点值→判断补状态 or 换 patch 点。
- 更根本方向重新浮现:**abcbypass 成功路径=让检测输入真判定未越狱**(而非事后翻 verdict),
  这样 Promon 走完整正常初始化,锚点/stub 表都正确建立,guarded body 不崩。
  但 Round46 已知检测不走 libc → 需定位 Promon 检测"读环境"的真实手段(可能内联更深层)。

## Round 47-48（2026-08-24,锚点排除 + 崩溃类型漂移(SIGSEGV→SIGILL)指向自毁)

### 锚点假设被推翻:0x838138/0x8493b0 正常/patch 版值一致
探针监视(pristine + patch 版对比):
- pristine: [0x838138]=0, [0x8493b0]=0x13ed29ff8(=静态0x3aeb1ff8+slide, 正常 rebase 指针)
- patch 版: [0x838138]=0, [0x8493b0]=0x13ccb1ff8(=静态+各自slide), 值同样正常。
⇒ **Round46 的"锚点未初始化"假设错误**。x8=[0x8493b0]-[0x838138] 崩溃前是正确运行时地址。
  崩溃不是锚点问题。

### ★ 崩溃类型漂移 + handler 抓不到 → 指向"篡改自毁"而非时序 bug
- 多次 patch 版启动:崩溃在 SIGSEGV(pc=0,寄存器全裸偏移) 与 **SIGILL**(非法指令)间漂移。
- 探针装了 BSD sigaction(SEGV/BUS/ILL/TRAP) **一次都没接到**(无 💥 日志)——
  同 Round6:Promon 用 mach 异常端口抢在 BSD signal 前, 或崩在特殊时机。
- SIGILL = 跳到非法指令/垃圾当代码执行。结合 pc=0 + 寄存器全是裸文件偏移(x21=0x3883f864,
  x24=0x73018b12, x23=0xcccc..cccd 除法魔数)——**像 Promon 检测到 patch 后故意跳乱地址自毁**,
  不是单纯初始化时序。

### 重要方向修正:0x712e10 patch 可能被 Promon 局部完整性自检发现
- 之前多轮判"无 __TEXT 自检"是指"无全局 hash 循环";但 Promon 可能对**关键检测函数/dispatcher
  做局部校验**(CRC 单个函数/校验特定指令),patch 0x712e10 改了 dispatcher 指令 → 被发现 → 自毁。
- 佐证:pristine 越狱是"干净 374ms 退出"(检测→退出);patch 版是"~600ms 后 SIGILL/SIGSEGV
  乱跳"(检测到篡改→自毁式崩溃),两者行为不同 = patch 触发了额外的反篡改响应。

### 下一步(重新聚焦)
1. 验证是否局部自检:patch 一个"无害"指令(如某 nop slide 或不影响逻辑处)看是否也 SIGILL——
   若无害改动也崩=有 __TEXT 局部校验;若只有改 dispatcher 崩=逻辑破坏非自检。
2. 若确有反篡改校验:回到**运行时内存 patch**(在校验之后改)或 **hook 检测函数入口**
   (但 Round20 知 inline-hook 被反制)——需找校验之后、检测判定之时的窗口。
3. 重新考虑 abcbypass 路径:hook 检测函数让其返回 clean(而非改 dispatcher 指令),
   但需绕过反 inline-hook——可能用 fishhook GOT(Round23 知不被反制)hook 解密后的检测函数调用点。

## Round 49（2026-08-24,★★ 纠正基线 + patch 效果重新定性)

### ★ 纠正长期误解:裸 pristine = ~3s 静默退出(非 374ms)
- 之前"374ms 退出"是**有探针注入时**的行为(探针改变了时序/触发额外检测)。
- **无探针裸 pristine: ~3s 静默退出, 无崩溃日志**(越狱检测→静默退出)。这才是真 baseline。

### patch 效果对照(均无探针)
| 版本 | 行为 |
|---|---|
| 裸 pristine | ~3s 静默退出(无崩溃) |
| 0x712e10 csel→nop (改 dispatcher verdict 消费) | ~2s SIGSEGV/SIGILL 漂移(pc=0/裸偏移寄存器) |
| 0x29b1ec nop→b.+4 | ~3s SIGSEGV |
| 0x29b1f0 nop→b.+4 | 存活>=15s **但 CPU 100% 忙自旋**(14.8s CPU/15s 墙钟)= 死循环空转, 非正常运行 |

### 关键定性:0x29b1f0 "存活"是死循环空转, 不是绕过
- CPU 时间线性涨满(≈100% 单核) = 忙自旋, 不是启动完成等待用户的正常 App。
- 与 0x712e10 的 20s 看门狗自旋同类;此处 uiopen 启动可能不受 launch watchdog 约束故不被杀。
- ⇒ 三种 patch 都没绕过:要么破坏逻辑崩溃, 要么陷入自旋。

### 完整性校验问题:未定论(证据混合)
- 0x29b1ec 改崩、0x29b1f0 改自旋、0x712e10 改崩/自旋 —— 都不是"干净 3s 退出"。
- 若有全局 __TEXT 校验: 任何改动都该被检测→统一响应。但三处响应不同(崩vs自旋)。
- 更可能: **无全局校验, 崩/自旋取决于改动破坏了什么执行逻辑**。0x29b1ec/0x29b1f0 看似
  padding nop 实则在某执行路径上(改了破坏循环/控制流)。
- ⇒ 倾向"无完整性校验, 是逻辑破坏", 但需干净对照(改一处 100% 不执行的字节)才能定论。

### 下一步(系统性重规划)
1. 找一处**确定不被执行**的字节(如 __TEXT 末尾真 padding / 字符串区)改, 看是否 3s 干净退出
   → 定论有无完整性校验。
2. 若无校验: 说明 dispatcher/检测逻辑比想象复杂, 单点 patch 破坏控制流。需更精确定位
   "检测 verdict 如何流向退出", 且 patch 后不破坏自旋依赖的状态。
3. 若有校验: 转运行时(校验后 hook)。abcbypass 路径(ObjC swizzle 检测方法)重新评估:
   但 Round46 已知检测不走 libc 文件, verdict 在解密后的 0x3bbef4/0x4365d4 内部函数。
4. 重新聚焦: 探针 hook 解密后的 0x3bbef4(检测函数A, 被调3次)入口, 看它返回什么、
   改返回值能否让 App 活(运行时改, 非磁盘 patch, 避开可能的校验)。

## Round 50（2026-08-24,★★★ 决定性: 无 __TEXT 完整性校验, binary patch 可行!)

### 决定性对照: 改 __cstring 数据字节 → 3s 干净退出(同 pristine)
- 改 0x7c33bc('clock_ge...' 错误串, 100% 不执行) 1 字节 → **App ~3s 干净退出, 无崩溃**。
- ⇒ **Promon SHIELD 无 __TEXT 完整性校验!** 改任意不执行的字节无感。
- ⇒ 之前 0x29b1ec 崩 / 0x29b1f0 自旋 / 0x712e10 崩/自旋 **全是逻辑破坏(改到被执行指令)**,
  不是反篡改自毁。**binary patch 路线仍可行**, 只是要 patch 对点、不破坏控制流。

### 修正认知
- 0x29b1ec/0x29b1f0 看似 padding nop, 实在 OLLVM 执行路径上(对齐跳板/被执行), 改了破坏流。
- 0x712e10 改 dispatcher verdict 消费, 让状态机走 clean 分支 → 但 clean 分支的 guarded body
  computed blr 依赖某未建立状态 → 崩(Round45)。不是校验, 是时序/状态依赖。

### 下一步: patch 真正的 verdict 判定点(更上游, 不碰 dispatcher)
- Round46 探针实测: 检测原语 = 解密后的 0x3bbef4(被调3次)/0x4365d4。
- 0x3bbef4 逻辑: `mov x16,#6; blr [0x8510c8](加密stub); b.lo 0x3bbf18(ret) / b 0x2a74a0`。
  → verdict 在 blr 返回后的 b.lo 分支。若强制走 ret 分支(未越狱)可能比改 dispatcher 干净。
- 但需先搞清 0x2a74a0 是什么(退出? 还是正常返回路径)。且 0x3bbef4 是薄封装, 真检测在
  0x8510c8 解密后的目标 + 0x2a74a0。
- 更优: 运行时探针 hook 0x3bbef4 入口, 记录它返回值 + 调用者如何用, 定位 verdict 布尔。

## Round 51（2026-08-24,验算 guarded body blr 目标 = 非法巨大地址)

### 0x712e10 崩溃的 blr 目标验算(用 Round47 实测值)
- guarded body 0x5d87d4 `blr x8`: x8 = [0x8493b0] - [0x838138] = 0x13c93dff8 - 0 = 0x13c93dff8。
- 减 slide(0x101a8c000) = **0x3aeb1ff8** —— **远超 hsbcchinax 大小(~0x8a5000)! 约 1GB 偏移, 非法。**
- ⇒ [0x8493b0] 存的不是指向 hsbcchinax 的正常指针。Round47 我误判"正常 rebase", 实际
  0x3aeb1ff8 本身就是非法巨大偏移。这个槽在(强制clean的)执行流里值是错的。
- 但注意: 探针在 +23ms 读的快照, 崩溃在 ~2s 后, 值可能被改写。需崩溃瞬间的值才准。

### 含义
- 0x8493b0 是另一个 Promon 运行时填充的槽(类似加密 stub 表)。强制 clean 走到 guarded body
  时它没被正确初始化 → blr 非法地址 → 崩。
- 印证: 强制 dispatcher verdict = clean 破坏了 Promon 的正常初始化序列, 使某些运行时槽
  (0x8493b0 等)未按正常流程填充。**中途改 verdict 治标不治本。**
- ⇒ 更确信正解是"让检测源头判定未越狱"(让 Promon 自己走完正常 clean 初始化, 所有槽正确填充),
  而非中途翻 verdict。等子代理定位检测源头 patch 点。

## Round 52（2026-08-24,★★★ 子代理突破: 退出机制 = 数据段 svc 跳板 + 独立巨型状态机 0x75bf7c)

### 退出机制彻底揭开: raw syscall 藏在 __const 数据段
- 全局槽 **0x8510c8**(__common BSS, 运行时填充, 83 处引用)存一个跳板地址。
- **0x346c68**(+load 早期调用)执行: `str 0x78befc → [0x8510c8]`。
- **0x78befc**(在 __const 只读数据段!)字节 = `svc #0x80; ret; brk #1`。
- ⇒ 83 个 syscall 封装用 `mov x16,#N; ldr x17,[0x8510c8]; blr x17` 直接陷入内核,
  **完全绕过 libSystem 具名符号**。这解释了为何 hook libc/文件 API 全噪声、hsbcchinax 0 命中。
- 之前"__text 无 svc"结论对——svc 藏在**数据段**,不在 __text。

### exit(1) = syscall N=1, 4 个调用点全在巨型函数 0x75bf7c 内
- 0x760570 / 0x760988 / 0x769484 / 0x76b078, 每处 `mov w0,#1; bl 0x1f05dc`(0x1f05dc=N=1 exit 封装)。
- 各 syscall 封装地址: 0x1f05dc(exit/1), 0x693a74(open/5), 0x3bbef4(close/6),
  0x4365d4(read/3), 0x34cb18(access/33)。**⚠️ 修正 Round46**: 0x3bbef4/0x4365d4 不是"检测函数",
  是 close/read 的 syscall 封装! 之前解密 stub 槽指向它们只是因为它们共用 0x8510c8 跳板。

### 0x75bf7c = +load 第一个重逻辑函数, 唯一调用者, 独立巨型状态机
- +load 链: `43e0bc bl 0x346c68`(装 svc 跳板)→ `43e0c0 bl 0x75bf7c`(唯一调用者!)→
  `43e0c4 bl 0x346c7c`(收尾)→ 43e0c8 继续到 blr x8→0x5d8758→0x712668 分发器链。
- 0x75bf7c(~4012字节): 开头 71 组 mov+movk+stur 拼 ~284 字节栈缓冲(密钥/哈希表, 非明文),
  主体是**另一个 OLLVM 状态机**(同 0x712668 结构但更大~4倍): 状态变量在栈对象 +0x24
  (初值 0x7251a64c @0x75c888), 50+ case 的 `sub w8,w8,w9;b.eq` switch, 4 个 exit(1) 是其中的 case。
- **0x75bf7c 在 0x712668 链之前执行!** 若它内部就能 exit(1), 则 3s 退出可能来自这里, 不是 0x712668。

### ★ 关键待验证(决定 patch 哪里): 3s 退出是 0x75bf7c 还是 0x712668 先触发?
子代理明确: 0x75bf7c 与 0x712668 更可能是**两个独立检测层**(0x75bf7c 更早)。
必须设备验证: 在 0x75bf7c 入口 + 4 个 exit(1) 调用点打日志, 看 pristine 3s 退出命中哪个。
- 若命中 0x75bf7c 的 exit → 之前 patch 0x712e10 根本没到点(0x75bf7c 更早就退了),
  这解释了为何 0x712e10 patch 后行为变(绕过了0x712668但0x75bf7c的exit仍在? 或时序变了)。
- 素材: /tmp/hsbc_75bf7c_full.txt (72万字节全反汇编)。

## Round 53（2026-08-24,exit 封装因果确认 + patch 拦截不足)

### patch exit 封装 0x1f05dc → ret: 因果确认但下游崩
- 0x1f05dc = exit(1) 封装(mov x16,#1), **仅 4 调用点全在 0x75bf7c 内**(专用于检测退出, 拦它安全)。
- patch → ret 后: 行为从"静默退出"变"~3s SIGSEGV"。⇒ **退出确经过 0x1f05dc(因果确认)**;
  但变 ret 后 0x75bf7c 状态机在"本该退出处"继续跑 → 到坏状态崩。同 0x712e10 教训: 下游没准备好。

### 收敛: 退出走 0x75bf7c 内的 exit(1), 拦"退出动作"不够, 得让检测判定为 clean
- 两次(0x712e10 改 verdict / 0x1f05dc 拦 exit)都是"中途改" → 下游崩。
- 正解还是**让检测源头判定未越狱**, 使 0x75bf7c 状态机自然走"未越狱→不 exit→正常初始化"路径。
- 待定位: 0x75bf7c 状态机里"越狱判定"的输入(子代理说 4 个 exit case 依赖栈槽值, 非立即数, 未追完)。

### 下一步
1. 最小扰动探针: 只 hook 0x1f05dc(exit 封装)记录 LR, 确认 3s 退出命中 4 个调用点中的哪个。
2. 或 hook 0x75bf7c 入口 + 那个决定 exit 的栈槽读取点, 看越狱判定怎么来的。
3. 定位判定输入后, 在**输入层**patch(让判定为未越狱), 而非拦 exit/改 verdict。

## Round 54（2026-08-24,nop 4个exit调用点 → 自旋(同0x712e10结局))

### 实测: nop 掉 0x75bf7c 里 4 个 exit(1) 调用(0x760570/760988/769484/76b078)
- exit case 块结构: `mov w0,#1; stur; bl 0x1f05dc; <后续正常状态机延续代码>`。
  nop 掉 bl 后状态机继续走延续代码(非拦 exit 封装本体, 不影响其他调用者)。
- 结果: 不再 3s 退出/不崩, 撑到 ~12-18s, 但 **CPU 忙自旋**(11s CPU/12s), 最终 20s 看门狗 0x8BADF00D。

### 定性: 中途拦截一律自旋/崩, OLLVM 状态机设计使然
- 改 verdict(0x712e10)/拦 exit 封装(0x1f05dc)/nop exit 调用(本轮) —— **全部自旋或崩**。
- 原因: 状态机的"正常终止路径"只在**越狱判定=未越狱**时可达; 检测到越狱就走 exit case,
  强行绕过 exit 则进入非终止状态循环。
- ⇒ **唯一干净解 = 让越狱判定输入=未越狱**, 使状态机自然走正常终止。

### 精确目标(已定位到指令级)
- exit 触发: `[x29-0x25c](当前状态w8) - [x9-0x100](目标w9); b.eq exit_case`(4处同构)。
- 需要: 让状态机的**越狱检测输入**为 clean, 使当前状态永不等于 exit case 的目标值。
- 检测输入 = 0x75bf7c 内某个 syscall(access/stat 查越狱文件, 走 0x8510c8 svc 跳板)的结果,
  如何流入状态变量 [x29-0x25c]。**这是最后要追的一环。**

### 下一步
- 子代理: 追 0x75bf7c 里 syscall 结果 → 状态变量的数据流, 定位"越狱→状态"的转换点。
- 或运行时探针: hook 0x8510c8 svc 跳板, 记录每次 syscall 的号+参数+返回, 看哪个查越狱、
  返回什么导致走 exit。这个 hook 点是全局槽, 改它的值可重定向所有 syscall(危险)或只观测。

## Round 55（2026-08-24,★ svc 跳板观测器成功 + 证明无网关指针完整性校验)

### 方法: 把 svc 网关槽 0x8510c8 重定向到自建汇编跳板
- Tweak %ctor 里把 slot[0x8510c8+slide] 写成自建 `_hsbc_svc_tramp`(保存全部传参寄存器→
  记录 nr/a0/a1/caller→原样 `svc #0x80; ret`)。这样所有 83 个 syscall 封装的 `ldr x17,[slot];blr x17`
  都经过我的跳板, **首次拿到 Promon 走 raw svc 的 syscall 地面真值**(libc/fishhook hook 全 0 命中的原因)。
- 关键测得: **%ctor 早于 App 安装点**(slot prior=0x0 = 理想)。但 App 的安装点 0x346c68 的
  `str x9,[x8,#0xc8]` 在 ctor 之后执行, 会把我的跳板覆盖回真网关 0x78befc。
  ⇒ 必须 nop 掉 0x346c74 的 str, 我的跳板才留得住。

### 55a(不 nop store): 跳板被覆盖, 3s 静默退出(= pristine 基线), 跳板仅 ctor 后短暂在位。
### 55b(nop store 0x346c74 → 1f2003d5): 跳板留住, 观测到 syscall, 但 16-20s 看门狗
- 前 1s: total=48 syscall = `open×4 close×4 access×4 #153(pread)×16 #197(mmap) #199(lseek) sysctl×1 #294×2`,
  全是 **dyld 共享缓存映射**(`/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e`)。
- **1s 之后完全静默**(poller 每秒快照, t=2s..t=35s 无任何 syscall 增量)—— **不是 syscall 风暴, 是纯 CPU 自旋**。
- **全程无一个越狱路径查询经过我的跳板**(★JB 0 命中)。自旋发生在越狱文件检查**之前**。

### ★★ 决定性结论: 二进制里无"网关指针完整性校验"
- 全 __text 反汇编搜 `add x?,x?,#0xefc`(计算网关地址 0x78befc)—— **全二进制仅 1 处**, 就是安装点 0x346c68。
- ⇒ 没有任何代码重算网关地址并与 slot 比较。**我的跳板指针按值不会被检测到**。
- 那 55b 的自旋不是"槽被篡改"检测, 而是 **nop store 破坏了安装序列**本身
  (`bl 0x346c68 装网关 → bl 0x75bf7c 检测 → bl 0x346c7c 收尾`, 收尾 0x346c7c 是另一个巨型 OLLVM 状态机)。
- dyld 共享缓存映射是 OneSpan/Promon 常见手法: 从磁盘映射干净 shared cache, 可能用其中干净 stub 发 syscall
  (绕过 inline hook)。但那些 syscall **也会经过 slot**(封装在 App __text 内, ldr x17,[slot]不变), 故仍应被我捕获——
  除非检测走了不经 slot 的另一条路(如直接 svc 内联, 或映射的 cache 里的 libSystem)。

### 待验证(下一步)
1. **不 nop store, 改用 poller 线程在 App 安装后持续重写 slot 为跳板**(赛过 App 的 str), 看能否既留住跳板又不破坏安装序列 → 若这样能观测到越狱路径查询, 说明问题是 nop store 破坏了收尾, 而非跳板本身。
2. 或: nop store 后, 自旋点定位——在 0x75bf7c/0x346c7c 里加日志或看自旋 PC。
3. 若确认检测 syscall 根本不经 slot(跳板 0 命中越狱路径), 则 svc 跳板方案对"文件检测"无效, 需换"检测走内联 svc 或映射 cache stub"的假设。

## Round 55d-e（2026-08-24,跳板确被调用但结果不确定, svc PC 检查假设未证实)

### 尝试尾调真网关(防 svc-PC 检查): @PAGE/@PAGEOFF reloc 在 tweak 内解析成 0 → br null → 2s SIGSEGV
- 内联 asm 里 `adrp x17,_hsbc_g_realgate@PAGE; ldr x17,[..@PAGEOFF]; br x17` 读回 0(reloc 未正确绑定)。
- 回退到自带 `svc #0x80; ret`(55b 已证明转发正确)。

### 加 readback + FIRST-CALL 同步标记后: 跳板确被调用, 但只 1 次(nr=294)然后 3s 退出
- ctor readback 确认槽=跳板(写入生效)。FIRST-CALL: nr=294 caller=+0x44ef20(在 OLLVM 混淆区, bl 0x240218 附近)。
- **但 poller 的 t=1s Δ 表和轨迹一行没落**——矛盾: 若跳板被调 g_total>0, poller 应打 Δ 表。
  ⇒ 要么 poller 线程没跑起来(pthread_create 在检测退出前没调度), 要么第一个 nr=294 后检测很快 exit。
- **对比 55b(48 call+16s 自旋) vs 55d-e(1 call+3s 退出): 同样 nop-store, 结果不同 = 非确定性**(ASLR/线程调度)。

### 定性: svc 跳板观测法受非确定性 + poller 时序困扰, 且 nop-store 破坏安装序列
- 反复出现: 有时 48 call 自旋, 有时 1 call 退出。跳板机制本身可用(readback/FIRST-CALL 证明), 但:
  1. poller 1s 落盘太慢, 检测在 1s 内就 exit → 拿不到轨迹。
  2. nop-store 破坏 0x346c68→0x75bf7c→0x346c7c 安装序列, 引入自旋/非确定。
- **反思(第3次中途拦截类失败): 不该继续在跳板+nop-store 上迭代。** 需换思路。

### 新方向候选(下一步选一, 避免再陷跳板泥潭)
- (A) 不 nop-store、不改控制流: 只在 ctor 后用**独立线程 busy-loop 持续把槽改回跳板**, 且跳板**同步落盘前 200 条**
  (不靠 poller), 抢在检测跑之前/之中就地记录, 看能否拿到完整越狱路径探测轨迹。纯观测, 不碰控制流。
- (B) 彻底换层: 用 lldb/debugserver attach(设备有 debugserver?)在 0x75bf7c 下断点单步, 看越狱判定输入。
- (C) 接受"检测输入=文件系统真实状态"的现实: 既然改控制流一律崩/旋, 改用**文件系统层面伪装**——
  把设备上越狱特征路径(/var/jb 等)对该 App 的沙箱视图隐藏(bind mount / RootHide 式), 使真实 syscall 返回 clean。
  这是 RootHide/Dopamine 生态的既有能力, 可能比对抗 Promon 状态机更实际。

## Round 56（2026-08-24,★ 关键负结果: Shadow 全 hook 集(含 Hook_Syscall)对 Promon 无效)

### 设备已装 Shadow(me.jjolano) + Choicy + ellekit + libhooker
- Shadow 偏好 me.jjolano.shadow.plist 里 **HSBC 早有条目但全部 hook 关闭**(`cn.com.hsbc.hsbcchina: []`)。
- 对比: 税务 App `cn.gov.tax.its` 开了**全 18 项 hook**(含 Hook_Syscall/Hook_AntiDebugging/Hook_Sandbox/
  Hook_MachBootstrap/Hook_Memory 等)—— 说明有人为税务 App 精调过, 但 HSBC 放弃了(空配置)。

### 实验: 把 HSBC 的 Shadow 配置设为税务 App 的全 18 项 hook, 禁用自研 tweak, 恢复 pristine 二进制
- 结果: **仍 3s 静默退出, 无变化, 无崩溃**。
- ⇒ **Shadow 的 Hook_Syscall 覆盖不到 Promon 的检测路径**。印证: Promon 走私有数据段 svc 网关(0x8510c8→
  0x78befc)发 `svc #0x80`, 不经 libSystem 具名 syscall 符号, 故 Shadow(hook 具名符号/syscall() 封装)拦不到。
- 已还原 Shadow 配置(hsbc 恢复空), 备份在设备 .bak.*。

### 战略结论(3 条路已排除, 收敛下一步)
1. ❌ 中途改控制流(verdict/exit/nop) → 一律自旋或崩(Round 49-54)。
2. ❌ Shadow/文件系统与 syscall 层伪装 → 覆盖不到 Promon 私有 svc 网关(本轮)。
3. ✅ 仅剩: **svc 跳板观测法**(Round 55, 机制已证可用: readback+FIRST-CALL 确认跳板被调),
   需解决非确定性 + 同步落盘, 拿到"越狱路径探测 → 状态变量"的完整数据流, 在**判定输入层**做最小改动。
   - 或: debugserver/lldb 在 0x75bf7c 下断点单步(设备有无 debugserver 待确认, basebin 里是 idownloadd/jailbreakd)。

### 下一步(具体)
- 修 svc 跳板观测的两个工程问题, 拿到确定、完整的检测 syscall 轨迹:
  a. 跳板热路径**同步落盘前 ~400 条**(小 fd 直写, 不靠 1s poller), 确保 3s 内就拿到完整轨迹。
  b. 不 nop-store(避免破坏安装序列致自旋); 改由**独立 busy 线程持续把槽写回跳板**, 抢在 0x75bf7c 检测用槽期间在位。
  c. 若拿到"越狱路径 open/access 返回值 → 状态变量"链, 则在跳板里对**这些特定路径**返回 ENOENT(OBSERVE_ONLY=0), 试最小拦截。

## Round 57（2026-08-24,★★ 同步落盘拿到完整检测 syscall 轨迹, 发现: 检测不查越狱文件!)

### 修复: 热路径用预开 fd 的 write() 同步落盘(不靠 poller), 秒退也不丢数据
- 之前 poller 1s 落盘, 检测常在 1s 内退出 → 拿不到轨迹。改为跳板→hsbc_svc_record→raw_emit(write fd)。
- 本轮 App **存活 >=12s**(未触看门狗), 日志 3129B, 拿到检测全程 syscall。

### ★★ 检测的完整 syscall footprint(经 svc 网关, 退出前):极小, 且**无一个越狱文件查询**
| syscall | 次数 | 调用点 | 说明 |
|---|---|---|---|
| nr=294 (BSD) | 2 | +0x44ef20, +0x6dd618 | 封装 0x240218; 294=? (待定, 非文件) |
| nr=202 sysctl | 1 | +0x348e3c | 封装 0x348da4; MIB={1,2}(CTL_KERN.?), 256B 输出 |
| nr=-31 mach_msg_trap | 13 | +0x40c738 | 封装 0x40c698 (mov x16,#-0x1f); Mach IPC |
| nr=5/33 dyld缓存 | 8 | +0x693b08 等 | 映射 /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e |
| nr=73 munmap | 1 | +0x3aa78c | 解映射 |

- **关键: 没有任何 /var/jb、Cydia、/bin/bash、apt、substrate 等越狱路径查询经过网关!**
- ⇒ 3s 退出的越狱判定**不是靠查越狱文件**。可能来自:
  1. **sysctl {1,2}**(CTL_KERN 子项, 查进程信息/调试标志 P_TRACED?), 或
  2. **mach_msg_trap + Mach IPC**(task_info/vm_region 查注入库、host 信息), 或
  3. **dyld 共享缓存比对**(映射磁盘干净 cache, 与内存中被 hook 的库比对, 检测 inline hook/注入)。
- dyld cache 映射高度可疑: OneSpan/Promon 已知手法 = 映射干净 cache 后**用其中的干净 syscall stub**发检测调用,
  这些调用**不经 App __text 的槽**(用的是 cache 里 libsystem 的 svc), 故我的网关观测不到真正的文件检测!
  这解释了"无越狱文件查询": 文件检测可能走了 cache 里的干净 stub。

### 战略转折
- 若检测靠 sysctl/mach(不查文件), 则文件系统伪装(Shadow)天然无效(已被 Round56 证实)。
- 若检测靠 dyld-cache-clean-stub 发文件查询, 则我的网关观测不到, 需 hook cache stub 或在更底层(内核/系统调用入口)拦。
- **下一步**: 
  a. 确定 nr=294 与 sysctl{1,2} 具体查什么(静态跟 0x240218/0x348dd0 的返回值如何影响判定)。
  b. 关键实验: **在跳板里对 sysctl(202) 的这次调用**观察其返回 buffer, 看是否含 P_TRACED/被判越狱的值。
  c. 若确认 sysctl 是判定输入, 在跳板里改写其返回(OBSERVE_ONLY=0 针对 202) → 最小拦截试。

## Round 58（2026-08-24,返回值观测: 检测 syscall 全部返回正常值; "存活">=12s 实为 99% CPU 自旋)

### 跳板增强: svc 返回后捕获 retval + sysctl 输出缓冲(不拆帧, 保存/恢复 nzcv 保证封装 b.lo 正确)
- `shared_region_check_np`(294) ×2 → **ret=0**(共享区正常)。
- `sysctl{1,2}`(202) → ret=0, oldp 前缓冲 = `32 31 2e 34 2e 30 00` = ASCII **"21.4.0"** = **KERN_OSRELEASE**(内核版本串, benign)。
  ⇒ MIB {1,2} = CTL_KERN, KERN_OSRELEASE。**不是越狱信号**。
- `mach_msg_trap`(-31) ×7、dyld cache access/open、munmap(73)。**全部正常返回, 无越狱判定值**。

### ★ 纠正"存活"假象: nop-store 下 App 2/3 概率"存活>=15s", 但 `ps` 显示 **99.3% CPU (Rs 自旋)**
- 不是正常运行到 UI, 是 Round54/55b 的**同一自旋**(状态机进入非终止循环), 偶尔撑过 20s 偶尔 1s 静默退出。
- nop-store 破坏 0x346c68→0x75bf7c→0x346c7c 安装序列 = 自旋根因。**再次确认 nop-store 不可行**。

### 汇总: 检测性质 = 内存完整性/反 hook, 非文件
- 观测到的检测 syscall(shared_region_check_np + KERN_OSRELEASE + mach_msg + dyld cache 映射)全部 benign 返回。
- 说明**真正的越狱判定不在这些 syscall 的返回值里**, 而在别处:
  1. dyld 共享缓存**比对**(映射磁盘 cache, 与内存中被 ElleKit 改过的 __TEXT/GOT 比对)—— 判定在内存比对逻辑, 不在 syscall。
  2. 或 mach_msg 背后的 **task_info/vm_region 枚举**(检测非 cache 的可执行内存 = 注入的 tweak/ElleKit)。
  3. 或**存在不经槽的检测路径**(cache 里干净 libsystem 的 svc, 或直接内联 svc 在别的函数)。

### 结论与转向
- svc 网关观测已到极限: 判定不体现在经槽的 syscall 返回值; 中途改控制流(nop-store)必自旋。
- **需换观测层**: 用 debugserver/lldb attach 在 0x75bf7c 状态机里下断点, 单步看"越狱→状态变量"的真实来源
  (是 dyld cache 内存比对? 还是 vm_region 枚举?)。或用调试器读退出时的调用栈。
- 或接受: 越狱环境的**根本特征**(ElleKit 注入改了内存 / 存在非 cache 可执行页)无法在不改内核的前提下对 Promon 隐藏,
  则本机(Dopamine KFD+PPL)可能需要**内核层**隐藏(如 vm_region 过滤), 超出 tweak 能力 → 记录为高难度阻塞。

## Round 59（2026-08-24,重断言线程无法赢得竞争: 检测在 init[42] 主线程同步完成)

### 尝试: 不 nop-store, 后台线程紧凑重写槽回跳板, 想观测未破坏的真实检测序列(含 exit)
- 结果: 跳板 **0 命中**, App 正常 3s 退出。
- 根因: 安装序列 `0x43e0bc bl 0x346c68(store) → 0x43e0c0 bl 0x75bf7c(检测+exit)` 在**同一 init[42] 主线程上背靠背同步执行**, 微秒级。
  App 的 str 覆盖我的跳板后, 检测立即用真网关跑完并 exit(1), 我的后台线程根本没被调度到就退了。

### ★ 决定性工程结论: svc 网关观测法对"真实检测路径"根本无效
- 要么 nop-store(破坏序列 → 自旋, 拿不到真实 exit 路径)。
- 要么不 nop-store(真实序列微秒级跑完, 后台线程赢不了竞争, 0 观测)。
- 二者不可兼得。**svc 网关观测到此为止**(已榨干: 确认检测 syscall footprint + 全 benign 返回 + 无文件查询)。

### 下一步(换观测层, 二选一)
- **(A) Frida Stalker trace 0x75bf7c**: 设备有 /var/jb/usr/sbin/frida-server。用 Stalker 记录 0x75bf7c 实际执行的指令流 +
  越狱判定分支处的寄存器值, 直接看"判定输入从哪来"。风险: Promon 反 Frida, 可能 attach 即变行为; 但 trace 到 exit 前的分支即可。
- **(B) 接受内核层结论**: 检测=内存完整性(dyld cache 比对/vm_region 枚举检测 ElleKit 注入页), tweak 层无法隐藏,
  需内核层(KFD/PPL 已有)做 vm_region 过滤 —— 工程量大, 记为高难阻塞。
- 倾向先试 (A): 一次 Stalker trace 可能直接定位判定点, 性价比高。

## Round 60（2026-08-24,★★★ 颠覆性发现: 0x75bf7c 正常返回, 退出不走任何标准 exit 路径)

### 用 ElleKit MSHookFunction hook 多个退出点(不 nop-store, 真实序列)
- hook: 0x1f05dc(网关exit封装), 0x75bf7c(状态机), libc exit/_exit/abort/pthread_kill/pthread_exit/kill。
- 结果(pristine 真实序列, App 3s 主动退出/无崩溃):
  - **[ENTER-0x75bf7c] t=452ms → [RETURN-0x75bf7c] t=455ms**: 状态机**正常返回, 只跑 3ms, 没在里面 exit!**
  - **其余所有 exit hook 一个没命中。** App 却在 3s 主动退出(无崩溃日志=非信号/看门狗)。

### ★★★ 推翻 Round 52-59 的核心假设
- **0x75bf7c 不是退出点**。它 3ms 就返回, 里面 4 个 exit(1) 是死代码(本次未走)。
- 之前"nop 4 个 exit 调用致自旋""patch 0x1f05dc 改行为"的因果链**站不住**——那些改动的副作用来自破坏 init 序列, 不是拦到了真实退出。
- 真实退出(~3s)**不经**: 0x1f05dc / libc exit / _exit / abort / pthread_kill / pthread_exit / kill。

### 退出机制的新假设(待验证)
1. **raw svc 直接 exit**(不用 0x1f05dc 封装, 别处内联 `mov x16,#1; svc`)—— 需 hook 网关槽抓 nr=1(但那需 nop-store)。
2. **Mach 终止**: task_terminate / thread_terminate_self(经 mach_msg 或 mach trap), 不走 BSD exit。
3. **系统杀**: Promon 让 App 不 checkin/不渲染, 被 SpringBoard/backboardd 正常终止(非崩溃)。3s ≈ 启动 checkin 超时。
4. 退出发生在 **0x75bf7c 返回之后**(455ms)到 3s 之间, 即 init[42] 后续(0x346c7c 收尾 / 0x43e0f8 blr x8)或更晚的检测层。

### 下一步
- hook 0x75bf7c 之后 init[42] 的调用: 0x346c7c(收尾状态机) + 0x43e0f8 的 blr x8 目标。
- hook mach: task_terminate/thread_terminate(dlsym) + exit 的所有别名(__exit/exit_group?)。
- 或回到网关观测(nop-store)但**只抓 nr=1(exit)的调用者**, 看退出的 caller(即使自旋, exit 前的 caller 也能抓到)。

## Round 60 续（★★★ 抓到真实退出点: init[42] 状态机 0x43ebc4 的 verdict 分支)

### fp-chain 回溯(pid 53235, 退出实例)命中真实退出调用者
- `[EXIT-0x1f05dc] t=471ms`(0x75bf7c 返回后 16ms), 回溯 frame#1 = **+0x43ebd4**。
- ⇒ 退出调用点 = **0x43ebd0: bl 0x774770**, 其前 `0x43ebcc: mov w0,#1`(exit(1))。
- 注意退出确实经 0x1f05dc(网关exit封装), 之前 Round60d 没抓到是因为**进程 fork/重启**(观测到 pid 53235→53251 两个进程,
  只有先退的 53235 命中)。exit **不总在同一进程**, 有重启对。

### ★ 真实 verdict 分支: init[42](0x43e114)的 OLLVM 状态机内
```
43ebb8: mov x8,x9
43ebbc: mov w10,#0xb99a ; movk w10,#0x144a,lsl#16  => w10=0x144ab99a
43ebc4: cmp w9, w10
43ebc8: b.ne 0x43e78c        ; 未越狱→继续状态机
43ebcc: mov w0, #1           ; 越狱→
43ebd0: bl 0x774770          ; = exit(1) (0x774770=加密stub表0x84c098槽, 运行时解析的 exit/cxa 系)
43ebd4: ...                  ; (回溯返回地址落这)
```
- **状态变量 w9 == 0x144ab99a ⇒ 判定越狱 ⇒ exit(1)**。
- 退出点在 **init[42] 0x43e114 的状态机**, 不是 0x75bf7c(0x75bf7c 只 3ms 正常返回)。
  → 纠正: 0x75bf7c 是检测**之一**(算某些值), 但**最终 verdict+exit 在 init[42] 自己的状态机**里。
- 0x774770 = __stubs, 走 `adrp x16,0x84c000; ldr x16,[x16,#0x98]` = 加密 stub 表(RC4 解析), 实为 exit。

### 下一步(定位 w9 来源 → 在输入层改)
- 追 init[42](0x43e114 起)状态机里 **w9 在 0x43ebc4 之前如何被赋值**(哪个检测结果 → w9=0x144ab99a)。
- 关键: 0x43ebc4 是"中途 verdict"还是"汇总 verdict"? 若 w9 直接来自某检测函数返回, 在那函数返回处改即可。
- patch 候选(比之前的都精确): `0x43ebc8 b.ne` → 无条件 `b 0x43e78c`(强制走未越狱分支)。
  但需验证 0x43e78c 分支下游状态是否完整(吸取 Round54 教训: 中途改可能自旋)。这次是"跳过 exit 走正常继续", 风险较低。

## Round 61（2026-08-24,patch verdict分支b.ne→b 仍自旋, 确认必须改状态变量w9来源)

### patch 0x43ebc8 b.ne 0x43e78c → 无条件 b 0x43e78c(强制走未越狱分支)
- 结果: App 从 3s 退出变 **16s 后退出, 但全程 100% CPU 自旋**(RSS 冻结 119264, Rs 态), 非正常运行。
- ⇒ 同 Round54: **CFF 状态机中途翻分支必自旋**。状态变量 w9 未自然变成"未越狱"值,
  强跳 0x43e78c 后下游状态不一致 → dispatcher 死循环。

### 铁律确认: 必须让状态变量 w9 在 0x43ebc4 处自然 != 0x144ab99a(改检测输入), 不能改分支
- 0x43ebc4 的 w9 = CFF dispatcher 的**状态索引**, 由之前一系列 `ldr w0,[jumptable+state<<2]; cmp; csel` 演化而来。
- 某个检测结果(布尔)通过 csel 把状态引向 0x144ab99a(越狱)或别的值(正常)。
- **必须定位那个 csel 的输入布尔来自哪个检测**, 在检测返回处让它=未越狱, 状态机自然走正常流。

### 下一步: 委派子代理做精确数据流分析
- 目标: 从 0x43e114(init[42])状态机入口追到 0x43ebc4, 找出决定 w9 走向 0x144ab99a 的那个检测布尔的来源。
- 素材: /tmp/hsbc_full_disasm.txt(全反汇编), app-binary/hsbcchinax。

## Round 62（2026-08-24,★★★ 定位检测布尔核心: w24 = f(0x7753c4), verdict 状态由它驱动)

### 状态机的越狱布尔 = w24, 在 0x43ea34 由检测函数结果算出
- 0x43e910: `tst w24,#0x1` → 决定状态机走向 exit 状态(0x144ab99a)还是继续。w24=越狱布尔。
- w24 的来源 (0x43e9f8-0x43ea34 状态块):
  ```
  43ea10: bl 0x774fec        ; 检测A(加密stub 0x84c000+0x978)
  43ea14: bl 0x774efc        ; 检测B(加密stub +0x950)
  43ea18: adrp x8,0x80c000; ldr x8,[x8,#0x58]; ldr w0,[x8]  ; 读全局(__got 0x80c058, 运行时绑定)
  43ea24: mov x1,x20; mov x2,x19    ; 两个栈缓冲(0x43e9f8-0x43ea0c 分配)
  43ea2c: bl 0x7753c4        ; 决策函数(加密stub +0x100)
  43ea30: cmp w0, #0x0
  43ea34: cset w24, ne       ; ★ w24 = (0x7753c4() != 0) = 越狱判定
  ```
- 三个检测函数(0x774fec/0x774efc/0x7753c4)全走**加密 stub 表 0x84c000**(RC4 运行时解密), 静态看不到目标。
- ⇒ 关键: **让 0x7753c4 返回 0**(或 w0=0), w24=0(未越狱), 状态机在 0x43e910 自然走继续分支。
  这是**改检测输入**(布尔的算出), 不是改状态分支 —— 符合"必须自然值"的铁律。

### 候选 patch(比 Round61 的分支 patch 精确, 应不自旋)
- patch A: `0x43ea2c bl 0x7753c4` → `mov w0,#0`(52800000)。让决策函数不被调, w0=0 → w24=0。
- 风险: 0x7753c4 可能有副作用(不只返回布尔), 或 w24 还有别的写入点。但值得一试。

### Round 62 实测: patch 0x43ea2c(检测决策→w0=0) 仍 2s 退出
- w24=0 后仍退出 ⇒ 要么还有第二 verdict(0x43e938 用别的输入), 要么 w24 有其他写入, 要么 0x7753c4 有副作用。
- init[42] 有 2 个 verdict(0x43e938/0x43ebc0), 可能走另一条。需要子代理的系统性数据流(state→state 完整图)才能理清多路 verdict。

## Round 63（2026-08-24,子代理未回文但产出CFF切片; 手工建 init[42] 6检测点map)

### init[42] 6 个检测决策点(bl 加密stub; cmp w0,#0; cset 布尔)
| # | 检测调用 | 结果 | 布尔寄存器 |
|---|---|---|---|
| 1 | 0x43e468: bl 0x7753e8 | cmp@0x43e46c | - |
| 2 | 0x43e528: bl 0x77540c | cmp@0x43e52c | - |
| 3 | 0x43e600: bl 0x7753c4 | cset@0x43e608 | w8 |
| 4 | 0x43e680: bl 0x7753f4 | cset@0x43e688 | w21 |
| 5 | 0x43e7e8: bl 0x775418 | cmp@0x43e7ec | w8 |
| 6 | 0x43ea2c: bl 0x7753c4 | cset@0x43ea34 | w24(→0x43e910 tst 决定 verdict) |
- 检测函数全走加密 stub 表(0x84c000, RC4 运行时解密), 静态不知目标。有些(如 0x775418)可能是状态解码helper非检测。
- 单 patch 0x43ea2c(#6)无效(Round62): 多检测点, 需知道**哪个真是越狱检测**。
- ⇒ 下一步: 运行时 probe 读加密表槽(0x84c000+off), 拿各 stub 的真实解析地址, 判断哪个是 access/stat/sysctl 等越狱检测。

## Round 64（2026-08-24,加密stub表解析: 检测函数是 Promon 内部函数, 非libc syscall)

### 运行时读加密表槽 0x84c000+off, 解析出真实目标(全在 hsbcchinax 内部)
| stub | 表槽off | 运行时偏移 | 性质 |
|---|---|---|---|
| 0x7753e8 | +0xb0 | 0x731010 | hsbcchinax 内部函数 |
| 0x7753c4 | +0x100 | 0x2292ac | 内部函数(调 0x6630f0, 复杂逻辑) |
| 0x7753f4 | +0x48 | 0x691870 | 内部函数 |
| 0x775418 | +0xf8 | 0x731a7c | 内部函数 |
- 加密 stub **不是** libc syscall 封装, 而是 Promon **内部函数**(RC4 表只是混淆内部调用)。
- ⇒ init[42] 的 6 个检测点调的是 Promon 自己的检测逻辑(每个又深入调用链)。多 verdict + 内部混淆函数。

### 战略评估: 已到"需完整逆向 Promon 检测算法"的深度
- 中途 patch 一律自旋(铁律); 单点 patch 无效(多 verdict); 检测函数是内部混淆逻辑(非简单 syscall)。
- 继续微观追每个内部函数可能不收敛。需要更高层策略。

## Round 65（2026-08-24,PRMShieldEventManager ObjC层 performSecurityChecks 不是3s退出的触发)

### swizzle -[PRMShieldEventManager performSecurityChecks] 观测: 3s 窗口内**从未被调用**
- Promon 的 ObjC 入口类 PRMShieldEventManager(+performSecurityChecks/setUpdateCallbacks:/ShieldCallbackManager)
  是**运行时(app启动后)**的检测层, 不是 init 期 3s 退出的触发。
- ⇒ 3s 退出 100% 来自 native init[42] C 初始化器, 早于任何 ObjC app 代码。ObjC 层 bypass 治不了它。

## 阶段性结论（Round 55-65 汇总, 2026-08-24)
汇丰中国 = **Promon SHIELD**, 极难。已彻底确认:
1. 检测=内存完整性/反hook(比对dyld cache等), 非文件; 走私有数据段 svc 网关, 绕开所有 libc/ObjC hook 点。
2. 3s 静默退出来自 native init[42] 的 OLLVM CFF 状态机, verdict `w9==0x144ab99a→exit(1)`(经 0x1f05dc)。
3. init[42] 内 ≥2 个 verdict、6 个检测决策点(bl 加密stub→cmp w0→cset 布尔), 检测函数是 Promon 内部混淆函数。
4. **铁律: 中途改控制流(verdict/exit/nop)一律 100% CPU 自旋**(CFF 要求状态变量自然值)。
5. Shadow(含Hook_Syscall)/ObjC swizzle(performSecurityChecks)/Frida 注入 —— 全部无效或被拦。
6. 无 __TEXT 完整性校验(binary patch 本身可行), 但要让状态机自然走 clean 需同时中和多个内部检测的**输入**。

### 可能的下一步(需较大投入或换层)
- (A) 运行时把 6 个检测点的**输入布尔**同时中和(hook 每个内部检测函数返回 clean), 让状态机自然走 —— 需逐个确认哪些是真检测、副作用。
- (B) 内核层(Dopamine KFD/PPL)隐藏越狱环境(改 vm/文件视图), 使 Promon 的内存比对看到 clean —— 工程量大。
- (C) 深逆 Promon 检测算法(dyld cache 比对逻辑), 找它到底比对什么, 针对性伪装那块内存。
- 现实评估: 这是业界公认最难的 RASP 之一, 单机 tweak 层完全绕过需要大量逆向; 已把问题定位到指令级, 但完全解决未达成。

## Round 66（2026-08-24,方向1: 中和检测函数返回值无效, 确认 verdict 数据驱动非返回值驱动)

### hook init[42] 全部 9 个内部 stub, 观测返回值
- `det_774fec` ×8: 返回**指针** 0x1051b4580(非布尔, 是数据gatherer/accessor)。
- `det_774c20` ×1: 返回 0x103(259)。
- `det_774efc` ×2 / `det_7753c4` ×1: 返回 **0(clean)**。
- ⇒ 检测函数**本身返回的就是 clean 值**(0), 没有一个返回"越狱=1"。

### NEUTRALIZE=1 强制全部返回 0: 仍 2s 退出(更快)
- 把 9 个函数返回强制 0 → App 仍退出, 且更快(det_774fec 返回0破坏了后续数据收集)。
- ★ **确认: verdict 不由这些函数的返回值驱动**。它们是**数据收集器**(774fec 返回数据缓冲指针),
  越狱判定在 Promon **内部对收集到的数据做比对**(内存完整性), 不体现为某个函数的布尔返回值。
- 中和返回值治不了 → **方向1(改检测输入布尔)此路不通**。转入方向2(逆比对逻辑)。

### 转方向2: 逆 0x774fec 数据收集 + 内部比对
- 0x774fec 返回 0x1051b4580(数据缓冲)。需看它收集什么(dyld cache? 内存页?), Promon 拿它和什么比对得出越狱。
- 这就是"内存完整性检测"的核心比对逻辑, 是最终要针对性伪装的目标。
