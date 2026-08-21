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

### 下一步（策略选择）

要看 VASCODSK 内联 syscall 的检测逻辑，需绕过其反调试。两条路：
1. **静态**：`llvm-objdump -d app-binary/VASCODSK`，在 `__text` 里找内联 `svc #0x80`
   （`0xd4001001`）附近的检测序列 + 比较 + 退出，定位判定分支，再决定 patch/hook 点。
2. **动态**：让我们的 tweak 先给 VASCODSK 的反调试"消毒"（hook 它依赖的少数 libc 入口 /
   拦 `ptrace`/`csops`），再放 Frida 进去 trace。风险是触发完整性自检。
优先走 1（静态反汇编，零风险），必要时配合 tweak 在 syscall 层（`__text` 内联 svc 无法 hook，
但可尝试 hook `svc` 前的高层封装或用 `MSHookFunction` 拦 VASCODSK 导出的检测入口）。
- 汇丰香港（含 `.appex`）稍后单独验证是否同一套 VASCODSK。
