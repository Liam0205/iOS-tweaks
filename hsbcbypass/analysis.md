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

### 下一步

1. 脱壳主二进制 + 用 Mach-O 工具（设备端 nm/otool 或 macOS）解析 `jailbreak6status`/
   `acceptJailbroken` 的符号地址（Linux nm 不认 Mach-O）。
2. 扩展探针：hook 这些 Swift 方法确认哪个是判定源头，优先在**源头层**改返回值（最稳，
   类似 abcbypass 的 `initRiskManage` 思路）。
3. 汇丰香港（232MB，含 `.appex`）单独验证是否同一套 RASPFramework。
