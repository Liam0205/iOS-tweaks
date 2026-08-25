# BMWBypass 分析记录

目标：My BMW（`de.bmw.connected.mobile20.cn`），绕过越狱检测弹窗。

## 环境

- 设备：iPhone 14 Pro Max（iPhone15,3 / T8120），iOS 16.3.x，rootless 越狱（`/var/jb`，ElleKit + TweakInject）。
- SSH 端口：2216（`mobile@localhost`）。
- App 路径：`/var/containers/Bundle/Application/EFCA2C6E-FA8A-4C3F-8108-6EC8094DF976/My BMW.app`。
- 主 binary：`My BMW`（约 119 MB），Flutter 应用（含 `Flutter.framework` + `App.framework`）。

## Round 0：静态定位（只读侦察）

### 假设
弹越狱框的检测来自某个已知安全 SDK。

### 验证 / 观察
- Frameworks 中发现 **`IOSSecuritySuite.framework`**（标准开源库，Securing 出品），另有 `Approov`（API 完整性防护）、`Dynatrace`（监控）。
- `IOSSecuritySuite` binary（218 KB）符号确认为**标准开源版**：
  - 顶层导出入口（均为 `T` 导出文本符号）：
    - `_$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ` = `amIJailbroken() -> Bool` @ `0x9364`
    - `_$s...28amIJailbrokenWithFailMessage...` = `amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String)` @ `0x93a0`
    - `_$s...29amIJailbrokenWithFailedChecks...` = `amIJailbrokenWithFailedChecks() -> (jailbroken: Bool, failedChecks: [...])` @ `0x93e8`
  - 内部 `JailbreakChecker` 私有方法（带混淆后缀 `LL`，仍导出符号）：`checkSymbolicLinks`、`checkExistenceOfSuspiciousFiles`、`checkSuspiciousFilesCanBeOpened`、`checkRestrictedDirectoriesWriteable`、`checkDYLD`、`performChecks`。
  - `checkDYLD` 黑名单精确命中当前 rootless 越狱注入库：`systemhook.dylib`、`TweakInject.dylib`、`libhooker`、`Substitute`、`roothideinit.dylib`、`CydiaSubstrate` 等。
- 裸跑现象：`uiopen` 启动后主 App 进程存活 ≥10s **不自杀**。→ 弹窗是「等用户点按钮才退」型（App 层 UIAlert），不是自动 kill 进程。
- 主 binary strings **不直接命中** `IOSSecuritySuite`/`amIJailbroken`（=0）。符合 Flutter 应用：调用方在某 framework 或 Flutter plugin，非主 binary 明文。

### 推论
- **已确认**：检测 SDK = 标准开源 IOSSecuritySuite；退出机制 = App 层弹窗，非 native 自杀；Shadow 文件隐藏挡不住是因为 `checkDYLD` 检测的是**已加载 dylib 名字**而非文件存在。
- **关键约束差异**：ISS 是检测工具，**无内存完整性自检**（不像农行 mPaaS/汇丰 Promon），因此可**安全 inline-hook** 其导出符号，无需限制为 ObjC swizzle。
- **对抗层级**：顶层短路 —— hook 三个 `amIJailbroken*` 导出入口，让越狱判定恒为 false。ABI 上 `amIJailbroken()` 返回单 Bool 最简单，先 hook 它反推 BMW 实际调哪个入口。
- **仍未知**：BMW 具体调用哪个入口；是否还用了 `amIDebugged`/`amIReverseEngineered`/`amIProxied`；Approov 侧是否有独立检测。

## Round 1：hook amIJailbroken() 单入口

### 假设
BMW 通过 `IOSSecuritySuite.amIJailbroken() -> Bool` 判定越狱，hook 它返回 false 即可消弹窗。

### 验证
- Tweak（ElleKit 注入）在 `%ctor` 用 `MSFindSymbol(NULL, SYM_AMI_JB)` 定位符号后 `MSHookFunction` 替换为恒返回 `false`。
- 日志改写到 **App 数据容器** `NSTemporaryDirectory()`（此前写 `/tmp` 读不到，是沙箱重定向，非未注入）。

### 观察（日志确证）
```
[BMWBypass] ==== ctor in process, ISS hook install ====
[BMWBypass] hooking _$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ @ 0x10bf5d364
[BMWBypass] amIJailbroken() called -> forcing false
```
- `%ctor` 执行、符号找到并 hook 成功、`amIJailbroken()` 被 BMW **实际调用一次**并被强制返回 false。
- 进程存活 ≥10s（与裸跑一致，本就不自杀）。

### 推论
- **已确认**：BMW 的越狱判定入口就是 `amIJailbroken()`（单 Bool 版），启动时调用一次。hook 命中。
- **待用户确认**：弹窗是否消失（宿主无法看屏）。

### 环境要点（踩坑）
- 日志一律写 App 数据容器，不写 `/tmp` 或 `/var/jb/tmp`（见 memory `feedback_tweak_log_path`）。
- 数据容器快速定位：`sudo grep -alr "<bundleid>" /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist`（比逐个 plutil 快，避免超时）。BMW 容器 = `5A3016AB-0F41-483E-86A6-3DA75AE0C826`。
- 构建需 `export THEOS=/home/liam/theos` + `LD_LIBRARY_PATH=/home/linuxbrew/.linuxbrew/lib`（补 `libtinfo.so.5`）。

## Round 2：hook amIJailbroken + _dyld_get_image_name（失败）

### 假设
弹窗来自 ISS `checkDYLD`（枚举已加载 dylib 名字命中越狱库），hook `_dyld_get_image_name` 过滤即可。

### 观察（SimTouch 截图 bmw_r2.jpg）
- `_dyld_get_image_name` 被密集调用，`systemhook`/`libinjector`/`libellekit`/`libroot` 等越狱库名全部被 mask。
- **弹窗仍在**（"App访问受限"）。

### 推论
- checkDYLD 过滤无效 → 弹窗不由 checkDYLD 主导。**不要在“看起来像”的检测面上反复试**（方法论：patch 前先用运行时证据证因果）。
- 转向：静态定位弹窗真正来源 + 运行时探针。

## Round 2.5：静态定位弹窗来源

- 弹窗文案在 **Flutter 侧**：`App.framework/flutter_assets/packages/localizations_sdk/.../intl_zh_Hans_CN.arb`。
- 文案 key = **`attestationPreCheckFailureDescriptionCn`**：`目前在您的设备中检测到可能存在越狱行为...`。
- 同文件另有 `attestationErrorDescription*`、`faqSecondSectionDescription`（提到 Magisk/Frida/隐藏 Root）——**attestation（证明）** 话术，Frameworks 里确有 `Approov.framework`（远程 App 完整性证明）+ `Dynatrace`。
- 主 binary **确实引用** `amIJailbroken`（ISS 调用方在主 binary，Swift 侧做原生检测后经 platform channel 上报 Dart，Dart 弹这个「pre-check」窗）。
- Dart AOT / Approov binary 均无明文检测串（AOT/混淆）。→ 用运行时探针定位。

## Round 3：探针式 hook 全部单-Bool ISS 入口 —— ✅ 弹窗消除

### 假设
BMW 调用了 `amIJailbroken` 之外的其它 ISS 顶层检测入口，其中之一触发 attestation pre-check 失败。

### 验证
hook 全部 8 个「`() -> Bool` 无参」ISS 顶层入口（amIJailbroken / amIProxied / amIDebugged / amIRunInEmulator / amIReverseEngineered / amIInLockdownMode / isParentPidUnexpected / hasWatchpoint），命中即记日志并返回 false。保留 `_dyld_get_image_name` mask。

### 观察（日志 + SimTouch 截图 bmw_r3.jpg）
- 8 个探针全部 hook 成功。
- BMW 启动实际**只调了两个**：`amIJailbroken()` 和 **`amIReverseEngineered()`**。
- **弹窗消失**，"新车详情"页正常显示（BMW X3 M50、月付、快速访问、配置爱车/预约试驾）。

### 推论
- **✅ 已确认弹窗根因**：`amIReverseEngineered()` 返回 true 触发 attestation pre-check 失败弹窗（Round 1 只 hook `amIJailbroken` 所以仍弹；补 `amIReverseEngineered` 后消除）。
- `amIReverseEngineered()` 内部检测的是运行时被 hook / 注入库存在（ISS 的 ReverseEngineeringToolsChecker：检测 SubstrateLoader / frida / cynject 等）——这正是注入 tweak 会命中的点。
- 最小稳定集 = hook `amIJailbroken` + `amIReverseEngineered` 返回 false。其余探针可保留作冗余（BMW 未来版本可能启用），但应权衡最小化原则。

## Round 4：收敛稳定版 —— ✅ 完成

### 改动
- 保留 hook 全部 8 个「`() -> Bool`」ISS 顶层检测入口，命中返回 false：
  - 必需项：`amIJailbroken`、`amIReverseEngineered`（弹窗根因）。
  - 冗余覆盖：`amIProxied`/`amIDebugged`/`amIRunInEmulator`/`amIInLockdownMode`/`isParentPidUnexpected`/`hasWatchpoint`（语义相同，返回 false 无副作用，扛版本升级）。
- **移除** `_dyld_get_image_name` mask（Round 2 已证明非必需，且有遍历开销与日志噪声）。
- 诊断日志改为编译开关 `BMW_DEBUG_LOG`，发布版默认 **关闭**；开启时写 App 数据容器。

### 验证（发布态，日志关闭）
- SimTouch 截图 bmw_r4.jpg：直接进入 App **主页「发现」**（搜索框、热点、iX3 预订、服务预约/会员权益、底部 Tab 发现/车辆/地图/悦购/我的），无任何越狱弹窗。
- 之前 Round 3 已用 SimTouch 点「开始」进入正常登录页（欢迎/手机号/验证码），进入过程未新增其它 ISS 检测调用。

### 结论
- **目标达成**：My BMW 越狱检测弹窗消除，App 可正常进入业务流程。
- 稳定方案 = inline-hook ISS 全部单-Bool 检测入口返回 false。ISS 无完整性自检，inline-hook 安全。
- 靠 mangled 符号定位、不依赖地址偏移，天然跨 App 小版本/机型/系统版本通用。

### 未覆盖 / 后续关注
- 登录后的深层联网功能是否触发 **Approov** 服务端 attestation 二次校验（需真实账号登录才能验证，超出本次范围）。若后续报「无法连接服务」，查 `attestationErrorDescription*` 链路与 Approov `/var/jb` 相关检测。
- App 版本升级后若复弹，先开 `BMW_DEBUG_LOG` 看命中哪个入口，再按需扩 hook（含 tuple 返回入口 `amIJailbrokenWithFailedChecks` 等）。
