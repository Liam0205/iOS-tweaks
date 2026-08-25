# BMWBypass 越狱检测向量

## 目的

汇总 My BMW（`de.bmw.connected.mobile20.cn`）的越狱检测向量与当前覆盖情况。验证环境：iPhone 14 Pro Max / iOS 16.3.x / rootless（Dopamine + ElleKit）。

## App 结构

- Flutter 应用：`Flutter.framework` + `App.framework`（Dart AOT，含 `flutter_assets/`）。主 binary `My BMW` 约 119 MB。
- 安全相关 Frameworks：**`IOSSecuritySuite.framework`**（越狱/逆向检测，本次根因）、`Approov.framework` + `ApproovURLSession`（远程 App 完整性证明 attestation）、`Dynatrace.framework`（监控）。

## 检测栈构成

| 框架 | 角色 | 是否直接杀进程 |
|------|------|----------------|
| `IOSSecuritySuite`（标准开源库，Securing 出品） | 本地越狱/逆向/调试检测，结果供 Dart 层判定 | ❌ 不杀进程，检测结果上报 Dart 层弹窗 |
| `Approov` | 远程 attestation（App 完整性证明），影响联网 API | ❌ 影响服务端可用性，非本地弹窗 |

## 弹窗链路

- 现象：弹「App访问受限 / 目前在您的设备中检测到可能存在越狱行为，导致您暂时不能继续使用App。[关闭APP]」。进程**不自杀**，等用户点按钮。
- 文案宿主：`App.framework/flutter_assets/packages/localizations_sdk/assets/translations/intl_zh_Hans_CN.arb`，key = **`attestationPreCheckFailureDescriptionCn`**。同文件另有 `attestationErrorDescription*`、`faqSecondSectionDescription`（提到 Magisk/Frida/隐藏 Root）——attestation 话术。
- 链路：主 binary 调 IOSSecuritySuite 检测入口 → 结果经 Flutter platform channel 上报 Dart 层 → Dart 侧 attestation **pre-check** → 失败则弹此窗。

## IOSSecuritySuite 检测入口（导出 T 符号）

顶层「`() -> Bool`」入口（Swift mangled 符号，`MSFindSymbol(NULL, sym)` 可定位）：

| 可读名 | mangled 符号 | 运行时是否被 BMW 调用 |
|--------|-------------|----------------------|
| amIJailbroken | `_$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ` | ✅ 调用（但非弹窗根因） |
| **amIReverseEngineered** | `_$s16IOSSecuritySuiteAAC20amIReverseEngineeredSbyFZ` | ✅ 调用，**返回 true = 弹窗根因** |
| amIProxied | `_$s16IOSSecuritySuiteAAC10amIProxiedSbyFZ` | ❌ 启动未调（冗余覆盖） |
| amIDebugged | `_$s16IOSSecuritySuiteAAC11amIDebuggedSbyFZ` | ❌ 启动未调（冗余覆盖） |
| amIRunInEmulator | `_$s16IOSSecuritySuiteAAC16amIRunInEmulatorSbyFZ` | ❌ 启动未调（冗余覆盖） |
| amIInLockdownMode | `_$s16IOSSecuritySuiteAAC17amIInLockdownModeSbyFZ` | ❌ 启动未调（冗余覆盖） |
| isParentPidUnexpected | `_$s16IOSSecuritySuiteAAC21isParentPidUnexpectedSbyFZ` | ❌ 启动未调（冗余覆盖） |
| hasWatchpoint | `_$s16IOSSecuritySuiteAAC13hasWatchpointSbyFZ` | ❌ 启动未调（冗余覆盖） |

tuple 返回入口（`amIJailbrokenWithFailMessage`、`amIJailbrokenWithFailedChecks`、`amIReverseEngineeredWithFailedChecks`、`amITampered` 等）ABI 复杂，BMW 未调用，未处理。

## 关键事实

- **运行时探针确认**：BMW 启动只调 `amIJailbroken` + `amIReverseEngineered`。`amIReverseEngineered`（ISS 的 ReverseEngineeringToolsChecker，检测 SubstrateLoader/frida/cynject 等注入痕迹）是弹窗主因——注入 tweak 必然命中。仅 hook `amIJailbroken` 无法消除弹窗。
- ISS 的 `checkDYLD` 黑名单精确命中当前 rootless 注入库（`systemhook.dylib`/`TweakInject.dylib`/`libhooker`/`SubstrateLoader.dylib` 等）。但实测 hook `_dyld_get_image_name` mask 库名**无法**消除弹窗——弹窗不由 checkDYLD 主导。
- ISS **无内存完整性自检**，inline-hook 其导出符号安全。

## 当前覆盖

- ✅ hook 全部 8 个单-Bool 顶层入口恒返回 false（必需项 amIJailbroken/amIReverseEngineered + 6 项冗余覆盖）。弹窗消除，可进入主页与登录页。

## 未覆盖 / 后续关注

- **Approov 服务端 attestation**：登录后深层联网功能可能触发远程校验，本地 hook 未必能过。需真实账号登录验证；若报「无法连接服务」查 Approov 相关 `/var/jb` 检测与 token 生成链路。
- 版本升级若复弹：开编译开关 `BMW_DEBUG_LOG` 看命中哪个入口，按需扩 hook（含 tuple 返回入口）。
