# BMWBypass 第 0-4 轮反思（2026-08-24）

My BMW（`de.bmw.connected.mobile20.cn`）越狱检测弹窗绕过，一次会话内 5 轮定位并解决。记录可推广的过程教训。

## 结果

- 检测 SDK = 标准**开源 IOSSecuritySuite**；弹窗由 Flutter/Dart 层 attestation pre-check 触发。
- 根因 = ISS `amIReverseEngineered()` 命中注入库返回 true（不是 `amIJailbroken`）。
- 方案 = MSHookFunction 挂 ISS 全部 8 个 `() -> Bool` 顶层入口恒返回 false。
- 环境：iPhone 14 Pro Max / iOS 16.3.x / rootless（Dopamine + ElleKit）。SimTouch 截图验证。

## 有效的做法

1. **先静态识别 SDK 身份**。Frameworks 目录直接看到 `IOSSecuritySuite.framework`，省去大量盲猜。开源库的检测手法已知、符号可读，是最有利的起点。llvm-nm（不是 GNU nm，后者不认 Mach-O）列出导出的 `amI*` 入口全集。
2. **运行时探针定位根因，不靠猜**。第 2 轮凭「checkDYLD 检测已加载库名」的合理推断去 hook `_dyld_get_image_name`，mask 掉所有越狱库名，弹窗照旧——合理推断也可能错。改成 hook 全部单-Bool 入口 + 记日志，让 App 自己告诉我它调了 `amIJailbroken` + `amIReverseEngineered`，一轮定位。
3. **SimTouch 截图闭环**。宿主看不到屏幕，靠 `simtouch screenshot` + `tap` 直接确认弹窗有无、并驱动进入下一界面复验。这是判断「绕过是否成功」的唯一可靠手段，比看进程存活/日志更直接（本目标进程本就不自杀）。
4. **弹窗文案反查检测语义**。Flutter 应用文案在 `flutter_assets/.../*.arb`，key=`attestationPreCheckFailureDescriptionCn` 直接点出「attestation pre-check」，结合 Frameworks 里的 Approov 锁定了检测性质。

## 踩过的坑

1. **日志路径**：初版写 `/tmp` 读不到（沙箱 App 的 `/tmp`、`NSTemporaryDirectory()` 重定向到数据容器），一度误判「没注入」。改写 App 数据容器后正常。这坑反复踩，已固化到 memory `feedback_tweak_log_path`：**tweak 日志一律写 App 数据容器**，宿主用 `sudo grep -alr "<bundleid>" /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist` 定位容器再读（比逐个 plutil 快，避免超时）。
2. **只 hook 最明显入口不够**：`amIJailbroken` 是最直觉的点，但它不是弹窗根因。检测类 SDK 常有多个并列入口，注入 tweak 最易命中的是「反逆向/反 hook」类（`amIReverseEngineered`），而非「越狱文件」类。
3. **包名前缀**：新子项目 control 的 Package 必须用 `page.0x01.<name>`，不要用 `com.liam.*`。

## 与其它目标的关键区别

- ISS **无内存完整性自检**，可安全 inline-hook 其导出符号——与农行 mPaaS、汇丰 Promon SHIELD「只能 ObjC swizzle / 私有 svc 网关」完全不同。不要把「银行类只能 swizzle」的约束机械套到这里。
- 靠 Swift mangled 符号定位，不依赖地址偏移，跨小版本/机型/系统通用。

## 遗留

- 登录后深层联网功能是否触发 **Approov** 服务端 attestation 二次校验，需真实账号才能验证，本次未覆盖。若报「无法连接服务」再查 Approov 层。

可推广结论已提炼到 memory `reference_iossecuritysuite`。
