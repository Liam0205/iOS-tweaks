# Changelog

## 0.0.2

- 补充验证信息：在 My BMW 6.8.2 版本验证可用

## 0.0.1

- 绕过 My BMW（`de.bmw.connected.mobile20.cn`）的越狱检测弹窗（「App访问受限 / 检测到可能存在越狱行为」）
- 检测 SDK = 标准开源 IOSSecuritySuite；弹窗由 Flutter/Dart 层的 attestation pre-check 触发，检测结果来自主 binary 调用的 ISS 入口
- 运行时探针确认 BMW 启动只调用 `amIJailbroken()` 与 `amIReverseEngineered()`，后者命中注入库是弹窗根因（仅绕 amIJailbroken 仍弹）
- 方案：inline-hook（MSHookFunction）ISS 全部 8 个「`() -> Bool`」顶层检测入口恒返回 false（含 amIJailbroken/amIReverseEngineered/amIProxied/amIDebugged/amIRunInEmulator/amIInLockdownMode/isParentPidUnexpected/hasWatchpoint）
- ISS 无内存完整性自检，inline-hook 安全；靠 Swift mangled 符号定位，跨 App 小版本/机型/系统通用
- 验证环境：iPhone 14 Pro Max / iOS 16.3.x / rootless（Dopamine + ElleKit）；SimTouch 截图确认进入 App 主页与登录页无弹窗
- 诊断日志由编译开关 `BMW_DEBUG_LOG` 控制，发布版默认关闭
