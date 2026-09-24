# CCTVBypass 更新日志

## 0.0.1

- 首个版本。解决央视频（`com.cctv.yangshipin.app.iphone`）在 rootless 越狱设备上启动秒退的问题。
- 闪退根因：主二进制内 2 处内联 `svc #0x80` → `exit(0)` 退出桩（检测到注入/调试后无痕自杀，绕开全部 libSystem 具名符号，不产生崩溃报告）。
- 核心修复：运行时 `__text` patch，扫描主镜像把 `movz w16/x16,#1 ; svc #0x80` 的 svc 改成 `nop`。
- 辅助：中和越狱判定 selector、路径型 C 函数 hook 隐藏越狱文件、清 `P_TRACED`、`getppid`/`getenv`/`canOpenURL` 处理、`exit/abort/kill/raise` 兜底拦截。
- 已在央视频 3.5.3 / iPhone 13 Pro / iOS 15.4.1 / Dopamine 验证：连续冷启动稳定进入首页。
