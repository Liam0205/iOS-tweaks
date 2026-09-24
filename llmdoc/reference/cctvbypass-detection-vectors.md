# CCTVBypass 越狱检测向量

## 目的

汇总央视频（CCTV 央视频，`com.cctv.yangshipin.app.iphone`，可执行文件 `CCTVVideo`）3.5.3 的越狱检测向量与当前覆盖情况。验证环境：iPhone 13 Pro / iOS 15.4.1 / Dopamine rootless。架构与实现见 `llmdoc/architecture/cctvbypass-architecture.md`。

## 闪退根因（关键）

闪退**不是** ObjC 遥测 getter 触发的，而是主二进制内的**内联 `svc #0x80` 退出桩**：

```
movz w0,  #0
movz w16, #1        ; SYS_exit
svc  #0x80          ; exit(0)
```

位于文件偏移 `0x51b4` 与 `0x5220`，两处均在 FairPlay 加密页 `[0x4000,0x5000)` 之外（磁盘字节即运行时字节，可静态定位并静态改写）。App 启动早期检测到注入/调试后跳到该桩 `exit(0)`。

该路径的特征完美解释了排查中的所有现象：

- 绕开全部 libSystem 具名符号（`exit`/`_exit`/`abort`/`kill`/`raise`/`exit_group`/`pthread_exit`/`task_terminate`/`__pthread_kill`/`syscall`），故 MSHookFunction 全部拦不到（已逐一验证 hook 生效但从不触发）；
- `exit(0)` 是干净退出，不产生苹果 `.ips`，也不触发 Bugly 的 mach 异常处理，无任何崩溃报告；
- 不是信号，`sigaction` 处理器不触发；
- 不是外部 SIGKILL，`runningboardd`/`launchd` 在启动窗口均未对该进程发信号（frida 附加二者 hook `kill` 证实）。

当前覆盖：运行时扫描主镜像可执行段，把 `movz w16/x16,#1` 紧邻的 `svc #0x80`（`0xd4001001`）就地改写为 nop（`0xd503201f`），遵循 W^X 流程。详见架构文档。

## 越狱判定 ObjC getter 清单

主二进制自研 + 多个第三方 SDK 采集越狱状态，均以干净的 ObjC `BOOL` getter 暴露，**属遥测/上报，非硬门禁**（不是闪退根因）：

- `-[VBInterfaceDeviceInfoImp isJailbreak]`（腾讯 OMG/Beacon 埋点设备信息）
- `-[QTUtils isDeviceJailBreak]` / `-deviceJailBreakString`（央视频自有 `QT` 前缀）
- `+[QTMobClick isJailbroken]`（友盟 UMeng 封装）
- `+[GDTActionStatsMgr isJailBroken]`（腾讯广点通）
- `+[HLSchInfo isJailbroken]`、`-[ODKVSystemInfo jailbroken]`、`-[QLVRPublicParams is_jailbreak]` 等

当前覆盖：`sweepJailbreakSelectors()` 遍历全部类，把命中保守白名单的整数返回 getter 恒改为 0（启动后延迟 0.5s 再扫一次）。

## 路径型文件检测

主二进制通过 libc 具名符号（`stat`/`lstat`/`access`/`fopen`/`open` 等）探测越狱路径：`/Applications/Cydia.app`、`/Library/MobileSubstrate`、`/usr/sbin/frida-server`、`/var/checkra1n.dmg`、`/bin/bash`，友盟另查 `/private/umTest_Jailbreak.txt` 等。

当前覆盖：C 函数 hook 对命中 `is_jb_path_c()`（纯 C 字符串前缀/子串匹配）的路径返回 `ENOENT`；`NSFileManager` 层过滤越狱条目、`canOpenURL:` 对 `cydia://` 等 URL scheme 返回 NO。

## 未发现的检测面

- **无商业 RASP**（无 Promon / OneSpan / DexGuard）。
- **无二进制完整性自检**（inline-hook 与 `__text` patch 安全，不触发校验崩溃）。
- **无私有 svc 网关**。二进制内的 `integrity` / `HMAC` / `checksum` 字符串均来自 Bugly/QAPM 崩溃上报的 SQLite `integrity_check` 与 HMAC，非 text 段自检。

## 排查方法闭环

定位内联 svc exit 根因的完整链路：

1. 逐一 hook 全部终止原语（`exit`/`_exit`/`abort`/`kill`/`raise`/`exit_group`/`pthread_exit`/`task_terminate`/`__pthread_kill`/`syscall`/`abort_with_payload`），验证 hook 生效但**全不触发**；
2. 确认**无崩溃报告**（无苹果 `.ips`、Bugly 无 mach 异常记录）；
3. 确认**非外部 SIGKILL**（frida 附加 `runningboardd`/`launchd` hook `kill`，启动窗口无信号）；
4. 三者叠加 → 判定为进程内、绕开具名符号、干净退出的内联 syscall → **on-device 字节扫描 `svc #0x80`** 定位偏移 `0x51b4`/`0x5220`；
5. 反查偏移是否在 FairPlay 加密页内（本例在 `[0x4000,0x5000)` 之外，可直接静态改写）；
6. 辅助工具：frida hook `strstr` 定位早期版本 dyld 镜像枚举 hook 导致的主线程冻结热点；SimTouch 截图确认屏幕状态。

## 当前覆盖状态（v0.0.1）

| 检测向量 | 状态 | 实现方式 |
|----------|------|----------|
| 内联 svc exit 桩（2 处，闪退根因） | ✅ 已消除 | 运行时 `__text` patch svc→nop |
| 越狱判定 ObjC getter（isJailbreak 等） | ✅ 已中和 | 遍历类 setImplementation 恒返回 0 |
| 路径型文件检测（stat 族/open/fopen） | ✅ 已隐藏 | C 函数 hook + ENOENT |
| NSFileManager 目录枚举 / canOpenURL | ✅ 已过滤 | ObjC hook |
| P_TRACED 反调试 / DYLD 环境变量 | ✅ 已清除 | sysctl / getenv / NSProcessInfo hook |
| dyld 镜像枚举 | ⚪ 不处理 | 无门禁需要，hook 会 O(N²) 冻结 |
| statfs/statvfs rootfs 可写检测 | ⚪ 不处理 | 只遥测，hook 会波及 App 自身容器 |
| 终止原语（exit/abort/kill/raise） | ⚪ 兜底 | 防后续版本新增走具名符号的退出 |

闪退已解决，正式版（关调试日志）连续 3 次冷启动均存活并进入首页（推荐/时事/体育、直播、亚运赛程、底部导航、开屏广告均正常）。

## 版本适配优先检查

央视频升级后建议检查顺序：

1. 内联 svc exit 的偏移、数量或前置指令编码是否变化（当前假定 `movz w16/x16,#1` 紧邻 `svc #0x80`）；
2. 退出桩是否落入 FairPlay 加密页内（若是，磁盘字节不再等于运行时字节，需换定位手段）；
3. 越狱判定 getter 是否新增不在保守白名单内的 selector 名；
4. 是否引入商业 RASP 或二进制完整性自检（会改变 inline-hook/patch 的安全性判断）。
