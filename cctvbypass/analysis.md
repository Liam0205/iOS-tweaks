# CCTVBypass 分析记录

## 目标

- App：央视频（CCTV 央视频），Bundle `com.cctv.yangshipin.app.iphone`，可执行文件 `CCTVVideo`
- 验证版本：3.5.3
- 设备：iPhone 13 Pro / iOS 15.4.1 / Dopamine rootless（反向隧道端口 22415）
- 现象：越狱设备上启动约 1~2 秒后闪退回主屏，不产生任何崩溃报告

## 检测面

主二进制内自研 + 多个第三方 SDK 采集越狱状态，均以干净的 ObjC `BOOL` getter 暴露（属遥测/上报，非硬门禁）：

- `-[VBInterfaceDeviceInfoImp isJailbreak]`（腾讯 OMG/Beacon 埋点设备信息）
- `-[QTUtils isDeviceJailBreak]` / `-deviceJailBreakString`（央视频自有 `QT` 前缀）
- `+[QTMobClick isJailbroken]`（友盟 UMeng 封装）
- `+[GDTActionStatsMgr isJailBroken]`（腾讯广点通）
- `+[HLSchInfo isJailbroken]`、`-[ODKVSystemInfo jailbroken]`、`-[QLVRPublicParams is_jailbreak]` 等

路径型文件检测（libc 具名符号 stat/access/fopen…）：`/Applications/Cydia.app`、`/Library/MobileSubstrate`、`/usr/sbin/frida-server`、`/var/checkra1n.dmg`、友盟 `/private/umTest_Jailbreak.txt` 等。

未发现商业 RASP（无 Promon/OneSpan/DexGuard）、无二进制完整性自检、无私有 svc 网关（`integrity`/`HMAC`/`checksum` 字符串均来自 Bugly/QAPM 崩溃上报的 SQLite `integrity_check` 与 HMAC）。

## 闪退根因（关键）

闪退**不是**上述 ObjC 遥测 getter 触发的，而是主二进制内的**内联 `svc #0x80` 退出桩**：

```
movz w0,  #0
movz w16, #1        ; SYS_exit
svc  #0x80          ; exit(0)
```

位于文件偏移 `0x51b4` 与 `0x5220`（镜像基址 + 偏移；两处均在 FairPlay 加密页 `[0x4000,0x5000)` 之外，磁盘字节即运行时字节）。App 启动早期检测到注入/调试后跳到该桩 `exit(0)`。

该路径的特征完美解释了排查中的所有现象：
- 绕开全部 libSystem 具名符号（`exit`/`_exit`/`abort`/`kill`/`raise`/`exit_group`/`pthread_exit`/`task_terminate`/`__pthread_kill`/`syscall`），故 MSHookFunction 全部拦不到（已逐一验证 hook 生效但从不触发）；
- `exit(0)` 是干净退出，故不产生苹果 `.ips`，也不触发 Bugly 的 mach 异常处理，无任何崩溃报告；
- 不是信号，故 `sigaction` 处理器不触发；
- 不是外部 SIGKILL，`runningboardd`/`launchd` 在启动窗口均未对该进程发信号（frida 附加二者 hook `kill` 证实）。

控制流对补丁友好：干净路径通过 `tbnz` 跳到 svc 之后（`0x51b8` / `0x522c`），检测命中才 fall-through 到 exit；第二处 svc 后紧跟 `b +8` 同样并入正常流程。因此把 svc 改成 nop，命中路径自然并入正常启动流程，不破坏控制流。

## 方案

运行时 `__text` patch（沿用 lianjiabypass 手法）：`%ctor` 中扫描主可执行镜像的可执行段，把 `movz w16/x16,#1` 紧跟 `svc #0x80` 的 svc 指令改成 `nop`（`vm_protect` 开可写 → 改指令 → 恢复 R+X → `sys_icache_invalidate`）。这是消除闪退的唯一有效手段。

辅助（防御纵深，非闪退必需）：中和越狱判定 selector 恒返回 0、路径型 C 函数 hook 隐藏越狱文件、清 `P_TRACED`、`getppid`→1、`canOpenURL(cydia://)`→NO 等；`exit/abort/kill/raise` 兜底拦截以防后续版本新增走具名符号的退出。

## 踩过的坑

- **dyld 镜像枚举 hook 导致主线程冻结**：早期版本 hook `_dyld_image_count`/`_dyld_get_image_name` 逐调用重算可见镜像列表（O(N²) + 每镜像多次 strstr），App 按索引遍历镜像时卡在启动闪屏。frida hook `strstr` 抓到热点 needle 全是自己的特征串，据此定位。已移除镜像枚举对抗（央视频无枚举触发的杀进程门禁）。教训与 lianjiabypass 反思一致。
- **`statfs`/`statvfs` 强制只读**会把 App 自己的数据容器（`/var/mobile/Containers…`）标成只读，影响视频缓存/下载，已移除。
- **日志假阴性**：tweak 日志写 App 沙箱 `NSTemporaryDirectory()`（正确），但用 `mobile` 用户 `find` 容器时无权限遍历，误判"ctor 没跑"。核对沙箱内文件须用 sudo。

## 验证

- 连续 3 次冷启动均存活；正式版（关调试日志）加载到首页（推荐/时事/体育、直播、亚运赛程、底部导航、开屏广告均正常）。
- 排查方法闭环：SimTouch 截图确认屏幕状态、frida 附加确认终止路径与热点、on-device 字节扫描定位 svc-exit 偏移。
