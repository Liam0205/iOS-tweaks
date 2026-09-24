# CCTVBypass 架构

## 定位

绕过央视频（CCTV 央视频，Bundle `com.cctv.yangshipin.app.iphone`，可执行文件 `CCTVVideo`）在越狱设备上启动约 1~2 秒后闪退回主屏的问题。子项目 `cctvbypass/`，包名 `page.0x01.cctvbypass`。目标版本 3.5.3，rootless，验证环境 iPhone 13 Pro / iOS 15.4.1 / Dopamine。检测面详见 `llmdoc/reference/cctvbypass-detection-vectors.md`。

当前版本 `0.0.1`，已验证连续冷启动稳定进入首页。

## 核心方案

**运行时 `__text` patch：把主二进制内 2 处内联 `svc #0x80` 退出桩的 svc 指令改成 nop。这是消除闪退的唯一有效手段。**

闪退根因是主二进制内的内联 exit 桩，而非任何 ObjC 遥测 getter：

```
movz w0,  #0
movz w16, #1        ; SYS_exit
svc  #0x80          ; exit(0)
```

位于文件偏移 `0x51b4` 与 `0x5220`（两处均在 FairPlay 加密页 `[0x4000,0x5000)` 之外，磁盘字节即运行时字节，可静态定位）。App 启动早期检测到注入/调试后跳到该桩 `exit(0)`。该路径绕开全部 libSystem 具名符号、不产生崩溃报告，故 ObjC swizzle 与 C 函数 hook 都拦不住（排查闭环见检测向量文档）。

控制流对补丁友好：干净路径本就通过 `tbnz` 跳到 svc 之后（`0x51b8` / `0x522c`），检测命中才 fall-through 到 exit；第二处 svc 后紧跟 `b +8` 同样并入正常流程。因此把 svc 改成 nop，命中路径自然并入正常启动流程，不破坏控制流。

## 实现结构（`Tweak.x`）

核心函数 `cctv_neutralize_inline_exits()`：`%ctor` 最优先执行。

1. `cctv_main_image_index()` 找到 `filetype == MH_EXECUTE` 的主镜像；
2. 遍历 `LC_SEGMENT_64` load command，只扫描 `initprot & VM_PROT_EXECUTE` 的可执行段；
3. 逐条 32 位指令匹配 `p[1] == svc #0x80`（`0xd4001001`）且 `p[0]` 为 `movz w16,#1`（`0x52800030`）或 `movz x16,#1`（`0xd2800030`）；
4. 命中后 `cctv_patch_word()` 把 svc 改写为 nop（`0xd503201f`）。

改写遵循标准 ARM64 W^X 流程（同 lianjiabypass）：

1. `vm_protect` 把所在页改为 `VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY`；
2. 写入 nop；
3. `vm_protect` **恢复**该页为 `VM_PROT_READ | VM_PROT_EXECUTE`；
4. `sys_icache_invalidate()` 刷指令缓存。

缺第 3、4 步会触发 `KERN_PROTECTION_FAILURE`（lianjiabypass 已踩过同类坑）。

## 辅助防御纵深（非闪退必需）

以下手段在闪退根因被 nop 掉之后并非必需，仅作为遥测中和与防后续版本新增走具名符号的退出路径的兜底：

- **越狱判定 selector 中和**：`sweepJailbreakSelectors()` 遍历全部类，把命中保守白名单（`isjailbreak`/`isjailbroken`/`isdevicejailbreak` 等）的实例/类方法整数返回值恒改为 0。启动后延迟 0.5s 再扫一次，覆盖启动后才注册的类。
- **路径型 C 函数 hook**：`stat`/`lstat`/`access`/`open`/`fopen`/`realpath`/`readlink` 对命中 `is_jb_path_c()` 的越狱路径返回 `ENOENT`；`dlopen` 拒绝越狱 dylib，`dladdr` 把越狱库名伪装成 `libsystem_c.dylib`。
- **进程/环境**：`sysctl` 清 `P_TRACED`、`getppid`→1、`getenv` 屏蔽 `DYLD_INSERT_LIBRARIES`/`_MSSafeMode` 等、`fork`→`ENOSYS`。
- **ObjC 层**：`NSFileManager` 的 `fileExistsAtPath:`/`contentsOfDirectoryAtPath:error:` 过滤越狱条目、`canOpenURL:` 对 `cydia://` 等返回 NO、`NSProcessInfo environment` 去掉注入相关变量。
- **终止拦截兜底**：`exit`/`_exit`/`abort` 命中后主线程转永久 RunLoop、后台线程 `pthread_exit`；`kill`/`raise` 吞掉针对自身的致命信号。

诊断日志由编译开关 `CCTV_DEBUG_LOG` 控制（发布版默认 0），开启时写 **App 数据容器**（`NSTemporaryDirectory()`），不写 `/tmp` 或 `/var/jb/tmp`。开启时另装一批仅用于定位终止路径的诊断 hook（`exit_group`/`pthread_exit`/`task_terminate`/`__pthread_kill`/`syscall`/`abort_with_payload` + 信号处理器 + 心跳），发布版整段 `#if` 排除。

## 明确记录的两条约束

这两条是踩坑后固化的边界，改代码时不要违反：

1. **不 hook dyld 镜像枚举（`_dyld_image_count`/`_dyld_get_image_name`）**。早期版本逐调用重算可见镜像列表，O(N²) + 每镜像多次 strstr，App 按索引遍历镜像时把主线程拖到近乎冻结、卡在启动闪屏（frida hook `strstr` 抓到热点 needle 全是自己的特征串据此定位）。央视频的越狱判定是遥测、无枚举镜像触发的杀进程门禁，隐藏注入库并非必需，故不做镜像枚举对抗。教训与 lianjiabypass 反思一致。
2. **不 hook `statfs`/`statvfs`**。强行给 `/` 及 `/var`、`/private` 前缀返回 `MNT_RDONLY` 会把 App 自己的数据容器（`/var/mobile/Containers…`）也标成只读，影响视频缓存与下载；且 rootfs 可写检测只是遥测向量、非闪退门禁，得不偿失。

## 与其他 tweak 的关键差异

| 维度 | cctvbypass | lianjiabypass | bmwbypass |
|------|-----------|----------------|-----------|
| 闪退/拦截根因 | 主二进制内 2 处内联 svc exit | JGBSDK 约 29 处内联 svc exit + 文件/dyld/注入检测 | Dart 层 attestation 弹窗（进程不自杀） |
| 内联 svc 手法 | 同源：运行时 `__text` patch svc→nop | 同源：运行时 `__text` patch svc→ret | 无内联 svc |
| patch 目标镜像 | 主可执行镜像（`MH_EXECUTE`） | `JGBSDK.framework` | 不 patch，inline-hook 导出符号 |
| dyld 镜像枚举对抗 | 不做（会 O(N²) 冻结，且无门禁需要） | 必须做但作用域限定 + vis-map 缓存 | 不需要 |
| 检测 SDK | 无商业 RASP、无二进制自检 | JGBSDK（疑似贝壳自研）+ du/a/senseid | 开源 IOSSecuritySuite |

cctvbypass 与 lianjiabypass 的内联 svc 手法同源（都是运行时改写 `__text`），差异在 cctvbypass patch 的是主可执行镜像而非独立 framework，且改成 nop（lianjiabypass 改成 ret，因其命中点在函数体内需正常返回），并且因目标无镜像枚举门禁而彻底放弃 dyld 枚举对抗。

## 依赖与边界

- 构建依赖：Theos、libsubstrate（`MSHookFunction`）、Foundation/UIKit。
- 打包依赖：rootless scheme，`Depends: ellekit`。
- 注入边界：进程 `CCTVVideo`。
- 实验记录：`cctvbypass/analysis.md`。

## 主要回归风险

- 央视频升级后内联 svc exit 的偏移、数量或前置指令编码变化（当前假定 `movz w16/x16,#1` 紧邻 `svc #0x80`）；若退出桩落入 FairPlay 加密页内，磁盘字节不再等于运行时字节，需重新定位。
- W^X 流程改动时不要漏掉恢复 R+X + 刷 icache。
- 不要为隐藏注入库而恢复 dyld 镜像枚举 hook，也不要恢复 `statfs`/`statvfs` 强制只读。
- 后续版本若新增走具名符号的退出路径，兜底的终止拦截可能需要扩展。
