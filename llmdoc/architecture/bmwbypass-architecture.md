# BMWBypass 架构

## 定位

绕过 My BMW（`de.bmw.connected.mobile20.cn`）的越狱检测弹窗。子项目 `bmwbypass/`，包名 `page.0x01.bmwbypass`。检测面详见 `llmdoc/reference/bmwbypass-detection-vectors.md`。

## 核心方案

**inline-hook（MSHookFunction）IOSSecuritySuite 全部「`() -> Bool`」顶层检测入口，命中恒返回 false。**

- 入口靠 Swift mangled 符号 `MSFindSymbol(NULL, sym)` 定位，不依赖地址偏移 → 跨 App 小版本/机型/系统通用。
- ISS 是检测工具、**无内存完整性自检**，inline-hook 其导出符号安全。这是与农行/汇丰的根本区别（后者只能 ObjC swizzle 或面对私有 svc 网关）。

## 实现结构（`Tweak.x`）

- 无 Logos hook、无 ObjC swizzle，纯 `%ctor` + C 函数指针表：
  - `kHooks[]` 表：8 个入口的 `{mangled 符号, 替换函数, orig 指针}`。
  - `MK_HOOK` 宏生成每个 `hooked_*` 替换函数（统一 `return false`）。
  - `%ctor` 遍历表，`MSFindSymbol` + `MSHookFunction` 逐个挂上，找不到的符号跳过（容错）。
- 覆盖入口：`amIJailbroken`、`amIReverseEngineered`（必需）+ `amIProxied`/`amIDebugged`/`amIRunInEmulator`/`amIInLockdownMode`/`isParentPidUnexpected`/`hasWatchpoint`（冗余，语义相同、无副作用，扛版本升级）。
- 诊断日志由编译开关 `BMW_DEBUG_LOG` 控制，发布版默认关闭；开启时写 **App 数据容器**（`NSTemporaryDirectory()`），不写 `/tmp` 或 `/var/jb/tmp`。

## 构建约束（Linux 交叉编译）

- `export THEOS=/home/liam/theos`。
- 链接需 `LD_LIBRARY_PATH=/home/linuxbrew/.linuxbrew/lib`（补 `libtinfo.so.5`，否则 ld 报缺共享库）。
- `THEOS_PACKAGE_SCHEME = rootless`，`Depends: ellekit`。

## 与其它 bypass 的关键差异

| 维度 | BMWBypass | abcbypass（农行） | hsbcbypass（汇丰） |
|------|-----------|-------------------|--------------------|
| 检测 SDK | 开源 IOSSecuritySuite | mPaaS（闭源） | Promon SHIELD |
| 内存完整性自检 | 无 | 有（inline-hook 触发崩溃） | 有 |
| 安全对抗手段 | inline-hook 导出符号 | 只能 ObjC swizzle | 私有 svc 网关，符号级 hook 全失效 |
| 退出机制 | Dart 层弹窗（进程不自杀） | native exit | 延迟退出 |
| 难度 | 低 | 中 | 极高（PoC 阶段） |

## 验证手段

- 目标进程本就不自杀，进程存活无法判断绕过成败。用 **SimTouch**（`simtouch screenshot` + `tap`）截图闭环确认弹窗有无并驱动进入下一界面。
- 已验证：进入 App 主页「发现」与登录页无弹窗。

## 遗留

- Approov 远程 attestation 二次校验未验证（需真实账号登录）。
