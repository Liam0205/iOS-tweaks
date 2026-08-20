# LianJiaBypass 架构

## 架构目标

`lianjiabypass/Tweak.x` 同时对抗链家（`com.exmart.HomeLink` 9.86.91）和贝壳找房（`com.lianjia.beike` 3.06.21，进程名 `LJShell`）的越狱检测。两个 App 同属贝壳集团，共用**同一套检测引擎**，因此一份 tweak 同时覆盖两者：`Makefile` 的 `INSTALL_TARGET_PROCESSES = LianJiaShell LJShell`。

当前版本 `0.1.0`，已发布，两个 App 的主界面均验证通过。

## 检测引擎构成

四个框架在启动约 0.08s 内全部加载完毕：

| 框架 | 大小 | 身份 | 作用 |
|------|------|------|------|
| `JGBSDK.framework` | 3MB | 疑似贝壳自研“精工”安全 SDK（URL scheme `beikejinggong`），@rpath 动态库，**非静态链入**主程序 | 越狱检测核心引擎，直接触发退出 |
| `du.framework` | 676KB | 数盟/数字联盟（Shuzilm）设备指纹 SDK，类 `DUNetwork` | 采集设备指纹（含越狱信号），一般只上报不杀进程 |
| `a.framework` | 90KB | 无独立品牌名的小型检测库 | 含 `_isInjectedWithDynamicLibrary`，主线程 strstr 扫描已加载 dylib |
| `senseid_ids` | — | 另一采集类框架 | 与 du 类似，只报不杀 |

JGBSDK 的 `XxxCheck` 系列 selector（`JailbrokenCheck`/`DylibCheck`/`detectDebugger` 等）与越狱特征字符串（`/Applications/Cydia.app`、`CydiaSubstrate.framework` 等）详见 `llmdoc/reference/lianjiabypass-detection-vectors.md`。检测结果通过 `receiveProtectEventWithCode:reason:` 报给业务层 `LJBRProtectManager` / `JGBProtect`。

## 四层对抗

这是本 tweak 的核心。四层检测彼此独立触发，必须逐层拆解才能定位：秒退（文件+dyld 检测）→ 冻结（注入检测拖慢主线程）→ 延迟无痕退出（内联 syscall）。

### 第 1 层：文件检测层

**机制**：JGBSDK 对已知越狱路径做 `stat`/`access` 探测（如遍历 `/var/jb/usr/lib/TweakInject/*.plist` 约 38 项黑名单逐个 `access()`），并枚举 `.../DynamicLibraries` 类目录匹配 `.dylib`/`.plist` 文件名。

**对抗**：fishhook 覆盖 `stat`/`lstat`/`access`/`opendir`/`dlopen`，对匹配 `is_jb_name_c()`（纯 C 字符串子串匹配）的路径统一返回 `ENOENT`（`errno` 由调用方读取）。`dladdr` 被覆盖，把越狱相关 dylib 的 `dli_fname` 伪装成 `/usr/lib/system/libsystem_c.dylib`。`NSFileManager` 的 `contentsOfDirectoryAtPath:error:` / `contentsOfDirectoryAtURL:...` 过滤越狱条目——只有当被扫描目录路径匹配 `is_dylib_dir()`（含 `DynamicLibraries`/`MobileSubstrate`/`TweakInject`）时才额外过滤 `.dylib`/`.plist` 文件，避免误伤 App 自身正常的 `.plist` 读取。

为什么不能只 hook 单一 API：早期版本单独 hook `opendir`/`stat` 不够，检测同时走 `access()` 遍历黑名单和 dyld 镜像枚举（见第 2 层），必须多路径同时覆盖才能消除秒退。

### 第 2 层：dyld 镜像枚举层

**机制**：JGBSDK 的 `DylibCheck` 通过 `_dyld_image_count`/`_dyld_get_image_name` 枚举已加载镜像，寻找越狱/注入相关 dylib（如自身 tweak dylib、ElleKit）。

**对抗**：fishhook 这两个函数，但**作用域限定**——用 `dladdr(__builtin_return_address(0), &info)` 判断调用方所属模块（`caller_is_detector()`：模块路径含 `JGBSDK`/`/du.framework/`/`senseid`/`/a.framework/`），只有来自检测框架的调用才重排/隐藏越狱镜像，来自 App/Flutter 或系统库的调用原样透传。

配合 `g_vis_map`（`visibleIdx -> realIdx` 缓存，`pthread_mutex` 保护，仅在原始镜像数变化时通过 `rebuild_vis_map_locked()` 重建）避免每次调用都做 O(n×strstr) 全量重排。

**为什么简单方案失败**：
- 全局重排（早期版本）能骗过 `DylibCheck` 但会让应用**冻结**——Flutter 引擎在紧循环里按索引调用 `_dyld_get_image_name(idx)`，若每次调用都重新做 O(n) 遍历+strstr 过滤，整体退化为 O(n²)，长时间占满主线程，表现为界面起不来。
- 用镜像地址范围判断调用来源（更早尝试）失败：`_dyld_get_image_header()` 返回的基址（如 `0x1127c4000`）与 `__builtin_return_address(0)` 实际执行地址（如 `0x111dd0638`）不在同一范围内，判断失效；改用 `dladdr` 判断调用方模块路径才可靠。

### 第 3 层：注入检测层（主线程冻结真凶）

**机制**：`a.framework` 的 `_isInjectedWithDynamicLibrary` 经 CFRunLoop → dispatch main queue 周期性执行，每轮对已加载 dylib 列表做昂贵的 strstr 扫描 → 主线程持续繁忙 → UI 永远起不来。表现上和"检测惩罚型冻结"完全一样，但根因其实是**己方响应速度不够**（第 2 层未覆盖到这个调用方）叠加**这个函数本身很慢**。

**对抗**：`MSHookFunction` 直接 hook `_isInjectedWithDynamicLibrary`（`dlsym(RTLD_DEFAULT, "isInjectedWithDynamicLibrary")`，找不到则退回带下划线的 `_isInjectedWithDynamicLibrary`），恒返回 `0`（未注入）。之所以必须用 `MSHookFunction` 而非 fishhook：这个函数在 `a.framework` 内部被直接调用（同镜像内跳转，不经过调用方的 GOT/PLT），fishhook 的导入表 rebinding 对同镜像内部调用无效。

**排错线索**：`caller_is_detector()` 最初漏判了 `a.framework`，导致它的 dyld 调用被第 2 层错误地透传、其内部 strstr 也未被第 3 层拦截，这是冻结长期定位不到的直接原因。

### 第 4 层：自杀退出层（直接 syscall）

**机制**：JGBSDK 的 `__text` 中散布约 **29 处** 内联 `mov w16,#1; svc #0x80`（即 `exit(1)`）序列，完全绕过 libc 的 `exit`/`_exit`/`abort` 符号入口。这类调用不经过 GOT/PLT，也不触发任何 signal，用户态无法通过 hook `exit`/`_exit`/`abort`/`kill`/`pthread_kill` 或安装 `sigaction` 信号处理器拦截（本仓库第 11-12 轮验证均未命中）。JGBSDK 还内建 anti-frida（含字符串 `"your app hooked by Frida"`），使动态 trace 路线也不可行。

**对抗**：运行时二进制 patch，而非 hook。`patch_jgb_exit_syscalls()` 在 ctor 阶段扫描 JGBSDK 的 `__TEXT,__text` 段（通过 `_dyld_image_count`/`_dyld_get_image_name` 找到 JGBSDK 镜像，遍历 `LC_SEGMENT_64` load command 定位 `__text` 的 `text_start`/`text_size`），逐条 32 位指令匹配：

```
mov w16, #1   编码 0x52800030
svc #0x80     编码 0xd4001001
```

命中后将 `svc #0x80` 就地改写为 `ret`（编码 `0xd65f03c0`），使原本走向自杀的检测失败分支变成正常函数返回。

**改写遵循标准 ARM64 W^X 流程**：
1. `vm_protect` 把所在页改为 `VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY`（优先尝试 COPY，失败则回退到不带 COPY 的 `RW`）
2. 写入 `ret` 指令
3. `vm_protect` **恢复** 该页为 `VM_PROT_READ|VM_PROT_EXECUTE`
4. `sys_icache_invalidate()` 刷新指令缓存

**关键教训（v0.0.18 曾踩坑）**：第 3 步的恢复不能省略。若用 `VM_PROT_COPY` 改权限后没有恢复回 `R+X`，页会停留在 `rw-`（可写不可执行）状态；之后 dyld 执行 JGBSDK 自身的模块初始化代码（该代码恰好落在同一页）时会触发 `KERN_PROTECTION_FAILURE` 崩溃。修复方式是严格执行"改 RW → 写 → 恢复 R+X → 刷 icache"的完整闭环，不能只做前两步。

## ctor 加载顺序

`%ctor` 内按顺序执行：

1. fishhook `rebind_symbols()`：`opendir`/`stat`/`lstat`/`access`/`_dyld_image_count`/`_dyld_get_image_name`/`dlopen`/`dladdr`（第 1、2 层）
2. `MSHookFunction` 覆盖 `_isInjectedWithDynamicLibrary`（第 3 层，通过 `dlsym` 定位函数地址）
3. `patch_jgb_exit_syscalls()`（第 4 层，运行时改写 JGBSDK `__text`）

`LJ_DEBUG_LOG` 编译开关（默认 `0`）控制日志：关闭时 `lj_log()` 函数体被 `#if` 整段排除，release 版本零开销；开启时日志写入 `NSTemporaryDirectory()/lianjiabypass.log`。

## 验证结果

- 存活 >30 秒，无秒退、无冻结（etime 持续增长）
- 链家：完整进入主界面，二手房/新房/租房/装修/找经纪人等功能齐全，"行情播报"在线数据正常加载
- 贝壳找房：同一套 tweak 验证通过（共用检测栈，无需额外适配）
- `patch_jgb_exit_syscalls()` 稳定命中并成功改写全部 29 处 exit syscall（`failed=0`）

## 与其他 tweak 的关键差异

| 维度 | abcbypass | lianjiabypass |
|------|-----------|----------------|
| 内联 svc exit | 存在，**无法解决**，只能通过线程挂起/巡逻定时器缓解 | 存在，**已彻底解决**——运行时改写 `__text` 把 `svc` 变成 `ret` |
| dyld 镜像枚举对抗 | 不需要（ABC 不靠索引访问镜像） | 必须作用域限定：目标是 Flutter，按索引访问镜像，全局重排会导致主线程冻结 |
| 冻结成因 | 无冻结场景 | 冻结不是检测层的惩罚性设计，而是己方 hook（或未覆盖到的检测函数）本身太慢/O(n²)，需看门狗式栈回溯定位真凶 |
| MSHookFunction 使用范围 | 部分函数因内存扫描器风险受限（libpthread 不安全） | 仅用于框架内部直接调用、fishhook 无法覆盖的场景（`_isInjectedWithDynamicLibrary`），未观察到反 hook 检测风险 |

## 依赖与边界

- 构建依赖：Theos、fishhook（项目内 `fishhook.c`/`fishhook.h`）、libsubstrate（`MSHookFunction`）、Foundation/UIKit
- 打包依赖：rootless scheme
- 注入边界：`lianjiabypass/LianJiaBypass.plist` 限定进程名 `LianJiaShell` / `LJShell`
- 实验记录：`lianjiabypass/analysis.md`（14 轮迭代，v0.0.1 → 0.1.0）

## 主要回归风险

- JGBSDK/du/a/senseid 任一框架升级后 exit syscall 数量、位置或前置指令编码变化（当前假定固定为 `mov w16,#1` 紧邻 `svc #0x80`）
- `caller_is_detector()` 的模块名匹配列表需要随检测框架改名/新增而更新
- Flutter 引擎升级后按索引访问 dyld 镜像的方式变化，可能需要重新验证 vis-map 缓存的正确性
- 贝壳找房版本升级后若检测栈与链家出现分叉（当前假定完全共用）
