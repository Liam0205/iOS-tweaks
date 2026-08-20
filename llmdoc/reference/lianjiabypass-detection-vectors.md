# LianJiaBypass 越狱检测向量

## 目的

本文档汇总链家（`com.exmart.HomeLink` 9.86.91）与贝壳找房（`com.lianjia.beike` 3.06.21，进程名 `LJShell`）已知的越狱检测向量与当前覆盖情况。两个 App 属贝壳集团，共用同一套检测栈，本文档同时适用。

## 检测栈构成

| 框架 | 角色 | 是否直接杀进程 |
|------|------|----------------|
| `JGBSDK.framework`（3MB，@rpath 动态库） | 核心越狱检测引擎，疑似贝壳自研“精工”安全 SDK（URL scheme `beikejinggong`） | ✅ 是（内联 syscall + 可能的业务层回调退出） |
| `du.framework`（676KB，类 `DUNetwork`） | 数盟/数字联盟（Shuzilm）设备指纹 SDK，路径含 `/Users/shuzilm/.../dna_iOS/du/` | ❌ 一般只采集上报 |
| `a.framework`（90KB） | 注入检测小库，含 `_isInjectedWithDynamicLibrary` | ❌ 不直接杀进程，但会拖慢主线程造成"冻结"假象 |
| `senseid_ids` | 另一采集类框架 | ❌ 一般只采集上报 |

四个框架均在启动约 0.08 秒内加载完毕。

## JGBSDK 检测清单（XxxCheck selector）

`JailbrokenCheck`、`DylibCheck` / `checkDylib`、`detectDebugger`、`ProxyCheck`、`VPNCheck` / `shareJGBVPNCheck`、`AppInfoCheck`、`ScreenRecordCheck`、`ScreenShotCheck`、`AirPlayCheck`、`VirtualPositionCheck`、`TextIntegrityCheck`。

其中越狱环境下会直接命中的三项：`JailbrokenCheck`、`DylibCheck`、`detectDebugger`。

## JGBSDK 越狱特征字符串

二进制内嵌以下字符串用于文件路径检测和反调试提示：

- `/Applications/Cydia.app`
- `CydiaSubstrate.framework`
- `/Library/MobileSubstrate/DynamicLibraries/`
- `.../xCon.dylib`
- `/Library/MobileSubstrate/MobileSubstrate.dylib`
- `/private/detect_log.txt`
- `/private/var/tmp/cydia.log`
- `your app hooked by Frida`（anti-frida 提示文案，证实内建反 Frida 逻辑）

## 检测结果上报链路

- `receiveProtectEventWithCode:reason:`：JGBSDK 把检测结果报给业务层的回调方法
- `LJBRProtectManager`：链家/贝壳统一保护管理器类，主 binary 也直接引用（**已确认存在**）
- `JGBProtect` / `JGBIntercept`：辅助保护类

`receiveProtectEventWithCode:reason:` 的确切宿主类未完全定位（不是 `LJBRProtectManager` 的实例方法），因当前四层对抗已完全覆盖检测面，未继续深挖此回调链路。

## 检测向量详情

### 1. 文件路径检测

JGBSDK 对越狱路径做 `stat`/`access` 探测，包括遍历 `/var/jb/usr/lib/TweakInject/*.plist`（约 38 项已知 tweak plist 黑名单）逐个 `access()` 探测，以及对 `/Applications/Cydia.app` 等标准路径的 `stat`。

当前覆盖：fishhook `stat`/`lstat`/`access`/`opendir`/`dlopen`，纯 C 字符串子串匹配（`is_jb_name_c()`）命中后返回 `ENOENT`。

### 2. DynamicLibraries 目录枚举

对 `.../DynamicLibraries` 类目录（含 `MobileSubstrate`/`TweakInject` 关键字路径）枚举匹配 `.dylib`/`.plist` 的文件名。

当前覆盖：`NSFileManager` 的 `contentsOfDirectoryAtPath:error:` / `contentsOfDirectoryAtURL:...` 过滤，仅在目录路径命中 `is_dylib_dir()` 时才额外过滤 `.dylib`/`.plist`（避免误伤 App 自身 `.plist` 读取）。

### 3. dyld 镜像枚举（DylibCheck）

通过 `_dyld_image_count`/`_dyld_get_image_name` 枚举加载镜像找越狱/注入 dylib（曾扫到 tweak 自身 dylib 和 ElleKit）。

当前覆盖：fishhook 这两个函数 + `dladdr` 作用域限定（仅对 JGBSDK/du/a/senseid 调用方生效）+ vis-map 缓存防 O(n²)。详见架构文档。

### 4. `dladdr` 反查伪装

JGBSDK 可能通过 `dladdr` 反查某地址所属镜像来识别注入/hook 痕迹。

当前覆盖：fishhook `dladdr`，把越狱相关 dylib 的 `dli_fname` 伪装成 `/usr/lib/system/libsystem_c.dylib`，`dli_sname`/`dli_saddr` 清空。

### 5. 主线程注入检测（a.framework）

`a.framework` 的 `_isInjectedWithDynamicLibrary` 经 CFRunLoop → dispatch main queue 周期性触发，每轮对已加载 dylib 名称做大量 `strstr` 扫描。此函数本身运行较慢，周期性占用主线程 → 表现为界面起不来（"冻结"），本质是性能问题而非主动惩罚。

当前覆盖：`MSHookFunction` 直接 hook 该函数（框架内部直接调用，fishhook 导入表 rebinding 无效），恒返回 `0`。

### 6. 内联 syscall 自杀退出

JGBSDK 的 `__TEXT,__text` 段内散布约 **29 处** 内联汇编序列：

```
mov w16, #1     ; 0x52800030
svc #0x80       ; 0xd4001001  (等价于 exit(1)，完全绕过 libc)
```

这类调用不经过 GOT/PLT，不产生 signal，用户态无法通过 hook `exit`/`_exit`/`abort`/`kill`/`pthread_kill` 或 `sigaction` 拦截。

当前覆盖：运行时扫描 JGBSDK `__text`，把匹配到的 `svc #0x80`（`0xd4001001`，前一条指令为 `mov w16,#1` / `0x52800030`）就地改写为 `ret`（`0xd65f03c0`），遵循标准 W^X 流程（`vm_protect` RW → 写 → 恢复 R+X → `sys_icache_invalidate`）。已确认稳定命中全部 29 处，无失败。

### 7. 反调试 / anti-frida

字符串 `"your app hooked by Frida"` 证实 JGBSDK 内建反 Frida 机制。实测中 Frida spawn/attach 均会被破坏（`script.load()` 连接被关闭、`create_script` 失败，或 spawn 成功后 <1s 内零命中即退出）——三种表现均指向 JGBSDK 主动检测到 Frida 后破坏会话或提前走内联 syscall 退出，绕过所有可 hook 的退出原语。

当前不做进一步对抗（不影响 tweak 正常工作，四层已足够覆盖真实使用场景；仅影响用 Frida 做动态分析）。

## 当前覆盖状态（v0.1.0）

| 检测向量 | 层级 | 状态 | 实现方式 |
|----------|------|------|----------|
| 文件路径检测（stat/access/opendir） | 1 | ✅ 已隐藏 | fishhook + ENOENT |
| DynamicLibraries 目录枚举 | 1 | ✅ 已过滤 | NSFileManager Hook |
| dyld 镜像枚举（DylibCheck） | 2 | ✅ 已绕过且不冻结 | fishhook + dladdr 作用域限定 + vis-map 缓存 |
| dladdr 反查伪装 | 2 | ✅ 已伪装 | fishhook dladdr |
| a.framework 注入检测（主线程慢扫描） | 3 | ✅ 已中和 | MSHookFunction 恒返回 0 |
| JGBSDK 内联 svc exit（29 处） | 4 | ✅ 已消除 | 运行时 __text patch svc→ret |
| du/senseid 设备指纹采集 | — | ⚪ 不处理 | 只采集上报，不影响可用性 |
| anti-frida | — | ⚪ 不处理 | 不影响 tweak 正常工作，仅阻碍动态分析 |
| receiveProtectEventWithCode:reason: 业务层回调 | — | ⚪ 未深挖 | 已被前四层覆盖，暂不需要 |

两个目标 App（链家、贝壳找房）均在此覆盖状态下验证通过主界面完整加载。

## 版本适配优先检查

链家/贝壳升级后建议检查顺序：

1. JGBSDK 是否升级导致内联 svc exit 的指令编码或前置指令变化（当前假定固定为 `mov w16,#1` 紧邻 `svc #0x80`）
2. `DylibCheck` 是否新增按镜像地址范围而非仅按名字判断的检测方式
3. `a.framework` 的 `_isInjectedWithDynamicLibrary` 是否改名或改为多个函数分摊扫描
4. `caller_is_detector()` 的模块名匹配列表（`JGBSDK`/`du.framework`/`senseid`/`a.framework`）是否需要因框架改名而更新
5. `receiveProtectEventWithCode:reason:` 回调链路是否成为新的退出触发点
6. 贝壳找房是否与链家在检测栈上出现分叉（当前假定完全共用）
