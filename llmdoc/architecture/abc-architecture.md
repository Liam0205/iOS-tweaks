# ABC Bypass 架构

> ⚠️ **2026-08-21 重大更正（第 15 轮）。** 本文档 v95 时期的多数"成功"结论
> **不可信**，因为它们基于错误的存活检测（`grep MbapMPaaS` 命中后台扩展进程
> `group.abc.toolExtension`，而非主 App）。经可信重测（`abctest.sh` 精确匹配
> `MbapMPaaS.app/MbapMPaaS` 且排除 `PlugIns`）确认：
>
> 1. **裸跑主 App ~13s 正常退出（无崩溃）**；**全量 hook 反而 ~1s 崩溃**。
> 2. **`0xb5a06000` SIGSEGV 崩溃 = 对 libc 函数 inline-hook（MSHookFunction/fishhook）
>    被 ABC 完整性自检发现所致**。范围覆盖 stat/open/access/sysctl/dlopen/`_dyld_*`
>    等——**不止 libpthread，libc 普遍在校验内**。下方"libdispatch 安全""内存扫描器
>    不覆盖 libdispatch"等说法**未经可信验证，勿依赖**。
> 3. **唯一确认安全的手段 = ObjC 方法 swizzle**（不改函数序言）。
> 4. **硬约束：禁 C 函数 inline-hook、禁 fishhook GOT 改写、禁 __text patch、禁 Frida。**
>
> **✅ 第 16 轮已解决**：native exit 的检测 block 定义在
> `-[DTFrameworkInterface initRiskManage]` 内，**swizzle 该方法为空实现**即可从源头
> 消除 exit，纯 ObjC swizzle 不触发完整性校验。实测主 App 存活并完整进入首页、交互正常。
> 有效方案就这一个 swizzle，不需要任何 exit 拦截/栈切换/longjmp/libc hook。
>
> 下方原始内容（四阶段 ctor、栈切换、双通道杀死、longjmp 恢复等）**几乎全部是失败尝试
> 的历史存档，已在代码中删除**。事实以本框、`analysis.md` 第 15-16 轮、
> `reference/abc-detection-vectors.md` 为准。

## 架构目标

`abcbypass/Tweak.x` 对抗中国农业银行 (com.bankabc.iphonerelease) v11.1.0 的越狱检测与退出杀死链路。当前版本 v0.1.0-95，状态：活跃开发中（尚未发布）。

目标 Binary：`MbapMPaaS`（~110MB arm64）——已确认为蚂蚁金服 mPaaS 框架，它封装了 UIApplicationMain 并控制整个 App 生命周期。

## 整体执行模型

入口为 `__attribute__((constructor))`，分四阶段执行（v95 ctor 重排序后）：

### 阶段 1：ctor 立即 — fishhook 文件系统 hook（最高优先）

在 ctor 时**第一步**执行 fishhook rebind，确保在 SDK 的 ObjC class scanning 之前就位：
- 文件路径隐藏：stat/lstat/access/open/fopen/opendir/readdir/realpath/readlink/statfs/statvfs
- 动态库枚举：_dyld_image_count/_dyld_get_image_name
- 系统信息：sysctl/sysctlbyname
- 环境变量：getenv

**关键发现（v95）**：fishhook 必须先于 ObjC hook 安装。SDK 在 ObjC class scanning 期间调用 stat/access/fopen 检查越狱文件，如果此时文件 hook 尚未安装则检测已完成。

### 阶段 2：ctor 立即 — CFRunLoop hook

紧接文件 hook 之后安装 CFRunLoop 层 hook：
- `CFRunLoopAddTimer`（MSHookFunction）：追踪并可选阻断 SDK 注册的定时器
- `CFRunLoopRunSpecific`（MSHookFunction）：在 RunLoop 入口设置 `setjmp` 恢复点

### 阶段 3：ctor 立即 — ObjC hook

- ObjC swizzle（method_setImplementation）：SecureUtilityPlus 13 个 Checker 类、IOSSecuritySuite、ABC 专有越狱检查方法
- 弹窗抑制

### 阶段 4：dispatch_after(200ms) 延迟执行

延迟是为避免 BSXPCServiceConnection SIGTRAP（ctor 时直接 hook exit 触发）。

延迟执行内容：
- fishhook：exit/_exit/abort/kill/signal/pthread_kill/__stack_chk_fail/objc_exception_throw/posix_spawn/sigaction/pthread_create
- MSHookFunction（inline hook）：dispatch_async/dispatch_async_f

### 阶段 5：检测触发（~15s 后）

检测在启动约 15 秒后触发：
- **CFRunLoop 定时器通道**：注册一次性 CFRunLoopTimer（delay 5-60s）触发 exit(0)
- **GCD dispatch_after 通道**：通过 dispatch_after 延迟投递 exit block 到 main queue

两个通道冗余执行，当前 CFRunLoop 通道已被拦截，GCD 通道尚未拦截。

## 核心约束：禁止一切 C 函数 inline-hook（第 15 轮更正）

SDK 内存完整性扫描器（`memmem`，运行在 GCD worker 线程）会检测 **libc 广泛函数**的
inline hook / GOT 改写。二分实验证实：MSHookFunction 覆盖
`stat/lstat/access/open/fopen/realpath/readlink/sysctl/getenv/fork/dlopen/dlsym`
及 `_dyld_*` 后，启动 ~1s 触发后台线程跳到固定哨兵地址 `0x00000000b5a06000` 的
SIGSEGV（地址每次相同 ⇒ 主动触发）。

> ⚠️ **旧说法"MSHookFunction 对 libdispatch 安全 / 内存扫描器不覆盖 libdispatch"
> 及"仅 libpthread 不安全"均未经可信验证。** 已确认范围至少覆盖上述 libc 函数。
> 保守结论：**对 ABC 任何 C 函数都不要 inline-hook**；越狱绕过只用 ObjC swizzle。

## Hook 策略（混合方案）

| 方法 | 目标 | 原因 |
|------|------|------|
| MSHookFunction (inline) | dispatch_async, dispatch_async_f | 捕获 ALL callers 包括 shared cache 内部调用（560+ 次重定向 vs fishhook 仅 5 次） |
| MSHookFunction (inline) | CFRunLoopAddTimer | 拦截 SDK 注册的杀死定时器（一次性、delay>5s） |
| MSHookFunction (inline) | CFRunLoopRunSpecific | 提供 setjmp 恢复点，longjmp 从 exit 中逃逸（backup） |
| fishhook (PLT/GOT) | exit, _exit, abort, kill, signal, pthread_kill, __stack_chk_fail, objc_exception_throw, posix_spawn, sigaction, pthread_create | 安全于 SDK 扫描器 |
| fishhook (PLT/GOT) | stat, access, fopen, open, ... | 文件系统级越狱隐藏 |
| ObjC swizzle | SecureUtilityPlus (13 classes), IOSSecuritySuite, ABC 方法, 弹窗 | runtime 层替换 |
| Logos %hook | NSFileManager, UIApplication, UIAlertController, NSProcessInfo | 标准 ObjC hook |

## 退出生存机制

### 1. exit 拦截

`hooked_exit()` 阻止 exit 调用，设置 `g_exit_blocked=1`。

### 2. ARM64 栈切换

exit 是 `_Noreturn` 函数，拦截后"返回"会导致 SIGSEGV 级联。解决方案是 ARM64 inline asm 栈切换到干净 trampoline：

```
mov sp, <clean_stack>
mov x29, #0
mov x30, <trampoline_fn>
ret
```

### 3. Trampoline 执行

栈切换后 trampoline 执行：
1. 挂起所有未命名线程（冻结检测线程）
2. 安装 0.3s 巡逻定时器（patrol timer），持续检测并挂起新创建的检测线程
3. 进入 CFRunLoopRun 保持存活

### 4. dispatch_async 重定向

当 `g_exit_blocked && queue == main_queue` 时，`hooked_dispatch_async` 将 block 重定向到：
```
CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, block)
```

原因：栈切换破坏了 dispatch queue 的内部状态，直接使用 dispatch_async 到 main queue 不再可靠。CFRunLoop 是独立于 GCD 的替代调度路径。

### 5. CFRunLoop 定时器拦截（v92+）

`hooked_CFRunLoopAddTimer` 过滤以下定时器注册：
- 一次性定时器（非 repeating）
- delay 在 5-60 秒范围
- 目标为 main RunLoop

匹配的定时器被直接丢弃，不注册到 RunLoop。此机制成功阻止了 CFRunLoop 通道的 kill timer。

### 6. longjmp 恢复（备用，当前不完善）

`hooked_CFRunLoopRunSpecific` 在 RunLoop 入口执行 `setjmp`，当 exit 被调用时 `longjmp` 回到 setjmp 点。

**限制**：longjmp 机械上成功（无 crash），但跳过了 CF RunLoop 内部的 timer callback 清理逻辑，导致 RunLoop 内部状态损坏 → UI 冻结。当前仅作为 backup 机制保留。

## 与 ICBC bypass 的关键差异

| 维度 | ICBC | ABC |
|------|------|-----|
| MSHookFunction | 禁用（MSHookFunctionChecker prologue 检测） | 部分可用（libdispatch 安全，libpthread 不安全） |
| 检测杀死机制 | ObjC 层冻结 + exit | svc #0x80 直接 syscall（不可 hook） |
| 退出 hook 策略 | RunLoop + 非主线程 block | 栈切换 + CFRunLoop trampoline |
| Dispatch queue | 正常 | 栈切换后损坏，通过 CFRunLoop 绕过 |
| 线程管理 | 不需要 | Mach thread suspend + 巡逻定时器 |
| 冻结对抗 | semaphore_wait 拦截 + UI 状态保护 | 不需要（ABC 不使用冻结循环） |

## 已知未解决问题

- **GCD dispatch_after 杀死通道**：SDK 通过 `dispatch_after` 投递 exit block，完全绕过 CFRunLoop 定时器拦截。GCD 定时器无法用相同方式 hook（无类似 CFRunLoopAddTimer 的注册 API）。
- **Hook 完整性检测（第二检测路径）**：即使越狱文件检测和 ObjC 检测均已绕过，SDK 仍有第二条检测路径（疑似 FishHookChecker 或 GOT 完整性校验）触发 exit。
- **longjmp UI 恢复失败**：longjmp 跳过 CF RunLoop 内部状态清理，导致 timer callback cleanup 缺失 → UI 永久冻结。
- **UI 完全恢复**：退出拦截后 UI 不能完全恢复正常。巡逻定时器可能过度挂起 GCD worker 线程，导致渐进式 UI 退化。
- **svc #0x80 后台杀死**：SmAntiFraud 后台线程执行 svc #0x80 直接 _exit()，用户态完全不可拦截。当前通过线程挂起缓解，但无法根本阻止。
- **Dispatch queue 损坏**：栈切换的副作用，通过 CFRunLoop 绕过但非根本解决。

## 依赖与边界

- 构建依赖：Theos、fishhook（项目内）、libsubstrate（MSHookFunction）、UIKit/Foundation
- 打包依赖：rootless scheme
- 注入边界：限定 `com.bankabc.iphonerelease`
- 测试设备：iPhone 13 Pro / iOS 15.4.1 / Dopamine 1.x
- 实验记录：`abcbypass/analysis.md`（12 轮，v1-v95）

## 主要回归风险

- SmAntiFraud 升级扩展 svc #0x80 路径覆盖（更多 syscall 更早执行）
- 内存扫描器范围扩大（覆盖 libdispatch → MSHookFunction 全部不可用）
- 检测触发时机前移（<200ms → 延迟 hook 窗口关闭）
- 巡逻定时器误挂起关键 GCD worker → 功能性退化
- mPaaS 框架升级引入新检测模块
