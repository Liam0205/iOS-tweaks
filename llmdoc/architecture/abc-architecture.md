# ABC Bypass 架构

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

## 核心约束：MSHookFunction 在 libpthread 不安全

SDK 内存完整性扫描器（`memmem` 运行在 `com.apple.uikit.xpc-service` 线程）会检测 libpthread 函数的 inline hook。MSHookFunction 覆盖 `pthread_create` 后触发 SIGSEGV（crash 在 unmapped shared cache region）。通过受控二分测试确认。

**安全范围**：MSHookFunction 对 libdispatch 函数（dispatch_async/dispatch_async_f）是安全的，内存扫描器不覆盖 libdispatch。

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
