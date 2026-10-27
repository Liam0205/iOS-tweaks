# WHBypass 实验记录

目标：`cn.cyberIdentity.certification`（国家网络身份认证，WHClient 1.2.38 build 13）。
设备：iPhone 13 Pro / iOS 15.4.1 / rootless Dopamine 1.x + ElleKit。

原始症状：打开即闪退。崩溃报告是 `EXC_BAD_ACCESS`，`pc = far = 0xb5a01000`，
发生在 `com.apple.root.default-qos` 的 GCD 工作线程上，`lr = 0`。

## 1. 检测栈身份

二进制里出现的组件，按重要性排列：

| 组件 | 证据 | 作用 |
|------|------|------|
| Bangcle Everisk | 字符串 `everisk_ZDAX iOS5.1.2.SP2-250207`、`everisk failed as license issue!`、`everisk cannot start as flow control issue` | 主检测引擎，启动时由 App 调用 |
| SecureUtilityPlus | Swift 类 `_TtC17SecureUtilityPlus16JailbreakChecker` 等 27 个类，全部 `baseMethods = 0x0` | 库名相同，但在本 App 里**没有导出任何 ObjC 方法**，运行期取不到入口 |
| everisk checker | 27 个混淆类，每个实现 `+(name)` / `-(check)` / `-(defaultPeriod)` | 具体检测项，`+name` 返回可读名（`jailbreak`、`frida`、`inject`、`debug`…） |
| KSCrash（腾讯 WPK 移植） | `WPKKSCrashInstallation`、`KSCrash Exception Handler (Secondary)` | 崩溃捕获，**不是检测方**（见第 5 节） |

App 层入口名是明文的：`setupEverisk()`、`setupEveriskAndUMService()`、
`initBangcleEverisk:`、`runEveriskWithKey:`。SDK 主控类被混淆成 `NgabsWzdwtYWXpPV`，
但方法名仍是 `initWithKey:` / `runEveriskWithKey:` / `onlineEntry` / `offlineEntry` / `dispatchCheckers`。

源码路径字符串 `/Users/duwenchu/Projects/iOS-WHClient_sec/WHClient/AppDelegate/AppDelegateExtension.swift`
说明这套东西是编译期静态链进主二进制的，没有独立的 framework 镜像。

## 2. 毒地址 0xb5a01000

启动 320～440ms 之间，有 4 个 GCD 工作线程被一条 `br` 送到 `0xb5a01000`。

- 这个地址落在 App 的 `__PAGEZERO`（3.05 GB，从 0 到 0x100000000）里。
- `vm_allocate(VM_FLAGS_FIXED)` 返回 `KERN_NO_SPACE`（1）；`mmap(MAP_FIXED)` 也失败。
  `vm_region` 显示该区间已被整块保留但未落实，四级页表里没有条目，进程无法在
  这个地址上映射内存。
- 二进制里搜不到这个常量：64 位、32 位、16 位三种形式都没有。它是运行时算出来的
  （生成方式见第 6 节）。

**结论：这是刻意选定的"必崩地址"，不打算被修复。** 任何"给它铺一页代码"的思路
在这个平台上都做不到。

## 3. 跳转的发起位置

跳飞线程的栈上留着完整帧链，四次里三次一致：

```
fp-80   WHClient+0x1349a8
fp-72   WHClient+0x1349c8
fp-64   WHClient+0x134988
fp-56   WHClient+0x13498c
fp-48   WHClient+0x1349d4
fp-24   WHClient+0x1406d8
fp+8    libdispatch.dylib+0x1e68
```

- `+0x1406d8` 是 `bl 0x100134730` 的下一条指令。
- `+0x134730` 是一个高度混淆的虚拟机入口（表驱动分派、常量分裂、`udf` 陷阱），
  入口第一条是 `sub sp, sp, #0x70`。
- 调用方 `+0x1406b0` 是带重入计数的守卫：
  ```asm
  1001406b0  stp x20, x19, [sp, #-0x20]!
  1001406b4  stp x29, x30, [sp, #0x10]
  1001406b8  add x29, sp, #0x10
  1001406bc  adrp x19, ...            ; 计数所在页
  1001406c0  ldr  w8, [x19, #0xf3c]   ; count
  1001406c4  cmp  w8, #0x2
  1001406c8  b.lt 0x1001406dc         ; count < 2 直接跳过
  1001406cc  bl   _getpid
  1001406d0  mov  w1, #0xb
  1001406d4  bl   0x100134730         ; 进混淆分派器，op=0xb
  1001406dc  ...
  1001406e0  add  w8, w8, #0x1
  1001406e4  str  w8, [x19, #0xf3c]   ; count++
  ```
  `getpid()` + `ptrace` 操作码 `0xb`（`PT_DENY_ATTACH`）是 iOS 反调试的标准写法。
  计数器在 `0x101cbf000 + 0xf3c`，全二进制有 74 处引用。

守卫入口整段换成 `ret` 之后，启动期的 4 次跳飞降到 **1 次**，且 App 能进首页。
剩下那 1 次（`pc = 0xb5a07000`，`lr = 0x1`）的发起方当时没定位到——它的栈帧被压平了，
帧链直接指向 libdispatch。这一处后来查清了，见第 6 节。

### 试过但无效的收窄手段

| 手段 | 结果 |
|------|------|
| 分派器入口改成 `ret` | 5 次异常，无改善 |
| 分派器入口换成跳板记录参数 | 证明被调用 **3 次**，`a1 = 0xb`，且换掉后异常照旧 → 分派器不是跳飞来源 |
| 只把 `b.lt` 改成无条件跳转（保留计数自增） | 5 次异常，6～8 秒后进程消失 |
| 守卫入口 `mov x0,#0; ret` | 1 次异常，App 存活；但破坏了返回约定之外的收尾，需要配合异常处理 |
| 短路 27 个 everisk `-(check)` | **对跳飞次数没有影响**（对照实验：开/关都是 4 次），说明结论不是从 `-(check)` 返回的 |
| 短路 Everisk 主控类 `initWithKey:` / `runEveriskWithKey:` | 没有影响。App 在 467ms 才调用它，而跳飞发生在 440ms 之前 |
| `GTCGbdDyncInfo` 的 `checkSafe` 等 21 个开关置 NO | 没有影响 |
| 挂 `ptrace` 恒返回 0 | 没有影响 |
| 16 处内联 `svc #0x80` | 与退出无关（都在 syscall 包装函数里） |

## 4. 接住异常之后的新问题：KSCrash

把 Mach 异常端口接管过来（任务级 + 线程级，`EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION`，
**不要带 `EXC_MASK_BREAKPOINT`**）之后，App 能起来，首页正常渲染。但接着出现两个现象：

1. 约 6.5 秒后界面卡死；
2. 十几秒后进程消失，没有崩溃报告。

日志显示 `thread_suspend` 每 6 秒被调用 7～8 次。反汇编调用点：

```
100cc4eb4  literal: "KSCrash Exception Handler (Secondary)"
100cc4ed0  bl _thread_suspend
100ce7a58  bl _thread_suspend    ; 遍历线程列表逐个挂起
```

**调用方是 KSCrash，不是检测方。** 它捕获到异常（就是那次跳飞），按自己的流程
把其它线程全部挂起抓现场，然后结束进程。现象与"SDK 判定风险后冻结退出"完全一样，
但成因不同——这一点差点被误判成 SecureUtilityPlus 的冻结机制。

把 `WPKKSCrashInstallation` / `WPKCrashInstallation` / `WPKKSCrash` 的
`install` 与 `setupCrashSettings` 换成空实现之后，`thread_suspend` 调用归零。

### 我们自己的两个坑

- **每 250ms 重新 `thread_set_exception_ports`**：会打断主线程，制造出"每 6.1 秒
  一次跳飞"的假象。这项诊断在测试里必须关掉。
- **回复异常消息但 pc 仍是毒地址**：内核恢复线程后立刻再次异常，实测直接变成
  100% 忙循环（`ps -M` 显示一个线程 `100.0 R`，其余 `T`）。对毒地址跳飞只能
  "不回复"，让它停在异常态。

## 5. 当前有效配置（0.1.77）

| 开关 | 值 | 作用 |
|------|----|------|
| `WH_BOMB_RET` | 1 | 把 6 个炸弹函数的入口改成 `ret`，跳飞从 1 次降到 0 次 |
| `WH_GUARD_RET` | 1 | 把 `+0x1406b0` 改成 `mov x0,#0; ret`，掐掉反调试调用 |
| `WH_EXC_TAKEOVER` | 0 | 不再接管 Mach 异常端口——启动期已经不会出异常 |
| `WH_DISABLE_KSCRASH` | 0 | 不再关 KSCrash，留着它做真正的崩溃上报 |
| `WH_BLOCK_SUSPEND` | 0 | 不再拦截 `thread_suspend` |
| `WH_NEUTER_CHECKERS` | 1 | 短路 27 个 everisk `-(check)`（对跳飞无影响，保留作纵深） |
| `WH_EVERISK_OFF` | 1 | 短路 Everisk 主控类入口（同上） |
| `WH_PARK_SENTINEL` | 0 | 停放页在 iOS 15 上无法映射 |

实测（0.1.77）：连续 3 次冷启动各 40 秒无异常、无退出，`EXCFAULT` 计数为 0；
之后持续运行 3 分钟以上，线程数稳定在 15，CPU 都在 1% 上下。
首页 → 管理 → 我的 → 网号网证申领 → 同意协议 → 证件类型选择，全程可交互。

## 6. 跳飞的真正来源：6 个"炸弹 block"

第 3 节里剩下那 1 次跳飞（`pc = 0xb5a07000`、`lr = 0x1`）定位到了，手段是一次
只读的现场采集，没有装任何 hook：

1. 钩住 `dispatch_async`，只在被投递的 block 的 `invoke` 等于嫌疑地址时记录队列标签
   和调用栈；
2. 查异常现场时把信号处理器、栈内容、`__TEXT` 的 12 MB 运行时字节一起落盘。

结论有三条，都推翻或修正了之前的猜测。

**一、`__TEXT` 的运行时字节与磁盘完全一致。** 拉取 0x1000000～0x1C00000 共 12 MB
比对，`__TEXT` 段内 0 处差异（差异全部从 0x1aa0000 的 `__DATA_CONST` 开始，是正常的
重定位与指针修正）。所以这不是"自解密没生效"，这段代码就长这样。

**二、跳飞来自 6 个故意写坏的函数。** 主程序里有 33 处 `br x14` 的目标落在
0xb5a0X000 上，其中 6 处是「函数入口」，函数体形如：

```asm
100148470  ldr  w8, [x0, #0x20]    ; 入口，x0 是上下文
100148474  mov  x0, x8
100148490  mov  sp, x0             ; 栈指针直接改成上下文里的值
1001484a0  mov  x30, x0            ; lr 也改掉
1001484ac  mov  w8, #0x7998
1001484b0  movk w8, #0x92ab, lsl #16
1001484b4  mov  w9, #0xf668
1001484b8  movk w9, #0x22f4, lsl #16
1001484c4  add  x14, x3, x5        ; 0x92ab7998 + 0x22f4f668 = 0xb5a07000
1001484c8  br   x14
```

毒地址就是这条 `add` 算出来的：两个立即数分别由 `mov`+`movk` 拼出来，所以
按 64/32/16 位在文件里搜这个常量都是 0 次。每个函数算出的地址不同（0xb5a00000、
0xb5a02000 … 0xb5a16000），`0xb5a07000` 属于 0x148470 这一个。

**三、调用方是主程序自己的混淆状态机。** 这 6 个地址在全二进制里没有一条 `bl`
指向它们，只有 6 处 `adrp`+`add` 把它们的地址写进 block 的 `invoke` 字段：

| 构造 block 的位置 | 写进去的 invoke |
|---|---|
| `WHClient+0x144334` | `0x148470` |
| `WHClient+0x144638` | `0x1484d0` |
| `WHClient+0x1455f0` | `0x14a1b0` |
| `WHClient+0x149d14` | `0x149db8` |
| `WHClient+0x14a428` | `0x14a4cc` |
| `WHClient+0x14a738` | `0x14a7dc` |

这些位置都在 0x13f000～0x145000 那段混淆状态机里。实际路径是：

```
工作线程执行一个 block（invoke = WHClient+0x13f140）
  → 状态机推进到某状态，dispatch_async(全局队列, block{ invoke = 0x148470 })
  → libdispatch 的 _dispatch_call_block_and_release（dylib+0x1e68）blr 该 invoke
  → 0x148470 把 sp、lr 改成上下文值，br 到 0xb5a07000 → 异常
```

同一个状态机也把 `+0x1406b0`（反调试守卫）当作 block 反复投递，间隔 6.2 秒左右，
这解释了为什么关掉守卫补丁后进程仍会在一分钟内消失。

### 修法

把 6 个入口的第一条指令改成 `ret`（`0xD65F03C0`）。block 照常被投递、照常结束，
只是不再跳。**不用 `MSHookFunction`**：一来会留下跳板，二来这个 App 自带
`MSHookFunctionChecker`；静态改一条指令代价最小，也不会被完整性校验发现——
`__TEXT` 本来就在启动后可以被 `vm_protect` 改成可写。

改完之后：

- 启动期 `EXCFAULT` 从 1 次降到 **0 次**；
- 不再需要接管 Mach 异常端口，也不再需要关 KSCrash、拦 `thread_suspend`；
- 3 次冷启动 + 3 分钟持续运行，线程数、CPU 都稳定，界面全程可交互。

## 7. 仍然存在的约束

- 日志不能写 `Documents`：加固壳会把那里的非常规文件删掉（实测整份 `whbypass.log`
  消失）。现在写 `Library/Caches/gtcfg.log`。
- 守卫计数 `[0x101cbf000+0xf3c]` 有 74 处引用，除了 `+0x1406b0` 还有
  `+0x8120c8`、`+0xab8a2c` 等读写点，尚未逐个确认语义。
- 0x13f000～0x145000 这段状态机到底在做什么检测，还没有读通。

