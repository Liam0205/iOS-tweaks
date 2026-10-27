# WHBypass 架构

## 定位

绕过国家网络身份认证（Bundle `cn.cyberIdentity.certification`，可执行文件 `WHClient`）在越狱设备上打开即闪退的问题。子项目 `whbypass/`，包名 `page.0x01.whbypass`。目标版本 1.2.38（build 13），rootless，验证环境 iPhone 13 Pro / iOS 15.4.1 / Dopamine + ElleKit。完整实验过程见 `whbypass/analysis.md`。

当前版本 `0.1.66`，已验证连续三次冷启动各存活 30 秒以上，首页 → 管理 → 我的 → 网号网证申领 → 同意协议 → 证件类型选择全程可交互，前后台往返正常。

## 检测栈与判定位置

主检测引擎是**梆梆安全 Everisk**（`everisk_ZDAX iOS5.1.2.SP2-250207`），编译期静态链入主二进制，没有独立 framework 镜像。同一二进制里还有一套 `SecureUtilityPlus` Swift 类，但在这个 App 里 27 个类全部 `baseMethods = 0x0`，运行期取不到任何入口——它只贡献了库名，不是检测主力。

App 层入口的名字是明文的（`setupEverisk()`、`setupEveriskAndUMService()`、`initBangcleEverisk:`、`runEveriskWithKey:`），但真正做判定的是主二进制里那套混淆虚拟机。27 个 everisk checker 的 `-(check)` 在 467ms 之后才被调用，而跳飞发生在 320～440ms，**判定早于 checker**。这是本节最重要的一条：短路 `-(check)` 对闪退没有任何作用，对照实验里开与关都是 4 次跳飞。

## 闪退机制：毒地址 0xb5a01000

启动 320～440ms 之间，4 个 GCD 工作线程被一条 `br` 送到 `0xb5a01000`。

这个地址落在 App 的 `__PAGEZERO`（3.05 GB，`0` 到 `0x100000000`）里，`vm_allocate(VM_FLAGS_FIXED)` 返回 `KERN_NO_SPACE`，`mmap(MAP_FIXED)` 也失败。四级页表在这个区间没有条目，进程无法在此映射内存。二进制里也搜不到这个常量（64 位、32 位、16 位三种形式都没有），它是运行时算出来的。

**所以它是刻意选定的必崩地址，不打算被修复。** 任何"在它上面铺一页停放代码"的思路在 iOS 上都做不到，`WH_PARK_SENTINEL` 保留在代码里只是为了记录这个负面结论。

## 三条有效手段

### 1. 掐掉反调试守卫（`WH_GUARD_RET`）

跳飞线程的栈上帧链指向 `WHClient+0x1406b0`，这是一个带重入计数的守卫：

```asm
1001406c0  ldr  w8, [x19, #0xf3c]   ; count
1001406c4  cmp  w8, #0x2
1001406c8  b.lt 0x1001406dc
1001406cc  bl   _getpid
1001406d0  mov  w1, #0xb            ; PT_DENY_ATTACH
1001406d4  bl   0x100134730         ; 混淆虚拟机
```

把入口两条指令改成 `mov x0,#0` / `ret` 之后，启动期跳飞从 4 次降到 1 次。这里有两个必须知道的细节：

- 只把 `b.lt` 改成无条件跳转（保留计数自增）**反而更糟**：跳飞 5 次，6～8 秒后进程消失。计数器的自增本身是被观察的。
- 整段只写 `ret` 会让 `x0` 保留调用方的垃圾值，返回约定被破坏。必须显式 `mov x0,#0`。

剩下那 1 次跳飞（`pc = 0xb5a07000`、`lr = 0x1`）不致命，来自另一处判定，目前没有定位到调用方。

### 2. 关掉 KSCrash 安装（`WH_DISABLE_KSCRASH`）

接管异常端口后 App 能进首页，但约 6.5 秒界面卡死、十几秒后进程消失，且没有崩溃报告。日志里 `thread_suspend` 每 6 秒被调用 7～8 次，反汇编调用点旁边的字符串是 `KSCrash Exception Handler (Secondary)`。

**调用方是 KSCrash（腾讯 WPK 移植版），不是检测 SDK。** 它捕获到那次跳飞，按自己的流程把其它线程全部挂起抓现场，然后结束进程。这个现象和"SDK 判定后冻结退出"一模一样，很容易误判——本项目就误判过一轮，直到把调用点反汇编出来。

把 `WPKKSCrashInstallation` / `WPKCrashInstallation` / `WPKKSCrash` 的 `install` 与 `setupCrashSettings` 换成空实现之后，`thread_suspend` 调用归零。

### 3. Mach 异常端口接管

任务级与线程级都要接管，掩码只用 `EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION`。

**不要带 `EXC_MASK_BREAKPOINT`。** 这个 App 自己注册了 `EXC_BREAKPOINT`（任务端口 `mask=0x40`），覆盖它会让 App 在 3 秒内退出。

跳向毒地址的异常**不回复**，让线程停在异常态。回复是错的：pc 仍是毒地址，内核恢复后必然再次异常，实测直接变成 100% 忙循环（`ps -M` 显示一个线程 `100.0 R`、其余 `T`）。

## 三条固化约束

1. **不要周期性重设异常端口。** 每 250ms 调一次 `thread_set_exception_ports` 会打断主线程，制造出"每 6.1 秒一次跳飞"的假象。这一个假象花掉了整轮排查时间。
2. **日志不能写 `Documents`。** 加固壳会把那里的非常规文件删掉（实测整份日志消失）。现在写 `Library/Caches/gtcfg.log`。
3. **镜像 0 不一定是主程序。** 这台设备上 `_dyld_get_image_header(0)` 返回的是 `IQKeyboardManagerSwift`，给 `__TEXT` 打补丁必须按可执行路径逐个比对镜像名。

## 与同族 tweak 的关系

检测库名与 icbcbypass / abcbypass 相同（都是 SecureUtilityPlus），但本 App 里那套 Swift 类没有方法，所以 icbc 那种"遍历 13 个 checker 类、把返回 BOOL 的安全方法改成 NO"的做法在这里无效。这里能落地的只有主二进制的指令补丁与异常端口接管。

与 aiabypass 的差别在于：友邦是"判定没绕过、只接住后果"，而这里判定本身被掐掉了三条路径中的两条，剩下的跳飞也不致命。
