# WHBypass 架构

## 定位

绕过国家网络身份认证（Bundle `cn.cyberIdentity.certification`，可执行文件 `WHClient`）在越狱设备上打开即闪退的问题。子项目 `whbypass/`，包名 `page.0x01.whbypass`。目标版本 1.2.38（build 13），rootless，验证环境 iPhone 13 Pro / iOS 15.4.1 / Dopamine + ElleKit。完整实验过程见 `whbypass/analysis.md`。

当前版本 `1.0.0`。启动期不再发生任何异常跳转（`EXCFAULT` 计数为 0），连续三次冷启动
各 40 秒、再持续运行 3 分钟以上都稳定，线程数稳定在 15 上下，首页 → 管理 → 我的 →
网号网证申领 → 同意协议 → 证件类型选择全程可交互。

## 日志：由构建类型自动开关

日志的开关是编译期的，不在运行时判断：

```c
#ifndef WH_LOG_ENABLED
#ifdef DEBUG
#define WH_LOG_ENABLED 1
#else
#define WH_LOG_ENABLED 0
#endif
#endif
```

theos 的 debug 构建会加 `-DDEBUG`，`make package` 默认就是这种；`make package FINALPACKAGE=1`
是 release 构建，不带 `-DDEBUG`。所以：

- `make package` → 带日志，写 `Library/Caches/gtcfg.log`，供排查用；
- `make package FINALPACKAGE=1` → 所有日志调用被编译掉，`open_log()` 不创建任何文件，
  信号处理器与异常现场导出也不安装。

发布包用后者。实测 release 包运行一分钟以上，容器里没有出现 `gtcfg.log`。

**改完这个宏必须 `make clean`**，否则 `.theos/obj` 里会残留上一次构建的产物。

## 检测栈与判定位置

主检测引擎是**梆梆安全 Everisk**（`everisk_ZDAX iOS5.1.2.SP2-250207`），编译期静态链入主二进制，没有独立 framework 镜像。同一二进制里还有一套 `SecureUtilityPlus` Swift 类，但在这个 App 里 27 个类全部 `baseMethods = 0x0`，运行期取不到任何入口——它只贡献了库名，不是检测主力。

App 层入口的名字是明文的（`setupEverisk()`、`setupEveriskAndUMService()`、`initBangcleEverisk:`、`runEveriskWithKey:`），但真正做判定的是主二进制里那套混淆虚拟机。27 个 everisk checker 的 `-(check)` 在 467ms 之后才被调用，而跳飞发生在 320～440ms，**判定早于 checker**。这是本节最重要的一条：短路 `-(check)` 对闪退没有任何作用，对照实验里开与关都是 4 次跳飞。

## 闪退机制：毒地址 0xb5a01000

启动 320～440ms 之间，GCD 工作线程被一条 `br` 送到 `0xb5a0X000` 区间（0xb5a00000 到
0xb5a16000，首次观察到的是 0xb5a01000，后来降到 0xb5a07000）。

这个地址落在 App 的 `__PAGEZERO`（3.05 GB，`0` 到 `0x100000000`）里，`vm_allocate(VM_FLAGS_FIXED)`
返回 `KERN_NO_SPACE`，`mmap(MAP_FIXED)` 也失败。四级页表在这个区间没有条目，进程无法在此映射内存。

**所以它是刻意选定的必崩地址，不打算被修复。** 任何"在它上面铺一页停放代码"的思路在 iOS 上都做不到，
`WH_PARK_SENTINEL` 保留在代码里只是为了记录这个负面结论。

### 跳转来源：6 个"炸弹 block"

主程序里有 6 个函数，函数体都是「把 `sp`、`lr` 一起改成上下文里的值，再 `br` 到毒地址」：

```asm
100148470  ldr  w8, [x0, #0x20]    ; 参数是上下文指针
100148474  mov  x0, x8
100148490  mov  sp, x0             ; sp 直接改成上下文里的值
1001484a0  mov  x30, x0            ; lr 同改
1001484ac  mov  w8, #0x7998
1001484b0  movk w8, #0x92ab, lsl #16
1001484b4  mov  w9, #0xf668
1001484b8  movk w9, #0x22f4, lsl #16
1001484c4  add  x14, x3, x5        ; 0x92ab7998 + 0x22f4f668 = 0xb5a07000
1001484c8  br   x14
```

毒地址就是这条 `add` 算出来的：两个立即数分别由 `mov`+`movk` 拼成，所以按 64/32/16 位
在文件里搜常量都是 0 次。

这 6 个地址在全二进制里没有一条 `bl` 指向它们，只有 6 处 `adrp`+`add` 把它们的地址写进
block 的 `invoke` 字段（`WHClient+0x144334`、`+0x144638`、`+0x1455f0`、`+0x149d14`、
`+0x14a428`、`+0x14a738`）。调用路径是：

```
工作线程执行 block（invoke = WHClient+0x13f140）
  → 混淆状态机推进到某状态，dispatch_async(全局队列, block{invoke = 0x148470})
  → libdispatch 的 _dispatch_call_block_and_release（dylib+0x1e68）blr 该 invoke
  → 炸弹函数改 sp/lr 后 br 到毒地址 → 异常
```

同一个状态机也把 `+0x1406b0`（反调试守卫）当 block 反复投递，间隔约 6.2 秒。

## 三条有效手段

### 1. 掐掉炸弹入口（`WH_BOMB_RET`）——根治手段

把 6 个入口的第一条指令改成 `ret`（`0xD65F03C0`）。block 照常被投递、照常结束，
只是不再跳。启动期异常从 1 次降到 **0 次**，此后不再需要接管异常端口、关 KSCrash
或拦 `thread_suspend`。

不用 `MSHookFunction`：它会留下跳板，而这个 App 自带 `MSHookFunctionChecker`；
静态改一条指令代价最小。

### 2. 掐掉反调试守卫（`WH_GUARD_RET`）

`WHClient+0x1406b0` 是一个带重入计数的守卫，被同一个状态机当 block 反复投递：

```asm
1001406c0  ldr  w8, [x19, #0xf3c]   ; count
1001406c4  cmp  w8, #0x2
1001406c8  b.lt 0x1001406dc
1001406cc  bl   _getpid
1001406d0  mov  w1, #0xb            ; PT_DENY_ATTACH
1001406d4  bl   0x100134730         ; 混淆虚拟机
```

把入口两条指令改成 `mov x0,#0` / `ret` 之后，启动期跳飞从 4 次降到 1 次。这里有两个
必须知道的细节：

- 只把 `b.lt` 改成无条件跳转（保留计数自增）**反而更糟**：跳飞 5 次，6～8 秒后进程消失。
  计数器的自增本身是被观察的。
- 整段只写 `ret` 会让 `x0` 保留调用方的垃圾值，返回约定被破坏。必须显式 `mov x0,#0`。

炸弹入口补上之后这一条仍然需要：关掉它时（0.1.76 实测）两次启动都在 45 秒内消失，
日志里没有任何异常记录，说明退出走的不是异常路径。

### 3. Mach 异常端口接管（`WH_EXC_TAKEOVER`，现已关闭）

0.1.66 用它把进程撑住：任务级与线程级都接管，掩码只用
`EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION`。**不要带 `EXC_MASK_BREAKPOINT`**，
这个 App 自己注册了 `EXC_MASK_BREAKPOINT`（任务端口 `mask=0x40`），覆盖它会让 App
在 3 秒内退出。

跳向毒地址的异常**不回复**，让线程停在异常态；回复是错的，pc 仍是毒地址，内核恢复后
必然再次异常，实测直接变成 100% 忙循环。

0.1.77 起启动期不再产生异常，这条接管已经关掉，代码保留作排查工具。

## 三条固化约束

1. **不要周期性重设异常端口。** 每 250ms 调一次 `thread_set_exception_ports` 会打断主线程，制造出"每 6.1 秒一次跳飞"的假象。这一个假象花掉了整轮排查时间。
2. **日志不能写 `Documents`。** 加固壳会把那里的非常规文件删掉（实测整份日志消失）。现在写 `Library/Caches/gtcfg.log`。
3. **镜像 0 不一定是主程序。** 这台设备上 `_dyld_get_image_header(0)` 返回的是 `IQKeyboardManagerSwift`，给 `__TEXT` 打补丁必须按可执行路径逐个比对镜像名。

## 定位这类跳转的办法

这一次真正起作用的是「只读现场采集」，装 hook 只用来回答一个问题——谁在投递这个 block：

- 钩住 `dispatch_async`，只在被投递 block 的 `invoke` 落在嫌疑地址区间时记录队列标签与调用栈，其余原样放行；
- 异常现场把信号处理器、`fp` 附近的原始栈、`__TEXT` 的运行时字节一起落盘，再和磁盘二进制逐字节比对。

字节比对这一步值得单独说：`__TEXT` 段 12 MB 内 0 处差异，直接排除了"自解密没生效"这条猜想，把方向从"运行时改写造成的"纠正为"代码本来就这样"。之前的几轮实验（停放页、分派器改 `ret`、退回调用方）都建立在错误前提上。

## 与同族 tweak 的关系

检测库名与 icbcbypass / abcbypass 相同（都是 SecureUtilityPlus），但本 App 里那套 Swift 类没有方法，所以 icbc 那种"遍历 13 个 checker 类、把返回 BOOL 的安全方法改成 NO"的做法在这里无效。这里能落地的是主二进制的指令补丁。

与 aiabypass 的差别在于：友邦是"判定没绕过、只接住后果"，这里是把两处会跳向毒地址的代码直接改掉，异常根本不发生。
