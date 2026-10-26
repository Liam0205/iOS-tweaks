# 友邦友享越狱检测绕过：分析记录

目标 App：`com.aia.china.YoubangHealthRelease`（友邦友享），版本 6.9.33，build 2026102012。

两台设备上安装的主二进制 `KYHAppStore` 完全一致（md5 `b779432ab7d51192e18446ea6e166910`，70 530 224 字节），因此二进制内的文件偏移可以跨设备复用；但 App 数据容器的 UUID 和 `/private/var/containers/Bundle/Application/<UUID>/` 路径每台设备、每次重装都会变，必须重新获取。

| 设备 | 端口 | 系统 | 越狱 |
|---|---|---|---|
| iPhone 13 Pro | 22215 | iOS 15.4.1（19E258） | rootless，预启动路径 `/private/preboot/9C4B5D63.../jb-0/procursus` |
| iPhone 14 Pro Max | 22216 | iOS 16.3.1 | rootless，Dopamine + ElleKit |

## 检测组件

App 内置 `JMCodeProtectKit.framework`（`com.IPACodeProtectTwoSDk`，v3.0.0.20260903.1），混淆标记 `ipa-asm-obf`、`ijm-obf-idc`、`ijm-obf-icf`、`ijm-obf-ivmp`。这是一个 RASP（运行时应用自我保护）组件：在进程内持续检查环境，判定失败后让进程退出，表现为"打开就闪退"。

## 已确认的结论

### 1. 检测对象是越狱注入基座，与装了哪些 tweak 无关

在 22215 上依次移走 `FLEXList`、`noJailbreak`、`Shadow`、任务里 6 个 `com.apple.UIKit` 全局 tweak（`HammerIt`、`bfdecryptor`、`fixxinamine`、`iapstore`、`killads`、`leftPan`）、`Choicy`、`Crane` 之后，App 仍然崩溃。此时进程里只剩越狱基座本身：

- `/usr/lib/systemhook.dylib`（Dopamine 注入入口）
- `.../usr/lib/ellekit/libinjector.dylib`
- `.../usr/lib/libellekit.dylib`

这解释了用户观察到的"用 Choicy 禁用注入后仍然闪退"：Choicy 只能挡住 tweak，挡不住基座。

### 2. 崩溃是主动制造异常，不是普通越狱分支

系统崩溃报告里，故障线程处于伪造上下文：

```
exc  EXC_BAD_ACCESS / SIGSEGV
pc = lr = fp = 0x8    x8 = x9 = x28 = 8    sp 有效
x16 = pthread_mutex_unlock    x17 = +[NSThread isMainThread]
```

也就是说有代码执行了 `blr xN` 而 `xN = 8`。同进程里 JM 的检查线程仍在运行，栈为：

```
JM+0x122784 → JM+0x186634 → JM+0x11a77c → JM+0x16f64c
            → JM+0x164794 → JM+0x1574f4 → JM+0x152ea8 → JM+0x11c720
```

### 3. `brk #0xdead` 不是主因

主二进制里唯一的 `brk #0xdead` 位于 `KYHAppStore+0x7c55f8`（文件偏移与运行时一致），周围是 ijm 混淆器 VM 的导入绑定器：`0x7c5590 cbz x15` 在绑定失败时跳到这里。全二进制没有直接 `bl` 指向它、也没有指针引用，只在最小实验模式下被走到过一次。它不是常规崩溃路径。

### 4. 改写镜像路径无效

把 `dyld_all_image_infos.infoArray` 里 all `/var/jb`、`preboot`、`basebin`、`procursus`、`ellekit`、`TweakInject` 的 `imageFilePath` 全部改写成 `/usr/lib/lib*.dylib` 形式的合法系统路径（实测成功改写 5 个镜像，包括 `systemhook.dylib`、`libinjector.dylib`、`libellekit.dylib` 和自己的 dylib），App 仍然以同样的 `0x8` 特征崩溃。**JM 不依赖 `imageFilePath` 判定。**

### 5. `exit(1)` 来自 ellekit，不是 JM 自己

用 tweak hook `exit`/`_exit` 并记录调用者，得到：

```
EXIT(1) caller=libellekit.dylib+0x1bae8
```

反汇编 libellekit 后确认 `0x1bae8` 位于 `ellekit.hookClassPair(class:class:)`，`0x1bae0` 是 `mov w0,#1; bl exit`。即 JM 触发异常后，ellekit 的 `ExceptionHandler.portLoop` 捕获并退出进程。

### 6. 拦掉 exit 会让 App 活下来但死锁

把 `exit(1)` / `_exit(1)` 改成直接返回后，App 从"5 秒内必死"变成存活 15 秒以上，随后被系统 watchdog 杀掉：

```
FRONTBOARD code 0x8BADF00D
process-launch watchdog transgression: exhausted real time allowance of 20.00 seconds
```

卡死时的主线程栈显示它停在我们自己的 `add_image` 回调里，正在转发给 JM 的回调，而 JM 的回调在做证书链校验（`EAP8021X EAPTLSVerifyServerCertificateChain`）。同时 `ellekit_exc_port` 线程正在 dyld 的 `withLoadersReadLock` 里等待。合理解释是：ellekit 的异常线程在持有 dyld 锁的情况下被我们拦住了退出，锁没有释放，主线程再调 `_dyld_image_count` 就死锁。**所以拦 exit 不是可行方向。**

### 7. frida-server 会污染基线

`frida-server` 常驻并被 launchd 自动重启，会在没有任何注入的情况下让 App 崩溃，制造"不装 tweak 也崩"的假象。做干净实验前必须停掉并禁用它的 LaunchDaemon：

```
sudo launchctl bootout system/re.frida.server
sudo mv /var/lib/LaunchDaemons/re.frida.server.plist <备份目录>   # 实际路径 /var/jb/Library/LaunchDaemons/
```

### 8. 唯一有效的干预：接管异常端口但不回复

关键发现来自一次"写坏"的版本：异常服务线程因为消息缓冲区太小一直收不到消息（自旋空转），等价于**接管了异常端口却从不回复**。这个状态下 App 不再闪退，能正常显示界面。

原因：JM 的处决方式是**破坏对象的 isa 再发 Objective-C 消息**，于是线程执行 `blr` 跳到非法地址。异常被内核抛给我们后我们不回复，触发处决的线程就永久停在异常状态，进程不会退出。

实测异常现场（`mach_exception_raise_state_identity`，消息 ID 2407）：

```
type=1 (EXC_BAD_ACCESS)  code0=1  code1=8
pc=lr=0x8   x0=0x4   x1=0x1f3821dae (+[NSThread isMainThread])   x8=x9=8
```

另一类异常跳到 `0xf3`。还有一类是 JM 自己的线程跳到 `0x99e11258` 这类无效地址（`x10` 与 pc 相同，说明是 `blr x10`）。

### 9. 异常消息的解析要点

`task_set_exception_ports` 用 `EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES` 时，内核发来 `msgh_id 2407`，消息里同时带线程端口和完整线程状态。**消息线上的 port descriptor 是 12 字节**，和结构体里的 16 字节不一致，按结构体解析会全部错位（曾经把 `exception` 读成 68、端口读成 1）。可靠的做法是按显式字节偏移读：

```
0 header(24) | 24 descriptor_count(4) | 28 thread(12) | 40 task(12)
52 NDR(8) | 60 exception(4) | 64 codeCnt(4) | 68 code(2×8)
84 flavor(4) | 88 old_stateCnt(4) | 92 old_state
```

`flavor=6` 就是 `ARM_THREAD_STATE64`，`old_state` 可直接按 `arm_thread_state64_t` 读。

### 10. 已排除但值得记录的尝试

- **终止处决线程**：`thread_terminate` 返回 53，从消息里拿到的端口没有终止权限。
- **伪造 dyld 镜像路径**：见第 4 条。
- **只伪装 `dladdr`**：JM 确实用 `dladdr` 逐个检查镜像（`JM+0x15e1c0` 连续查询 systemhook、Choicy、Crane、ellekit、AppSync 等），但只改 `dli_fname` 不足以通过。
- **枚举伪造 + `dladdr` 伪装同时做**（`AIA_STEALTH`）：仍然崩溃。
- **UI 层拦截**：卡住时窗口层级完全正常，`hitTest` 能命中 `YBSubHeaderComponentView` 且 `userInteractionEnabled=1`，没有遮罩层。所以不是 UI 拦截。

### 11. "几分钟后触摸失效"的真正机制：主线程被挂起

之前的判断有误。用 `simtouch` 客观计时后看清了完整链条：

1. App 自己会在 `sendEvent:` 里做埋点，调用 ijm 保护的方法 `requstQueryTaskStateInfo`。
2. 该方法的 ijm 导入绑定失败，走到 `KYHAppStore+0x7c55f8` 的 `brk #0xdead`。
3. 这次 `brk` 发生在**主线程**上，异常类型 `type=6`（`EXC_BREAKPOINT`）。
4. 旧的"不回复"策略把主线程永久挂在异常状态。

主线程一挂：动画照常（由 render server 独立合成），窗口层级和 `hitTest` 都正常，但触摸事件没人处理。这与之前观察到的现象完全一致。

异常现场（`main=1 type=6`）的栈上全是 Dynatrace 的返回地址，`x1` 指向字符串 `requstQueryTaskStateInfo`，`x15=0` 说明走的是绑定器的失败分支：

```
pc=KYHAppStore+0x7c55f8 (brk #0xdead)  lr=Dynatrace+0xb0xxx
x1 = "requstQueryTaskStateInfo"   x15=0
```

反汇编 `0x7c55f8` 之后是 `nop` 和 `0x7c5600` 的上下文恢复代码，而 `0x7c5600` 读的是绑定器在 `0x7c5560` 存到 `[sp,#0x110]` 的错误处理指针。也就是说 `brk` 之后紧跟的就是"错误路径的继续执行"，把 PC 推到 `+4` 是能接上的。

**结论：断点类异常应当回复"PC 前进 4 字节"而不是不回复。** 这就是 `AIA_EXC_SKIP_BRK`。

### 12. `sendEvent:` 探针会自己制造这个故障

加 `MSHookMessageEx(UIApplication/UIWindow, sendEvent:)` 做事件计数后，主线程 `brk` 出现得更早（约 150 秒）。去掉探针后同样的 100 次点击循环里异常数稳定在 2，不再增长。原因是多插一层 swizzle 改变了 App 自己 `sendEvent:` 埋点的调用链。

所以**事件计数不能作为常驻诊断手段**，只在需要时用 `AIA_EVENT_PROBE=1` 打开。

### 13. 主线程还会在 JM 的执行路径上被挂起

不做任何 `sendEvent:` hook，App 在切换 tab、滑动页面若干次之后仍会撞上主线程异常：

```
EXCFAULT main=1 type=1 code0=1 code1=0x99ccd258
pc=0x99ccd258 (未映射)  lr=JMCodeProtectKit+0x186634
x10 = 0x99ccd258
```

`x10` 是把 64 位指针截断成 32 位的结果（原值约 `0x1_0899ccd258`），`pc = x10`，说明执行到 `blr x10` 时目标无效。`x2` 恰好是 `KYHAppStore+0x7c558c`，即 ijm 绑定器 `blr x16` 之后的那条 `ldr x30, [sp], #0x30`，可见调用是从绑定器返回后进到 JM 里再跳飞的。

只要主线程在这里不回复，界面就永久失去触摸。处理方法见 `AIA_EXC_RECOVER_MAIN`：**把 PC 设成 LR**，让这次调用"返回"，JM 继续往下走。

### 14. `new_stateCnt` 必须用 `ARM_THREAD_STATE64_COUNT`

回复异常时填 `new_stateCnt = 34` 是错的。`arm_thread_state64_t` 是 272 字节，内核按 32 位字计数，`ARM_THREAD_STATE64_COUNT` 为 68。填 34 只会传回一半状态（`x0`–`x16`），PC 根本没送到，内核会按残留内容恢复上下文。所有回复分支统一用 `ARM_THREAD_STATE64_COUNT`。

### 15. 真正的根因：Dynatrace 的 swizzle 配置器

`brk #0xdead` 那条断言，加上扩展后的主线程帧指针链，给出了完整调用路径：

```
FP#00  KYHAppStore+0xf3426c      ← App 埋点方法的原实现（ijm VM）
FP#01  Dynatrace+0xb0754         ← Dynatrace 的回调
FP#02  Dynatrace+0xb01e0
FP#03  UIKitCore+0x1aa950        ← UIKit 事件派发
```

也就是说：**Dynatrace 把 App 的埋点方法 swizzle 掉，回调原实现时走进了 ijm VM，而 VM 在本进程里解析导入绑定器失败**。

Dynatrace 只导入了 `_method_setImplementation` 和 `_class_addMethod` 两个写入口，真正批量装 hook 的是：

```
+[DTXSwizzleDetectionConfigurator addClass:selectors:detector:updateImplementation:]
+[DTXSwizzleDetectionConfigurator addConfig:forSections:exclude:]
+[DTXSwizzleDetectionConfigurator addLifeCycleClass:detector:updateImplementation:]
...
```

把 `DTXSwizzleDetectionConfigurator` 上以 `add` 开头的 11 个类方法、以及 `+[DTXStartupMeasurements swizzleUIKitClasses]` 全部变成空操作后，**主线程不再撞 ijm 绑定器**（`AIA_KILL_DT_SWIZZLE`）。

这是目前唯一真正消掉该故障的干预。之前的 `AIA_BLOCK_DYNATRACE`（拦 `method_setImplementation`）只挡住了一部分，因为 Dynatrace 的配置器会在别处绕过它。

### 16. 绑定失败后无法从异常层补救

试过三种处理方式，都失败：

| 处理 | 结果 |
|---|---|
| 不回复（挂起线程） | 主线程永久卡死，触摸失效 |
| 把 PC 设成 LR | `x0` 现场无效，`0x186634` 之后立刻二次崩溃 |
| 把 `brk #0xdead` 补成 NOP | 绑定器入口出现对齐异常（`pc=x0=KYHAppStore+0x7c5508`，`code0=2`） |

原因是 `0x7c5600` 之后的代码要从 `x0` 指向的结构里恢复 `x26..x29`、`x30`、`sp`、`nzcv`，绑定失败时这个现场根本不存在。**必须在故障发生之前拦，不能事后补救。**

### 17. 主线程跳飞的精确成因：两套 ijm 解释器的描述符互相串了

这一条把第 13 条的"`x10` 被截断"现象追到了底。

App 主二进制 `KYHAppStore` 自己有一套 ijm 解释器，`KYHAppStore+0x7c56b8` 是入口，`+0x7c5a28` 是分派循环，它用自己的分派表 `+0x7c56d8`，**密钥是 0**。而 `JMCodeProtectKit` 另有自己的一套，`JM+0x11ee28` 是入口，分派表 `JM+0x11ee78`，**密钥是 0xff**。

故障现场一直稳定出现同一组值：

```
pc   = 0x…d258（未映射）        lr = JMCodeProtectKit+0x186634
x12  = JM+0x11f388             x13 = KYHAppStore+0x7c5dd0
x14  = 0xa2                    x15 = 0xff
x10  = 0x…9258                 x2  = KYHAppStore+0x7c558c
```

逐条验算后可以完整复原：

1. `x13` 是分派器算出的**下一个**游标。按 `步长 = 2 + 10 × op2`（`低字节×10`，`+0x11f244..0x11f254` 的 `add w17,w17,lsl#2` 再 `lsl#1`）反推，`0x7c5dd0 − 902 = 0x7c5a4a`，这一处正是 `0x7c5a4a` 减 2 得到的游标 `KYHAppStore+0x7c5a48`。
2. `0x7c5a48` 处的字节解出来就是 `x14 = 0xa2`、`x15 = 0xff`，两个值同时吻合，不是巧合。
3. `opcode 0xa2 = 162`，而 JM 的分派表从 `JM+0x11ee78` 到 `JM+0x11f1d0` 只有 **107 项**（`0x358 / 8`），合法 opcode 只能是 0..106。于是 `add x12, x10, w14, uxtw #3` 越界，`ldrsw x11, [x12]` 把后面的**代码字节** `0x911c23e0` 当成了表项偏移。
4. `x10 = 0x109906e78 + 0xffffffff911c23e0 = 0x9AAC9258`，与现场 `x10` 逐位一致；`br x10` 就跳到了这个未映射地址。

所以主线程是**拿着主二进制的字节码、用 JM 的分派表和密钥去解释**。这不是数据被写坏，是两个组件的上下文串了：JM 的导入绑定器把 App 的 ijm 桩接管了，却没有把 App 的解释器上下文一起接管。

### 18. 绑定器慢路径本来就是坏的

绑定器 `KYHAppStore+0x7c5508` 在缓存槽为空时走慢路径，有两条路：

- `[meta+0x48]`（运行时是 `__LINKEDIT` 的 `0x4058008`）→ 若为 0，继续
- `[meta+0x10]` = `0x7c5600` → 真正被 `blr` 的解析器

而 `0x7c5600` 拿到的是 `0x7c5500`（绑定器自己在 `0x7c5558` 用 `adr` 构造的占位描述符），把它当脚本交给解释器。实测两种密钥下都不成立：

| 密钥 | 结果 |
|---|---|
| 0（主二进制解释器自己的密钥） | `5d 00` 合法，`00 00` 合法，`00 00` 也合法，但随后 `cf` 越界（主表 37 项） |
| 0xff（JM 的密钥） | 第一条 `30 ^ 0xff = 0xcf` 就越界 |

`0x7c5500` 不是脚本，它是给失败路径准备的占位数据。全二进制里只有绑定器自己引用它（`adr` 只有 `0x7c552c`、`0x7c5558`、`0x7c555c` 三处，全部在绑定器内部），也没有任何 `b`/`bl` 直接跳进 `0x7c5508`。**这个导入在本进程里从来没有被真正绑定过。**

### 19. 绕过 brk 一定失败，因为它是设计上的中止点

`brk #0xdead` 在 `0x7c55f8`。推进 4 字节会走 `0x7c5600` 的失败续跑路径：

```
0x7c5648  bl   #0x7c56b8      ; 慢路径解释器
0x7c564c  ldr  x1, [x0, #8]   ; x0 = 0 时这里读 0x8
```

实测日志完全一致：`BRKSKIP sigtrap imm=0xdead -> +4` 之后立刻收到 `EXCFAULT code0=1 code1=-32`（读 `0xffffffe0`），随后 `SIGSEGV addr=0xffffffffffffffe0 pc=KYHAppStore+0x7cd0f0`。

反过来，把绑定器入口用 `MSHookFunction` 顶成"直接返回 nil"也失败：`IMPORTNIL` 确实命中，但调用方在 `KYHAppStore+0x1685010` 一带继续解引用返回值。**这个导入的返回值会被当作有效对象使用，不是单纯的埋点。**

### 20. 改 `__TEXT` 里的元数据会连带失去执行权限

元数据表 `0x7c54b0` 嵌在 `__TEXT` 里。用 `vm_protect(..., VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)` 打开可写后，绑定器自己所在的同一页立刻无法执行（故障现场 `pc = KYHAppStore+0x7c5508`，`code0=2`）。补上 `VM_PROT_EXECUTE` 也一样。在 iOS 上不要试图就地改代码页里的指针。

### 21. 异常回复消息的长度曾经算错

`exc_reply_t` 的线上头部是 `Head(24) + NDR(8) + RetCode(4) + new_stateCnt(4) = 40` 字节，旧代码写成 `8+8+4+4 = 24`，少发 16 字节。内核拒收，`brk` 随即以 `SIGTRAP` 重新投递到同一个 PC。已在所有回复分支统一改成 `EXC_REPLY_HDR_SIZE`。

注意：修好之后内核**仍然**会为 `brk` 补发一次 `SIGTRAP`，这属于 Darwin 的正常行为，需要在信号层再推进 4 字节（`AIA_EXC_SKIP_BRK` 里的 `BRKSKIP` 分支）。

## 当前状态

**能启动、能进首页、能连续交互，且不再出现主线程卡死。**

默认构建的几层干预：

| 层 | 作用 |
|---|---|
| Mach 异常端口接管 | 接住处决跳转，进程不退出 |
| `AIA_EXC_SKIP_BRK` | 任意线程的 `brk` 断言推进 4 字节，并在信号层补一次 `SIGTRAP` 跳过 |
| `AIA_BLOCK_DYNATRACE` | 拦住 Dynatrace 直接调 `method_setImplementation` |
| 其余处决跳转 | 不回复，线程永久挂起 |

越狱判定仍未真正通过：JM 每次检查都会走到处决分支，只是被我们在异常层接住。这是"能用"而不是"通过"。

**已知未解决**：App 交互若干次之后，主线程会进到第 17 条描述的 ijm 交叉现场并跳飞，被"不回复"策略挂住，界面从此失去触摸（进程仍然活着，动画由 render server 独立合成，所以看起来像卡住而不像崩溃）。重新启动 App 可恢复。

`AIA_KILL_DT_SWIZZLE=1` 能彻底消除这条故障（Dynatrace 不再 swizzle 那些 ijm 方法，主线程也就不会进 JM 的 VM），但代价是 App 完全不响应触摸：视图树只剩 `UIWindow → UITransitionView → UIDropShadowView` 三层系统容器，截图仍有内容是因为 render server 保着最后一帧。所以它只能作为对照实验，不能作为默认配置。

### 设备上的操作要点

`simtouch` 的 `tap`/`swipe` 参数是**物理像素**（本机 1170×2532），不是逻辑点。之前按 390×844 传坐标会全部点到屏幕左上角区域，导致误判为"点不动"。

底部 tab 的物理像素坐标：推荐 121、友任务 362、友保障 603、友健康 845、我的 1086，y 均为 2388。

另外，点「友保障」「我的」等需要身份的页面会拉起**微信**登录；如果那台设备的微信自己未登录，就会停在微信的扫码页。这时左上角状态栏会显示「◀ 友邦友享」。这属于正常跳转，不是卡死。

## 可复现的实验开关

`Tweak.x` 里的编译期开关，用 `ADDITIONAL_OBJCFLAGS` 传入：

| 开关 | 作用 |
|---|---|
| `AIA_TRULY_EMPTY=1` | 构造函数里什么都不做，只写一行日志 |
| `AIA_EMPTY=1` | 记录模块快照后直接返回，不装 hook |
| `AIA_MINIMAL=1` | 只 hook `_dyld_register_func_for_add_image` |
| `AIA_DYLD_ONLY=1` | 只装 dyld 枚举、`objc_copyImageNames`、`dladdr` 相关 hook |
| `AIA_HIDE_IMAGES=1` | 从 `_dyld_*` 枚举里过滤掉越狱相关镜像 |
| `AIA_BLOCK_ADD_IMAGE=1` | 吞掉对 `_dyld_register_func_for_add_image` 的注册 |
| `AIA_FAKE_PATH=1` | 改写 dyld 镜像表里的 `imageFilePath` |
| `AIA_LOG_IMAGES=1` | 启动时打印所有非系统镜像路径 |
| `AIA_BLOCK_EXIT=1` | 拦下 `exit(1)`/`_exit(1)`（实验用，会导致死锁） |
| `AIA_EXC_RECOVER_FAULT=1` | 主线程跳飞时把 PC 设成 LR（默认关；实测必然二次崩溃） |
| `AIA_EXC_UNWIND_JM=1` | 主线程跳飞时沿帧链退回调用方（默认关；实验性） |
| `AIA_HOOK_IJM_BINDER=1` | 把 ijm 导入绑定器顶成"直接返回 nil"（默认关；调用方会解引用返回值） |
| `AIA_KILL_DT_SWIZZLE=1` | 关掉 Dynatrace 的 swizzle 配置器（默认关；会彻底失去触摸） |

构建（Linux + Theos）：

```
unset PERL5LIB PERL_MB_OPT PERL_MM_OPT PERL_LOCAL_LIB_ROOT
export THEOS=/home/safe/theos
cd aiabypass && make package FINALPACKAGE=1 ADDITIONAL_OBJCFLAGS="-DAIA_EMPTY=1"
```

## 观测手段

tweak 的日志写在 App 数据容器的 `Documents/aiabypass.log`，不写 `/tmp` 或 `/var/jb/tmp`。数据容器路径按 bundle id 查找：

```
sudo grep -l YoubangHealth /var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist
```

崩溃的权威信息来自系统崩溃报告 `/var/mobile/Library/Logs/CrashReporter/KYHAppStore-*.ips`，其中的 `faultingThread`、`usedImages` 和 `threadState` 比自行展开栈更可靠——尤其在 ellekit 抢先把 Mach 异常处理掉的时候。

`probes/` 是早期用 Frida 写的一次性探针脚本，`crashtools/` 是配套的驱动脚本，保留下来方便后续复用。
