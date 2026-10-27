# 国家网络身份认证检测向量

目标：`cn.cyberIdentity.certification` / 可执行文件 `WHClient` 1.2.38（build 13）。
设备：iPhone 13 Pro / iOS 15.4.1 / rootless Dopamine 1.x + ElleKit。
架构与修复方案见 `llmdoc/architecture/whbypass-architecture.md`，原始实验记录见 `whbypass/analysis.md`。

## 检测组件

| 组件 | 证据 | 在本 App 里的实际作用 |
|------|------|------------------------|
| Bangcle Everisk | `everisk_ZDAX iOS5.1.2.SP2-250207`、`everisk failed as license issue!`、`everisk cannot start as flow control issue` | 主检测引擎，静态链入主二进制 |
| SecureUtilityPlus | 27 个 `_TtC17SecureUtilityPlus*` 类，全部 `baseMethods = 0x0` | 只有库名，运行期无 ObjC 入口 |
| everisk checker | 27 个混淆类，实现 `+(name)` / `-(check)` / `-(defaultPeriod)` | 具体检测项，467ms 之后才被调度 |
| KSCrash（WPK 移植） | `WPKKSCrashInstallation`、`KSCrash Exception Handler (Secondary)` | 崩溃捕获，**不是检测方** |

Everisk 的 27 个 checker 与可读名（运行时用 `+name` 枚举得到）：
`userdata`、`crash`、`auto_click`、`host_fraud`、`keepalive`、`resign`、`position`、
`https`、`self_process`、`trollstore`、`gyroscope`、`inject`、`remote_control`、
`screen_sharing`、`facetime_on_the_phone`、`debug`、`start_info`、`proxy`、`frida`、
`processes`、`devinfo`、`emulator`、`apkinfo`、`env_check`、`devices_reuse`、`start`、`speed`。

SDK 主控类被混淆成 `NgabsWzdwtYWXpPV`，方法名仍是明文：`initWithKey:`、
`runEveriskWithKey:`、`onlineEntry`、`offlineEntry`、`dispatchCheckers`、`isInitSuccess`。
App 层调用链：

```
application:didFinishLaunching
  → WHClient+0xaa2754 → +0xaa0f0c → +0xa9d8b0
  → +0xa9eb5c  setupEveriskAndUMService()
  → +0x725e70  setupEverisk()
  → Everisk 主控类 runEveriskWithKey:   （467ms）
```

## 闪退机制

启动 320～440ms 有 GCD 工作线程被 `br` 送到 `0xb5a0X000`（`0xb5a00000`～`0xb5a16000`）。

- 该区间落在 `__PAGEZERO`（`0`～`0x100000000`，3.05 GB），四级页表无条目。
- `vm_allocate(VM_FLAGS_FIXED)` → `KERN_NO_SPACE`（1）；`mmap(MAP_FIXED)` → `MAP_FAILED`。
- 二进制里搜不到这个常量：64 位、32 位、16 位三种形式均为 0 次——它由 `mov`+`movk`
  拼出的两个立即数相加得到（`0x92ab7998 + 0x22f4f668 = 0xb5a07000`）。
- 崩溃报告特征：`EXC_BAD_ACCESS / SIGSEGV`，`pc = far = 毒地址`，`lr = 1`，`sp = 1`，
  `com.apple.root.default-qos` 线程。

### 6 个"炸弹 block"

主程序里有 6 个函数，函数体是「把 `sp`、`lr` 改成上下文里的值，再 `br` 到毒地址」：

| 函数入口 | 跳向 |
|---|---|
| `WHClient+0x148470` | `0xb5a07000` |
| `WHClient+0x1484d0` | `0xb5a10000` |
| `WHClient+0x149db8` | `0xb5a0b000` |
| `WHClient+0x14a1b0` | `0xb5a11000` |
| `WHClient+0x14a4cc` | `0xb5a0d000` |
| `WHClient+0x14a7dc` | `0xb5a15000` |

全二进制没有一条 `bl` 指向它们，只有 6 处 `adrp`+`add` 把地址写进 block 的 `invoke`
字段：`+0x144334`、`+0x144638`、`+0x1455f0`、`+0x149d14`、`+0x14a428`、`+0x14a738`。
这些位置都在 `0x13f000`～`0x145000` 那段混淆状态机里。

调用路径：

```
工作线程执行 block（invoke = WHClient+0x13f140）
  → 状态机 dispatch_async(全局队列, block{invoke = 0x148470})
  → libdispatch 的 _dispatch_call_block_and_release（dylib+0x1e68）blr 该 invoke
  → 炸弹函数改 sp/lr 后 br 到毒地址
```

同一个状态机还把 `+0x1406b0`（反调试守卫）当 block 反复投递，间隔约 6.2 秒。

**修法**：6 个入口的第一条指令改成 `ret`（`0xD65F03C0`），启动期异常归零。

## 反调试守卫

`WHClient+0x1406b0`，带重入计数（计数器在 `0x101cbf000 + 0xf3c`，全二进制 74 处引用）：

```asm
1001406b0  stp x20, x19, [sp, #-0x20]!
1001406b4  stp x29, x30, [sp, #0x10]
1001406b8  add x29, sp, #0x10
1001406bc  adrp x19, ...
1001406c0  ldr  w8, [x19, #0xf3c]      ; count
1001406c4  cmp  w8, #0x2
1001406c8  b.lt 0x1001406dc            ; count < 2 跳过
1001406cc  bl   _getpid
1001406d0  mov  w1, #0xb               ; PT_DENY_ATTACH
1001406d4  bl   0x100134730            ; 混淆虚拟机
1001406dc  ...
1001406e0  add  w8, w8, #0x1
1001406e4  str  w8, [x19, #0xf3c]      ; count++
```

`0x134730` 是表驱动的混淆虚拟机（常量分裂、`cmp w8,#0x1` 状态机、`udf` 陷阱）。
只调了 3 次，参数 `a1 = 0xb`。

计数的自增本身会被观察：只改 `b.lt` 为无条件跳转、保留自增时，跳飞反而升到 5 次
且 6～8 秒后退出。改成 `mov x0,#0; ret` 才是有效解。

## KSCrash 于 6.5 秒掐死进程

```
100cc4eb4  "KSCrash Exception Handler (Secondary)"
100cc4ed0  bl _thread_suspend
100ce7a58  bl _thread_suspend        ; 遍历线程逐个挂起
```

捕获到跳飞后，KSCrash 把其它线程全部挂起抓现场，再结束进程。表现为"界面卡死 →
十几秒后进程消失、无崩溃报告"，极容易被误判成检测 SDK 的冻结机制。

## 已排除的手法（都做过实验）

| 手法 | 结果 |
|------|------|
| 短路 27 个 everisk `-(check)` | 跳飞次数不变（开/关都是 4 次） |
| 短路 Everisk 主控类 `initWithKey:` / `runEveriskWithKey:` / `onlineEntry` / `offlineEntry` | 无影响，调用发生在 467ms，晚于跳飞 |
| `GTCGbdDyncInfo` 的 `checkSafe` + 20 个 `setT*Enable:` 置 NO | 无影响 |
| `ptrace` 恒返回 0 | 无影响 |
| 哨兵地址铺停放页（`wfe` + `b .`） | 地址在 `__PAGEZONE` 之外，无法映射 |
| 分派器 `+0x134730` 入口改 `ret` | 5 次异常，无改善 |
| 16 处内联 `svc #0x80` | 都在 syscall 包装函数里，与退出无关 |
| 异常回复但 pc 仍是毒地址 | 立即变成 100% 忙循环 |
| 每 250ms 重设线程异常端口 | 打断主线程，制造假的每 6.1 秒一次跳飞 |
| 覆盖 `EXC_MASK_BREAKPOINT` | App 3 秒内退出（它自己注册了这个掩码） |

## 日志位置

日志不能写 `Documents`：加固壳会删掉那里的非常规文件。当前写
`Library/Caches/gtcfg.log`。`/dev/console` 只可写不可读，`syslog` 在 iOS 15 上不可用。
