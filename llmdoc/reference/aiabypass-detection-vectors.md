# 友邦友享检测向量

目标：`com.aia.china.YoubangHealthRelease`（友邦友享），可执行文件 `KYHAppStore`，验证版本 6.9.33。实现见 `llmdoc/architecture/aiabypass-architecture.md`，完整实验记录见 `aiabypass/analysis.md`。

## 检测组件

App 内置 `JMCodeProtectKit.framework`（bundle id `com.IPACodeProtectTwoSDk`，v3.0.0.20260903.1），混淆标记 `ipa-asm-obf`、`ijm-obf-idc`、`ijm-obf-icf`、`ijm-obf-ivmp`。这是商业 RASP（运行时应用自我保护）组件：进程内持续检查环境，判定失败后主动处决进程。

**检测对象是越狱注入基座本身，与装了哪些 tweak 无关。** 移走全部第三方 tweak 后仍然闪退，此时进程里只剩 `/usr/lib/systemhook.dylib`、`libinjector.dylib`、`libellekit.dylib`。这解释了"用 Choicy 禁用注入后照样闪退"——Choicy 挡不住基座。

## 处决手法

两段故障，时机固定在 tweak 构造函数之后约 7ms 与 12ms（多次运行时刻一致）：

| 时机 | 表现 | 说明 |
|---|---|---|
| 7ms | `pc = lr = fp = 0x8`，`x8 = x9 = x28 = 8`，`EXC_BAD_ACCESS` | 破坏对象 `isa` 后发 Objective-C 消息，执行了 `blr xN` 而 `xN = 8` |
| 12ms | `pc = lr = 0xeee1`，`SIGUSR1` | 另一条处决路径，信号由更底层的手段投递 |

`SIGUSR1` 不经过 `kill`/`raise`/`pthread_kill`：三个函数都挂住过一次调用都没记录到，信号照样送达。

**注意异常消息的长度**：`exc_reply_t` 线上头部是 `Head(24) + NDR(8) + RetCode(4) + new_stateCnt(4) = 40` 字节。少发 16 字节时内核拒收，`brk` 会以 `SIGTRAP` 重新投递到同一个 PC。

## 完整性校验

JM 的检查函数是 `JM+0x14fc40`，由调度循环（`JM+0x11a708` 一带）对每个检查项调用。传进来的 `x1` 指向一个 0x48 字节的结构：

```
char     sectname[16];   // "__got" / "__la_symbol_ptr"
char     segname[16];    // "__DATA_CONST" / "__DATA"
uint64_t addr;           // 节的运行时地址（主二进制）或节内偏移（内嵌框架）
uint64_t size;
```

启动期共调用 **50 次**，正好是 25 个 App 内嵌镜像各查 `__got` 与 `__la_symbol_ptr` 两个节。也就是逐镜像的导入表完整性校验。

## systemhook 留下的痕迹（已确认不是触发点）

在这 7 个槽里能找到指向 `systemhook.dylib` 的条目，且在 tweak 构造函数跑起来之前就已写好：

| 位置 | systemhook 偏移 | 符号 |
|---|---|---|
| `KYHAppStore __got+0x1dc8` | `+0x6ad8` | `dlopen` |
| `KYHAppStore __got+0x1dd0` | `+0x6bd0` | `dlopen_preflight` |
| `KYHAppStore __got+0x1e08` | `+0x6eb0` | `fork` |
| `KYHAppStore __got+0x25e0` | `+0x65a8` | `posix_spawn` |
| `KYHAppStore __got+0x2738` | `+0x6f0c` | `vfork` |
| `KYHAppStore __la_symbol_ptr+0x1ea8` | `+0x6ad8` | `dlopen` |
| `MPIDRSSDK __la_symbol_ptr+0xdb0` | `+0x6ad8` | `dlopen` |

主二进制导入的相关符号恰好就是这 6 个（`llvm-nm -u` 可查：`_dlopen`、`_dlopen_preflight`、`_fork`、`_posix_spawn`、`_pthread_atfork`、`_vfork`）。

**已实测排除**：把这 7 个槽全部还原成未被劫持的真实地址后，App 稳定但处决次数仍是 2。它们不是触发点。另外，故意多挂 4 个透传 hook 后命中数仍是 7，说明这些条目是 systemhook 装载镜像时自己写进去的，不是我们的 `MSHookFunction` 造成的。

## 已排除的向量

以下都做过实验并证伪，不要重复：

- **镜像路径检测**：改写 `dyld_all_image_infos` 里全部 `/var/jb`、`preboot`、`basebin`、`procursus`、`ellekit` 相关 `imageFilePath`（实测成功改写 5 个），崩溃特征不变。
- **`dyld` 枚举过滤**：`_dyld_image_count`/`_dyld_get_image_name` 一类 hook 对判定无影响。
- **`dladdr` 伪装、`getsectiondata` 伪造、`task_info`/`csops`**：均无效果。
- **进程枚举**：JM 在沙盒里看不到外部进程（`sysctl` EPERM）。
- **App 不调用 `dlsym`**：挂住 `dlsym` 后从启动到首屏稳定，调用次数为 0。
- **`__DATA,__interpose` 在 tweak 里不生效**：挂了 6 个符号，构造函数里读到的记录数是 0。interpose 只对在它之后绑定的镜像生效，而 tweak 被 ElleKit 追加在主程序加载命令末尾。
- **拦 `exit`**：会让 ElleKit 的异常线程在持有 dyld 锁时卡住，主线程随后死锁，最终被 watchdog 杀掉（`0x8BADF00D`）。

## 当前时间窗结论

JM 是主程序的依赖，初始化早于被 ElleKit 追加的 tweak；它做判定时看到的已经是 systemhook 改过的 GOT，判定在那一刻就定了；7ms 和 12ms 后的两次处决是后果。构造函数里扫描全部线程想挂起 PC 落在 JM 内的线程，实测**一个都找不到**，说明这些线程是稍后才被创建或才进入 JM 代码的。

所以在 tweak 注入这个范围内，"让判定本身不成立"做不到。真要走这条路，只有两个方向，都不属于 tweak：一是改主程序的加载命令顺序让我们的镜像排在 JM 之前；二是定位到发起处决的那段 JM 代码并在那里改结果。处决线程的栈上留有 6 个可用的 JM 返回地址（`+0x11c4ac`、`+0x11c720`、`+0x15063c`、`+0x15298c`、`+0x16773c`、`+0x180100`、`+0x1818b8`、`+0x1829ac`），后续可以据此往上找发起处决的那一段。

## 一个尚未验证的假设

这两次故障时机固定、手法一致，也可能是 JM 自己的启动防调试自检——在干净设备上同样会发生，由它自己的处理器接住后继续运行。若如此，把它们当成"检测命中"就是误判，而异常端口接住它们恰好还原了原本的行为。验证这个假设需要一台未越狱的同型号设备，本机做不到。

## 排查方法要点

- 崩溃的权威信息来自 `/var/mobile/Library/Logs/CrashReporter/KYHAppStore-*.ips` 里的 `faultingThread`、`usedImages`、`threadState`，比自行展开栈可靠，尤其在 ElleKit 先抢走 Mach 异常的时候。
- 计数进程存活时用 `ps aux | grep '[K]YHAppStore' | wc -l`。`grep -c` 在 zsh 下遇到无匹配会报 `no matches`。
- arm64e 的返回地址带 PAC 签名，48 位掩码不够。重建方法：先按 48 位掩码试，不成就取低 32 位配上高位段 `0x1`–`0x3` 逐个试，命中即采用。
- 多线程日志必须加互斥锁，否则整行会被切碎，之前多次因此误判。
- 日志路径固定写 App 数据容器的 `Documents/`，不写 `/tmp` 或 `/var/jb/tmp`。
- `simtouch` 的 `tap`/`swipe` 参数是物理像素（本机 1170×2532）。底部 tab 的 x 坐标是 121 / 362 / 603 / 845 / 1086，y 均为 2388。
