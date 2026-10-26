# AIABypass 架构

## 定位

绕过友邦友享（Bundle `com.aia.china.YoubangHealthRelease`，可执行文件 `KYHAppStore`）在越狱设备上打开即闪退的问题。子项目 `aiabypass/`，包名 `page.0x01.aiabypass`。目标版本 6.9.33，rootless，验证环境 iPhone 13 Pro / iOS 15.4.1 / Dopamine + ElleKit。检测面详见 `llmdoc/reference/aiabypass-detection-vectors.md`。

当前版本 `1.0.0`，已验证连续三次冷启动进入首页，5 个 tab 切换、滚动、前后台往返均正常。

## 先说清楚这不是「检测通过」

这是本项目里唯一一个**判定没有绕过、只把后果接住**的 tweak，写文档时必须保持这个措辞，不要写成"绕过成功"。

JM（`JMCodeProtectKit.framework`）的判定发生在它自己的初始化阶段，而 tweak 由 ElleKit 追加在主程序加载命令末尾、构造函数执行得更晚。等我们的代码能跑起来时，判定早就做完了，处决已经在路上。所有"让 JM 看不到痕迹"的思路（改写镜像路径、过滤 dyld 枚举、还原 GOT 条目）都做过并实测无效，原因都不在手段本身，而在时间窗。

因此本 tweak 的能力边界是：**判定照旧命中，但处决打不动进程**。用户能正常使用，启动期仍有 2 次处决被异常端口接住后挂起。

## 核心方案：接管 Mach 异常端口

JM 的处决方式是主动制造故障，而不是调用 `exit`。默认构建把 `EXC_BAD_ACCESS`、`EXC_BAD_INSTRUCTION`、`EXC_BREAKPOINT` 收到自己分配的异常端口上：

| 异常类型 | 处理 |
|---|---|
| 处决跳转（`pc=lr=0x8`、`pc=lr=0xeee1`） | 不回复，触发线程永久停在异常状态 |
| `brk #0xdead` 断言 | 回复"PC 前进 4 字节"，线程继续执行 |
| 其余 | 不回复 |

`brk` 单独处理有一个必须记住的原因：Darwin 把 `EXC_BREAKPOINT` 交给 Mach 异常端口之后，**还会补发一次 `SIGTRAP`**。只靠 Mach 回复推进 PC 挡不住这条路，信号层必须再跳过它，否则同一个 `brk` 会反复投递。

异常回复消息的长度也踩过坑：`exc_reply_t` 的线上头部是 `Head(24) + NDR(8) + RetCode(4) + new_stateCnt(4) = 40` 字节，不是 `24`。少发 16 字节时内核拒收回复，`brk` 立刻以 `SIGTRAP` 重新投递到同一个 PC。所有回复分支统一用 `EXC_REPLY_HDR_SIZE`。

## 修主线程跳飞：清零 ijm 解析器槽

这是本 tweak 唯一一处主动改写内存，也是主线程能稳定工作的关键。

主二进制的 ijm 导入绑定器 `KYHAppStore+0x7c5508` 在缓存槽为空时，会读元数据 `[meta+0x48]` 指向的 `__DATA` 槽（相对 App 基址偏移 `0x4058008`）挑解析器。这个槽在运行时被填成了 `JMCodeProtectKit+0x1865dc`，也就是 JM 自己的解析器。于是 JM 拿主二进制的 ijm 字节码、套自己的分派表和索引去解释，越界后把代码字节当表项偏移，跳到未映射地址。

默认配置 `AIA_IJM_RESOLVER=2` 把这个槽清零，绑定器走 `cbz x16` → `[meta+0x10] = 0x7c5600` 的回退分支，改用 App 自己的解析器、自己的描述符，ABI 天然一致。实测主线程异常从多次降到 0。

槽在 `__DATA`，用 `vm_protect` 打开即可写。**不要改成改 `__TEXT` 里的元数据**——那会让整个代码页失去执行权限。槽要等 App 自己的初始化写完之后再换，所以安装点在 `dispatch_after(2s)`。

早期版本里 `AIA_NEUTER_IJM`（把 ijm 方法实现换成返回 nil 的桩）默认开启过，后来关掉了：在 arm64e 上那样做会破坏方法缓存的一致性，实测主线程随即在 `objc_msgSend` 里 PAC 认证失败（`pc=libobjc+0x7f8c`）。

## 发布版不留自身痕迹

`AIA_DEBUG_LOG` 默认 **0**。日志写在 App 数据容器的 `Documents/aiabypass.log`，文件名本身就是一处显眼的痕迹，不值得为排查能力在正式版里留着。关闭后不创建日志文件，每 5 秒枚举线程与端口的统计线程也不启动。排查时用 `ADDITIONAL_OBJCFLAGS="-DAIA_DEBUG_LOG=1"` 重新构建。

## 诊断开关

`Tweak.x` 顶部的编译期开关，用 `ADDITIONAL_OBJCFLAGS` 传入，除特别说明外默认全部关闭：

| 开关 | 用途 |
|---|---|
| `AIA_DEBUG_LOG=1` | 打开日志文件与统计线程 |
| `AIA_IJM_RESOLVER=2` | 清零解析器槽（默认值，不要改） |
| `AIA_GOT_AUDIT=1` | 审计各镜像 `__got`/`__la_symbol_ptr` 里指向越狱库的条目 |
| `AIA_GOT_RESTORE=1` | 还原这些条目（`AIA_GOT_RESTORE_GOT=1` 连 `__got` 一起） |
| `AIA_CHECK_TRACE=1` | 打印 JM 检查项的原始结构 |
| `AIA_DLSYM_PROBE=1` | 记录所有 `dlsym` 调用与调用方 |
| `AIA_KILL_PROBE=1` | 记录 `kill`/`raise`/`pthread_kill` |
| `AIA_EARLY_TRACE=1` | 加载期 interpose 探针（在本项目中不生效，见下） |
| `AIA_FREEZE_JM=1` | 构造函数里挂起 PC 落在 JM 内的线程 |
| `AIA_TRULY_EMPTY=1` | 构造函数只写一行日志，用于零 hook 基线 |
| `AIA_EMPTY=1` | 记录模块快照后直接返回 |

## 三条固化约束

1. **改 `ADDITIONAL_OBJCFLAGS` 必须先 `make clean`**。增量构建会产出缺 `__DATA` 段的 dylib（实测 88640 字节降到 33888 字节），装到设备上 App 在 dyld 阶段直接退出，连构造函数里的日志都写不出来，表现为"日志 0 字节、进程不在"，很容易误判成检测加固了。
2. **不要用 `dlsym` 取"原始地址"**。`systemhook` 挂过的符号，`dlsym(RTLD_DEFAULT, ...)` 返回的就是 systemhook 的地址。要拿干净地址必须自己解析 `__LINKEDIT` 符号表；且共享缓存里的镜像 `symoff`/`stroff` 是缓存文件内偏移，得按 `le->vmaddr + (off - fileoff) + slide` 换算并做范围校验，直接按镜像头加会段错误。
3. **不要在正式版打开诊断探针**。高频探针会触发系统唤醒限制（`KYHAppStore.wakeups_resource-*.ips`），App 会被系统杀掉，看起来像检测命中。

## 与其他 tweak 的关键差异

| 维度 | aiabypass | icbcbypass | bmwbypass |
|------|-----------|------------|-----------|
| 判定是否绕过 | **没有，只接住后果** | 是 | 是 |
| 主要手段 | Mach 异常端口接管 + 清零解析器槽 | fishhook + 三层防御 | inline-hook ISS 入口返回 false |
| 检测组件 | JMCodeProtectKit（商业 RASP，ijm VM 混淆） | SecureUtilityPlus | IOSSecuritySuite（开源） |
| 处决手法 | 主动制造 Mach 异常 / SIGUSR1 | 冻结 + 弹窗退出 | 弹窗，进程不自杀 |

## 依赖与边界

- 构建：Theos、libsubstrate（`MSHookFunction`）、Foundation/UIKit。
- 打包：rootless scheme，`Depends: ellekit`。
- 注入边界：进程 `KYHAppStore`。
- 实验记录：`aiabypass/analysis.md`（最终结论在第 41–54 节）。

## 主要回归风险

- App 升级后 JM 的处决手法若从"制造异常"改成别的形态（例如直接 `exit`），异常端口不再够用，需要按 `llmdoc/reference/aiabypass-detection-vectors.md` 的排查顺序重新定位。
- 解析器槽偏移 `0x4058008` 与绑定器 `0x7c5508` 都是相对当前版本的固定偏移，App 升级后必须重新核对。核对方法是看 `BINDER slot` 日志与 `RESV` 探针是否还对得上。
- 不要因为"想让它真正通过"而恢复镜像路径改写、dyld 枚举过滤一类手段——已实测无效，且会引入 O(N²) 冻结风险。
