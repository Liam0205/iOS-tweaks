# AIABypass 更新日志

## 0.0.7

- **查清 JM 的检查项是什么**。钩住 `JM+0x14fc40` 后可以看到，每次调用传入的是 0x48 字节的节描述结构：`sectname[16]`、`segname[16]`、`addr`、`size`。启动期一共调用 50 次，正好是 25 个 App 内嵌镜像各查 `__got` 与 `__la_symbol_ptr` 两个节，也就是逐镜像的导入表完整性校验。
- **查清 GOT 命中的来源**。开启 `AIA_GOT_AUDIT` 时命中的 7 条（主二进制 `__got` 5 条、`__la_symbol_ptr` 1 条，`MPIDRSSDK` 的 `__la_symbol_ptr` 1 条）全部指向 `systemhook.dylib`，而且在我们的构造函数跑起来之前就已经写好。故意多挂四个透传 hook 后命中数仍是 7，说明不是我们的 `MSHookFunction` 造成的，而是 systemhook 装载镜像时自己改写的。
- **更正一个诊断假象**。此前"零 hook 对照命中 0 条"的说法不成立：`module_for` 依赖 `snapshot_modules()` 填的模块表，在快照之前调用一律返回 NULL，所有条目都被判成"不是越狱库"。补上分时点审计后，命中数在快照前后从 0 变成 7，变的只是解析能力，内存内容没变。
- **排除两条还原路径**。把 5 个 `__got` 槽写回磁盘值 0 会让 App 立刻退出，说明这些槽启动早期就会被调用；`dlsym(RTLD_DEFAULT, "dlopen")` 返回的仍是 systemhook 的地址，也没法用来还原 `__la_symbol_ptr`。
- **排除两条猜测**。App 完全不调用 `dlsym`（挂住 `dlsym` 后启动到首屏调用次数为 0）；JM 处决也不走 `kill`/`raise`/`pthread_kill`（三个都挂住，一次调用都没有），但 `SIGUSR1` 照样送达。
- **新增四个诊断开关**（全部默认关闭）：`AIA_GOT_RESTORE`（还原被 systemhook 改写的槽）、`AIA_DLSYM_PROBE`、`AIA_KILL_PROBE`、`AIA_EXTRA_HOOKS`。
- 记录构建陷阱：改动 `ADDITIONAL_OBJCFLAGS` 必须先 `make clean`，否则产物缺 `__DATA` 段，App 在 dyld 阶段直接退出，连日志都写不出来。
- **查出 7 个槽对应的函数**。systemhook 对自己挂过的符号经 `dlsym` 会返回同一地址，逐个比对候选符号后确认：5 个 `__got` 槽分别是 `dlopen`、`dlopen_preflight`、`fork`、`posix_spawn`、`vfork`，两个 `__la_symbol_ptr` 槽都是 `dlopen`。主二进制导入的相关符号正好就是这 6 个，systemhook 把它们全部换成了自己的实现。
- **把 7 个槽全部还原后，处决次数不变**。用自解析 `__LINKEDIT` 符号表的方式取得未被劫持的地址（不能用 `dlsym`，它返回的就是 systemhook 的地址）写回后，App 连续三次启动都稳定，`exc` 仍然是 2。说明这些 GOT 条目不是处决的触发点。
- **两次处决发生在进程启动后 7ms 和 12ms**。加上相对时间戳后，三次运行都是同一时刻，远早于 JM 的 50 项 GOT 检查。判定不是这批检查做出的。
- **加载期 interpose 在 tweak 里不生效**。用 `__DATA,__interpose` 挂 `_dyld_image_count`、`_dyld_get_image_name`、`_dyld_get_image_header`、`getenv`、`sysctl`、`dlsym` 六个，构造函数里读到的记录数是 0。interpose 只对在它之后绑定的镜像生效，而 tweak 是追加到主程序加载命令末尾的，App 及其框架早已绑定完毕。
- **构造函数里停不住处决线程**。扫描全部线程、把 PC 落在 JM 范围内的线程挂起，实测构造函数执行时一个都找不到；两次处决是 7ms 和 12ms 之后才发生的。
- 综合第 48–50 节：JM 作为主程序依赖，初始化早于被 ellekit 追加的 tweak，判定在看到 systemhook 改过的 GOT 时就已做出，7ms/12ms 的两次处决是后果。按目前 tweak 注入的范围，改内存改变不了这个顺序。
- 实测默认构建连续三次启动均为 `exc=2 alive=1`，App 可用。**检测本身仍未真正通过**：两条处决（`pc=lr=0x8`、`pc=lr=0xeee1`）仍由异常端口接住，而不是被消除。要让判定本身不成立，需要在比 tweak 构造函数更早的阶段介入加载顺序，或者定位到发起处决的那段 JM 代码。

## 0.0.6

- **查清主线程跳飞的真正成因：解析器槽被 JM 占了**。主二进制的 ijm 导入绑定器 `KYHAppStore+0x7c5508` 在缓存槽为空时，会读元数据 `[meta+0x48]` 指向的 `__DATA` 槽（偏移 `0x4058008`）。运行时读出来是 `JMCodeProtectKit+0x1865dc`，也就是 JM 自己的解析器。它拿主二进制的字节码，用 JM 的分派表和索引去解释，越界后把代码字节当表项偏移，跳到未映射地址。故障现场 `x2` 恒为 `KYHAppStore+0x7c558c`（绑定器 `blr` 的返回点），两条证据互相印证。此前记的"绑定器慢路径本来就坏"要修正：慢路径之所以从没走通，是因为槽一直被 JM 占着。
- **修复方式：把槽清零**。槽在 `__DATA`，用 `vm_protect` 打开即可写，不像改 `__TEXT` 那样让代码页失去执行权限。清零后绑定器走 `cbz x16` → `[meta+0x10] = 0x7c5600` 的回退分支，改用 App 自己的解析器、自己的描述符，ABI 天然一致。新增 `AIA_IJM_RESOLVER` 开关，值 2 为清零（默认），值 1 为替换成自己写的解析器。
- **`AIA_NEUTER_IJM` 改为默认关闭**。它在 3 秒后遍历所有类，把落在绑定器区域的方法实现换成返回空值的桩。在 arm64e 上这样做会破坏方法缓存的一致性，实测主线程随即在 `objc_msgSend` 里 PAC 认证失败（`pc=libobjc+0x7f8c`，`code0=2`）。
- **三个 Dynatrace swizzle 拦截改为默认关闭**。它们是 0.0.3 之前用来挡住主线程进 ijm VM 的；槽清零后不再需要。实测三个同时打开会让进程在 ctor 阶段就卡住，连 2 秒后安装槽清零的任务都跑不到；单独打开任意一个则正常，属组合效应。
- **信号处理器不再把 `SIGUSR1` 放大成默认终止动作**。JM 用这个信号处决进程，之前的表现是"静默退出"，日志里只有一行 `SIGNAL 10` 就没了。
- **主线程恢复分支增加运行时库判定**。`LR` 落在 `libobjc`/`libdyld` 内部时，不再把 `PC` 送进去接续执行（那等于在 `objc_msgSend` 半途插入），改为把 `x0` 清零、按"这次消息得到 nil"返回。
- **修好两个诊断问题**。栈扫描和帧链此前几乎打不出东西，因为 arm64e 的返回地址带 PAC 签名，`module_for` 认不出来。新增 `aia_real_ptr`：先用 48 位掩码，不成就取低 32 位配上 `0x1`–`0x3` 的高位段逐个试，命中即采用。修好后主线程的故障现场第一次能看到完整调用链。
- 新增 `AIA_TRACE_IJM_VM` 开关，观察主二进制解释器 `KYHAppStore+0x7c56b8` 的每次调用与返回结果。实测装上去之后一次都没被调用，说明绑定器慢路径在槽被占用时根本不会走到那里。
- 实测结果：连续 10 轮切遍 5 个 tab（50 次点击）加 10 次滚动全部通过，主线程异常 0 次；前台后台往返与长时间静置同样稳定。启动期仍有 3 次 JM 自己的线程在 VM 里跳飞后被挂起，但不再影响 App 使用。**检测本身仍未真正通过**，仍是"接住"而非"通过"。

## 0.0.5

- **摸清了触摸"失效"的两种情形**。之前反复误判，是因为把两件事混成了一件：一是屏幕熄灭，simtouch 的注入依赖 backboardd 在亮屏下处理 HID 事件，屏幕一黑就发不出去；二是主线程真的被挂起。可靠的判别方法是打开 `AIA_EVENT_PROBE` 看 `touch` 计数是否还在增长，光看截图和 `ps` 会得出错误结论。
- 用事件探针实测确认了一个重要事实：主线程被挂起时，`evt`/`touch` 计数停止增长，说明故障发生在事件送入 App 之后、视图处理之前。
- 新增 `AIA_EXC_UNWIND_JM`（默认关闭）并在异常现场打印 `UNWINDJM`。实测展开的第一帧返回地址仍然是 `JM+0x186634`，整条调用链都在 JM 内部，退回一层只是换一条 JM 内的返回路径，随后照样跳飞，因此不能作为默认配置。
- 新增 `VMSLOT` 转储（`x0` 指向 VM 游标槽时打印 `[sp+0x110]`、`[sp+0x740..0x750]`）和 `RESV` 转储（绑定器共享解析器槽随时间的变化），用来判断 VM 上下文结构地址和绑定器状态。
- 记录 `RESV` 探针的关键发现：解析器槽在 ctor 阶段是 0，运行期会被 dyld 填成 `KYHAppStore+0x2a5dc`。
- 记录一次完整崩溃序列：`brk #0xdead` → 推进 4 字节 → `KYHAppStore+0x7cd0f0` 读 `0x8` → `SIGBUS` 退出；另一条路径是主线程在交叉现场跳飞后被挂起。两者同源。

## 0.0.4

- **修复异常回复消息的长度**。`exc_reply_t` 的线上头部是 `Head(24) + NDR(8) + RetCode(4) + new_stateCnt(4) = 40` 字节，旧代码写成 `8+8+4+4 = 24`，少发 16 字节，内核拒收我们的回复，`brk` 随即以 `SIGTRAP` 重新投递到同一个 PC。所有回复分支统一改用 `EXC_REPLY_HDR_SIZE`。
- 在信号层补上 `brk` 的 `SIGTRAP` 处理。Darwin 在把 `EXC_BREAKPOINT` 交给 Mach 异常端口之后仍会补发一次 `SIGTRAP`，只靠 Mach 回复推进 PC 挡不住这条路。
- **查清主线程跳飞的精确成因**：`JMCodeProtectKit` 的 ijm 解释器（`JM+0x11ee28`，分派表 `JM+0x11ee78`，密钥 `0xff`）拿到的是主二进制 `KYHAppStore` 的 ijm 描述符 `0x7c5500`，于是游标算成 `0x7c5504`，解出 `opcode 0xa2`。JM 的分派表只有 107 项，越界后把后面的代码字节当表项，算出未映射地址 `0x…9258` 直接跳过去。`x10` 与 `ldrsw` 的验算逐位吻合。
- 记录绑定器慢路径本来就不成立：`0x7c5600` 把 `0x7c5500` 当脚本解释，密钥 0 和 `0xff` 下都会解出越界 opcode。全二进制里只有绑定器自己引用这个地址，也没有任何跳转进入 `0x7c5508`。
- 记录三条失败路线：绕过 `brk` 必然在 `0x7c564c` 空指针崩溃；把绑定器顶成返回 nil 会让调用方解引用空值；改 `__TEXT` 里的元数据会让同页失去执行权限。
- 新增 `AIA_EXC_RECOVER_FAULT` / `AIA_EXC_UNWIND_JM` / `AIA_HOOK_IJM_BINDER` 三个实验开关（默认全部关闭），并在分析记录里写明各自的实测结果。
- 异常现场新增 `VMSLOT` 转储：当 `x0` 指向 VM 的游标槽时，打出 `[sp+0x110]`、`[sp+0x6b8]`、`[sp+0x740..0x750]` 等关键槽位，用来判断 VM 的上下文结构地址。
- 已知未解决：App 交互若干次后主线程仍会在上述交叉现场跳飞并被挂起，界面失去触摸。重启 App 可恢复。`AIA_KILL_DT_SWIZZLE=1` 能消掉故障，但会让 App 完全不响应触摸，不能作为默认配置。

## 0.0.3

- **修复"运行几分钟后触摸失效"**。查清了完整机制：App 自己的 `sendEvent:` 埋点会调用 ijm 保护的方法 `requstQueryTaskStateInfo`，绑定失败后走到 `KYHAppStore+0x7c55f8` 的 `brk #0xdead`。这次 `brk` 发生在主线程上，旧版"收到异常一律不回复"的策略把主线程永久挂起。动画由 render server 独立合成，所以界面看起来还在动，只是没人处理触摸。
- 新增 `AIA_EXC_SKIP_BRK`（默认开启）：断点类异常回复"PC 前进 4 字节"，线程继续执行而不是被挂起；处决跳转那类异常仍然不回复。
- 修正在 `AIA_EXC_NO_REPLY=0` 时把 `pc=0x8` 原样回复给内核的问题。那会让线程反复重跑同一条非法指令，进程随即被杀。
- 新增 `AIA_EVENT_PROBE`（默认关闭）：hook `sendEvent:` 统计事件数量。实测这层 hook 会改变 swizzle 链、让主线程更早撞上 `brk`，所以只在排查时打开。
- 新增每 5 秒一次的资源统计（异常数、事件数、线程数、端口数、主线程 PC），用来区分"资源耗尽"和"主线程被挂起"两种可能。
- 分析记录补充 `simtouch` 的坐标约定：`tap`/`swipe` 的参数是物理像素，不是逻辑点。

## 0.0.2

- 改用 **Mach 异常端口接管** 实现启动：捕获 JM 处决线程的非法跳转后不回复，触发处决的线程永久停在异常状态，进程不再被自杀。
- 修正异常消息解析。`EXCEPTION_STATE_IDENTITY` 下的消息线上 port descriptor 是 12 字节而非结构体的 16 字节，按显式字节偏移读取才正确。
- 确认处决手法：破坏对象 `isa` 后发 Objective-C 消息，`pc=lr=0x8`、`x0=0x4`、`x1=+[NSThread isMainThread]`、`x8=x9=8`。
- 异常端口看门狗常驻运行（原先 200 秒后停止，正是"几分钟后失效"的原因之一）。
- 新增诊断开关：`AIA_DUMP_ON_SIGNAL`（SIGUSR1 转储全部线程、SIGUSR2 转储窗口层级与 hitTest）。
- 排除四条路径：`dladdr` 伪装、dyld 枚举伪造、`thread_terminate`、UI 层拦截。
- **已知问题**：能进入首页，但运行几分钟后触摸事件失效。进程存活、CPU 归零、动画照常渲染、窗口层级与 hitTest 正常。

## 0.0.1

- 首个版本，**尚未解决**。目标是友邦友享（`com.aia.china.YoubangHealthRelease`）在 rootless 越狱设备上打开即闪退的问题。
- 已确认闪退来自 App 内置的 `JMCodeProtectKit.framework` RASP，不是普通越狱判定。
- 已排除：镜像路径检测、多装载一个 tweak 触发、`brk #0xdead` 陷阱桩。
- 已确认检测对象是越狱注入基座（`systemhook.dylib`、`libinjector.dylib`、`libellekit.dylib`），移除所有 tweak 后仍然闪退。
