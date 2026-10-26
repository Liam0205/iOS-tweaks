# AIABypass 更新日志

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
