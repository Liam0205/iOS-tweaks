# AIABypass 更新日志

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
