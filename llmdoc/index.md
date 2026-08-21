# llmdoc 索引

本目录保存 DEV-iOS 项目的稳定文档，按”启动必读、项目概览、架构、参考、操作指南”组织，便于在后续分析、构建、回归测试和适配新版本时快速定位信息。

## 启动入口

- `llmdoc/startup.md`：新会话启动时的阅读顺序，只列出建议优先阅读的文档。

## overview/

- `llmdoc/overview/project-overview.md`：项目目标（多 tweak 仓库 + 设备端开发工具）、目标环境、当前工作状态、软件源与 CI/CD 架构。

## architecture/

- `llmdoc/architecture/tweak-architecture.md`：mybankbypass 的核心执行模型、Hook 分层、业务层 launcher 中和与关键实现约束。
- `llmdoc/architecture/icbc-architecture.md`：icbcbypass 的架构——fishhook + Logos 组合、三层防御对抗（检测+冻结+弹窗退出）、CALayer 速率限制策略、解冻定时器永久运行与降频机制、已知性能考量、与 mybankbypass 的关键差异。
- `llmdoc/architecture/abc-architecture.md`：abcbypass 的架构——四阶段 ctor 加载（fishhooks-first 顺序）、MSHookFunction + fishhook 混合策略、CFRunLoopAddTimer 定时器拦截、CFRunLoopRunSpecific longjmp 备用恢复、ARM64 栈切换退出生存、双通道杀死对抗（CFRunLoop timer + GCD dispatch_after）、与 icbcbypass 的关键差异。
- `llmdoc/architecture/lianjiabypass-architecture.md`：lianjiabypass 的架构——链家/贝壳找房共用同一检测栈（JGBSDK/du/a/senseid）、四层对抗（文件检测 fishhook + dyld 镜像枚举作用域限定与 vis-map 缓存 + a.framework 注入检测 MSHookFunction + JGBSDK 内联 svc exit 运行时 __text patch）、W^X 权限流程教训、与 abcbypass 的关键差异。
- `llmdoc/architecture/sshtunnel-architecture.md`：SSHTunnel v1.3.2 架构——4 态状态机（Disconnected/Connecting/Connected/Reconnecting）、进程存活健康检查、指数退避自动重连、LaunchDaemon 开机持久化、sysctl 孤儿进程检测。
- `llmdoc/architecture/simtouch-architecture.md`：SimTouch 架构——双路径设计（HID 事件注入 for 常规触摸 + SpringBoard 私有 API for 系统手势）、_BKHandleIOHIDEventFromSender hook + 事件克隆注入、单次 IPC swipe 轨迹生成、gesture arbiter 投递路径限制、录制/回放引擎、Phase 3 新增自定义曲线/键盘输入/多指 pinch。

## reference/

- `llmdoc/reference/detection-vectors.md`：网商银行已知越狱检测向量、4.7.36 新增检测点、调试经验与当前覆盖情况。
- `llmdoc/reference/icbc-detection-vectors.md`：工商银行检测框架（SecureUtilityPlus）、冻结机制（持续 freeze 循环及版本间时序差异）、弹窗退出链路、版本适配记录（3.0.80、3.0.90）与覆盖情况。
- `llmdoc/reference/abc-detection-vectors.md`：农业银行三层检测架构（SecureUtilityPlus + SecurityGuard + SmAntiFraud）、SDK 识别为 mPaaS、SDK 识别与 exit 源头静态分析。**⚠️ 含 2026-08-21 第 15 轮重大更正**：可信基线（裸跑主 App ~13s 正常退出、全量 hook ~1s 崩溃）、`0xb5a06000` 崩溃根因 = libc 函数 inline-hook 被完整性自检发现、唯一安全手段为 ObjC swizzle；旧 v95"双通道杀死/覆盖成功"多为误判（存活检测匹配到扩展进程），已标注作废。
- `llmdoc/reference/lianjiabypass-detection-vectors.md`：链家/贝壳找房检测栈（JGBSDK 核心引擎 + du/senseid 指纹采集器 + a.framework 注入检测）、JGBSDK XxxCheck selector 与越狱特征字符串、DynamicLibraries 目录扫描、a.framework 主线程慢扫描机制、29 处内联 svc #0x80 退出点、anti-frida、当前覆盖状态（四层全覆盖，两 App 均验证）。
- `llmdoc/reference/simtouch-technical-decisions.md`：SimTouch 技术决策——Phase 1（_UICreateScreenUIImage、JPEG 压缩、CIImage redraw、CLI CoreFoundation）+ Phase 2（事件克隆 vs 从零创建、hook 选型、Darwin notification IPC 复用、backboardd 沙箱录制路径、单次 IPC swipe 消除合并竞态、gesture arbiter 投递路径限制迫使系统手势走 SpringBoard API、edge mask 诊断用途）+ Phase 3（从零创建多指事件、cubic-bezier、HID keyboard、killall backboardd）。

## guides/

- `llmdoc/guides/build-deploy.md`：本地构建、Linux 交叉编译、部署到设备、反向隧道工作流、部署后验证、各 tweak 回归关注点。
- `llmdoc/guides/ci-cd-release.md`：发版 tag 规则、CI Release/Build workflow、gh-pages 部署流程、macOS CI 缺私有 framework stub 的两种修复路径、CI 矩阵 fail-fast 配置、Logos 跨平台注意事项、发版检查清单。
- `llmdoc/guides/reverse-engineering-methodology.md`：逆向分析与反检测对抗的实验方法论、诊断顺序与 analysis.md 记录纪律。

## memory/reflections/

- `llmdoc/memory/reflections/hsbc-methodology-lesson.md`：HSBC 分析经验反思。
- `llmdoc/memory/reflections/icbcbypass-v1.0.0-release.md`：icbcbypass v1.0.0 发布反思——嵌套 RunLoop 死锁教训、fishhook 替代 MSHookFunction 约束、semaphore 区分策略。
- `llmdoc/memory/reflections/icbc-3090-adaptation.md`：ICBC 3.0.90 适配反思——全局阻断框架方法的隐性退化、速率限制优于时间门控、sched_yield 缓解忙循环。
- `llmdoc/memory/reflections/anti-detection-deep-analysis.md`：MSHookFunction 风险决策、inline SVC 对抗哲学、fishhook 被禁极端场景分析、发版配置教训。
- `llmdoc/memory/reflections/linux-cross-compile-setup.md`：Linux 无 sudo 环境搭建 Theos 交叉编译的完整踩坑记录。
- `llmdoc/memory/reflections/deploy-via-reverse-tunnel.md`：反向隧道部署踩坑——端口号/用户名缺失导致试错、root vs mobile 约束、SSHTunnel 自举问题。
- `llmdoc/memory/reflections/sshtunnel-autossh-development.md`：SSHTunnel 1.1.1-1.2.1 开发周期——autossh 集成的两个关键 bug（PATH 不传播、process group 继承杀死子进程）、iOS posix_spawn 约束总结。
- `llmdoc/memory/reflections/abcbypass-round1-9.md`：ABCBypass v1-v81（9 轮迭代）——MSHookFunction 内存扫描触发、inline SVC 不可拦截、_Noreturn 栈切换、dispatch queue 损坏绕过、巡逻定时器策略演进。
- `llmdoc/memory/reflections/abcbypass-round10-12.md`：ABCBypass v86-v95（3 轮迭代）——exit 存活策略全灭（栈损坏/嵌套 RunLoop/longjmp 状态损坏）、CFRunLoop 定时器拦截、SDK 识别为 mPaaS、ctor 重排序消除文件检测、发现第二检测路径（hook 完整性 + GCD dispatch_after）。⚠️ 存活类结论受"grep 匹配到扩展进程"方法论错误影响，见 round13-16 更正。
- `llmdoc/memory/reflections/abcbypass-round13-16.md`：ABCBypass 第13-16轮（2026-08-21）——**✅ 最终成功**。纠正致命方法论错误（`grep MbapMPaaS` 误匹配扩展进程 `group.abc.toolExtension`，导致大批存活结论失效）；二分定位 `0xb5a06000` 崩溃根因=libc inline-hook 触发完整性自检（自伤而非 ABC 检测）；最终方案=swizzle `-[DTFrameworkInterface initRiskManage]` 从源头消除 native exit，纯 ObjC swizzle 不触发校验，实测进入首页且交互正常。含可推广教训（先验证测量工具、裸跑对照区分自伤、有完整性自检的App只用ObjC swizzle）。
- `llmdoc/memory/reflections/sshtunnel-v132-release.md`：SSHTunnel v1.3.2 发布反思——TCP 探测在 iOS sandbox 下不可用、sysctl(KERN_PROCARGS2) 替代 ps|grep、SSH 自愈参数组合消除外部健康检查需求、文档滞后复发。
- `llmdoc/memory/reflections/simtouch-phase2-development.md`：SimTouch Phase 2 (v1-v24) 开发反思——事件克隆优于从零创建、Darwin notification 新通道不可靠、backboardd 沙箱写入限制、录制分析方法论、回放无效待查。
- `llmdoc/memory/reflections/simtouch-phase3-development.md`：SimTouch Phase 3 (v25-v36) 开发反思——pinch 从零创建 vs 克隆的条件性规则、sbreload 不重启 backboardd 部署陷阱、DIAG_NOTIFY 诊断通知从未工作。
- `llmdoc/memory/reflections/lianjiabypass-release-and-ci-hardening.md`：lianjiabypass 发布与 CI/CD 加固反思——发布版本混入诊断脚手架的清理教训、macOS CI 缺私有 framework stub 是 simtouch 从未发布成功的根因、两种修复路径（objc_getClass 运行时解耦 vs SYSROOT 强制指定 SDK）、CI 矩阵 fail-fast 掩盖独立结果、Logos %orig 跨平台展开差异、发版验证需直接核对 gh-pages。
