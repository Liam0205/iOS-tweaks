# llmdoc 索引

本目录保存 DEV-iOS 项目的稳定文档，按”启动必读、项目概览、架构、参考、操作指南”组织，便于在后续分析、构建、回归测试和适配新版本时快速定位信息。

## 启动入口

- `llmdoc/startup.md`：新会话启动时的阅读顺序，只列出建议优先阅读的文档。

## overview/

- `llmdoc/overview/project-overview.md`：项目目标（多 tweak 仓库 + 设备端开发工具）、目标环境、当前工作状态、软件源与 CI/CD 架构。

## architecture/

- `llmdoc/architecture/tweak-architecture.md`：mybankbypass 的核心执行模型、Hook 分层、业务层 launcher 中和与关键实现约束。
- `llmdoc/architecture/icbc-architecture.md`：icbcbypass 的架构——fishhook + Logos 组合、三层防御对抗（检测+冻结+弹窗退出）、CALayer 速率限制策略、解冻定时器永久运行与降频机制、已知性能考量、与 mybankbypass 的关键差异。
- `llmdoc/architecture/abc-architecture.md`：abcbypass 的架构（2026-08-21 重写为最终方案）——**核心=纯 ObjC swizzle `-[DTFrameworkInterface initRiskManage]` 为空实现**，从源头消除检测退出 block；极简 `%ctor`（7 个 ObjC swizzle + 5 个 Logos hook，无 C 函数 hook）；核心约束「禁一切 C 函数 inline-hook/fishhook/__text patch/Frida，只用 ObjC swizzle」（ABC 有内存完整性自检，libc inline-hook 触发 `0xb5a06000` 崩溃）；已验证 11.1.0/iOS15.4.1 + 11.2.0/iOS16.3.1；版本适配检查顺序与历史教训。
- `llmdoc/architecture/bmwbypass-architecture.md`：bmwbypass 的架构——核心=inline-hook（MSHookFunction）开源 IOSSecuritySuite 全部 8 个 `()->Bool` 顶层检测入口恒返回 false；靠 Swift mangled 符号定位跨版本通用；ISS 无内存完整性自检故 inline-hook 安全（与农行/汇丰根本区别）；纯 `%ctor` + 函数指针表无 Logos/swizzle；构建需 `libtinfo.so.5`；SimTouch 截图验证；Approov 远程 attestation 遗留。
- `llmdoc/architecture/lianjiabypass-architecture.md`：lianjiabypass 的架构——链家/贝壳找房共用同一检测栈（JGBSDK/du/a/senseid）、四层对抗（文件检测 fishhook + dyld 镜像枚举作用域限定与 vis-map 缓存 + a.framework 注入检测 MSHookFunction + JGBSDK 内联 svc exit 运行时 __text patch）、W^X 权限流程教训、与 abcbypass 的关键差异。
- `llmdoc/architecture/cctvbypass-architecture.md`：cctvbypass 的架构——核心=运行时 `__text` patch 把主二进制内 2 处内联 `svc #0x80` 退出桩（偏移 0x51b4/0x5220，在 FairPlay 加密页之外）改成 nop，这是闪退唯一有效修复；W^X 权限流程（vm_protect RW→改→恢复 R+X→刷 icache）同 lianjiabypass；辅助防御纵深（越狱 selector 中和、路径型 C 函数 hook、P_TRACED 清除、终止拦截兜底）非闪退必需；两条固化约束（不 hook dyld 镜像枚举避免 O(N²) 冻结、不 hook statfs/statvfs 避免波及 App 自身容器）；与 lianjiabypass（内联 svc 手法同源）、bmwbypass 的差异。
- `llmdoc/architecture/aiabypass-architecture.md`：aiabypass 的架构（v1.0.0）——**唯一一个「判定没绕过、只把后果接住」的 tweak**：接管 Mach 异常端口让 JM 的处决打不动进程（处决跳转不回复、`brk` 推进 4 字节 + 信号层补跳 `SIGTRAP`）、清零主二进制 ijm 解析器槽消除主线程跳飞、发布版默认关闭日志与统计线程；三条固化约束（改编译开关必须 `make clean` 否则产物缺 `__DATA` 段、不能用 `dlsym` 取原始地址、正式版不开高频探针）；与 icbcbypass/bmwbypass 的定位差异。
- `llmdoc/architecture/whbypass-architecture.md`：whbypass 的架构（v1.0.0）——目标 App 的检测引擎是**梆梆安全 Everisk**（静态链入主二进制，27 个 checker 在 467ms 之后才调度）；闪退根因是主程序里 **6 个"炸弹函数"**（`+0x148470` 等）把 `sp`/`lr` 改成上下文值后 `br` 到 `0xb5a0X000`（落在 `__PAGEZERO` 保留区、无法映射），这些地址只被 6 处 `adrp`+`add` 写进 block 的 `invoke` 字段、由 `0x13f000`～`0x145000` 的混淆状态机投递给全局队列；根治手段=`WH_BOMB_RET` 把 6 个入口改成 `ret`（启动期异常 1→0 次），辅助=`WH_GUARD_RET` 掐掉 `+0x1406b0` 的 `getpid`+`ptrace` 守卫（关掉它 App 会在 45 秒内静默退出）；日志由 `DEBUG` 宏自动开关（`make package` 带日志、`make package FINALPACKAGE=1` 不带）；三条固化约束（不周期性重设异常端口、日志不写 `Documents`、镜像 0 不一定是主程序）。
- `llmdoc/architecture/sshtunnel-architecture.md`：SSHTunnel v1.3.2 架构——4 态状态机（Disconnected/Connecting/Connected/Reconnecting）、进程存活健康检查、指数退避自动重连、LaunchDaemon 开机持久化、sysctl 孤儿进程检测。
- `llmdoc/architecture/simtouch-architecture.md`：SimTouch 架构——双路径设计（HID 事件注入 for 常规触摸 + SpringBoard 私有 API for 系统手势）、_BKHandleIOHIDEventFromSender hook + 事件克隆注入、单次 IPC swipe 轨迹生成、gesture arbiter 投递路径限制、录制/回放引擎、Phase 3 新增自定义曲线/键盘输入/多指 pinch。

## reference/

- `llmdoc/reference/detection-vectors.md`：网商银行已知越狱检测向量、4.7.36 新增检测点、调试经验与当前覆盖情况。
- `llmdoc/reference/icbc-detection-vectors.md`：工商银行检测框架（SecureUtilityPlus）、冻结机制（持续 freeze 循环及版本间时序差异）、弹窗退出链路、版本适配记录（3.0.80、3.0.90）与覆盖情况。
- `llmdoc/reference/abc-detection-vectors.md`：农业银行三层检测架构（SecureUtilityPlus + SecurityGuard + SmAntiFraud）、SDK 识别为 mPaaS、SDK 识别与 exit 源头静态分析。**⚠️ 含 2026-08-21 第 15 轮重大更正**：可信基线（裸跑主 App ~13s 正常退出、全量 hook ~1s 崩溃）、`0xb5a06000` 崩溃根因 = libc 函数 inline-hook 被完整性自检发现、唯一安全手段为 ObjC swizzle；旧 v95"双通道杀死/覆盖成功"多为误判（存活检测匹配到扩展进程），已标注作废。
- `llmdoc/reference/bmwbypass-detection-vectors.md`：My BMW（`de.bmw.connected.mobile20.cn`）检测向量——Flutter 应用，检测 SDK=标准开源 IOSSecuritySuite（另有 Approov 远程 attestation + Dynatrace）；弹窗由 Dart 层 attestation pre-check 触发（文案 key `attestationPreCheckFailureDescriptionCn`），进程不自杀；运行时探针确认启动只调 `amIJailbroken`+`amIReverseEngineered`，**后者是弹窗根因**；8 个单-Bool 入口符号表与运行时调用情况；checkDYLD/`_dyld_get_image_name` mask 无效的记录；Approov 服务端校验遗留。
- `llmdoc/reference/lianjiabypass-detection-vectors.md`：链家/贝壳找房检测栈（JGBSDK 核心引擎 + du/senseid 指纹采集器 + a.framework 注入检测）、JGBSDK XxxCheck selector 与越狱特征字符串、DynamicLibraries 目录扫描、a.framework 主线程慢扫描机制、29 处内联 svc #0x80 退出点、anti-frida、当前覆盖状态（四层全覆盖，两 App 均验证）。
- `llmdoc/reference/cctvbypass-detection-vectors.md`：央视频（`com.cctv.yangshipin.app.iphone` / CCTVVideo 3.5.3）检测向量——闪退根因=主二进制内 2 处内联 svc exit 桩（非 ObjC 遥测，绕开全部具名符号、无崩溃报告）；越狱判定 ObjC getter 清单（VBInterfaceDeviceInfoImp/QTUtils/QTMobClick 友盟/GDTActionStatsMgr 广点通等，均遥测非门禁）；路径型文件检测清单；无商业 RASP、无二进制自检、无私有 svc 网关（integrity/HMAC 来自 Bugly/QAPM）；排查方法闭环（逐一 hook 终止原语全不触发 + 无崩溃报告 + 非外部 SIGKILL→字节扫描 svc#0x80 定位；frida hook strstr 定位 dyld 枚举冻结热点）；当前覆盖状态（闪退已解决，连续冷启动进首页）。
- `llmdoc/reference/aiabypass-detection-vectors.md`：友邦友享（`com.aia.china.YoubangHealthRelease` 6.9.33）检测向量——检测组件 JMCodeProtectKit（v3.0.0.20260903.1，ijm VM 混淆）、检测对象是越狱注入基座本身（移走全部 tweak 仍闪退）、处决手法（7ms 破坏 `isa` 发消息 `pc=lr=0x8`、12ms `SIGUSR1` `pc=lr=0xeee1`，均不走 `kill`/`raise`/`pthread_kill`）、完整性校验结构（`JM+0x14fc40`，0x48 字节节描述，50 次 = 25 镜像 × 2 节）、systemhook 改写的 7 个 GOT 槽及对应符号（已实测还原后处决次数不变，非触发点）、已排除向量清单、时间窗结论（判定早于任何 tweak 代码）。
- `llmdoc/reference/whbypass-detection-vectors.md`：国家网络身份认证（`cn.cyberIdentity.certification` / WHClient 1.2.38）检测向量——Bangcle Everisk（`everisk_ZDAX iOS5.1.2.SP2-250207`）+ 27 个 checker 与其可读名、`SecureUtilityPlus` 在本 App 里零方法、6 个炸弹函数的偏移/跳向/构造点清单与毒地址 `0xb5a0X000` 的生成方式（`mov`+`movk` 拼两个立即数相加）、反调试守卫 `+0x1406b0` 的指令级清单与"计数自增会被观察"的实测、KSCrash 的 `thread_suspend` 调用点、已排除手法。
- `llmdoc/reference/simtouch-technical-decisions.md`：SimTouch 技术决策——Phase 1（_UICreateScreenUIImage、JPEG 压缩、CIImage redraw、CLI CoreFoundation）+ Phase 2（事件克隆 vs 从零创建、hook 选型、Darwin notification IPC 复用、backboardd 沙箱录制路径、单次 IPC swipe 消除合并竞态、gesture arbiter 投递路径限制迫使系统手势走 SpringBoard API、edge mask 诊断用途）+ Phase 3（从零创建多指事件、cubic-bezier、HID keyboard、killall backboardd）。
- `llmdoc/reference/hsbc-china-detection-vectors.md`：汇丰中国（`cn.com.hsbc.hsbcchina` 3.72.15）检测向量——SDK 识别为 **Promon SHIELD**（更正早期 OneSpan/ThreatMetrix 误判）、私有 svc 网关机制（全局槽跳板绕开 libSystem 具名符号致符号级 hook 全失效）、init[42] CFF 状态机 verdict、`mach_vm_read_overwrite` 读库头识别注入库（`systemhook.dylib`）、已排除向量清单；**Round 77 用 Unject 证伪 systemhook-only 假设（彻底不注入仍闪退且更快）→ 确认用户态存在二律背反、必须走内核层**。

## guides/

- `llmdoc/guides/build-deploy.md`：本地构建、Linux 交叉编译、部署到设备、反向隧道工作流、部署后验证、各 tweak 回归关注点。
- `llmdoc/guides/ci-cd-release.md`：发版 tag 规则、CI Release/Build workflow、gh-pages 部署流程、macOS CI 缺私有 framework stub 的两种修复路径、CI 矩阵 fail-fast 配置、Logos 跨平台注意事项、发版检查清单；**批量发多个 tweak 的三坑**（多 tag 一次 push 不触发 workflow→逐个推、concurrency 取消兄弟 run→逐个 rerun、`actions/cache@v5` 偶发失败→重跑不改配置）、CDN 缓存致刚发版短暂显示旧版本。
- `llmdoc/guides/reverse-engineering-methodology.md`：逆向分析与反检测对抗的实验方法论、诊断顺序与 analysis.md 记录纪律。含（2026-08-21 补充）进程存活监控必须排除 App Extension（`.appex`）避免误判、「先排除自伤再谈检测」（裸跑对照 + 二分开关 + 固定哨兵地址崩溃识别）、有完整性自检的目标只用 ObjC swizzle。

## memory/reflections/

- `llmdoc/memory/reflections/bmwbypass-round0-4.md`：BMWBypass 第 0-4 轮反思（2026-08-24，一次会话解决）——先静态识别 SDK 身份（Frameworks 直接看到 IOSSecuritySuite）、运行时探针定位根因（凭「checkDYLD 检测库名」的合理推断 hook `_dyld_get_image_name` 失败，改全 hook 单-Bool 入口 + 记日志一轮定位到 `amIReverseEngineered`）、SimTouch 截图闭环验证、弹窗文案 arb key 反查检测语义；踩坑：日志路径（`/tmp` 被沙箱重定向读不到，一律写 App 数据容器）、只 hook 最明显入口不够、包名前缀 `page.0x01`；与农行/汇丰「只能 swizzle」的区别。
- `llmdoc/memory/reflections/hsbc-methodology-lesson.md`：HSBC 早期分析方法论反思（10+ 轮），结论已被 `hsbc-china-promon-poc` 更正（SDK 身份 OneSpan→Promon SHIELD），仅存档参考。
- `llmdoc/memory/reflections/hsbc-china-promon-poc.md`：汇丰中国 Promon SHIELD 检测定位与绕过 PoC 反思（第 55-76 轮）——追错函数 8 轮的教训（`0x75bf7c` 实测与退出无关）、SDK 身份更正为 Promon SHIELD、私有 svc 网关机制与 `mach_vm_read_overwrite` 读库头识别 `systemhook.dylib` 的完整检测链路、多 SDK 并存误判排除过程、用户态干预效果（3s→17s，未达净启动）。
- `llmdoc/memory/reflections/hsbc-china-unject-round77.md`：汇丰中国 Round 77 —— **Unject 实验证伪 systemhook-only 假设**（决定性负面结果）。用定制 Dopamine 的 Unject（commit `980bf0f`，按可执行名黑名单只授信不注入）彻底不注入 systemhook 到汇丰，结果仍闪退且比 3s 更快 → Promon 有独立于注入库的环境层检测；用户态二律背反（不注入=无法干预，注入=被检测）故纯用户态走不通，唯一自洽方向是内核层。教训：plist 改后必须 ubreboot 才生效、缺内存工具时用行为可见的 tweak（微信登录页按钮条）作"是否注入"判据、移除单一向量前先想是否暴露更深检测或废掉自己的干预手段。
- `llmdoc/memory/reflections/hsbc-china-roothide-eval.md`：汇丰中国 —— 评估 **roothide Dopamine** 作为内核隐藏参考实现，并在"不能动越狱本体"约束下判定汇丰**可行域为空**。roothide 四支柱（随机 jbroot 路径 / 内核改写 `all_image_info` 让 App 枚举不到注入库 / dyld 入口 hook / per-app 黑名单不注入但隐藏）全部落地在越狱本体；因不能动本体，方案 A（换 roothide）B（移植）C（自研内核隐藏）卡在同一禁区，C 非难度问题而是无落脚点。核心教训：区分"正确的层"与"可动的层"、评估方案前先确认可动区边界、负面结论要写清是"难度"还是"可行域"。与我们越狱同源（皆 Dopamine fork）故放宽约束时 B 比 C 现实。
- `llmdoc/memory/reflections/icbcbypass-v1.0.0-release.md`：icbcbypass v1.0.0 发布反思——嵌套 RunLoop 死锁教训、fishhook 替代 MSHookFunction 约束、semaphore 区分策略。
- `llmdoc/memory/reflections/icbc-3090-adaptation.md`：ICBC 3.0.90 适配反思——全局阻断框架方法的隐性退化、速率限制优于时间门控、sched_yield 缓解忙循环。
- `llmdoc/memory/reflections/anti-detection-deep-analysis.md`：MSHookFunction 风险决策、inline SVC 对抗哲学、fishhook 被禁极端场景分析、发版配置教训。
- `llmdoc/memory/reflections/linux-cross-compile-setup.md`：Linux 无 sudo 环境搭建 Theos 交叉编译的完整踩坑记录。
- `llmdoc/memory/reflections/deploy-via-reverse-tunnel.md`：反向隧道部署踩坑——端口号/用户名缺失导致试错、root vs mobile 约束、SSHTunnel 自举问题。
- `llmdoc/memory/reflections/sshtunnel-autossh-development.md`：SSHTunnel 1.1.1-1.2.1 开发周期——autossh 集成的两个关键 bug（PATH 不传播、process group 继承杀死子进程）、iOS posix_spawn 约束总结。
- `llmdoc/memory/reflections/abcbypass-round1-9.md`：ABCBypass v1-v81（9 轮迭代）——MSHookFunction 内存扫描触发、inline SVC 不可拦截、_Noreturn 栈切换、dispatch queue 损坏绕过、巡逻定时器策略演进。
- `llmdoc/memory/reflections/abcbypass-round10-12.md`：ABCBypass v86-v95（3 轮迭代）——exit 存活策略全灭（栈损坏/嵌套 RunLoop/longjmp 状态损坏）、CFRunLoop 定时器拦截、SDK 识别为 mPaaS、ctor 重排序消除文件检测、发现第二检测路径（hook 完整性 + GCD dispatch_after）。⚠️ 存活类结论受"grep 匹配到扩展进程"方法论错误影响，见 round13-16 更正。
- `llmdoc/memory/reflections/abcbypass-round13-16.md`：ABCBypass 第13-16轮（2026-08-21）——**✅ 最终成功并收尾**。纠正致命方法论错误（`grep MbapMPaaS` 误匹配扩展进程 `group.abc.toolExtension`，导致大批存活结论失效）；二分定位 `0xb5a06000` 崩溃根因=libc inline-hook 触发完整性自检（自伤而非 ABC 检测）；最终方案=swizzle `-[DTFrameworkInterface initRiskManage]` 从源头消除 native exit，纯 ObjC swizzle 不触发校验。收尾：死代码清理 1660→483 行、跨版本/跨设备验证（11.1.0/iOS15.4.1 + 11.2.0/iOS16.3.1）、长时间运行稳定。含可推广教训（先验证测量工具、裸跑对照区分自伤、有完整性自检的App只用ObjC swizzle）。
- `llmdoc/memory/reflections/sshtunnel-v132-release.md`：SSHTunnel v1.3.2 发布反思——TCP 探测在 iOS sandbox 下不可用、sysctl(KERN_PROCARGS2) 替代 ps|grep、SSH 自愈参数组合消除外部健康检查需求、文档滞后复发。
- `llmdoc/memory/reflections/simtouch-phase2-development.md`：SimTouch Phase 2 (v1-v24) 开发反思——事件克隆优于从零创建、Darwin notification 新通道不可靠、backboardd 沙箱写入限制、录制分析方法论、回放无效待查。
- `llmdoc/memory/reflections/simtouch-phase3-development.md`：SimTouch Phase 3 (v25-v36) 开发反思——pinch 从零创建 vs 克隆的条件性规则、sbreload 不重启 backboardd 部署陷阱、DIAG_NOTIFY 诊断通知从未工作。
- `llmdoc/memory/reflections/aiabypass-v1.0.0-release.md`：aiabypass v1.0.0 发布反思（2026-10-26）——**判定没绕过、只接住后果的收尾**；三次假象（增量构建缺 `__DATA` 段导致构造函数都没跑、诊断工具查表函数在快照前一律返回 NULL 造成"零 hook 命中 0 条"、hook 装上但没被调用与没装上长得一样）；两种"数据对、假设错"的还原实验；核心教训=时间窗比手段重要（三种不同原理的手段全部无效且无效方式一致时该怀疑时间窗，用相对构造函数的时间戳确认）、负面结论要带数字才有复用价值。
- `llmdoc/memory/reflections/whbypass-first-round.md`：whbypass 排查反思（2026-10-27）——四类假象（grep 计数口径不一致得出"改 SDK 内部触发自检"的错误结论、每 250ms 重设异常端口造出"每 6.1 秒一次跳飞"的假律、把 KSCrash 捕获异常当成检测 SDK 冻结、先试停放页而不是先想毒地址怎么生成）；四类有效做法（先做单变量对照再谈机制、用最小破坏性补丁确认元凶再读混淆代码、先做运行时/磁盘字节比对再谈"代码被改写"、用"谁引用了这个地址"定位发起方）。
- `llmdoc/memory/reflections/lianjiabypass-release-and-ci-hardening.md`：lianjiabypass 发布与 CI/CD 加固反思——发布版本混入诊断脚手架的清理教训、macOS CI 缺私有 framework stub 是 simtouch 从未发布成功的根因、两种修复路径（objc_getClass 运行时解耦 vs SYSROOT 强制指定 SDK）、CI 矩阵 fail-fast 掩盖独立结果、Logos %orig 跨平台展开差异、发版验证需直接核对 gh-pages。
