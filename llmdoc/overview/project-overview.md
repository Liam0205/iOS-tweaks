# 项目概览

## 项目是什么

MYBankBypass 是一个基于 Theos 的 iOS 越狱检测绕过 tweak，目标 App 为网商银行 `com.mybank.ios.phone`，当前已知适配版本为 `4.6.4` 与 `4.7.36`。项目的主要目的，是让目标 App 在已越狱设备上正常启动并保持可用，而不是做通用 Hook 框架或多 App 兼容产品。

## 目标环境

- 目标 App：网商银行 `com.mybank.ios.phone`
- 已验证 App 版本：`4.6.4`、`4.7.36`
- 主进程：`Portal`
- 测试设备：iPhone 14 Pro Max
- 系统版本：iOS `16.3.1`
- 越狱环境：Dopamine（rootless）
- 包管理器：Sileo
- 设备 SSH：`root@192.168.1.253`
- 构建体系：Theos（`~/theos`），`rootless` 打包方案，`arm64`

## 当前状态

项目当前状态是“已工作并已验证”的 Theos rootless tweak：

- tweak 包名：`com.liam.mybankbypass`
- tweak 当前版本：`1.1.0`
- 已确认能绕过网商银行 `4.6.4` 与 `4.7.36` 的越狱检测
- 关键经验已收敛到当前 `mybankbypass/Tweak.x`

与早期调查阶段不同，当前文档应以“已验证的工作方案”为主，而不是把项目描述成未确认原型。

## 项目边界

本项目文档聚焦以下内容：

- 网商银行当前版本的本地越狱检测绕过方案
- rootless Dopamine 设备上的构建、部署与验证流程
- 当前已知检测向量与 `mybankbypass/Tweak.x` 的对应实现
- 会影响稳定性的实现约束与回归风险

本项目文档不负责：

- 记录临时调查过程或未收敛实验结论
- 维护通用逆向工程教程
- 扩展到其他银行 App 的兼容性说明

临时发现应保留在 `.llmdoc-tmp/investigations/`，只有已经稳定、可复用、能指导后续工作的知识才进入 llmdoc。

## 当前稳定结论

- 目标 App 使用阿里系 SecurityGuard SDK 作为核心安全框架之一。
- 仅拦截单一文件 API 不足以绕过，需要同时覆盖文件、URL scheme、动态库枚举、环境变量、进程/调试检测以及退出链路。
- rootless 环境必须把 `/var/jb` 及相关派生路径视为一等检测面。
- `4.7.36` 的关键新增适配点是 `MYBLauncherController.checkJailbroken`；业务层 launcher 在命中越狱检测后会继续走 exit 链路。
- 已验证的稳定实现依赖三个关键修正：
  1. C 层 Hook 内部必须使用纯 C 字符串匹配，避免在低层 Hook 中引入 ObjC 调用。
  2. 目录枚举相关策略不能通过 `opendir` 粗暴拦截；此前该做法会触发 watchdog 或异常行为，当前方案改为保留 `NSFileManager` 目录结果过滤并移除 `opendir` Hook。
  3. `exit()` / `_exit()` / `abort()` 这类 `noreturn` 终止函数不能“拦截后返回”；当前稳定方案是在主线程保持 RunLoop、非主线程永久阻塞，确保行为满足 `noreturn` 语义。
- `4.7.36` 的新增经验是：若出现“App 不退出但业务冻结”，优先检查 launcher/controller 级别的 jailbreak check，而不是先怀疑 RPC 层。

## 代码入口

- `mybankbypass/Tweak.x`：所有 Hook 与初始化逻辑的主入口
- `mybankbypass/Makefile`：Theos 构建、架构、设备与 rootless 配置
- `mybankbypass/control`：Debian 包元数据与依赖声明
- `mybankbypass/MYBankBypass.plist`：注入过滤，限定到 `com.mybank.ios.phone`
- `ANALYSIS.md`：早期技术分析，仍可作为补充证据，但不是最终稳定说明
