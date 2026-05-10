# 项目概览

## 项目是什么

DEV-iOS 是一个基于 Theos 的 iOS 越狱项目仓库，主体是多个银行 App 的越狱检测绕过 tweak，同时包含设备端开发辅助工具。所有 tweak 面向 rootless 越狱环境（Dopamine / palera1n），通过 Sileo 软件源 `https://tweaks.0x01.page/` 分发。

## 包含的 Tweaks

| 包名 | 目标 App | Bundle ID | 支持版本 |
|------|----------|-----------|----------|
| `page.0x01.mybankbypass` | 网商银行 | `com.mybank.ios.phone` | 4.6.4 ~ 4.7.36 |
| `page.0x01.bankcommbypass` | 交通银行 | `com.bankcomm.Bankcomm` | 10.3.0 |
| `page.0x01.icbcbypass` | 工商银行 | `com.icbc.iphoneclient` | 3.0.80 ~ 3.0.90 |

mybankbypass / bankcommbypass 从旧名 `com.liam.*` 迁移而来，通过 `Conflicts`/`Replaces` 字段实现无缝升级。icbcbypass 是全新包。

## 开发工具

| 包名 | 类型 | 用途 |
|------|------|------|
| `page.0x01.sshtunnel` | Theos Application | SSH 反向隧道管理器，从设备建立到构建服务器的反向隧道，用于远程调试和部署 |

sshtunnel 不是 tweak，而是独立的 iOS 应用（`APPLICATION_NAME`，安装到 `/Applications`）。依赖设备已安装 `openssh-client`。使用场景：手机在内网、Linux 构建服务器在公网时，通过反向隧道让服务器 SSH 回手机，实现远程安装和调试。

## 目标环境

- 测试设备：iPhone 14 Pro Max
- 系统版本：iOS `16.3.1`
- 越狱环境：Dopamine（rootless）
- 包管理器：Sileo
- 设备 SSH：`root@192.168.1.253`
- 构建体系：Theos（`~/theos`），`rootless` 打包方案，`arm64`

## 当前状态

- mybankbypass 当前版本：`1.2.0`，已确认绕过网商银行 4.6.4 与 4.7.36 的越狱检测
- bankcommbypass 当前版本：`0.2.0`，可绕过交通银行 10.3.0 的越狱检测弹窗（存在已知卡顿，进入主页后约 2 秒闪退，待优化）
- icbcbypass 当前版本：`1.1.0`，已完全绕过工商银行 3.0.80 ~ 3.0.90 的越狱检测+主线程冻结+退出弹窗三层防御，登录和使用均正常（v1.1.0 修复了 3.0.90 的 CALayer 动画累积性能问题）

## 软件源与 CI/CD 架构

- Sileo 源名称：`0x01`
- Pages 内容托管在 `gh-pages` 孤儿分支（master 不含 repo 目录）
- Release workflow（tag 触发）自编译、更新 Packages/Release/depictions/index.html、force push 到 gh-pages
- Build workflow（push/PR 触发）做 matrix 验证构建
- 发版 tag 格式：`<tweak目录名>_<版本号>`（如 `bankcommbypass_0.2.0`）

## 项目边界

本项目文档聚焦：

- 各目标 App 当前版本的本地越狱检测绕过方案
- rootless Dopamine 设备上的构建、部署与验证流程
- 已知检测向量与各 tweak 的对应实现
- 会影响稳定性的实现约束与回归风险

## 当前稳定结论（mybankbypass）

- 目标 App 使用阿里系 SecurityGuard SDK 作为核心安全框架之一。
- 仅拦截单一文件 API 不足以绕过，需要同时覆盖文件、URL scheme、动态库枚举、环境变量、进程/调试检测以及退出链路。
- rootless 环境必须把 `/var/jb` 及相关派生路径视为一等检测面。
- `4.7.36` 的关键新增适配点是 `MYBLauncherController.checkJailbroken`；业务层 launcher 在命中越狱检测后会继续走 exit 链路。
- 已验证的稳定实现依赖三个关键修正：
  1. C 层 Hook 内部必须使用纯 C 字符串匹配，避免在低层 Hook 中引入 ObjC 调用。
  2. 目录枚举相关策略不能通过 `opendir` 粗暴拦截；此前该做法会触发 watchdog 或异常行为，当前方案改为保留 `NSFileManager` 目录结果过滤并移除 `opendir` Hook。
  3. `exit()` / `_exit()` / `abort()` 这类 `noreturn` 终止函数不能”拦截后返回”；当前稳定方案是在主线程保持 RunLoop、非主线程永久阻塞，确保行为满足 `noreturn` 语义。

## 代码入口

- `mybankbypass/Tweak.x`：网商银行 Hook 主入口
- `bankcommbypass/Tweak.x`：交通银行 Hook 主入口
- `icbcbypass/Tweak.x`：工商银行 Hook 主入口（fishhook + Logos）
- `sshtunnel/`：SSH 反向隧道应用（`TunnelManager.m` 为核心，通过 posix_spawn 启动 ssh 进程）
- `mybankbypass/Makefile` / `bankcommbypass/Makefile` / `icbcbypass/Makefile`：Theos 构建配置
- `mybankbypass/control` / `bankcommbypass/control` / `icbcbypass/control`：Debian 包元数据
- `.github/workflows/release.yml`：发版与 Pages 部署 workflow
