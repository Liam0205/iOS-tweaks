# 反向隧道部署模式踩坑反思

## 时间

2026-05-10

## Task

通过 SSHTunnel 建立的反向 SSH 隧道，从 Linux 构建服务器向 iOS 设备部署 tweak .deb 包。具体操作包括 scp 传输 deb 文件和 ssh 远程执行 dpkg 安装。

## Expected vs Actual

- **预期**: 参照 `guides/build-deploy.md` 的"反向隧道开发工作流"章节，顺利完成部署。
- **实际**: 文档只给出了概念性的 4 步流程，没有写明端口号和用户名。首次尝试用 `root@localhost` 连接失败（`Too many authentication failures`），经排查后才确定应使用 `mobile@localhost`。同时发现无法通过隧道自身部署 SSHTunnel 更新（自举悖论）。

## What Went Wrong

1. **用错 SSH 用户名**: 习惯性使用 root 连接越狱设备，但 SSHTunnel 的反向隧道映射的是设备的 SSH 服务端口，该服务默认的有效用户是 mobile（rootless 越狱环境下 root 的 SSH 密钥/认证配置不同），导致 `Too many authentication failures`
2. **缺少具体部署命令**: 文档说"通过映射端口 SSH 到手机安装 deb"，但没有给出 `scp -P 2222` 和 `ssh -p 2222` 的具体命令模板，需要自行推断端口号
3. **未记录自举问题**: 尝试通过隧道部署 SSHTunnel 新版本时，dpkg 安装过程中 SSHTunnel 进程被替换/重启，导致隧道断开、部署中断

## Root Cause

- `guides/build-deploy.md` 的反向隧道工作流章节写于功能初期，只记录了概念流程，未补充经过验证的具体参数
- rootless 越狱（Dopamine）环境下，root 用户的 SSH 认证与传统越狱不同，这个差异未被文档化
- SSHTunnel 作为隧道载体本身的部署属于边界场景，容易被忽略

## Missing Docs or Signals

1. **端口号**: 反向隧道默认映射到构建服务器的 `localhost:2222`，文档中未写明
2. **SSH 用户名**: 应使用 `mobile` 而非 `root`，文档中未写明。rootless 越狱环境下 root SSH 不可靠是一个重要约束
3. **具体部署命令模板**: 缺少 scp + ssh dpkg 的完整命令示例：
   - `scp -P 2222 <deb> mobile@localhost:/tmp/`
   - `ssh -p 2222 mobile@localhost "sudo dpkg -i /tmp/<deb>"`
4. **自举问题警告**: 不能通过 SSHTunnel 自己的隧道来部署 SSHTunnel 更新，需要直接 SSH 到设备或使用其他传输方式

## Promotion Candidates

| 内容 | 目标位置 | 理由 |
|------|----------|------|
| 完整的隧道部署命令（端口、用户名、scp + dpkg） | `guides/build-deploy.md` "反向隧道开发工作流" 章节 | 已验证的稳定操作流程，消除试错成本 |
| rootless 越狱使用 mobile 用户的约束 | `guides/build-deploy.md` 或 `reference/` | 环境约束，影响所有 SSH 相关操作 |
| SSHTunnel 自举问题警告 | `guides/build-deploy.md` SSHTunnel 部署小节 | 边界场景但后果严重（部署中断），需显式警告 |

## Follow-up

1. 将 `guides/build-deploy.md` 的"反向隧道开发工作流"章节从概念描述升级为包含具体命令的操作指南，补充端口号 2222、用户名 mobile、完整的 scp/ssh 命令模板
2. 在 SSHTunnel 部署小节加入自举问题警告框（明确说明不能通过隧道部署 SSHTunnel 自身）
3. 考虑在 `reference/` 中记录 rootless 越狱环境的 SSH 用户约束（mobile vs root），因为这影响所有涉及设备 SSH 的操作
