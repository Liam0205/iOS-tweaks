# Changelog

## 1.1.1

- 连接失败时显示 SSH stderr 详细错误信息（替代原来的 "exit code 255"）
- 连接状态改为先显示 Connecting，存活 3 秒后再切换为 Connected
- 修复 iOS 15.4.1 上 posix_spawn_file_actions_addopen 被沙盒拒绝的问题（改用 pipe + adddup2）
- 进程被信号杀死时显示具体信号编号

## 1.1.0

- 添加应用图标（绿色隧道图形）

## 1.0.0

- SSH 反向隧道管理器，支持从设备建立到远程服务器的反向隧道
- 密钥管理与 ssh-copy-id 支持
- 后台保活
