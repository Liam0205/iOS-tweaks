# Changelog

## 1.2.0

- 支持 autossh 自动重连（安装 autossh 后自动启用，未安装则回退到 ssh）
- 隧道进程在 APP 退出后持续运行，重新打开 APP 自动恢复连接状态
- 通过 PID 文件 + 配置文件识别并接管已有隧道，不干扰用户自行启动的隧道
- stderr 重定向到日志文件，支持跨 APP 生命周期的错误回溯

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
