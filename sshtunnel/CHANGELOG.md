# Changelog

## 1.3.0

- TCP 健康检查：每 30 秒通过非阻塞 socket 检测服务器连通性，连续 3 次失败自动杀掉隧道并重连
- 自动重连与指数退避：隧道意外断开后自动重连（3s → 6s → 12s → 24s → 48s → 60s 上限），可通过开关关闭
- 连接验证改进：TCP 轮询替代原来的 3 秒盲等待，每 2 秒检测一次，最多 8 次
- LaunchDaemon 开机自启：通过 PathState 条件触发，boot-cmd 文件存在时自动建立隧道
- 孤儿进程检测：启动时通过 pgrep 扫描匹配的 SSH 进程，PID 文件丢失也能恢复连接
- probe 不再误杀隧道：TCP 测试失败时不杀进程，改由健康检查判断
- Connect 前自动清理占用端口的旧进程
- UI：新增 Options 区（Auto Reconnect / Start on Boot 开关）
- UI：按钮点击触觉反馈 + 缩放动画
- UI：按钮下方显示彩色连接状态指示器（● Connected ●）
- UI：连接/断开时触觉通知（成功/错误）

## 1.2.1

- 修复 autossh 在 rootless 越狱上找不到 ssh 的问题（设置 AUTOSSH_PATH 指向 /var/jb/usr/bin/ssh）
- 修复杀掉 APP 后隧道一并断开的问题（POSIX_SPAWN_SETPGROUP 让 autossh 在独立进程组运行）

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
