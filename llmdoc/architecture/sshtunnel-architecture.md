# SSHTunnel 架构 (v1.3.0)

## 核心职责

TunnelManager 是单例状态机，管理 autossh/ssh 子进程的完整生命周期：启动、验证、健康监控、自动恢复、开机持久化。

## 状态机

```
Disconnected ──connect──► Connecting ──TCP verify OK──► Connected
     ▲                         │                            │
     │                   verify timeout /                health check
     │                   process died                    3x TCP fail /
     │                         │                        process exit
     │                         ▼                            │
     └──── disconnect ◄── Reconnecting ◄────────────────────┘
              (clears state,         │
               prevents auto-        │  delay (exponential backoff)
               reconnect)            └──────► Connecting
```

四个状态定义于 `sshtunnel/TunnelManager.h` (`TunnelState` enum)：

| 状态 | 含义 | UI 行为 |
|------|------|---------|
| `Disconnected` | 空闲，无进程 | "Connect" 按钮 |
| `Connecting` | spawn 已发，等待 TCP 验证 | spinner |
| `Connected` | 隧道已验证，健康检查运行中 | "Disconnect" 按钮 |
| `Reconnecting` | 等待退避延迟后重试 | 橙色 "Cancel" 按钮 |

## 连接流程

1. `connect` 入口校验 → 状态设为 Connecting
2. `spawnTunnel`：选择 autossh（优先）或 ssh；构造参数；`posix_spawn` + `POSIX_SPAWN_SETPGROUP` 隔离进程组
3. `attachMonitor`：创建 `DISPATCH_SOURCE_TYPE_PROC` 监听 `DISPATCH_PROC_EXIT`
4. `verifyConnection:attempt:`：TCP 轮询（每 2s 一次，最多 8 次）替代旧版 3s 盲等
5. 验证通过 → Connected + `startHealthCheck`；超时 → kill → `handleTunnelDeath`

## TCP 健康检查

实现位置：`sshtunnel/TunnelManager.m` (`tcpConnectTestWithTimeout:`)

- 非阻塞 `connect()` + `select()` 超时
- 目标：服务器 host:port（验证 SSH 可达性）
- 健康定时器：30s 间隔，Connected 状态期间持续运行
- 策略：3 次连续 TCP 失败 → `SIGTERM` kill 进程 → 触发 `handleTunnelDeath`
- 进程存活但 TCP 不通（zombie tunnel）：probe 阶段也会检测并清理

## 自动重连（指数退避）

实现位置：`sshtunnel/TunnelManager.m` (`handleTunnelDeath:`)

退避序列：3, 6, 12, 24, 48, 60s (max)

```
delay = 3 * (1 << min(backoffCount, 4))   // cap at 2^4=16 → 48s, 之后 cap 60s
```

触发条件：
- 进程退出（`DISPATCH_PROC_EXIT` 通知）
- 健康检查 3 次失败
- 连接验证超时（8 轮 TCP poll 失败）

中止条件：
- `disconnect` 调用：先清除状态再 kill（防止状态机进入 Reconnecting）
- `autoReconnect` 为 NO
- 缺少必填字段（host / username）

成功连接后 `_reconnectBackoff` 重置为 0。

## 开机持久化（LaunchDaemon）

| 文件 | 用途 |
|------|------|
| `sshtunnel/layout/var/jb/Library/LaunchDaemons/page.0x01.sshtunnel.plist` | 系统 daemon 定义 |
| `/var/jb/var/mobile/.sshtunnel/boot-cmd` | 当前隧道配置的 shell 脚本 |

机制：
- `KeepAlive.PathState`：只要 `boot-cmd` 文件存在，launchd 自动启动/重启 daemon
- `writeBootCmd`：连接验证成功后生成 shell 脚本（`exec autossh/ssh ...`），写入 PID 文件
- `removeBootCmd`：`disconnect` 时删除文件，launchd 停止 daemon
- UI 开关：`autoStartOnBoot` 属性

## 进程 spawn 约束

关键参数（从 v1.2.1 教训继承）：

- `POSIX_SPAWN_SETPGROUP` + `posix_spawnattr_setpgroup(&attr, 0)`：隔离子进程组，防止 iOS 杀 app 时连带杀 autossh
- `setenv("AUTOSSH_PATH", sshPath, 1)`：显式告诉 autossh 到哪找 ssh（app 的 PATH 不含 `/var/jb/usr/bin`）
- stderr 重定向至 `~/.sshtunnel/stderr.log`（用 `adddup2` 而非 `addopen`，iOS sandbox 限制后者）

## Probe（启动时状态恢复）

`probe` 在 `init` 时调用：

1. 读 PID 文件 → `kill(pid, 0)` 检查进程存活
2. 进程不在 → 清理 state files
3. 进程存活 → TCP 验证 → 通过则恢复 Connected + 启动健康检查；TCP 失败则 kill（zombie tunnel 修复）

## 状态持久化文件

所有文件位于 `/var/jb/var/mobile/.sshtunnel/`：

| 文件 | 内容 |
|------|------|
| `autossh.pid` | 子进程 PID |
| `tunnel.json` | 当前隧道配置快照（host, port, user, remotePort, localPort, autossh flag） |
| `stderr.log` | 子进程 stderr 输出（用于诊断） |
| `boot-cmd` | 开机启动脚本（存在 = daemon 激活） |

## 与 v1.2.1 的关键差异

| 能力 | v1.2.1 | v1.3.0 |
|------|--------|--------|
| 连接验证 | 3s 盲等 | TCP 轮询 (2s x 8) |
| 健康检查 | 无 | 30s TCP 探测 |
| 进程 zombie 检测 | 无 | probe + 健康检查双重覆盖 |
| 断线恢复 | 手动 | 自动重连 + 指数退避 |
| 开机启动 | 无 | LaunchDaemon + PathState |
| 状态数 | 3 (无 Reconnecting) | 4 |
