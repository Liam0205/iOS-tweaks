# SSHTunnel 1.1.1 - 1.2.1 开发周期反思

## 时间

2026-05-11

## Task

SSHTunnel tweak 从 1.1.1（基础 bugfix）经 1.2.0（autossh 持久隧道）到 1.2.1（两个关键 bugfix）的完整开发周期。核心目标：让反向隧道在 app 退出后仍能存活，实现真正的持久连接。

## Expected vs Actual

- **预期**: 引入 autossh 替代 ssh，配合 PID 文件实现进程持久化和状态恢复，一次到位。
- **实际**: autossh 集成后遇到两个严重问题——(1) autossh 找不到 ssh 可执行文件导致隧道静默失败；(2) app 被 iOS 杀死时 autossh 一起被杀。两个 bug 都需要对 posix_spawn 行为有深入理解才能定位。

## What Went Wrong

### Bug 1: autossh 找不到 ssh（1.2.1 修复）

- autossh 内部通过 PATH 查找 `ssh`，但 app 进程的 environ 不包含 `/var/jb/usr/bin`
- `which ssh` 在交互 shell 中正常工作，误导了测试判断
- 表面现象：autossh 进程存活（PID 文件有效），但实际未建立任何连接
- 修复：spawn 前 `setenv("AUTOSSH_PATH", sshPath, 1)`

### Bug 2: app 退出杀死 autossh（1.2.1 修复）

- autossh 继承了 app 的 process group
- iOS 终止 app 时杀掉整个 process group
- 持久化设计（PID 文件、stderr 写文件而非 pipe）全部失效，因为进程根本活不下来
- 修复：`POSIX_SPAWN_SETPGROUP` + `posix_spawnattr_setpgroup(&attr, 0)`

### 1.1.1 的 stderr 处理教训

- `posix_spawn_file_actions_addopen` 在 iOS 15.4.1 sandbox 下返回 EPERM
- 改用 pipe + adddup2 绕过，说明 posix_spawn 的 file_actions 在 iOS sandbox 中受限

## Root Cause

1. **进程环境隔离认知不足**: iOS app 进程的 environ 与交互 shell 差异巨大。当 A spawn B、B 再 spawn C 时，必须确保 B 能找到 C——不能假设 PATH 会自动传播
2. **process group 生命周期盲区**: 没有意识到 iOS 杀 app 是按 process group 而非单个 PID 操作的。所有"持久化子进程"的设计（PID 文件、stderr 日志）在进程存活的前提下才有意义
3. **"进程存活 = 功能正常"的错误假设**: 3 秒存活检测通过，但 autossh alive 不代表 ssh 连接建立成功。缺少端口监听验证

## Missing Docs or Signals

1. **iOS posix_spawn 约束清单**: 缺少一份记录 iOS 环境下 posix_spawn 各种限制的参考文档（sandbox 对 file_actions 的限制、environ 不含 jailbreak 路径、process group 继承行为）
2. **"spawn 链"模式指南**: 当需要 spawn 一个会再 spawn 其他程序的进程时，需要显式设置的环境变量和属性清单
3. **健康检查设计模式**: "进程存活"不等于"服务可用"，对于网络服务类子进程，应有端口监听验证或连接探测

## Promotion Candidates

| 内容 | 目标位置 | 理由 |
|------|----------|------|
| iOS posix_spawn 约束（sandbox EPERM、PATH 不传播、process group 继承） | `reference/` 新文档 `ios-posix-spawn-constraints.md` | 影响所有 spawn 子进程的场景，属于环境级约束 |
| 持久子进程必须 POSIX_SPAWN_SETPGROUP | `guides/build-deploy.md` 或架构文档 | 任何需要 app 退出后存活的子进程都必须遵守 |
| autossh 集成模式（AUTOSSH_PATH + SETPGROUP + probe） | SSHTunnel 架构文档 | 已验证的稳定模式，后续维护需要参考 |

## Follow-up

1. 考虑建立 `reference/ios-posix-spawn-constraints.md`，系统性记录 iOS 环境下 posix_spawn 的已知限制和正确用法
2. 健康检查应从"PID 存活 3 秒"升级为"验证端口实际在监听"（如 `probe` 阶段尝试连接映射端口），当前方案在 autossh 找不到 ssh 时会误报 Connected
3. 将 `POSIX_SPAWN_SETPGROUP` 作为所有 iOS 持久子进程的必选项，写入开发规范
