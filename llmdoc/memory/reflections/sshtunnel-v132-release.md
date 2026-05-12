# SSHTunnel v1.3.2 Release Reflection

## 时间

2026-05-12

## Task

SSHTunnel v1.3.2 发布：移除所有 TCP 探测逻辑和 `/bin/sh` 依赖，改用 sysctl(KERN_PROCARGS2) 实现孤儿进程检测，连接验证和健康检查简化为纯 process-alive 模式。

## Expected vs Actual

- **预期**: v1.3.0 引入的 TCP 验证/健康检查应能可靠工作；v1.3.1 的 ps|grep 孤儿检测应兼容 rootless。
- **实际**: TCP 在 iOS app 进程中根本不可用（sandbox 阻止出站连接），ps|grep 依赖的 `/bin/sh` 在 rootless jailbreak (Dopamine) 上不存在。两个核心机制都需要全面重写。

## What Went Wrong

1. **TCP 探测方向性错误（跨越两个版本）**: v1.3.0 设计了完整的 TCP 健康检查体系（`tcpConnectTestWithTimeout:`, 30s 定时器, 3 次失败策略），但 iOS sandbox 阻止 app 进程发起出站 TCP 连接，即使拥有 `com.apple.private.security.no-sandbox` entitlement 也无效。这个错误从 v1.3.0 存在到 v1.3.2 才完全清除。

2. **`/bin/sh` 假设错误（v1.3.1）**: 孤儿检测通过 `posix_spawn("/bin/sh", "ps | grep autossh")` 实现。rootless jailbreak 的系统分区是只读的，`/bin/sh` 不存在（Shell 在 `/var/jb/usr/bin/sh`）。这是 rootless 意识不足的又一次表现。

3. **Dead code 清理延迟**: `tcpConnectTestWithTimeout:` 方法在功能变更后仍保留在代码中（50 行），直到 release commit 才删除。应在功能变更的同一 commit 中清理。

4. **架构文档滞后**: `sshtunnel-architecture.md` 在 v1.3.1 时未更新（仍描述 v1.3.0 的 TCP 模式）。这是一个反复出现的模式——功能变更后文档不同步。

5. **发版流程初次遗漏 tag 步骤**: 第一次尝试发版时忘了 push tag（只 push 了 commit），CI 未触发。阅读 `guides/build-deploy.md` 的"发版与 Tag 规则"章节后才正确操作。

## Root Cause

1. **iOS sandbox 理解不完整**: 对 sandbox 限制的认知停留在"文件系统受限"，未意识到 app 进程的网络出站也受限。`no-sandbox` entitlement 在 TCP connect 场景下无效，这一行为未被文档化。

2. **错误的验证哲学**: 试图从 app 内部主动验证隧道（TCP probe），但正确方式是利用 SSH 自身机制。`ExitOnForwardFailure=yes` 让 ssh 在绑定失败时自行退出，`ServerAliveInterval/ServerAliveCountMax` 负责死连接检测。进程存活即服务可用——前提是 SSH 参数配置正确。

3. **Rootless 适配惯性缺失**: 尽管 v1.2.1 已修复过 rootless 相关问题（PATH 传播），但对 rootless 的"系统二进制位于 `/var/jb/`"这一约束仍未形成系统性检查习惯。

4. **文档更新未绑定到发版流程**: 没有把"架构文档更新"作为发版检查清单的一项。

## Missing Docs or Signals

1. **iOS sandbox 网络限制文档**: 缺少记录 app 进程（即使 entitlement 去 sandbox）在 TCP 出站方面的限制。这影响任何试图从 tweak/app 内发起网络连接的设计。

2. **sysctl(KERN_PROCARGS2) 使用模式**: 这是 iOS/macOS 上无需 shell 依赖即可读取进程参数的标准方法，应作为参考文档记录（CTL_KERN, KERN_PROCARGS2, pid -> argv 解析流程）。

3. **SSH 自愈参数组合**: `ExitOnForwardFailure=yes` + `ServerAliveInterval` + `ServerAliveCountMax` 的组合让 SSH 自行处理失败检测，不需要外部健康检查。这个模式应记录为 SSHTunnel 的设计原则。

4. **架构文档更新提醒**: 发版检查清单缺少"架构文档是否反映当前版本"一项。

## Promotion Candidates

| 内容 | 目标位置 | 理由 |
|------|----------|------|
| sysctl(KERN_PROCARGS2) 进程参数读取模式 | `reference/` 新文档或 SSHTunnel 架构文档 | 无 shell 依赖的 iOS 进程检查标准方法 |
| iOS app 进程 TCP 出站受限（即使 no-sandbox） | `reference/ios-posix-spawn-constraints.md` 扩展 | 影响所有从 app 内发起网络探测的设计 |
| SSH 自愈参数组合作为设计原则 | `architecture/sshtunnel-architecture.md` | 架构层面的核心决策，决定不需要外部健康检查 |
| 发版检查清单增加"架构文档同步" | `guides/build-deploy.md` | 防止文档滞后复发 |
| Rootless 约束检查清单（/bin/sh 不存在等） | `reference/` | 影响所有使用系统二进制的代码 |

## Key Technical Decisions

### 为什么 process-alive 足够

```
ExitOnForwardFailure=yes  → 绑定失败 = 进程退出
ServerAliveInterval=15    → 服务器无响应 45s 后 = 进程退出
POSIX_SPAWN_SETPGROUP     → 进程不受 app 退出连坐

∴ 进程存活 5s = 隧道端口绑定成功 + 服务器可达
∴ 进程退出 = 自动触发 reconnect（通过 DISPATCH_PROC_EXIT）
```

不需要外部 TCP 探测、不需要定时健康检查——SSH 自身就是最可靠的健康检查器。

### sysctl vs ps|grep

| 维度 | ps\|grep | sysctl(KERN_PROCARGS2) |
|------|----------|------------------------|
| Shell 依赖 | /bin/sh（rootless 不存在） | 无 |
| 解析可靠性 | grep 可能误匹配 | 精确读取目标 PID 的 argv |
| 权限 | 需要 ps 可执行文件 | 直接 syscall，任何进程可调用 |
| 性能 | fork+exec+pipe | 单次 sysctl 调用 |

## Follow-up

1. 更新 `architecture/sshtunnel-architecture.md` 内容以反映 v1.3.2 实际状态（移除 TCP 相关描述，加入 process-alive 验证原理和 sysctl 孤儿检测）
2. 在 `guides/build-deploy.md` 发版检查清单中增加"架构文档是否反映当前版本"一项
3. 考虑创建 `reference/ios-sandbox-network-constraints.md`，记录 app 进程网络限制
4. 将 dead code 清理纳入 commit 纪律：功能变更和相关 dead code 删除应在同一 commit
