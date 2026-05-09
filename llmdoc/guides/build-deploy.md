# 构建、部署与验证指南

## 适用范围

本指南用于在当前已验证环境中构建并部署 tweak：

- macOS 开发机
- Theos 安装在 `~/theos`
- 目标设备为 rootless 越狱环境
- 当前已验证设备：iPhone 14 Pro Max / iOS 16.3.1 / Dopamine / Sileo

## 相关文件

- `mybankbypass/` — 网商银行绕过 tweak
- `bankcommbypass/` — 交通银行绕过 tweak
- `icbcbypass/` — 工商银行绕过 tweak（fishhook + Logos）
- `.github/workflows/release.yml` — 自动发版与 Pages 部署
- `.github/workflows/build.yml` — CI 验证构建

## 构建步骤

在项目根目录下进入 tweak 子目录后执行：

```bash
cd <tweak目录>
make clean
make package FINALPACKAGE=1
```

产物在 `<tweak目录>/packages/` 下。

## 部署到设备

```bash
cd <tweak目录>
make install
```

需要设备可通过 SSH 访问（Makefile 中配置了 `THEOS_DEVICE_IP` 和 `THEOS_DEVICE_PORT`）。

## 发版与 Tag 规则

Release workflow 由 tag push 触发，tag 格式：`<tweak目录名>_<版本号>`

示例：
- `bankcommbypass_0.2.0`
- `mybankbypass_1.2.0`
- `icbcbypass_1.0.0`

发版流程（全自动）：
1. 安装 Theos 并编译目标 tweak
2. 创建 GitHub Release 并上传 .deb
3. 从 gh-pages 拉取当前软件源内容
4. 更新 Packages/Release/depictions/index.html
5. Force push 到 gh-pages 分支

多个 tag 同时推送时，`concurrency: release-deploy` 保证串行执行。

## CI/CD 架构要点

- Pages 内容在 `gh-pages` 孤儿分支，master 不含 `repo/` 目录
- Release workflow 从 `gh-pages` 通过 git worktree 获取当前内容
- Release 文件从 scratch 生成（Origin/Label: 0x01）
- index.html 从所有 `*/control` 自动生成
- Packages 由 `dpkg-scanpackages` 生成后，用 sed patch Section 和 SileoDepiction
- 旧包名的 deb/depiction 会被自动清理（通过读取 Conflicts 字段）

## 部署后验证

最小验证流程：

1. 确认设备上已安装最新版本 tweak 包
2. 完全关闭目标 App
3. 重新启动目标 App
4. 观察是否能稳定停留在前台
5. 进入常用页面做基本冒烟验证

## 回归关注点（mybankbypass）

每次修改 `Tweak.x` 后，优先回归以下风险点：

1. **低层 C Hook 是否仍然纯 C** — 不要在 stat/open/readlink 等 Hook 中引入 ObjC 调用
2. **不要恢复 opendir Hook** — 历史验证会触发 watchdog
3. **退出 Hook 必须保持 noreturn 安全** — 主线程跑 RunLoop、后台线程永久阻塞
4. **rootless 路径覆盖完整** — `/var/jb` 派生路径、Frida 痕迹
5. **安全框架类名是否变化** — App 升级后检查 class/selector 变更
