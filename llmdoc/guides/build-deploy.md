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
- `sshtunnel/` — SSH 反向隧道管理应用（Theos Application，非 tweak）
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

## Linux 交叉编译

在 Linux x86_64 环境中构建 iOS tweak（无需 macOS）。

### 前置依赖

通过 Homebrew (linuxbrew) 安装（无需 sudo）：

```bash
brew install ldid xz ncurses
# libtinfo.so.5 兼容 symlink
ln -s /home/linuxbrew/.linuxbrew/lib/libtinfo.so /home/linuxbrew/.linuxbrew/lib/libtinfo.so.5
```

系统需已有：`dpkg`、`fakeroot`、`make`、`git`。

### 安装 Theos + SDK + 工具链

```bash
# Theos
git clone --recursive https://github.com/theos/theos.git ~/theos

# iOS SDK
curl -sL https://github.com/theos/sdks/archive/master.tar.gz | tar xz --strip-components=1 -C ~/theos/sdks/

# 交叉编译工具链（提供 ld64 链接器）
curl -sL https://github.com/sbingner/llvm-project/releases/latest/download/linux-ios-arm64e-clang-toolchain.tar.lzma \
  | xz -d | tar xf - -C ~/theos/toolchain
mv ~/theos/toolchain/ios-arm64e-clang-toolchain ~/theos/toolchain/linux/iphone
```

### 替换工具链 clang

工具链自带的 clang-10 无法处理 iOS 16.5 SDK 的 module 系统，需用系统 clang 替代：

```bash
mv ~/theos/toolchain/linux/iphone/bin/clang ~/theos/toolchain/linux/iphone/bin/clang.orig
mv ~/theos/toolchain/linux/iphone/bin/clang++ ~/theos/toolchain/linux/iphone/bin/clang++.orig
ln -s $(which clang) ~/theos/toolchain/linux/iphone/bin/clang
ln -s $(which clang++) ~/theos/toolchain/linux/iphone/bin/clang++
```

### 构建命令

```bash
export THEOS=~/theos
export LD_LIBRARY_PATH=/home/linuxbrew/.linuxbrew/lib:$LD_LIBRARY_PATH
cd <tweak目录>
make clean
make package FINALPACKAGE=1 \
  ADDITIONAL_LDFLAGS="-B$THEOS/toolchain/linux/iphone/bin -fuse-ld=$THEOS/toolchain/linux/iphone/bin/ld"
```

`ADDITIONAL_LDFLAGS` 确保系统 clang 使用工具链的 ld64 而非 GNU ld。`libtinfo.so.5` 版本警告可忽略。

## sshtunnel 构建与部署

sshtunnel 是 Theos Application（`APPLICATION_NAME`），不是 tweak。构建和安装步骤与 tweak 相同，但有以下差异：

- Makefile 中已内置 Linux 交叉编译的 `LD_LIBRARY_PATH` 和 `LDFLAGS`，无需额外传递
- 安装到 `/Applications`（不是 tweak 目录），安装后需 `uicache` 刷新图标
- 不通过 Sileo 源分发，仅本地开发使用
- 依赖设备已有 `openssh-client`

```bash
cd sshtunnel
make clean && make package FINALPACKAGE=1
# 部署到设备（需 SSH 可达）
make install THEOS_DEVICE_IP=<device-ip>
# 在设备上执行
uicache -p /Applications/SSHTunnel.app
```

### 反向隧道开发工作流

当手机在内网、构建服务器在公网时，通过 sshtunnel 建立反向隧道后，服务器可以 SSH 回手机：

1. 构建服务器上编译 tweak：`make package FINALPACKAGE=1`
2. 在手机上打开 SSHTunnel，配置服务器地址和端口，点击连接
3. 隧道建立后，从构建服务器通过映射端口 SSH 到手机安装 deb
4. 在手机上验证 tweak 效果

## 发版与 Tag 规则

Release workflow 由 tag push 触发，tag 格式：`<tweak目录名>_<版本号>`

示例：
- `bankcommbypass_0.2.0`
- `mybankbypass_1.2.0`
- `icbcbypass_1.1.0`

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

## 发版检查清单

新增 tweak 或发版前应确认：

1. `control` 文件包含 `SileoDepiction: https://tweaks.0x01.page/depictions/<package-id>.json`
2. tweak 目录下存在 `CHANGELOG.md`（否则 depiction 使用 fallback 文本）
3. `release.yml` 第 93 行的 gh-pages 清理列表包含该 tweak 目录名
4. `build.yml` 的 `paths-ignore` 列表中不要意外排除新 tweak 的文件
5. Release notes 范围为 `PREV_TAG..TAG`（不是 HEAD），确认 workflow 逻辑正确
