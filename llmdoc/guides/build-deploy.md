# 构建、部署与验证指南

## 适用范围

本指南用于在当前已验证环境中构建并部署 tweak：

- macOS 开发机
- Theos 安装在 `~/theos`
- 目标设备为 rootless 越狱环境
- 当前已验证设备：iPhone 14 Pro Max / iOS 16.3.1 / Dopamine 2.x；iPhone 13 Pro / iOS 15.4.1 / Dopamine 1.x

## 相关文件

- `mybankbypass/` — 网商银行绕过 tweak
- `bankcommbypass/` — 交通银行绕过 tweak
- `icbcbypass/` — 工商银行绕过 tweak（fishhook + Logos）
- `abcbypass/` — 农业银行绕过 tweak（fishhook + MSHookFunction + Logos）
- `lianjiabypass/` — 链家/贝壳找房绕过 tweak（fishhook + MSHookFunction + 运行时 __text patch）
- `sshtunnel/` — SSH 反向隧道管理应用（Theos Application，非 tweak）
- `simtouch/` — 远程触摸模拟与截图捕获工具（Theos Tweak + CLI + PreferenceBundle）
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
- 依赖设备已有 `openssh-client`、`sshpass`；推荐安装 `autossh`（持久化隧道）

```bash
cd sshtunnel
make clean && make package FINALPACKAGE=1
# 部署到设备（需 SSH 可达）
make install THEOS_DEVICE_IP=<device-ip>
# 在设备上执行
uicache -p /Applications/SSHTunnel.app
```

**自举问题警告**：不要通过 SSHTunnel 自身维护的反向隧道来部署 SSHTunnel 新版本。dpkg 安装过程中 SSHTunnel 进程被替换，隧道立即断开，后续命令（如 uicache）将失败。部署 SSHTunnel 应使用其他连接方式（USB 直连 iproxy 或 Wi-Fi 局域网 SSH）。

### 反向隧道开发工作流

当手机在内网、构建服务器在公网时，通过 SSHTunnel 建立反向隧道后，服务器可通过 localhost SSH 回手机。

**端口约定**：`22xx`，其中 `xx` 为 iOS 主版本号。
- iOS 15 设备：`localhost:2215`
- iOS 16 设备：`localhost:2216`

**多设备支持**：当前环境有两台设备可用，通过端口区分：
- iPhone 14 Pro Max / iOS 16.3.1 → 端口 2216
- iPhone 13 Pro / iOS 15.4.1 → 端口 2215

**隧道持久化**：SSHTunnel v1.2.1 使用 autossh 维持隧道持久连接，App 退出后隧道进程继续存活（通过 PID 文件管理）。下次打开 App 时自动探活，已有活跃连接则直接显示状态。设备未安装 autossh 时降级为普通 ssh（App 退出即断开）。

**连接约束**：rootless 越狱（Dopamine）环境下，SSH 用户必须使用 `mobile`，不要用 `root`（root 的 SSH 认证配置不同，会导致 `Too many authentication failures`）。

操作步骤：

1. 构建服务器上编译 tweak：`make package FINALPACKAGE=1`
2. 在手机上打开 SSHTunnel，配置服务器地址和端口，点击连接
3. 隧道建立后，传输并安装 deb：

```bash
# 传输 deb 到设备（端口按设备选择 2215 或 2216）
scp -P 22xx packages/<name>.deb mobile@localhost:/tmp/
# 远程安装
ssh -p 22xx mobile@localhost "sudo dpkg -i /tmp/<name>.deb"
```

4. 验证部署结果：
   - **tweak**：重启目标 App，确认 tweak 生效
   - **sshtunnel**：不适用此工作流（见上方自举问题警告）

## 部署后验证

最小验证流程：

1. 确认设备上已安装最新版本 tweak 包
2. 完全关闭目标 App
3. 重新启动目标 App
4. 观察是否能稳定停留在前台
5. 进入常用页面做基本冒烟验证

发版相关流程（tag 规则、CI 矩阵配置、macOS CI 私有 framework 差异、Logos 跨平台注意事项、发版检查清单）见 `llmdoc/guides/ci-cd-release.md`。

## 回归关注点（mybankbypass）

每次修改 `Tweak.x` 后，优先回归以下风险点：

1. **低层 C Hook 是否仍然纯 C** — 不要在 stat/open/readlink 等 Hook 中引入 ObjC 调用
2. **不要恢复 opendir Hook** — 历史验证会触发 watchdog
3. **退出 Hook 必须保持 noreturn 安全** — 主线程跑 RunLoop、后台线程永久阻塞
4. **rootless 路径覆盖完整** — `/var/jb` 派生路径、Frida 痕迹
5. **安全框架类名是否变化** — App 升级后检查 class/selector 变更

## 回归关注点（lianjiabypass）

每次修改 `Tweak.x` 或 App 升级后，优先回归以下风险点：

1. **JGBSDK 内联 exit syscall 的指令编码是否变化** — 当前 patch 逻辑假定固定为 `mov w16,#1`（`0x52800030`）紧邻 `svc #0x80`（`0xd4001001`），编译器/SDK 升级可能改变寄存器编号或指令顺序
2. **patch 后是否严格恢复 R+X 权限** — 改 `vm_protect` 流程时不要漏掉"恢复 RX + 刷 icache"这一步，否则 dyld 执行 JGBSDK 自身初始化代码时会 `KERN_PROTECTION_FAILURE`
3. **dyld 镜像枚举对抗不能改回全局重排** — 必须保持 `dladdr` 作用域限定（`caller_is_detector()`）+ vis-map 缓存，否则 Flutter 按索引访问镜像会导致主线程冻结
4. **贝壳找房与链家是否分叉** — 当前假定两者共用同一检测栈，一份 tweak 覆盖两者；若某一方单独出现新检测面需要分别验证
5. 详见 `llmdoc/architecture/lianjiabypass-architecture.md`、`llmdoc/reference/lianjiabypass-detection-vectors.md`

发版检查清单见 `llmdoc/guides/ci-cd-release.md`。
