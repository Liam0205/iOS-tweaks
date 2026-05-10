# Linux x86_64 交叉编译环境搭建反思

## 时间

2026-05-09

## Task

在 Linux x86_64 (Ubuntu, 无 sudo 权限) 环境中搭建 Theos iOS 交叉编译环境，使其能在非 macOS 系统上编译 iOS tweak 的 .deb 包。

## Expected vs Actual

- **预期**: 按 Theos 官方文档安装即可直接编译。
- **实际**: 工具链 clang 版本过旧导致无法处理 iOS 16.5 SDK 的 module 系统，需混合使用系统 clang + 工具链 ld64，并手动解决多个库路径和符号链接问题。

## What Went Wrong

1. sbingner 工具链的 clang-10 无法编译针对 iOS 16.5 SDK 的代码（报 `could not build module 'Foundation'`）
2. 工具链下载后目录名 (`ios-arm64e-clang-toolchain`) 与 Theos 期望路径 (`~/theos/toolchain/linux/iphone/bin/`) 不一致
3. 系统 clang 替代工具链 clang 后，默认使用 GNU ld 而非工具链的 ld64，产生 `unrecognised emulation mode: llvm` 链接错误
4. brew ncurses 只提供 `libtinfo.so` 而工具链期望 `libtinfo.so.5`

## Root Cause

- sbingner 工具链长期未维护，内置 clang-10 与现代 iOS SDK (16.x+) 的 Clang Module 系统不兼容
- Theos 的 Linux 工具链路径约定是硬编码的，不容许目录名偏差
- 系统 clang 对链接器的选择逻辑与 Theos 工具链假设冲突——Theos 假设 clang 和 ld 在同一目录
- brew 的 ncurses 包遵循现代 soname 约定 (不带数字后缀)，与工具链二进制的 NEEDED 记录不一致

## 解决方案

### 依赖安装 (无 sudo, 用 Homebrew)

```bash
brew install ldid xz ncurses
# 系统已有: dpkg, fakeroot, make
```

### Theos + SDK 安装

```bash
git clone --recursive https://github.com/theos/theos.git ~/theos
curl -sL https://github.com/theos/sdks/archive/master.tar.gz | tar xz --strip-components=1 -C ~/theos/sdks/
```

### 工具链修复: 系统 clang 替代 + 保留 ld64

```bash
# 在 ~/theos/toolchain/linux/iphone/bin/ 中:
mv clang clang.orig
ln -s $(which clang) clang
# 保留 ld (ld64) 不动——这是 Linux 上唯一可用的 Mach-O 链接器
```

### libtinfo 兼容 symlink

```bash
ln -s /home/linuxbrew/.linuxbrew/lib/libtinfo.so /home/linuxbrew/.linuxbrew/lib/libtinfo.so.5
```

### 最终构建命令

```bash
export THEOS=~/theos
export LD_LIBRARY_PATH=/home/linuxbrew/.linuxbrew/lib:$LD_LIBRARY_PATH
make package FINALPACKAGE=1 ADDITIONAL_LDFLAGS="-B$THEOS/toolchain/linux/iphone/bin -fuse-ld=$THEOS/toolchain/linux/iphone/bin/ld"
```

关键参数说明:
- `-B<path>`: 告诉 clang 在该路径搜索辅助程序 (ld)
- `-fuse-ld=<path>`: 显式指定链接器二进制路径，绕过系统 GNU ld

## 风险与局限

- 混合方案脆弱: 未来系统 clang 大版本升级可能生成工具链 ld64 无法处理的 object 格式
- libtinfo.so.5 symlink 是 workaround，brew 升级 ncurses 时可能需要重建
- 此方案依赖 sbingner ld64 作为唯一的 Linux Mach-O 链接器——如果 ld64 也不兼容，唯一退路是在 macOS 或 CI (GitHub Actions macOS runner) 上构建

## Missing Docs or Signals

- `guides/build-deploy.md` 仅描述 macOS 构建流程，无 Linux 交叉编译的说明
- 项目文档中未记录 CI runner 的实际运行环境与工具链版本
- Theos 工具链路径约定 (`toolchain/linux/iphone/bin/`) 未在项目文档中明确标注

## Promotion Candidates

| 内容 | 目标位置 | 理由 |
|------|----------|------|
| Linux 交叉编译完整步骤 | `guides/build-deploy.md` 新增 "Linux 环境" 章节 | 可复现的操作指南，非一次性知识 |
| ADDITIONAL_LDFLAGS 参数 | `guides/build-deploy.md` 构建步骤 | 必要的环境差异说明 |
| 工具链版本兼容矩阵 (clang vs SDK) | `reference/` 新建或加入现有参考文档 | 帮助判断未来升级 SDK 时是否需要更新 clang |

## Follow-up

1. 在 `guides/build-deploy.md` 中补充 Linux 交叉编译章节（含依赖、工具链修复步骤、构建命令）
2. 确认 GitHub Actions CI 的 `build.yml` 是否也受此问题影响（CI 用 macOS runner 则不受影响）
3. 监控 sbingner toolchain 仓库是否有更新版 clang 发布；如有，测试是否可去除混合方案
