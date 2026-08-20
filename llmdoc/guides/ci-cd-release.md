# CI/CD 与发版指南

## 适用范围

本指南覆盖 tag 触发的自动发版流程、GitHub Actions 矩阵构建配置，以及 macOS CI 环境与本地 Linux 交叉编译环境的差异排查。本地构建与部署步骤见 `llmdoc/guides/build-deploy.md`。

## 相关文件

- `.github/workflows/release.yml` — 自动发版与 Pages 部署
- `.github/workflows/build.yml` — CI 验证构建（矩阵）

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

## macOS CI 与本地 Linux 交叉编译的结构性差异

本地 Linux 开发机用的是打过 patch 的 `iPhoneOS16.5.sdk`（含 `Preferences.framework`、`FrontBoardServices` 等私有 framework 的 stub），GitHub 的 macOS runner 用 Xcode 自带的标准 iOS SDK，**不含任何私有 framework stub**。链接私有 framework 时 macOS CI 会直接报 `ld: framework 'X' not found`，本地却能正常编译——这个差异只在 CI 上才会暴露，且历史失败日志会在约一个月后被 GitHub 回收（HTTP 410），排查前通常需要重新触发一次 run 才能拿到新鲜报错。

引用私有 framework 有两种不同根因，修法不同：

1. **仅运行时消息发送使用的类**（如 `FBSSystemService`、`LSApplicationWorkspace`，本地 `@interface` 声明后 `[SomeClass method]` 调用）：链接器仍会在符号表里留下 `_OBJC_CLASS_$_` 引用。改成 `objc_getClass("ClassName")` 运行时获取类即可从源头消除这个链接期符号，干净且可移植，不依赖特定 SDK。
2. **编译期继承依赖**（如某个类的父类是 `PSListController`，必须实际链接 `Preferences.framework`）：无法用运行时技巧绕开，必须让 CI 拿到带 stub 的 SDK。做法是从 `https://github.com/theos/sdks` 用 sparse-checkout 只拉取需要的那一个 SDK 版本到 `$THEOS/sdks`，并用 `actions/cache` 以 `theos-sdk-<SDK名>` 为 key 缓存，避免每次 CI 都重新拉取。

**关键陷阱**：仅仅把带 stub 的 SDK 放进 `$THEOS/sdks` 并不够。theos 的 `TARGET := iphone:clang:latest:X` 里的 `latest` 会解析为"当前可用 SDK 中版本号最高的那个"，而 Xcode 自带标准 SDK 的版本号通常比打过 patch 的 SDK 更高（如标准 SDK 18.x vs 打 patch 的 16.5），theos 仍会挑中没有 stub 的标准 SDK,构建照样失败。必须在 Build 步骤的环境变量里显式传 `SYSROOT=$THEOS/sdks/iPhoneOS16.5.sdk`（替换为实际需要的 SDK 版本），强制锁定到带 stub 的那个,不能依赖 `latest` 的自动解析。

## CI 矩阵与 workflow 配置要点

- **`strategy.fail-fast: false` 是硬性要求**：`build.yml` 对多个 tweak 做矩阵构建，默认 `fail-fast: true` 会让某一个 tweak 失败时直接取消其余所有任务（显示为 "cancelled"，视觉上和"失败"混在一起，无法分辨哪个 tweak 真正出了问题）。必须设为 `false`，让每个 tweak 独立构建、独立报告结果。
- **新增 GitHub Action 时要核对其自身 Node 运行时版本**，不能只看主版本号升级就认为已跟上最新 runtime。例如 `actions/cache` v4 仍停留在 node20，即使是"新加入"的 action 也可能引入 Node 20 弃用警告。已知需要 node24 的稳定版本：`actions/checkout` v5、`actions/upload-artifact` v6+（v5 仍是 node20）、`softprops/action-gh-release` v3、`actions/cache` v5。

## Logos 跨平台注意事项

`%orig` **不能直接作为消息发送的接收者**，要先赋值给局部变量再使用。同一份 Logos 源码在 Linux theos 上编译正常，但在 macOS theos 上会在 `%orig` 展开位置报 `error: expected identifier`——两个平台的 Logos 版本对这种写法的展开方式不一致。

```objc
// 错误：%orig 直接作为接收者，macOS 上编译失败
NSMutableDictionary *env = [%orig mutableCopy];

// 正确：先赋值给局部变量
NSDictionary *orig = %orig;
NSMutableDictionary *env = [orig mutableCopy];
```

## 发版后验证

**必须直接核对服务端，不能只看 tag/CI 状态**：tag 已推送、CI 显示成功，都不等于"已经发布成功"。必须直接 curl gh-pages 上的 Packages 索引和真实 deb 下载 URL 确认存在。若设备上仍看不到新版本，先分开排查"服务端是否正确"（Packages 索引 + deb URL + CDN 缓存头）和"客户端缓存是否过期"（Sileo 的 Sources 标签页下拉刷新通常能解决），不要一开始就假设发版流程本身出了问题。

## 发版检查清单

新增 tweak 或发版前应确认：

1. `control` 文件包含 `SileoDepiction: https://tweaks.0x01.page/depictions/<package-id>.json`
2. tweak 目录下存在 `CHANGELOG.md`（否则 depiction 使用 fallback 文本）
3. `release.yml` 第 93 行的 gh-pages 清理列表包含该 tweak 目录名
4. `build.yml` 的 `paths-ignore` 列表中不要意外排除新 tweak 的文件
5. Release notes 范围为 `PREV_TAG..TAG`（不是 HEAD），确认 workflow 逻辑正确
6. 对应的 `llmdoc/architecture/` 文档已同步更新（版本号、行为变更）
7. 若新 tweak/App 引用私有 framework（如继承 `PSListController`），确认 CI 的 `SYSROOT` 环境变量已锁定到带 stub 的 SDK 版本，不要依赖 theos `latest` 自动解析
8. 确认 `build.yml` 矩阵仍设置 `strategy.fail-fast: false`，避免单个 tweak 失败掩盖其余任务结果
9. 发版后直接 curl gh-pages 的 Packages 索引和真实 deb URL 验证，不要只看 tag/CI 状态
