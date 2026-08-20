# lianjiabypass 发布与 CI/CD 加固反思

## 任务

单次会话完成两件事：

1. lianjiabypass（链家 com.exmart.HomeLink + 贝壳找房 com.lianjia.beike，进程名 LJShell，两者共享 JGBSDK + a.framework 检测）从 v0.0.20 清理为发布版本，作为首次公开发布 0.1.0。
2. 在诊断 simtouch 为何从未真正出现在 Sileo 源上的过程中，顺带加固了整条 CI/CD 发版流水线（`.github/workflows/release.yml`、`.github/workflows/build.yml`）。

## 预期与实际结果

- 预期：lianjiabypass 发布是常规流程；simtouch 只是需要重新触发一次发版。
- 实际：lianjiabypass v0.0.20 里混有大量诊断脚手架，必须先清理才能发布；simtouch 从未发布成功过，根因是 macOS CI 的 iOS SDK 天生缺少私有 framework stub，且这个问题被 CI 矩阵的 `fail-fast` 掩盖，历史失败日志又因 GitHub 410 过期而无法直接查证，需要重新触发才能看到真实报错。

## 出现的问题

### 1. 发布版本混入诊断脚手架（lianjiabypass）

v0.0.20 中存在：定时 `thread_suspend` 主线程的看门狗线程；对 SIGABRT/SEGV 等信号的 sigaction 探针；对 exit/_exit/abort/kill/pthread_kill 的追踪 Hook（含 fp-chain 回溯打印）；`LJ_TRACE_ALL_STAT` 路径追踪器。这些代码在诊断阶段有用，但看门狗定时挂起主线程本身就是生产环境的稳定性风险，必须在发布前整段剥离，而不是留着"以防以后要用"。

处理方式：把诊断代码收进编译期开关 `LJ_DEBUG_LOG`（关闭时编译结果为零开销），看门狗类代码直接物理删除，不留开关。需要清楚区分"诊断用的临时观测代码"和"真正生效的绕过层"，前者可以整段删，后者才是要保留和维护的核心逻辑。

### 2. macOS CI 缺少私有 framework stub，是 simtouch 从未发布成功的根因

Linux 开发机上 theos 用的是打过 patch 的 iPhoneOS15.6.sdk，里面带有 Preferences.framework、FrontBoardServices 等私有 framework 的 stub，所以本地能编译通过。GitHub 的 macOS runner 用 Xcode 自带的标准 iOS SDK，没有任何私有 framework stub，链接 `Preferences` 或 `FrontBoardServices` 时直接报 `ld: framework 'X' not found`。

simtouch 的偏好设置 bundle 继承自 `PSListController`（Preferences 私有框架的类），Tweak.x 里又引用了 `_OBJC_CLASS_$_FBSSystemService` / `_OBJC_CLASS_$_LSApplicationWorkspace`，每次 CI 发版都在 Build 步骤直接失败。因为矩阵 `fail-fast: true`，这个失败会连带取消其他 tweak 的构建任务，日志上看起来像"全部失败"，掩盖了真实情况；旧的失败日志又在约一个月后被 GitHub 回收（HTTP 410），只能重新触发一次 run 才能拿到新鲜的报错信息。

**教训**：不能把"有 tag、CI 跑过"当作"已经发布成功"的证据，必须直接核对 gh-pages 上的 Packages 索引和真实的 deb 下载 URL 才算验证到位。诊断 CI 问题前先确认矩阵有没有 `fail-fast` 掩盖了单独失败项。

### 3. 私有 framework 的两种不同修复路径

同样是"引用私有 framework"，但根因不同,修法也不同：

- (a) 只是通过 `[SomeClass method]` 运行时消息发送使用的类（如 `FBSSystemService`、`LSApplicationWorkspace`，本地 `@interface` 声明），链接器仍会在符号表里留下 `_OBJC_CLASS_$_` 引用。改成 `objc_getClass("ClassName")` 运行时获取类,即可从源头消除这个链接期符号,干净且可移植。
- (b) 真正的编译期继承依赖(如 `PSListController` 是父类，必须实际链接 Preferences)无法用运行时技巧绕开，必须让 CI 拿到带 stub 的 SDK。做法是从 https://github.com/theos/sdks 用 sparse-checkout 只拉取需要的那一个 SDK 到 `$THEOS/sdks`。

**关键陷阱**：仅仅把带 stub 的 SDK 丢进 `$THEOS/sdks` 并不够。theos 的 `TARGET := iphone:clang:latest:X` 里的 `latest` 会解析成"当前可用 SDK 里版本号最高的那个"，而 Xcode 自带的标准 SDK 版本号（如 18.x）通常比打过 patch 的 SDK（如 16.5）更高，于是 theos 仍然会挑中没有 stub 的标准 SDK，构建照样失败。必须在 Build 步骤的环境变量里显式传 `SYSROOT=$THEOS/sdks/iPhoneOS16.5.sdk`，强制锁定到带 stub 的那个 SDK,不能依赖 `latest` 的自动解析。

### 4. CI 矩阵的 fail-fast 会掩盖独立结果

`.github/workflows/build.yml` 的 build job 是对所有 tweak 的矩阵构建，默认 `fail-fast: true`，导致某一个 tweak 失败会直接取消其余所有任务（显示为 "cancelled"，视觉上和"失败"混在一起，无法分辨哪个 tweak 真正出了问题）。改为 `strategy.fail-fast: false` 后每个 tweak 独立构建、独立报告结果。

### 5. Logos 里 `%orig` 直接作为消息接收者,在不同环境下展开方式不一致

`abcbypass`/`bankcommbypass`/`icbcbypass`/`mybankbypass` 的 NSProcessInfo environment Hook 里都有类似写法：

```objc
NSMutableDictionary *env = [%orig mutableCopy];
```

这段代码在 Linux theos 的 Logos 上编译正常，但在 macOS theos 上会在 `%orig` 展开的位置报 `error: expected identifier`。即同一份 Logos 源码,在 Linux 和 macOS 上用的 Logos 版本对"`%orig` 直接作为消息发送的接收者"这种写法的展开方式不一致。

修复：拆成两条语句，不要让 `%orig` 直接出现在方括号消息发送的接收者位置：

```objc
NSDictionary *orig = %orig;
NSMutableDictionary *env = [orig mutableCopy];
```

**规则**：以后新写 Logos Hook,永远不要把 `%orig` 直接放在消息发送的接收者位置,先赋值给局部变量再使用。

### 6. GitHub Actions 的 Node 20 弃用

以下 action 版本升级以消除 Node 20 弃用警告：`actions/checkout` v4→v5（v5 是 node24）、`actions/upload-artifact` v4→v7（v5 仍是 node20，v6 起才是 node24）、`softprops/action-gh-release` v2→v3（v3 是 node24）、`actions/cache` v4→v5（v5 是 node24）。

**教训**：新增一个之前没用过的 action（本次是 `actions/cache`）时,要单独确认它自己的 Node 运行时版本,不能假设"看起来是新加的就一定是新版本"——`actions/cache` v4 仍然停留在 node20,新增后反而重新引入了弃用警告。

### 7. SDK 下载慢，需要缓存

每次 CI 运行都从 theos/sdks 做 sparse-checkout 比较慢，用 `actions/cache` 以 `theos-sdk-iPhoneOS16.5` 为 key 缓存 `~/sdk-cache`；Install 步骤改为仅在缓存目录不存在时才执行 clone。

### 8. Sileo 客户端缓存导致"看起来没发布成功"

simtouch 发布流程本身跑通之后，用户在设备上的 Sileo 里仍然看不到新版本。服务端其实是正常的（gh-pages 上的 Packages 索引、真实 deb URL、CDN 的 `max-age=600` 都正确），根因是 Sileo 客户端自身的缓存，在 Sources 标签页下拉刷新后就恢复正常。

**教训**：遇到"发布了但设备上看不到"时，要先把"服务端是否真的正确"（直接 curl Packages 索引和 deb URL）和"客户端缓存是否过期"分开排查，不要一开始就假设是发版流程出了问题。

## 根本原因

- lianjiabypass 问题的根源是开发阶段的诊断代码没有和发布代码物理隔离，导致"发布"退化成"删代码"而不是"切换编译开关"。
- simtouch 从未发布成功的根源是本地开发环境（Linux + 打过 patch 的 SDK）和 CI 环境（macOS + Xcode 标准 SDK）在私有 framework 可用性上存在结构性差异，而这个差异被 CI 矩阵的 `fail-fast` 和 GitHub 日志的时效性（410 过期）共同掩盖，导致问题存在了较长时间才被发现。

## 缺失的文档或信号

- `llmdoc/guides/build-deploy.md` 里没有说明"本地 Linux 交叉编译环境的 SDK 和 macOS CI 的 SDK 在私有 framework 支持上不同"这一结构性差异，导致这个问题只能靠现场排查发现。
- 没有文档说明"tag 已推送 / CI 显示成功"不等于"gh-pages 上确实能下载到对应 deb"，需要有一条明确的发版后验证步骤。
- 没有文档记录 Logos `%orig` 作为消息接收者在 Linux/macOS 两种 theos 环境下行为不一致，这是本仓库多个 tweak 共享的历史写法，容易在下一次跨平台构建时重新踩坑。

## 晋升候选

以下几条是稳定的、后续大概率会再次用到的构建/CI 知识，建议提给 recorder 晋升进 `llmdoc/guides/build-deploy.md`：

1. macOS CI 私有 framework 缺 stub 问题及两种修复路径（`objc_getClass` 运行时解耦 vs `SYSROOT=$THEOS/sdks/<SDK>` 强制指定 SDK，因为 `latest` 会被更高版本号的标准 SDK 抢占）。
2. CI 矩阵构建必须设置 `strategy.fail-fast: false`，否则一个 tweak 失败会掩盖其余 tweak 的独立构建结果。
3. Logos 规则：`%orig` 不能直接作为消息发送的接收者，要先赋值给局部变量。
4. 发版验证不能只看 tag/CI 状态，要直接核对 gh-pages Packages 索引和真实 deb URL；客户端（Sileo）缓存问题和服务端问题要分开排查。
5. 新增 GitHub Action 时要核对该 action 自身的 Node 运行时版本，不能只看主版本号升级就认为已经跟上最新 runtime。

## 后续行动

- 下次改动任何 tweak 的 CI 相关内容（`build.yml` / `release.yml`）时，先确认 `fail-fast` 设置和 SYSROOT 是否仍然生效，避免这两处配置在后续修改中被无意覆盖。
- 若后续新增 tweak 依赖其他私有 framework，直接复用本次总结的两种修复路径判断准则（运行时消息 vs 编译期继承），不必重新排查。
- 建议在下一次执行 `/llmdoc:update` 时，把本反思中的晋升候选条目写入 `llmdoc/guides/build-deploy.md`。
