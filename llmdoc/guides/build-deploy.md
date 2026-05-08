# 构建、部署与验证指南

## 适用范围

本指南用于在当前已验证环境中构建并部署 MYBankBypass：

- macOS 开发机
- Theos 安装在 `~/theos`
- 目标设备为 rootless 越狱环境
- 当前已验证设备：iPhone 14 Pro Max / iOS 16.3.1 / Dopamine / Sileo
- 当前目标 App：网商银行 `4.6.4`、`4.7.36`

## 相关文件

- `mybankbypass/Makefile`
- `mybankbypass/control`
- `mybankbypass/MYBankBypass.plist`
- `mybankbypass/Tweak.x`

## 构建前确认

先确认以下事实与当前环境一致：

- `mybankbypass/Makefile` 中使用 `THEOS_PACKAGE_SCHEME = rootless`
- 架构为 `arm64`
- 目标进程为 `Portal`
- 目标设备 SSH 为 `root@192.168.1.253:22`
- 目标包过滤为 `com.mybank.ios.phone`
- `control` 中版本号与准备发布的 tweak 版本一致

当前发布版本为 `1.1.0`，文档、`control` 与发版 tag 应保持同步。

## 构建步骤

在项目根目录下进入 tweak 子目录后执行：

```bash
make clean
make package
```

说明：

- `make clean` 用于清理旧的构建产物，避免调试残留影响判断。
- `make package` 会编译 `Tweak.x` 并在 `packages/` 下生成 rootless `.deb` 包。

如果只想快速验证能否编译，也可以先执行：

```bash
make
```

## 部署到设备

在 `mybankbypass/` 目录执行：

```bash
make install
```

该流程会使用 Makefile 中的设备 IP/端口，通过 SSH 把生成的 `.deb` 安装到设备，并按 Theos 流程处理目标进程重载。

如果需要手动安装，可使用等价流程：

1. 通过 `scp` 把 `packages/` 中最新 `.deb` 传到设备
2. 在设备上用 `dpkg -i` 安装
3. 重新启动目标 App

## 发版与 Tag 规则

当前 GitHub Actions Release workflow 依赖特定 tag 格式：

- 生效 tag 格式：`mybankbypass_X.Y.Z`
- `1.1.0` 对应的生效 tag：`mybankbypass_1.1.0`
- `v1.1.0` 这类 tag 可以保留作版本标记，但不会触发当前 release workflow

发布流程结果：

- Release workflow 自动构建 `.deb`
- 自动创建 GitHub Release
- 自动更新 Sileo 软件源内容

因此发版时应优先确认触发 CI 的 tag 是否符合 `*_X.Y.Z` 规则，而不要只打 `vX.Y.Z`。

## 部署后验证

最小验证流程：

1. 确认设备上已安装最新版本 tweak 包。
2. 完全关闭网商银行 App。
3. 重新启动网商银行。
4. 观察是否能稳定停留在前台，不再在 3-5 秒内退出。
5. 进入常用页面做基本冒烟验证，确认未出现明显卡死、白屏或异常跳转。

如果需要更细的回归检查，建议依次确认：

- App 启动后是否立即闪退
- 启动后 3-5 秒内是否触发延迟退出
- 登录前页面是否正常渲染
- 登录后基础导航是否正常
- 是否出现因目录访问或线程异常引发的卡死
- 是否出现“App 没退出，但首页或后续业务冻结”的假活状态

## 回归关注点

每次修改 `Tweak.x` 后，优先回归以下风险点：

### 1. 低层 C Hook 是否仍然纯 C

不要在 `stat/open/readlink` 等 Hook 中引入 ObjC 对象创建、`NSString` 转换或其他消息发送逻辑。若这样做，容易重新引入重入和稳定性问题。

### 2. 不要恢复 `opendir` Hook

历史经验表明，`opendir` Hook 会带来 watchdog 或其他异常行为。若确实怀疑目录枚举出现新检测，优先从高层目录结果过滤入手，而不是重新拦截 `opendir`。

### 3. 退出 Hook 必须保持 `noreturn` 安全

若调整 `exit` / `_exit` / `abort` Hook，必须保证实现不会返回。主线程继续跑 RunLoop、后台线程永久阻塞是当前已验证方案。

### 4. rootless 路径与文件系统探针是否覆盖完整

新版本 App 若新增 `/var/jb` 派生路径、Frida 痕迹检查、`statfs` / `statvfs` 探针，需同步扩展覆盖点。

### 5. 安全框架与 launcher 类名是否变化

若 App 升级后再次检测命中，优先检查 `IOSSecuritySuite`、`SecurityGuard`、`MYBLauncherController` 及相关 selector 和返回类型是否发生变化。

## 常见问题排查

### 编译成功但 App 仍退出

优先检查：

1. 是否安装到了正确设备
2. 注入过滤是否仍匹配 `com.mybank.ios.phone`
3. 目标进程名 `Portal` 是否变化
4. 是否回退了三个关键修正：纯 C 匹配、移除 `opendir`、`noreturn` 安全退出 Hook
5. App 是否升级到了未验证版本

### 安装后 App 卡死或表现异常

优先怀疑：

- 新增 Hook 在低层路径上引入 ObjC 调用
- 修改了终止 Hook 但破坏了主线程 RunLoop 行为
- dyld 镜像计数与名称映射不一致
- launcher/controller 级别的 jailbreak check 仍在命中，导致业务流被冻结

### Frida 枚举类或方法失败

当前环境下 Frida 的 ObjC bridge 不可用。此时应：

1. 改用 `libobjc` 原生 C 接口做手工 introspection
2. 避免把“ObjC bridge 无输出”误判为类不存在
3. 判断目标进程时优先使用 bundle id `com.mybank.ios.phone`，不要依赖 Frida 中显示的中文进程名“网商银行”

### 版本更新时怎么开始适配

建议顺序：

1. 先比对 `ANALYSIS.md`、`llmdoc/reference/detection-vectors.md` 与新版本行为差异
2. 优先检查 launcher/controller 的本地越狱判断是否新增或变更
3. 再检查 `Tweak.x` 当前覆盖点是否仍存在
4. 仅对出现变化的检测面增量补 Hook
5. 每次改动后都回归启动稳定性、3-5 秒退出现象，以及是否出现“假活冻结”
