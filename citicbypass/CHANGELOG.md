# CITICBypass 更新日志

## 1.0.0

首个发布版。目标 App 中信银行（`com.citic.mobile`）12.2.8，在 rootless 越狱（Dopamine + ElleKit）环境下不再弹出「检测到当前设备存在注入风险」，首页、账户、我的页面均可正常打开。验证到登录页为止。

- **检测栈**：梆梆安全 Everisk（BCES），编译期静态链入主二进制，与国家网络身份认证（whbypass）同源。主二进制里一共 23 个检测项，形状都是 `+(name)` 加 `-(check)`，其中两个有可读类名（`BCESCheckerEnvironment`、`BCESCheckerInject`），另外 21 个类名随机化。
- **三种弹窗对应三条判定**：「检测到存在攻击框架」只在 frida-server 运行时出现；「监测到您的系统已越狱」来自 `+[CBAppRiskEvent jailBreakJudge]`；「检测到当前设备存在注入风险」只由「有没有额外镜像被加载」触发，与具体 hook 了哪个方法无关——只载入 dylib、零 hook 的探针同样会弹。
- **主要手段是短路全部检测项**：枚举主二进制里的类，凡是同时实现 `-(check)` 和 `+(name)` 的，把 `-(check)` 换成空实现。检测照常被跑过，但不产生结论。只遍历主二进制而不遍历全类表，是因为这台设备上有 44620 个类，逐个做 `respondsToSelector` 会把启动拖过 watchdog 的 20 秒预算。
- **发布版没有使用 `%hook`**：0.0.4 用 15 个 `%hook` 之后，主线程立刻 `EXC_BAD_ACCESS`：`SP` 里是含 `DEAD` 的哨兵值，`PC` 落在 `__PAGEZERO` 区间内的 `0xb5a98000`，与 whbypass 记录过的毒地址 `0xb5a01000` 是同一手法。全部改用 `method_setImplementation` 之后崩溃消失。**崩溃的触发条件没有查清**，这两者都只改方法表、不碰指令字节，所以不能据此断定检测方是在查 hook。三个待验证的候选写在 `analysis.md` 第 3 节。发布版的动态依赖只剩系统库，不再链接 substrate。
- **置空 `+[CBAppRiskEvent jailBreakJudge]`**：它是 `void` 函数，唯一副作用是弹出「监测到您的系统已越狱」对话框并上报 `rootOpen` 埋点。那句文案在函数体里以 XOR 内联加密存放（密钥是 `i - 0x18`），运行时解出来交给 `localizedStringForKey:`，再交给 `CBAlert` 建单按钮对话框。
- **另外两条判定**：`+[GMRZIsJailBreak isJailBreak]` 和 `+[exJailBreak isJailBreak]` 一并置否。
- **已知边界**：只验证到登录页，转账、理财等需要实名的业务没有测试。`rootOpen` 埋点被跳过后，服务端是否会另行判定，本地没有观测手段。`CITICSquareSDK` 的 `deviceRiskCheck` 与 WebView 里的 `showDeviceRisk` 在登录后才走到，目前没有触发过。

## 0.0.1 – 0.0.6

> 诊断迭代，未发布。过程记录在 `analysis.md`。
