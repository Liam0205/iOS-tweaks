# CITICBypass 实验记录

目标：`com.citic.mobile`（中信银行 CiticMobileBank 12.2.8 build 2），
设备 iPhone 13 Pro / iOS 15.4.1 / rootless Dopamine + ElleKit。

原始症状：App 能进首页，随后弹出一个自绘对话框，文案是
「检测到当前设备存在注入风险，为了您的账户资金安全，请更换设备。」，
点「确定」后进程退出。

## 1. 检测栈身份

主二进制 69 MB，arm64，检测引擎是梆梆 Everisk（BCES），静态链入，没有独立框架。
与国家网络身份认证（whbypass）同源，但表现不同：那边直接闪退，这边弹对话框。

主二进制里与检测相关的类：

| 类 | 关键方法 | 作用 |
|---|---|---|
| `BCESCheckerEnvironment` | `-(check)`、`+name`、`initWithCheckRoot:checkRiskFrame:checkFrida:` | 环境（越狱根、Frida）检查 |
| `BCESCheckerInject` | `-(check)`、`+name`、`inlineHookedInfo`、`swizzleHookedInfo`、`attackFrame` | 注入检查；后两个方法名指向 hook 自检，实际检查对象未经验证 |
| `BCESRiskStub` | `+alertForEvent:withAction:` 等 30 个类方法 | SDK 对外接口 |
| `CBAppRiskEvent` | `+jailBreakJudge`、`+riskEventJudge`、`+riskEventAlert:` | 中信自己的风控汇总 |
| `CBAlert` | `-initOneBtnWithTitle:message:type:priority:blockType:block:` | 自绘对话框 |
| `GMRZIsJailBreak` | `+isJailBreak`、`+checkCydia/checkDylibs/checkInject` | 另一套越狱判定 |
| `exJailBreak` | `+isJailBreak` | 第三个越狱判定 |

此外还有 21 个名字随机化的类，形状与上面两个 `BCESChecker*` 完全一样，
都是 `+(name)` + `-(check)`。运行期枚举主二进制里的类，一共命中 23 个。

## 2. 三条弹窗文案，各自对应一条判定

| 文案 | 触发条件 | 来源 |
|---|---|---|
| 检测到存在攻击框架，为了您的账户资金安全，请更换设备。 | frida-server 在运行 | `BCESCheckerEnvironment` 的 Frida 检查 |
| 监测到您的系统已越狱，继续使用可能造成安全隐患。 | 没有 tweak 绕过越狱判定 | `+[CBAppRiskEvent jailBreakJudge]` |
| 检测到当前设备存在注入风险，为了您的账户资金安全，请更换设备。 | 有任意第三方 dylib 被注入 | Everisk 的注入检查 |

第三条最关键：**探针 A（只载入 dylib、零 hook）同样会触发它**，说明它判的是
「有没有额外镜像被加载」，与具体 hook 了哪个方法无关。

## 3. 0.0.4 的崩溃

0.0.4 用了 15 个 `%hook`，App 启动后主线程立刻崩溃：

```
EXC_BAD_ACCESS (SIGSEGV), KERN_INVALID_ADDRESS at 0xb5a98000
reportNotes: SP register contains suspicious bits (0x21915ECDDEAD52FC)
```

`0xb5a98000` 落在 App 的 `__PAGEZERO` 区间（0 到 0x100000000）内，永远无法映射。
SP 里那个含 `DEAD` 的常量是典型的哨兵值，意思很明确：检测方主动破坏栈指针再跳飞。
whbypass 记录过同一个手法，毒地址是 `0xb5a01000`，两者只差一个页表项。

崩溃的触发条件至今没有查清。0.0.4 之后的探针改用 `method_setImplementation`，崩溃消失，
但两者都在方法表层面，差别没有落在最初的猜测上。

早前写的归因是「`%hook` 底层走 `MSHookFunction`，改了函数序言字节，被
`BCESCheckerInject` 的 `inlineHookedInfo` 查出来」。这条是错的：`%hook` 由 Logos
展开成 `MSHookMessageEx`，换的是 Method 里的 IMP，不碰指令字节。把
`inlineHookedInfo` 当成拦截点，等于假设它查了它实际查不到的东西。

目前没有证据支持任何一条解释，只有三个待验证的候选：

1. `MSHookMessageEx` 在方法来自父类时会用 `class_addMethod` 往本类方法表加一条新记录，
   而 `method_setImplementation` 只改已有条目的 IMP。类自己多出一条方法，是可观测的。
2. 0.0.4 的 Makefile 里还留着 `substrate`，二进制因此多一条对注入框架的动态依赖；
   1.0.0 删掉之后，动态依赖只剩系统库。
3. 检测方看的是别的特征。具体是什么，还没有定位。

要分清这三条，需要两组对照探针：一组只链 substrate、零 hook，一组只链 substrate、
只用 `method_setImplementation`。这组实验一直没做。

## 4. 解法

三步，都在 constructor 里完成，总耗时不到 100 ms：

1. **短路全部检测项。**枚举主二进制里的类，凡是同时实现 `-(check)` 和 `+(name)`
   的，把 `-(check)` 换成空实现。检测照常被「跑过」，但不产生结论。
   必须只遍历主二进制，不能遍历全类表——这台设备上有 44620 个类，
   逐个做 `respondsToSelector` 会把启动拖过 watchdog 的 20 秒预算。

2. **置空 `+[CBAppRiskEvent jailBreakJudge]`。**
   这条文案在函数里以 XOR 内联加密存放（密钥是 `i - 0x18`），
   运行时解出来交给 `localizedStringForKey:` 取文案，随后调 `CBAlert` 建单按钮弹窗，
   并上报埋点 `rootOpen`。函数返回类型是 `void`，返回值无人使用，
   所以直接跳过原实现就等于把这项判定判为无风险。

3. **把 `GMRZIsJailBreak` 和 `exJailBreak` 的 `+isJailBreak` 置否。**

## 5. 验证结果

| 版本 | 手段 | 结果 |
|---|---|---|
| 0.0.1–0.0.3 | `%hook` 各类 | 弹窗仍在 |
| 0.0.4 | 15 个 `%hook` | 主线程 EXC_BAD_ACCESS，SP 被破坏 |
| 探针 A | 只载入、零 hook | 「注入风险」弹窗仍在 |
| 探针 B | `method_setImplementation` | 拦截弹窗消失，仅剩剪贴板授权提示 |
| 0.0.6 | 探针 B + 风控层置空 | 直接进首页；点「账户」能到登录页 |

## 6. 尚未验证的部分

- 只验证到登录页。转账、理财等需要实名的业务没有测试。
- 埋点 `rootOpen` 被跳过后，服务端是否会另行判定，没有观测手段。
- `CITICSquareSDK` 的 `deviceRiskCheck` 与 WebView 里的 `showDeviceRisk`
  在登录后才走到，目前没有触发过。
