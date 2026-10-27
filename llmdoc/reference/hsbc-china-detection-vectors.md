# 汇丰中国越狱检测向量

## 目的

本文档汇总汇丰中国 App 已知的越狱检测向量、判定输出与当前绕过覆盖状态。

## 目标与背景

- 目标 App：`cn.com.hsbc.hsbcchina`
- 当前版本：**`3.75.0`（build 129890）**，2026-10 实测
- 主 Binary：`China.app/China`（arm64, ~12.6 MB）
- 测试设备：iPhone 13 Pro / iOS 15.4.1（22215，rootless Dopamine + ElleKit）
- 判定引擎：**ZDefend.framework（Zimperium）**
- 对应 tweak：项目目录 `hsbcchinabypass/`，包名 `page.0x01.hsbcchinabypass`，
  1.0.1 起生效（1.0.0 及更早叫 `hsbcbypass` / `page.0x01.hsbcbypass`，已由
  `Conflicts`/`Replaces` 接替）

> ⚠️ **本文档只讲汇丰中国。** 汇丰香港（`hk.com.hsbc.hsbchkmobilebanking`）是另一套
> 技术栈，既没有 ZDefend 也没有 Promon，见
> `llmdoc/reference/hsbc-hk-detection-vectors.md`。两者曾在同一个 `hsbcbypass` 包里，
> 2026-10-27 拆分改名。

> ⚠️ **本文档在 Round 78 重写。** 3.75.0 之前的版本用的是 Promon SHIELD，
> 可执行文件也是 `Frameworks/hsbcchinax.framework/hsbcchinax`，两者都已不存在。
> Promon 时期的结论（私有 svc 网关、`PRMShieldEventManager`、`mach_vm_read_overwrite`
> 读库头）只对 3.72.15 及更早版本成立，存档在
> `llmdoc/memory/reflections/hsbc-china-promon-poc.md`。
> 3.75.0 里 `ShieldSDK.framework` 直接不在包里。

## 检测栈

| 组件 | 存在 | 作用 |
|---|---|---|
| `ZDefend.framework`（Zimperium） | 是，4.5 MB | 判定引擎，全部规则都在这里 |
| `PlatformRASP.framework` | 是，160 KB | Swift 胶水层，把威胁转成拦截页 |
| `ShieldSDK.framework`（Promon） | 否 | 3.75.0 已移除 |
| `BioCatchSDK` / `ThreatmetrixWrapper` / `TuringShield*` | 是 | 行为风控，与越狱检测无关 |

`RASPConfig.json`（`CN.bundle/EntityConfigurations/release/`）里 developerMode、
hookingFramework、debugger、libraryInjection、emulatorDetection 全部 `disabled`，
只有 `untrustedBlocker` 是 `enabled`。但 ZDefend 自己的规则引擎不受这个文件约束——
实测的 11 条威胁里多数来自 ZDefend 内置规则。

## 判定结果（这是本节的要点）

ZDefend 的 ObjC 接口会原样交出判定内容。App 起来之后调用
`+[ZDefendImpl getAllThreats]`，能拿到每一条威胁的 `humanThreatName`、
`threatVector` 和完整的 `threatJson`。3.75.0 实测 11 条，分三类。

### 一、注入检测：`apptampering_hooked`

```
Reasons: Library hooking detected
forensic_function_hooks: [
  {function:"_dlsym",        image:"/usr/lib/system/libdyld.dylib",          status:"not restored (variant)"},
  {function:"_fopen",        image:"/usr/lib/system/libsystem_c.dylib",     status:"not restored (variant)"},
  {function:"_getenv",       image:"/usr/lib/system/libsystem_c.dylib",     status:"not restored (variant)"},
  {function:"_sysctl",       image:"/usr/lib/system/libsystem_c.dylib",     status:"not restored (variant)"},
  {function:"_sysctlbyname", image:"/usr/lib/system/libsystem_c.dylib",     status:"not restored (variant)"},
  {function:"_access",       image:"/usr/lib/system/libsystem_kernel.dylib",status:"not restored (variant)"},
  {function:"_lstat",        image:"/usr/lib/system/libsystem_kernel.dylib",status:"not restored (variant)"},
  {function:"_open",         image:"/usr/lib/system/libsystem_kernel.dylib",status:"not restored (variant)"}]
```

ZDefend 不比代码字节，它比的是"自己导入的函数指针和实际实现是否一致"。这条对
"注入即被测"是必然成立的：任何一个 tweak 对这些符号做了 inline hook，同进程里
ZDefend 看到的实现就变了，它不需要去找 hook 的痕迹，只需要发现自己调用的函数不在
原来的位置。

### 二、dlopen 被替换：`app_tampering_interposed`

```
interposed_functions: [
  {funcname:"_dlopen", name:"BioCatchSDK",      value:"/usr/lib/systemhook.dylib"},
  {funcname:"_dlopen", name:"HKEApiFramework",  value:"/usr/lib/systemhook.dylib"},
  {funcname:"_dlopen", name:"TMXProfiling",     value:"/usr/lib/systemhook.dylib"}]
```

这是 rootless 越狱的 systemhook 本身被看见，与 Round 77 的结论一致。

### 三、越狱环境：`JB Dopamine-Roothide`

```
Reasons: Behaves like Dopamine jailbreak
jb_forensics: {
  f_fstypename:   "bindfs",
  f_mntonname:    "/usr/lib",
  f_mntfromname:  "/private/preboot/<hash>/jb-0/procursus/basebin/.fakelib", ...}
```

来源是 `statfs("/usr/lib")`。rootless 越狱把 `/usr/lib` 用 bindfs 挂到 preboot 下的
`.fakelib`，原版设备这里应该是根分区的 apfs。**这是唯一一条与"我们注入了什么"无关的
检测**，也是唯一一条理论上能干净消除的——但它只能靠 hook `statfs` 来改，而那样第一类
立刻会多出一条 `_statfs` 记录，净效果不会更好。

另有一类 `ios_combined_classifier`（28 维特征向量，第一维为 1）配合 `injected_libs`
列出 TweakInject 目录下的所有 dylib，本质仍是注入痕迹。

## 终止链与拦截页

```
ZDefend+0x23a3c8 → ZDefend+0x23a380（在新线程里）→ ZDefend+0x1e569c
                 → mov w0,#0 / bl exit
```

`+0x1e569c` 按静态全局 `0x33e06c` 分派：值为 1 时正常返回，其余取值都走 exit。
该全局在文件里初值为 0，未找到写入点，所以裸启动约 2.8 秒必然退出。

`exit` 被拦下时 ZDefend 会用 `pthread_kill(SIGABRT)` 重试，所以只拦 `exit` 不够。

判定完成后，`PlatformRASP` 通过 `+[ZDefendImpl getAllThreats]` 一类接口取威胁列表，
再渲染成写着「抱歉，您无法在此设备上使用此应用程序」的拦截页。

## 当前覆盖状态

| 手段 | 作用 | 位置 |
|---|---|---|
| 自杀线程入口改 `ret` | 进程不再被打断 | `ZDefend+0x23a380` 第一条指令 |
| 威胁列表返回空 | 不弹拦截页 | `+[ZDefend getAllThreats]`、`+[ZDefendImpl getAllThreats]`、`-[ZDeviceStatus allThreats/activeThreats/activeNewThreats]` |

覆盖的含义是"判定结果没有消费者"：ZDefend 照样认为设备不安全，照样跑完整流程，
只是既杀不掉进程，也没人把威胁拿去渲染。**判定本身没有被消除。**

### 试过但更差的做法

- **改 `+0x1e569c` 里的 `b.eq`**（让它永远走"正常返回"分支）：App 多活十秒后变成
  `SIGILL`。那条分支之后的清理流程照常执行，破坏了别的状态。
- **把 `/var/jb` 从文件系统查询里藏掉**：只把退出时间从 2.6 秒推迟到 2.84 秒，
  其余威胁一条不少——ZDefend 的主要输入根本不是越狱路径。
- **拦下 `dlsym("zshield_report")`**：App 仍退出，ZDefend 由别处驱动。
- **移除 `ZDefend.framework`**：`PlatformRASP+0x8d10` 空指针解引用崩溃，App 更早退出。

## 仍然成立的矛盾

第一类和第二类证据无法在"已经注入"的前提下消除：只要还挂着任何一个 hook，
ZDefend 就能看见；要它看不见，唯一办法是不注入，而那就没有任何手段可以干预。
这就是 Round 77 记下的二律背反，在 3.75.0 上依然成立。

和 Promon 时期不同的是，ZDefend 的自杀动作**可以被拦下**（它走的是普通的
`exit`/`pthread_kill`，不是 Promon 那种内联 `svc`），威胁列表也只是一个 ObjC 数组，
所以"判定照旧、后果可控"这条路在这一版是通的。Promon 时期这条路走不通，
是因为它的退出藏在私有 svc 网关里，用户态拦不住。

## 排查方法（可复用）

这一轮真正省时间的一步是**不猜、直接问**：找到判定 SDK 的对外查询接口，
在 App 起来之后调用一次，让它把自己的判定结果连同证据一起交出来。
ZDefend 的 `+getAllThreats` 返回的 `threatJson` 里连规则名（`_rule_name`）、
规则版本、时间戳、具体证据都写着，比逐条 hook 文件系统调用反推快得多。

配套的做法：
- 用 `pthread_create` 钩子看 SDK 起了哪些线程、入口在哪，能快速定位它自己的收尾逻辑；
- 崩溃报告里 `usedImages` 的 base/size 可以直接把 pc/lr 换算成"哪个库 + 什么偏移"；
- 镜像归属要按段算，不能用"最小始址～最大末址"的边界框——共享缓存里的库紧挨着排，
  那样算会把相邻库圈进来，栈帧归属全错。
