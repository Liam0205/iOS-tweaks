# ABC Bypass 架构

## 架构目标

`abcbypass/Tweak.x` 绕过中国农业银行 (`com.bankabc.iphonerelease`) 的越狱检测与
检测后 `exit(0)` 杀进程链路，使其在越狱设备上正常运行。

- 目标 Binary：`MbapMPaaS`（~110MB arm64）= 蚂蚁金服 **mPaaS** 框架，封装了
  `UIApplicationMain` 并控制整个 App 生命周期。
- **已验证可用**：ABC 11.1.0 / iPhone 13 Pro / iOS 15.4.1；ABC 11.2.0 /
  iPhone 14 Pro Max / iOS 16.3.1。进入首页、交互正常、长时间运行稳定。

## 核心方案：纯 ObjC swizzle（一句话）

**swizzle `-[DTFrameworkInterface initRiskManage]` 为空实现**，从源头消除检测退出。

- 触发退出的检测 block（在 11.1.0 上 invoke=`MbapMPaaS+0x8dad68`，含
  `cmp w24,#3` → `bl _exit`，`w24=[receiver action]`，==3 即风险）**定义在
  `-[DTFrameworkInterface initRiskManage]` 方法体内**。
- 把该方法替换成空 `void` 实现 → 风险管理不初始化 → 检测 block 永不创建/投递 →
  `exit` 从源头消失。
- **关键：ObjC 方法 swizzle 不改任何函数序言字节，因此不触发 ABC 的完整性自检**
  （这正是所有 C 函数 inline-hook 方案失败的根因，见下）。
- 方案靠 ObjC 类名/方法名（mPaaS 稳定接口），**不依赖地址偏移**，故跨 ABC 小版本、
  机型、iOS 版本通用。上面的偏移仅是 11.1.0 的定位依据，运行时不使用。

## 执行模型（%ctor，全部同步完成）

`%ctor` 极简，只做 ObjC 层的安装，无延迟 hook、无 C 函数 hook：

1. 初始化日志（`/var/jb/tmp/abcbypass.log`，回退到 App 容器 Documents）。
2. 设 `NSUserDefaults` 的 `kUPWHomePageJailBrokenToastNotAgainKey=YES`（抑制越狱提示）。
3. `NSSetUncaughtExceptionHandler(abc_exception_handler)`（仅记录异常，不吞）。
4. 安装 7 个 ObjC swizzle：
   - `hookSecureUtilityPlus` — SecureUtilityPlus 的 jailbreak/检测 selector 返回 NO/空
   - `hookSmAntiFraud` — 数美反欺诈初始化/检测方法中和
   - `hookIOSSecuritySuite` — 标准 `amIJailbroken` 系列返回 NO
   - `hookABCJailbreakMethods` — 遍历类表，中和 `isJailbroken`/`checkIsJailBreak`/
     `isDeviceJailBreak` 等越狱判定方法
   - **`hookInitRiskManage`** — 核心，空实现（见上）
   - `hookAuthorityJailBreakFlag` — `authorityWithJailBreakFlag:` 传入 flag 强制清零
   - `hookShowJailBrokenAlert` — 越狱弹窗方法空实现

Logos `%hook`（编译期静态注册，等价 ObjC swizzle）：

- `NSFileManager` — `fileExistsAtPath:` 等对越狱路径返回 NO、目录列举过滤
- `UIApplication` — `canOpenURL:` 屏蔽 cydia/sileo/filza scheme；`terminateWithSuccess`
  与 `_terminateWithStatus:`（<30s 视为检测退出，直接拦下不 `%orig`，作为安全网）
- `UIAlertController` — 标题/正文含"越狱/jailbr/安全/root"的弹窗替换为空并阻止 present
- `UIViewController` — 阻止被标记的越狱弹窗 present
- `NSProcessInfo` — `environment` 移除 `DYLD_INSERT_LIBRARIES`/`_MSSafeMode`

`is_jb_path` 是唯一的 C 辅助函数（纯字符串比较，不 hook 任何东西）。

## 核心约束：禁止一切 C 函数 inline-hook

ABC（mPaaS）有 **内存完整性自检**（`memmem`，运行在 GCD worker 线程），会发现对
**libc 广泛函数**的 inline-hook / GOT 改写。二分实验（第 15 轮）证实：
MSHookFunction 覆盖 `stat/lstat/access/open/fopen/realpath/readlink/sysctl/getenv/
fork/dlopen/dlsym` 及 `_dyld_*` 后，启动 ~1s 就在后台 GCD 线程跳到**固定哨兵地址
`0x00000000b5a06000`** 触发 SIGSEGV（地址每次相同 ⇒ 主动触发，非随机内存错误）。

**硬约束（对 ABC 必须遵守）：**

- ❌ 禁 C 函数 inline-hook（MSHookFunction 任何 libc/系统函数）
- ❌ 禁 fishhook GOT 改写
- ❌ 禁 `__text` patch（同一完整性自检会发现，第 13 轮已证实 SIGILL 崩溃）
- ❌ 禁 Frida（反注入，spawn 时 frida-agent 注入即在 dyld 早期自毁）
- ✅ 只用 ObjC 方法 swizzle（Logos `%hook` / `method_setImplementation`）——不改序言字节

> 旧文档曾称"MSHookFunction 对 libdispatch 安全 / 内存扫描不覆盖 libdispatch / 仅
> libpthread 不安全"——**均未经可信验证，已作废**。保守结论：任何 C 函数都不要 hook。

## 与 ICBC bypass 的关键差异

| 维度 | ICBC | ABC |
|------|------|-----|
| 有效手段 | fishhook + Logos + semaphore 拦截 | **仅 ObjC swizzle**（C 函数 hook 会触发完整性自检崩溃） |
| 退出机制 | ObjC 层冻结 + exit | 检测 block 判定 `[receiver action]==3` → `exit(0)` |
| 对抗策略 | 拦冻结循环 + 保护 UI 状态 | swizzle 检测 block 宿主方法，源头消除 exit |
| 完整性自检 | 无（fishhook 可用） | 有（覆盖 libc 广泛函数，禁一切 inline-hook） |

## 依赖与边界

- 构建：Theos、libsubstrate（仅用于 Logos runtime，不主动 MSHookFunction）、UIKit/Foundation
- 打包：rootless scheme；注入边界限定 `com.bankabc.iphonerelease`
- 定位工具：`abcbypass/tmp/objcparse.py`（手动解析 `__objc_classlist`，用 IMP ≤ block
  invoke 地址且最近者定位 block 宿主方法）、`abcbypass/tmp/abctest.sh`（可信进程测试）
- 实验历史：`abcbypass/analysis.md`（第 15-16 轮为最终可信结论）

## 主要回归风险（版本适配检查顺序）

1. `-[DTFrameworkInterface initRiskManage]` 是否仍是检测 block 宿主（改名/重构则用
   `objcparse.py` 重新定位）
2. 是否新增独立 exit 路径（用 `abctest.sh` 裸跑对照，先区分「检测」vs「自伤」）
3. SecureUtilityPlus / SmAntiFraud 是否新增检测类或方法
4. mPaaS 框架大版本升级引入新检测模块

## 历史教训（勿重蹈）

- **存活检测必须精确匹配主 App 进程**：`ps -eo args | grep -E
  'MbapMPaaS\.app/MbapMPaaS( |$)' | grep -v PlugIns`。曾用 `grep MbapMPaaS` 误匹配
  后台扩展 `group.abc.toolExtension`，导致大批"存活成功"结论失效、在假信号上反复打补丁。
- **崩溃先问"是不是自伤"**：卸载 tweak 裸跑对照 + 二分编译开关，快速区分 ABC 检测与
  自身 hook 副作用。此前大量"检测"其实是 libc inline-hook 触发完整性自检的自伤。
- 详见 `memory/reflections/abcbypass-round13-16.md` 与 `reference/abc-detection-vectors.md`。
