# ABCBypass Rounds 13-16 Reflection (2026-08-20 ~ 08-21)

## Task

在 2215 设备上继续 abcbypass 开发，让农业银行 (com.bankabc.iphonerelease,
binary MbapMPaaS = 蚂蚁 mPaaS) 在越狱设备上正常可用。本阶段从"多轮打补丁失败"
走到"纠正方法论错误后一击成功"。

## Expected vs Actual

- 预期（进入本阶段时）：在既有的 exit-hook/栈切换/longjmp/drain-pump 体系上继续
  微调，解决 UI 冻结。
- 实际：发现整套体系建立在**错误的存活信号**上；推倒重来后，用**一个 ObjC swizzle**
  从源头解决，进入首页且交互正常。

## What Went Wrong（关键教训）

1. **存活检测匹配错进程（致命方法论错误）**：多轮用 `grep MbapMPaaS` 判断主 App
   是否存活，实际命中的是后台扩展 `group.abc.toolExtension`（常驻）。导致
   "存活 30s/90s/3min""进入业务流程""UI 正常"等一大批结论**全是假象**，在假信号上
   反复打补丁，越修越糟（tweak 让主 App 从裸跑的 13s 提前到 1s 崩溃）。
   - 正确匹配：`ps -eo args | grep -E 'MbapMPaaS\.app/MbapMPaaS( |$)' | grep -v PlugIns`。
2. **自己的 hook 是崩溃元凶而非 ABC**：反复出现的 `0xb5a06000` SIGSEGV，二分定位为
   **对 libc 函数 inline-hook（MSHookFunction）被 ABC 完整性自检发现**。地址每次固定
   ⇒ 主动触发。此前一直误当成"ABC 的多重时序敏感检测"。
3. **objc_exception_throw hook 破坏 noreturn 契约**：吞掉异常后 return，而该函数是
   noreturn，调用点后无恢复代码 → 跌入垃圾指令 PAC-fail 崩溃。DTRpcException 是
   mPaaS 正常业务异常，本就该 rethrow。
4. **Frida 不可用**：ABC 反注入，spawn 时 frida-agent 注入即在 dyld 早期自毁；
   frida-server 存在还会让 ABC 更快崩。

## Root Cause（为什么最终能成）

- native exit（`MbapMPaaS+0x8db260`，`[receiver action]==3` 判定）所在的检测 block
  （invoke=`0x8dad68`）**定义在 ObjC 方法 `-[DTFrameworkInterface initRiskManage]` 内**。
- ObjC 方法可被 swizzle，而 swizzle **不改函数序言字节**，不触发完整性自检。
- swizzle `initRiskManage` 为空 → 风险管理不初始化 → 检测 block 永不创建 → exit 消失。
- 一个 swizzle 解决，不需要任何 exit 拦截/栈切换/longjmp/libc hook。

## Key Technical Decisions

| 决策 | 依据 |
|------|------|
| 停止打补丁，先建可信测试工具 `abctest.sh` | 失败远超两次；根因是信号不可信 |
| 二分（AGGRESSIVE / LIBC_HOOKS 编译开关）定位有害 hook | 隔离出 libc inline-hook = 崩溃源 |
| 放弃一切 C 函数 inline-hook / fishhook / __text patch / Frida | 均触发完整性自检或反注入 |
| 只用 ObjC swizzle | 唯一实测安全的手段 |
| 手动解析 __objc_classlist 定位 block 宿主方法 | LIEF extended 不可用；IMP≤invoke 且最近者即宿主 |

## Lessons Learned（可推广）

1. **先验证测量工具，再信任测量结果**。进程存活判断必须精确匹配主可执行文件路径并
   排除 `PlugIns` 扩展（`.appex`）。扩展进程常驻会伪造"App 存活"。
2. **崩溃先问"是不是我造成的"**：卸载 tweak 做裸跑对照 + 二分编译开关，能快速区分
   "ABC 的检测" vs "我的 hook 副作用"。本例大量"检测"其实是自伤。
3. **对有完整性自检的 App（mPaaS/银行类）：只用 ObjC swizzle**。任何 C 函数序言
   inline-hook、GOT 改写、__text patch 都会被发现（范围覆盖 libc 广泛函数，不止
   libpthread）。
4. **源头 > 事后补救**：定位检测逻辑所在的 ObjC 方法整体短路，远胜于 hook exit 后
   用 longjmp/栈切换抢救（后者破坏 CF/GCD/UIKit 内部状态，不可恢复）。
5. **noreturn 函数的 hook 必须保持 noreturn 契约**（objc_exception_throw / exit 等），
   吞掉后 return 会崩。

## Follow-up

1. 死代码清理（本轮进行中）：删除 exit-hook/栈切换/longjmp/drain/libc-hook 等全部
   失败尝试，只留 ObjC swizzle + Logos hooks。
2. 版本适配：ABC 升级后优先确认 `DTFrameworkInterface initRiskManage` 是否仍是
   检测 block 宿主；若方法改名/重构，用 objcparse.py 重新定位 `0x8db260` exit 的
   block invoke 宿主方法。
3. 关注是否有第二条独立 exit 路径（本轮只确认了这一条；进入首页后长时间运行的
   稳定性待长测）。
