# 汇丰中国 Round 77：Unject 实验证伪 systemhook-only 假设

> 衔接 [[hsbc-china-promon-poc]]（Round 55-76）。上一篇把检测链路追到
> "Promon 经 svc 网关 mach_vm_read_overwrite 逐库读 Mach-O 头，systemhook.dylib 触发退出"，
> 并把下一步定为"构造自洽的合法库伪装"或"内核层"。本轮用 Unject 做了最干净的判决性实验，
> 结论推翻了 systemhook-only 假设。

## Task

用定制 Dopamine 的 Unject 能力（systemhook `spawn_config_for_executable` 按可执行名黑名单
返回 `kSpawnConfigTrust` = 只授信不注入，commit `980bf0f`）彻底不注入 systemhook 到汇丰
`China` 进程，验证"让 Promon 读不到 systemhook 就能净启动"这一假设。设备 22415（iPhone 13
Pro / iOS 15.4.1），汇丰中国 3.72.15。

## Expected vs Actual

- 预期：systemhook 不注入 → Promon 的 `mach_vm_read` 读不到 systemhook.dylib 头 → 3s 退出消失。
- 实际：汇丰**仍然闪退，且比带注入的 3s 更快（<1s）**，无 crash log（干净 exit）。假设被证伪。

## 关键过程与教训

1. **plist 改后必须 userspace reboot 才生效**。systemhook 是 launchd 早期加载的常驻组件，
   运行时不重读 `/var/mobile/zp.unject.plist`。第一次没 reboot 就冷启动 App 观察，数据不可信；
   这一步差点让我把"未生效"误判成"第二检测"。→ 已知规则：任何 systemhook 级配置变更都要
   ubreboot 后再测。
2. **先证明工具生效，再信结果**。"1s 退出"单独看有两种解释（unject 生效后暴露第二检测 / unject
   根本没生效照旧带注入）。必须用独立对照区分。设备上 `vmmap`/`lsof`/`frida-cli`/本地 python
   frida 全不可用，最终用**微信 tweak 的可见 UI**（登录页 `默认/iPad登录/iPhone/iPad` 按钮条）
   作判据：微信加入 unject 名单 + reboot 后按钮条消失，证明 systemhook 确实不再注入。**行为可见的
   tweak 是验证"注入与否"的最省事判据**，胜过缺失的内存工具。
3. **证伪本身是高价值收敛**。这是一次决定性的负面结果：Round 68-76 建立在"systemhook 是唯一
   元凶"上，unject 是这个假设最干净的实验（连伪装库头都不用）。结果证明 Promon 还有独立于
   任何用户态注入库的检测（很可能是环境层：`/var/jb`、trustcache、amfid、内核补丁痕迹）。
   Round 74"改 systemhook 头撑过 3s"重新理解为：只是扰动众多检测之一的计时/分支，非唯一开关。

## Root Cause（为什么用户态走不通）

**二律背反**：要 Promon 检测不到注入 ⇒ 不能注入 systemhook ⇒ 我们也无法用 tweak 在进程内
干预 Promon；要用 tweak 干预 ⇒ 必须注入 systemhook ⇒ Promon 又能检测到。纯用户态无法同时
满足"不被检测"与"能干预"。这个矛盾是结构性的，不是调参能解的。

## Follow-up

- 唯一自洽方向 = 内核层隐藏越狱环境（issue #1）：不注入目标进程故不触发注入检测，同时隐藏
  Promon 依赖的环境特征。
- "构造自洽合法库伪装"降级：即便做成也只覆盖 systemhook 头一个向量，已知还有环境层检测。
- 用户态 PoC 到此收束。已更新 `reference/hsbc-china-detection-vectors.md` 覆盖状态（Round 77 段）。
- **可复用教训**（供 `guides/reverse-engineering-methodology.md` 后续吸收）：验证"是否注入/hook
  生效"缺内存工具时，用行为可见的 tweak 作判据；systemhook 级配置变更必须 ubreboot 后再测；
  移除单一检测向量前，先想清楚"移除后是否反而暴露更早/环境层的检测"以及"移除是否同时废掉了自己
  的干预手段"。
