# 汇丰中国：roothide Dopamine 评估 —— 内核隐藏是对的层，但被"不能动本体"约束排除

> 衔接 [[hsbc-china-unject-round77.md]]。Round 77 结论是"用户态二律背反，唯一自洽方向=内核层"。
> 本次评估 roothide Dopamine（`github.com/roothide/Dopamine2-roothide`，分支 2.x）作为现成的
> 内核层参考实现，并在"不能动越狱本体"这一用户约束下重新判定汇丰的可行性。

## roothide 的反检测架构（四支柱）

roothide 也是 opa334 Dopamine 的 fork，BaseBin 结构与我们的越狱**完全同构**
（libjailbreak / systemhook / launchdhook / jailbreakd / opainject / boomerang），
内核原语（kread/kwrite/kcall、`kalloc_data_external`）现成。其"几乎完整解决越狱检测"靠：

1. **随机 jbroot 路径**：不再用固定 `/var/jb`，每次越狱把 jbroot 装到随机名目录，依赖库用
   `@loader_path/.jbroot/...` 相对定位。直接废掉所有"检测 `/var/jb` 固定路径"的向量。
2. **内核改写 `all_image_info`**（核心）：`BaseBin/libjailbreak/src/roothider/dyld_patch.m` 的
   `task_set_dyld_info` 用 kwrite64 直接改目标进程 task 里的 `all_image_info_addr/size`，
   把 App 看到的已加载镜像列表替换成干净的 ⇒ **App 枚举模块时看不到注入库**。还有
   `hook_dyld_entry`/`hook_dyld_function`（vm_write 改 dyld 代码，arm64e 需处理 PAC）。
3. **per-app 黑名单**：`blacklist.m` + `JBROOT/var/mobile/Library/RootHide/RootHideConfig.plist`
   的 `appconfig`（按 bundle id）。命中的 App：systemhook 走**不注入 tweak + 应用 dyld patch**
   的路径（区别于我们 unject 的"纯裸奔不隐藏"）。
4. **签名/沙箱一致性配套**：`lv_bypass.c`（library validation 绕过）、`unsandbox*.m`、
   `signatures.m`，保证隐藏后不因签名/沙箱异常露馅。

**为什么这对汇丰是对的层**：Promon 用 `mach_vm_read` 读库头找 systemhook → all_image_info
改写让它枚举不到；查 `/var/jb` 固定路径 → 随机 jbroot 查不到。且这些**不需要往汇丰注入我们的
tweak**，故不触发注入检测——精确破解了 Round 77 的二律背反。

## 判决：被"不能动越狱本体"约束排除

用户明确约束：**不能动越狱本体**（不改 basebin、不 rebuild、不刷定制/roothide Dopamine）。

- roothide 的四支柱**全部落地在越狱本体**（systemhook/launchdhook/dyldhook/jailbreakd/内核）。
- 方案 A（换 roothide 越狱）、B（移植到本体）被此约束直接排除。
- 方案 C（自研内核隐藏）与 B **卡在同一禁区**：隐藏机制没有本体之外的落脚点。C 不是"工作量大"，
  是**可落脚位置为空**。若强行约束回进程内 tweak，就退化成 Round 74-76 已证伪的用户态伪装。
- 唯一可动区 = 注入进 App 的用户态 tweak = Round 77 的二律背反区。

**⇒ 在此约束下，汇丰 Promon SHIELD 可行域为空（非难度问题，是可行域问题）。**

## 教训

1. **"正确的层"和"可动的层"是两回事**。我们花了 20+ 轮把检测追到 mach_vm_read 读库头，又通过
   roothide 确认了内核隐藏是正解——但如果那一层是禁区，再正确也无法落地。评估方案前应先问清
   **可动区边界**，否则会像本次一样把 C 估成"2000-4000 行移植"，实则可行域为空。
2. **同源是把双刃剑**。我们和 roothide 同为 Dopamine fork，代码可直接借鉴（利好 B）；但只要
   "不能动本体"，同源也用不上。
3. **负面结论要写清是"难度"还是"可行域"**。本次是后者——收敛价值在于：未来若放宽约束，直接从
   A/B 起步；不放宽，则汇丰应结案，不要再投入用户态尝试。

## Follow-up

- 汇丰线在当前约束下结案。已更新 `reference/hsbc-china-detection-vectors.md` 覆盖状态。
- 重启条件：用户可接受维护定制/roothide 越狱，或提供一台可专用刷 roothide 的设备（方案 A 验证
  成本极低——把 `cn.com.hsbc.hsbcchina` 加进 RootHideConfig appconfig 冷启动即可试）。
