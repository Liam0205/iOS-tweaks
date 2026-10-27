# 汇丰中国 3.75.0：从"猜检测项"改成"问判定引擎"（2026-10-27）

## 背景

Round 55～77 用了二十多轮去反推 Promon 在检测什么，最后卡在"用户态二律背反"上。
Round 78 打开 App 发现整个检测栈已经换掉了：汇丰中国升到 3.75.0，Promon 的
`ShieldSDK.framework` 直接不在包里，判定方换成了 ZDefend（Zimperium）。

## 起作用的一步

不是反推，是直接问。

ZDefend 有一套 ObjC 接口给自己的平台层用。App 起来之后在进程内调用
`+[ZDefendImpl getAllThreats]`，它把 11 条威胁连同 `threatJson` 全部交了出来——
每条都写着规则名、规则版本、证据。八条"Library hooking detected"列出的正是我们
自己装的那八个探针；两条"JB Dopamine-Roothide"直接给出 `statfs("/usr/lib")` 的
原始返回，`f_mntfromname` 里明明白白写着 `basebin/.fakelib`。

整个检测项清单一次就拿到了，而前面二十轮靠 hook 文件系统调用反推，得到的只是
"它查了这些路径"，不知道哪些算命中。

## 得到的教训

**先找判定引擎的对外接口，再去反推它的输入。** 这类商业 SDK 都要把结果交给宿主
App 展示（拦截页要写文案、要上报），所以必然有一条"把判定交出去"的路径。那条路径
比判定逻辑好找得多，信息量也大得多——它交出去的是结论加证据，不是原料。

判断"该问谁"的办法：`nm -u` 看它导入了什么。ZDefend 没有导入 `_dyld_image_count`、
`mach_vm_*`、`task_info`、`csops`，说明它拿不到镜像列表、读不了别人的内存，
能力边界一下就清楚了，反推时的假设空间也随之收缩。

## 同时记下的两个坑

**一、同路径换内容会触发 CODESIGNING 杀进程。** 在 `/var/jb/usr/lib/TweakInject/`
下用同一个文件名反复覆盖 dylib，dyld 会报 `SIGKILL - CODESIGNING`，栈停在
`dyld3::MachOFile::compatibleSlice`。看起来像"新代码把 App 搞崩了"，实际上是加载
都没走到。排查期间每次换一个新文件名就绕开了。

**二、在 constructor 里调 `class_getMethodImplementation` 会死锁。** 它会触发
`UIScreen` 的 `+initialize`，而那时 dyld 还持有初始化锁，主线程卡在
`_dispatch_once_wait`，20 秒后被启动看门狗杀掉（`0x8BADF00D`）。要枚举某个镜像里
注册了哪些类，得等 App 起来之后再做，或者改用别的判据。

## 结论的边界

这轮做到的是"判定照旧、后果可控"，不是"判定被消除"。ZDefend 依然认为设备不安全，
八条 hook 证据和一条 systemhook 证据都还在，只是它的自杀线程被改成 `ret`、
威胁列表没人读了。要在根上消除这些证据，只有"不注入任何 tweak"一条路，
那与"用 tweak 干预"直接矛盾——Round 77 的二律背反仍然成立，只是这次它的后果
可以被按住。
