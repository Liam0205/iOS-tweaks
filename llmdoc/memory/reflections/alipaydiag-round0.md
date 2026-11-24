# AlipayDiag 第 0 轮反思（2026-11-24）

目标：支付宝 12.12.56 的北京实名刷脸入口报「当前手机暂不能使用刷脸功能」。
一次会话内做了 0.0.1 → 0.0.5 五轮只读诊断，把失败点从「本地检测组件」纠正到
「服务端对 `module/auth` 的判定」。

## 有效做法

1. **先看服务端响应，再猜本地检测。** 第一轮之前先去 App 容器的 NSURLCache 里翻，
   直接拿到 `query`/`auth` 两条响应：`query` 成功、`auth` 返回 `DEVICE_NOT_SUPPORT`。
   这一条就把「哪个本地布尔值挡住的」这个方向废掉了，省掉很多 hook 实验。
2. **静态能拿到的，不要抓包。** open-certify 页面的 pre-request 脚本就在 WebKit 的
   NetworkCache 里，读出来就能看到 `clientInfo` 是 `zimIdentity.getBioInfo` 的
   `actionResult` 原样透传，字段清单当场就有了。
3. **进程内 hook 比跨进程 attach 稳。** 请求由 App 主进程的网络栈发出（缓存落在
   `com.alipay.iphoneclient/Cache.db`），在插件里 hook `NSURLSession` 一次就拿到完整
   body；相比之下跨进程附着 WebKit XPC 反复失败。
4. **零命中要有正例对照。** 越狱判定入口全部零调用时，同一轮里 `ZimJSApi.getMetaInfo`
   有命中，说明 Logos hook 在这个进程、这个时刻是有效的，零命中才站得住。

## 踩坑

1. **spawn gating 把设备挂住了。** `enumerate_pending_spawn()` 返回的 `Spawn` 没有
   `name` 属性，脚本在放行前抛异常，所有新拉起的进程都没被 `resume`，用户看到的是
   「页面一直 loading」，甚至连支付宝自己都被暂停。教训：观测手段不能改变被测对象的
   状态；这类会暂停进程的工具，没有可靠放行逻辑（含异常退出）不要开。
2. **WebKit.Networking 是短命的 XPC 进程。** 轮询 attach 反复得到
   `the connection is closed`，因为进程在 attach 完成前已经退出。不要把它当成稳定目标。
3. **工具放在仓库外、没有逐轮记录。** 五轮改动全在 `/var/tmp/alipaydiag`，
   没有 `analysis.md`、没有提交；中途还因为 hook `TBSDKSecurity` 让 App 启动 SIGABRT。
   这违反了本仓库的方法论：每轮实验后更新 `analysis.md` 才能开始下一轮。
   现在已把插件与逐轮记录搬进 `alipaydiag/`。

## 可复用的判断

- 开放平台核身这类 H5 流程，设备信息是容器（pre-request）算好、页面原样带走的；
  要枚举字段，读页面脚本比猜接口快。
- 请求落在谁的缓存目录里，就说明是谁发的：`com.alipay.iphoneclient/Cache.db` 是
  App 主进程，`com.apple.WebKit.Networking/` 才是 WebKit 网络进程。
- 「服务端说设备不支持」不等于「本地检测没绕过」。先把请求体和本地调用清单都拿到，
  再决定往哪一层使劲。
