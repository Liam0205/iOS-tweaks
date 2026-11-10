# SimTouch 更新日志

## 0.1.2

修正一处会让 SpringBoard 在启动早期崩溃的写法。

- `STTouchInjector` 原来在 `init` 里直接读 `[UIScreen mainScreen]` 拿屏幕尺寸。`init` 由 `sharedInstance` 的 `dispatch_once` 块执行，而 `sharedInstance` 是在 socket 队列上被调用的。SpringBoard 刚启动、界面子系统还没就绪时，`UIScreen` 会抛异常；`_dispatch_client_callout` 会把 `dispatch_once` 块里抛出的异常直接按 `terminate` 处理，调用方再包 `@try` 也接不住，进程当场 `abort`。
- 屏幕尺寸改为惰性获取：第一次用到时在 Main Thread 上读，套 `@try`，读不到就返回 0 并让命令回 `ERR`，下次再试。
- `info` 命令不再自己读 `UIScreen`，改用 `STTouchInjector` 缓存的尺寸；拿不到时返回 `ERR screen metrics not ready`。
- 截图兜底路径（`_UICreateScreenUIImage` 失败时走 UIKit 合成）加了 `@try`。
- socket 客户端的读循环外包一层 `@try`，任何一条命令的异常都只影响该条命令。
- 现场：2026-11-10 18:18，SpringBoard 被内存回收杀掉后重启，重启 3.4 秒后收到 socket 命令，`+[UIScreen mainScreen]` 抛异常，SpringBoard 以 `std::terminate` 退出并进入 Safe Mode。iOS 16.3.1 / iPhone 14 Pro Max 的崩溃报告确认了这条栈。

## 0.1.1

修正 `info` 输出的坐标约定说明，避免按点坐标传参导致触摸落到屏幕左上角。

- `tap`、`swipe` 等命令一直收的是**像素坐标**（与 `screenshot` 输出图片的尺寸一致，iPhone 13 Pro 上是 1170x2532），但 `info` 只报 `bounds` 的点尺寸 `390x844 @3x`，看起来像要传点坐标。实际按点坐标传会落到屏幕左上角。
- `info` 现在把两套尺寸写在同一行，像素值放在前面，并加上 `coord=pixel`：

  ```
  OK 1170x2532 px (390x844pt @3x) coord=pixel conn=connected hook=captured
  ```

- CLI 的 usage 文本和 `DESIGN.md` 的坐标系一节同步更新。
- 在 iPhone 13 Pro / iOS 15.4.1 上验证：`killall SpringBoard` 后 `info` 输出新格式；用像素坐标 `tap 148 452` 命中中信银行首页的「账户」按钮，正常进入登录页。

## 0.1.0

首个发布版。远程触控注入、截图、录制回放、系统手势。
