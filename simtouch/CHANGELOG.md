# SimTouch 更新日志

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
