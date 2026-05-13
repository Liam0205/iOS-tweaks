# SimTouch 技术决策记录

Phase 1 截图 MVP、Phase 2 触摸注入、Phase 3 自定义曲线/键盘输入/多指 pinch 开发过程中的关键技术决策。

## 1. _UICreateScreenUIImage vs CARenderServerRenderDisplay

**选择**：`_UICreateScreenUIImage`

**原因**：`CARenderServerRenderDisplay` 在测试中返回空白图像。`_UICreateScreenUIImage` 是 SpringBoard 内部使用的截图 API，注入 SpringBoard 后可直接调用，输出完整屏幕内容。

## 2. JPEG 0.8 vs PNG

**选择**：JPEG quality 0.8

**对比**：
- JPEG 0.8：约 646KB
- PNG：约 7MB

**原因**：远程传输场景下，截图需频繁回传到开发机。10 倍以上的体积差使得 PNG 在网络传输上不可接受。JPEG 0.8 在视觉质量和文件大小间取得合理平衡。

## 3. CIImage bitmap redraw

**问题**：`UIImageJPEGRepresentation()` 对 CIImage-backed UIImage 返回 nil。

**原因**：`_UICreateScreenUIImage` 返回的 UIImage 内部持有 CIImage 而非 CGImage。UIKit 的 JPEG 序列化 API 不支持 CIImage 直接编码。

**解决方案**：CIImage → CIContext render 到 CGBitmapContext → CGBitmapContextCreateImage → UIImage(CGImage:)。这次 bitmap redraw 将 CIImage 物化为 CGImage，之后 UIImageJPEGRepresentation 正常工作。

## 4. CLI enable/disable 用 CoreFoundation 绕 socket

**问题**：CLI 执行 `simtouch enable` 时，socket server 可能尚未启动（tweak 处于 disabled 状态）。

**解决方案**：CLI 的 enable/disable 命令不走 socket 通信，而是直接调用：
- `CFPreferencesSetAppValue()` 写入 preference 值
- `CFNotificationCenterPostNotification()` 发送 Darwin notification

Tweak 收到通知后读取 preference 并启动/停止 socket server。这避免了 enable 操作依赖 socket 的循环依赖。

## 5. CydiaSubstrate 链接

**问题**：Tweak dylib 编译成功但不被加载。

**原因**：rootless 越狱的 hook 引擎 ellekit 的加载逻辑仅扫描链接了 `libsubstrate.dylib` 的 dylib。未链接 CydiaSubstrate 的 dylib 不会被 ellekit 注入到目标进程。

**解决方案**：Makefile 中显式添加 `<tweak>_LIBRARIES = substrate`。

## 6. arm64 + arm64e 双架构

**问题**：仅编译 arm64 的 tweak 无法注入 SpringBoard。

**原因**：iPhone 13 Pro (A15) 上 SpringBoard 运行在 arm64e slice。ellekit/substrate 在加载 dylib 时会匹配目标进程的架构 slice，arm64-only dylib 无法注入 arm64e 进程。

**解决方案**：`ARCHS = arm64 arm64e`，生成 fat binary。

## 7. Linux 交叉编译 LD_LIBRARY_PATH

**问题**：Linux 上 Theos 交叉编译失败，clang 报找不到 libtinfo.so.5。

**原因**：Theos 自带的 toolchain（Apple Clang）运行时依赖 libtinfo.so.5。在某些 Linux 发行版中该库不在默认搜索路径。

**解决方案**：设置 `LD_LIBRARY_PATH` 包含 libtinfo.so.5 所在目录（通常是用户本地安装的 ncurses 5 兼容库路径）。

## 8. 事件克隆 vs 从零创建 IOHIDEvent

**选择**：`IOHIDEventCreateCopy` 克隆真实事件

**尝试的方案**：先用 `IOHIDEventCreateDigitizerEvent` + `IOHIDEventCreateDigitizerFingerEvent` 从零创建事件，设置所有已知字段（坐标、phase、mask、senderID），通过 `IOHIDEventSystemClientDispatchEvent` 和 `orig_HandleFromSender` 分发。

**结果**：从零创建的事件不产生任何可见触摸效果。

**原因**：BackBoardServices 在 IOHIDEvent 上附加了隐式内部属性（超出公开的 senderID 和 digitizer 字段），从零创建的事件缺少这些属性，被 BKS 管道丢弃。

**解决方案**：捕获首个真实触摸事件（带 touch 属性的 digitizer type=11），通过 `IOHIDEventCreateCopy` 克隆保存为模板。后续注入都基于此模板克隆，修改坐标/phase/mask/timestamp 即可。

## 9. Hook _BKHandleIOHIDEventFromSender vs IOHIDEventSystemClient

**选择**：直接 hook backboardd 的 `_BKHandleIOHIDEventFromSender`

**原因**：这是 backboardd 中所有 HID 事件的入口点。在此处 hook 可以：(1) 捕获真实事件作为克隆模板；(2) 注入的事件直接进入原始管道，保留完整的 BKS 处理流程。相比之下，`IOHIDEventSystemClientDispatchEvent` 在 SpringBoard 侧分发事件，绕过了 backboardd 的验证和路由逻辑。

## 10. 跨进程 IPC：文件 + Darwin notification 复用

**选择**：复用单一 `BB_CMD_NOTIFY` 通道，通过 STTouchCmd.phase 编码不同操作

**尝试的方案**：为录制控制（start/stop）和回放注册独立的 Darwin notification name（`BB_RECORD_START` / `BB_RECORD_STOP` / `BB_REPLAY_NOTIFY`），从 SpringBoard 发到 backboardd。

**结果**：新注册的 notification 回调在 backboardd 中从不触发（原因不明）。

**解决方案**：复用已证明工作的 `BB_CMD_NOTIFY` 通道。在 STTouchCmd 的 `phase` 字段中编码特殊值（0xF0=录制开始、0xF1=停止、0xF2=回放），backboardd 的 `onTouchCommand` 回调检查 phase 值分发到对应处理逻辑。

## 11. backboardd 录制路径选择

**选择**：`/tmp/simtouch-record.bin`（→ `/private/var/tmp/`）

**尝试的方案**：写到 `/var/jb/tmp/simtouch-record.bin`（与命令文件同目录）。

**结果**：文件始终无法创建/写入，即使 SpringBoard 预创建文件后 backboardd 仍无法写入。

**原因**：`/var/jb/` 实际指向 preboot 分区（`/private/preboot/.../procursus/`），backboardd 的沙箱 profile 禁止写入该路径。backboardd 可以读取该路径下的文件（命令文件由 SpringBoard 写入后 backboardd 读取），但不能写入。

**解决方案**：改用 `/tmp/`（→ `/private/var/tmp/`），这是标准 iOS 临时目录，所有进程均可读写。

## 12. 单次 IPC swipe 替代逐步 IPC swipe

**选择**：发送单个 `STSwipeCmd` 结构体，由 backboardd 内部生成轨迹

**尝试的方案**：每个 swipe 步骤（Down → N 个 Move → Up）各发一次文件写入 + Darwin notification IPC，由 SpringBoard 用 `dispatch_after` 按 16ms 间隔驱动。

**结果**：Darwin notification 存在合并（coalescing）——连续快速发送的多个 notification 可能被系统合并为一次回调。导致 swipe 步骤丢失、轨迹不连续。

**解决方案**：设计 `STSwipeCmd` 结构体包含完整 swipe 参数（起点、终点、时长），一次 IPC 传递所有信息。backboardd 的 `performSwipe()` 使用 `dispatch_after` 在进程内按 16ms 间隔生成线性插值轨迹，调用 `dispatchTouch()` 注入每帧。消除跨进程 notification 合并竞态。

## 13. 系统手势使用 SpringBoard 私有 API 而非 HID 事件注入

**选择**：直接调用 SpringBoard 私有 API（`SBUIController`、`SBControlCenterController` 等）

**尝试的方案**：通过 HID 事件注入实现系统手势（Home、控制中心、通知中心、App 切换器）——在注入的 IOHIDEvent 上设置录制中发现的 edge mask 位（`0x1040000` = Home，`0x2040000` = 通知中心）。

**结果**：无论如何设置事件的 mask、phase、坐标、edge flags，系统手势均不触发。常规 tap/swipe 仍正常工作。

**根因**：iOS gesture arbiter 验证事件的**投递路径**（delivery path），不仅仅是事件数据内容。通过 `_BKHandleIOHIDEventFromSender` hook 注入的事件虽然通过了 BKS 管道的基本验证（因为是从真实事件克隆），但 arbiter 知道该事件不是从物理硬件经过完整的 IOHIDEventDriver → IOHIDEventSystem → backboardd 链路到达的。这是 iOS 的安全设计，防止软件层伪造系统手势。

**解决方案**：系统手势走独立路径——在 SpringBoard 进程内直接调用私有 API：
- `home`：`[SBUIController handleHomeButtonSinglePressUp]`
- `cc`：`[SBControlCenterController presentAnimated:]`
- `notif`：`[SBCoverSheetPresentationManager setCoverSheetPresented:animated:withCompletion:]`
- `switcher`：`[SBMainSwitcherViewController toggleMainSwitcherNoninteractivelyWithSource:animated:]`

这些 API 直接触发 UI 状态转换，绕过 gesture arbiter 验证。因为 Tweak 本身运行在 SpringBoard 进程中，调用这些 API 等同于 SpringBoard 自身发起操作。

## 14. 边缘手势 mask 位（仅诊断参考）

**发现来源**：录制真实 Home 手势和通知中心下拉后，对比 event_mask 字段差异。

**mask 值**：
- `0x40000`（bit 18）= 通用边缘手势标志
- `0x1000000`（bit 24）= 底部边缘（Home 手势）
- `0x2000000`（bit 25）= 顶部边缘（通知中心）

**用途限制**：这些 mask 值仅用于录制分析诊断（识别用户执行了何种手势），**不能用于注入系统手势**——原因见决策 13（arbiter 验证投递路径）。

## 15. 多指触摸：从零创建 vs 克隆模板（决策 #8 修正）

**原始结论（Phase 2 决策 #8）**：从零创建 IOHIDEvent 不生效，必须克隆真实事件。

**Phase 3 修正**：这是条件性规则，取决于事件类型：
- 单指触摸：必须克隆（BKS 附加的隐式内部属性无法通过公开 API 复制）
- 多指 pinch/zoom：必须从零创建（克隆的单指模板 parent 为 Finger type，而多指需要 Hand type；且模板子事件数量不可控）

**根因**：
- 单指：BKS 验证事件的 routing info/policy flags 等隐式属性
- 多指：手势识别器验证事件结构（parent type=Hand + N 个 Finger children），对隐式属性要求较松

**技术实现**：
```c
IOHIDEventCreateDigitizerEvent(allocator, ts, 3/*Hand*/, 0, 0, mask, 0, midX, midY, 0, pressure, 0, range, touch, 0)
IOHIDEventCreateDigitizerFingerEvent(allocator, ts, 0/*index*/, 1/*identity*/, ...)  // finger 1
IOHIDEventCreateDigitizerFingerEvent(allocator, ts, 1/*index*/, 2/*identity*/, ...)  // finger 2
```

设置：`kIOHIDEventFieldDigitizerCollection=1`, `kIOHIDEventFieldDigitizerIsDisplayIntegrated=1`, `kIOHIDEventFieldIsBuiltIn=1`, 正确的 SenderID。

## 16. 自定义曲线：Newton's method cubic-bezier

**选择**：Newton's method 迭代求解（8 iterations）

**原因**：与 CSS `cubic-bezier()` 行为一致。输入为 t 对应的 X 坐标，输出为 Y 坐标（进度）。8 次迭代在 ARM64 上收敛速度足够且计算开销极低。

## 17. 键盘输入：HID keyboard + 剪贴板粘贴

**选择**：混合方案

两种输入模式：
- 特殊键（enter/tab/backspace/arrows/a-z/0-9）：直接注入 `IOHIDEventCreateKeyboardEvent`（USB HID usage page 0x07）
- 文本字符串：`UIPasteboard.generalPasteboard.string` + Cmd+V（usage 0xE3 + 0x19）

**原因**：HID keyboard 用 USB usage code（page 0x07），逐字符注入需要处理 shift 组合、输入法状态等复杂性。剪贴板方案绕过输入法直接粘贴完整文本。

## 18. backboardd 部署：killall 而非 sbreload

**选择**：`sudo killall backboardd`

**问题**：更新 backboardd hook dylib 后需要重启进程加载新代码。

**陷阱**：`sbreload` 只重启 SpringBoard（通过 launchd 发信号），backboardd 是独立的 launchd 守护进程（`com.apple.backboardd`），不受 sbreload 影响。

**解决方案**：`sudo killall backboardd`，launchd 会自动重启它（因为 backboardd 的 plist 配置了 `KeepAlive`）。注意：killall backboardd 会同时导致 SpringBoard 重启（因 SpringBoard 依赖 backboardd 的 Mach port）。
