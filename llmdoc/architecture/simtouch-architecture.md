# SimTouch 架构

## 核心职责

SimTouch 是远程触摸模拟与截图捕获工具。Phase 1 完成了截图 MVP，Phase 2 实现了基于 backboardd hook 的触摸注入、事件录制，以及 SpringBoard 私有 API 系统手势。

目标环境：iPhone 13 Pro / iOS 15.4.1 / Dopamine 1.x（rootless）

## 组件拓扑

```
┌─────────────────────┐         ┌──────────────────────┐
│   simtouchprefs     │         │   tools/simtouch.c   │
│  (PreferenceBundle) │         │      (CLI 工具)       │
└────────┬────────────┘         └──────────┬───────────┘
         │ Darwin notification              │ socket / CFPreferences
         ▼                                  ▼
┌─────────────────────────────────────────────────────────┐
│                  Tweak.x (SpringBoard)                   │
│  SocketServer ← AF_UNIX IPC                              │
│  ScreenCapture ← 截图管道                                │
│  TouchInjector ── 文件+Darwin notify ──┐                 │
│  系统手势命令 ── SpringBoard 私有 API（进程内直接调用）   │
└────────────────────────────────────────┼────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────┐
│              BackboardHook.x (backboardd)                │
│  hook _BKHandleIOHIDEventFromSender                      │
│  · 事件捕获/克隆注入 · 录制/回放 · swipe 轨迹生成       │
└─────────────────────────────────────────────────────────┘
```

| 组件 | 文件 | 进程 | 职责 |
|------|------|------|------|
| Tweak | `Tweak.x` | SpringBoard | ctor + 开关监听 + 命令注册 + 系统手势 API |
| SocketServer | `SocketServer.m` | SpringBoard | AF_UNIX socket 命令分发 |
| ScreenCapture | `ScreenCapture.m` | SpringBoard | 截图捕获、格式转换、文件写入 |
| TouchInjector | `TouchInjector.m` | SpringBoard | 触摸命令 IPC 中继到 backboardd（tap/longpress/swipe） |
| BackboardHook | `BackboardHook.x` | backboardd | HID 事件 hook + 捕获 + 注入 + swipe 轨迹生成 + 录制 |
| CLI | `tools/simtouch.c` | 独立进程 | 命令行接口 |
| PreferenceBundle | `simtouchprefs/` | Settings.app | 开关面板 |

## Socket 协议

- 地址：`/var/jb/tmp/simtouch.sock`（AF_UNIX stream）
- 协议格式：文本行协议（newline 分隔）
- 命令集：

| 命令 | 参数 | 响应 |
|------|------|------|
| `info` | 无 | 屏幕尺寸、scale、backboardd 状态 |
| `screenshot` | `[path]` | 截图路径或错误 |
| `tap` | `<x> <y>` | OK + bb 状态 |
| `swipe` | `<x1> <y1> <x2> <y2> [ms]` | OK + bb 状态 |
| `longpress` | `<x> <y> [ms]` | OK + bb 状态 |
| `home` | 无 | OK springboard-api |
| `cc` | 无 | OK cc presented |
| `notif` | 无 | OK notif presented |
| `switcher` | 无 | OK switcher toggled |
| `record` | `<start\|stop\|dump>` | 录制控制 |
| `replay` | 无 | 回放录制事件 |
| `bbstatus` | 无 | ping backboardd 返回状态 |
| `diag` | 无 | 列出可用 API 和内部类 |

## 截图管道

捕获链路：

```
_UICreateScreenUIImage() → UIImage (CIImage-backed)
    → CIImage bitmap redraw → CGBitmapContext → UIImage (CGImage-backed)
        → UIImageJPEGRepresentation(image, 0.8) → NSData
            → [data writeToFile:path]
```

关键约束：
- `_UICreateScreenUIImage` 返回的 UIImage 内部持有 CIImage（非 CGImage）
- `UIImageJPEGRepresentation` 对 CIImage-backed UIImage 返回 nil
- 必须通过 CIImage → CGBitmapContext → CGImage 路径做一次 bitmap 重绘

## 开关控制流

### Settings.app 路径

```
用户 toggle → PreferenceBundle 写 CFPreferences
    → postDarwinNotification("page.0x01.simtouch/settingschanged")
        → Tweak callback 读取 preference → 启动/停止 socket server
```

### CLI 路径

```
simtouch enable/disable
    → CFPreferencesSetAppValue() 直接写 preference
    → CFNotificationCenterPostNotification() 发 Darwin notification
```

CLI enable/disable 不依赖 socket 连接（socket 可能尚未启动），直接通过 CoreFoundation API 操作 preferences 和通知。

## 清理策略

| Phase | 策略 | 实现 |
|-------|------|------|
| Phase 1 | 按 mtime 删除 >maxAge 的截图 | 截图写入后触发清理检查 |
| Phase 2（规划） | 按 mtime 排序裁减到 maxSize | 总文件大小超限时删除最旧的文件 |

## 构建约束

| 约束 | 原因 |
|------|------|
| `ARCHS = arm64 arm64e` | iPhone 13 Pro (A15) SpringBoard + backboardd 运行在 arm64e slice |
| 链接 CydiaSubstrate | ellekit（rootless hook 引擎）只加载链接了 libsubstrate 的 dylib |
| `SimTouch.plist` 使用 `Executables` | 需同时注入 SpringBoard 和 backboardd 两个进程 |
| Linux 交叉编译需设置 `LD_LIBRARY_PATH` | clang 运行时需要 libtinfo.so.5 |

## 依赖与边界

- 构建依赖：Theos、CydiaSubstrate（链接）、UIKit/CoreImage/CoreGraphics/IOKit
- 注入目标：SpringBoard + backboardd
- 打包方案：rootless
- 包名：`page.0x01.simtouch`
- 类型：Theos Tweak + CLI Tool + PreferenceBundle

## Phase 2 触摸注入核心机制

### 双路径架构

触摸模拟分为两条路径，取决于操作类型：

**路径 1：HID 事件注入（常规触摸）**

适用于 tap、swipe、longpress。通过 backboardd hook 注入克隆的 IOHIDEvent。

```
SpringBoard (TouchInjector)
    → 写文件 /var/jb/tmp/simtouch-cmd
    → Darwin notification
    → backboardd (BackboardHook)
        → dispatchTouch() / performSwipe()
        → IOHIDEventCreateCopy + 修改字段
        → orig_HandleFromSender（进入原始 HID 管道）
```

**路径 2：SpringBoard 私有 API（系统手势）**

适用于 home、cc、notif、switcher。直接在 SpringBoard 进程内调用私有 API。

```
SpringBoard (Tweak.x)
    → [SBUIController handleHomeButtonSinglePressUp]          (home)
    → [SBControlCenterController presentAnimated:]            (cc)
    → [SBCoverSheetPresentationManager setCoverSheetPresented:animated:withCompletion:]  (notif)
    → [SBMainSwitcherViewController toggleMainSwitcherNoninteractivelyWithSource:animated:]  (switcher)
```

### 平台限制：系统手势仲裁器

iOS gesture arbiter 不信任通过 `_BKHandleIOHIDEventFromSender` hook 注入的 HID 事件用于系统手势——无论事件内容（mask、phase、坐标、edge flags）如何设置。arbiter 验证的是事件的投递路径（delivery path），而非事件数据本身。

因此：
- 常规 tap/swipe/longpress → HID 事件注入有效
- 系统手势（Home/CC/通知中心/App 切换器）→ 必须使用 SpringBoard 私有 API

录制数据中发现的 edge mask 位（`0x40000`/`0x1000000`/`0x2000000`）仅为诊断参考，不能用于注入系统手势。

### _BKHandleIOHIDEventFromSender Hook

backboardd 的 HID 事件入口函数。SimTouch 通过 `MSHookFunction` 安装 hook：

1. **事件捕获**：首次收到 digitizer（type=11）事件时，`CFRetain` sender 指针、记录 senderID、`IOHIDEventCreateCopy` 克隆事件作为模板
2. **事件注入**：clone 模板 → 修改坐标/phase/mask/timestamp → 调用 `orig_HandleFromSender`
3. **录制**：inline 在 hook 中，当 `_recording && !_injecting` 时记录 digitizer 事件的完整字段

关键约束：从零创建 IOHIDEvent 不生效（缺少 BKS 内部属性），必须克隆真实事件。

### 跨进程 IPC

SpringBoard → backboardd 通过文件 + Darwin notification：
- SpringBoard 写命令结构体到 `/var/jb/tmp/simtouch-cmd`
- 发 Darwin notification `page.0x01.simtouch.cmd`
- backboardd 读取 cmd 文件并执行

**命令结构体**（根据 phase 字段区分类型）：

| phase 值 | 结构体 | 语义 |
|-----------|--------|------|
| 0 (Down) / 1 (Move) / 2 (Up) | `STTouchCmd` (13B) | 单次触摸事件 |
| 3 (Swipe) | `STSwipeCmd` (25B) | 完整 swipe 轨迹（一次 IPC） |
| 0xF0 / 0xF1 / 0xF2 | `STTouchCmd` (仅 phase) | 录制开始/停止/回放 |

### Swipe IPC 设计（单次投递）

旧方案（已废弃）：每个 swipe 步骤发一次文件+notification IPC，存在 Darwin notification 合并竞态。

当前方案：SpringBoard 发送单个 `STSwipeCmd` 结构体（起点、终点、时长），backboardd 的 `performSwipe()` 内部生成 16ms 间隔的线性插值轨迹：

```c
typedef struct {
    uint8_t phase;       // = kSTPhaseSwipe (3)
    float x1, y1;       // 归一化起点
    float x2, y2;       // 归一化终点
    uint32_t duration_ms;
    uint32_t edge_mask;  // 保留字段（当前未使用）
} STSwipeCmd;
```

backboardd 收到后：
1. 立即 `dispatchTouch(Down, x1, y1)`
2. `dispatch_after` 按 16ms 间隔发出 N 个 Move 事件（线性插值）
3. 最后一帧发出 `dispatchTouch(Up, x2, y2)`
