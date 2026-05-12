# SimTouch 架构

## 核心职责

SimTouch 是远程触摸模拟与截图捕获工具。Phase 1 完成了截图 MVP，Phase 2 实现了基于 backboardd hook 的触摸注入和事件录制。

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
└────────────────────────────────────────┼────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────┐
│              BackboardHook.x (backboardd)                │
│  hook _BKHandleIOHIDEventFromSender                      │
│  · 事件捕获/克隆注入 · 录制/回放引擎                     │
└─────────────────────────────────────────────────────────┘
```

| 组件 | 文件 | 进程 | 职责 |
|------|------|------|------|
| Tweak | `Tweak.x` | SpringBoard | ctor + 开关监听 + 命令注册 |
| SocketServer | `SocketServer.m` | SpringBoard | AF_UNIX socket 命令分发 |
| ScreenCapture | `ScreenCapture.m` | SpringBoard | 截图捕获、格式转换、文件写入 |
| TouchInjector | `TouchInjector.m` | SpringBoard | 触摸命令 IPC 中继到 backboardd |
| BackboardHook | `BackboardHook.x` | backboardd | HID 事件 hook + 捕获 + 注入 + 录制 |
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

### _BKHandleIOHIDEventFromSender Hook

backboardd 的 HID 事件入口函数。SimTouch 通过 `MSHookFunction` 安装 hook：

1. **事件捕获**：首次收到 digitizer（type=11）事件时，`CFRetain` sender 指针、记录 senderID、`IOHIDEventCreateCopy` 克隆事件作为模板
2. **事件注入**：clone 模板 → 修改坐标/phase/mask/timestamp → 调用 `orig_HandleFromSender`
3. **录制**：inline 在 hook 中，当 `_recording && !_injecting` 时记录 digitizer 事件的完整字段

关键约束：从零创建 IOHIDEvent 不生效（缺少 BKS 内部属性），必须克隆真实事件。

### 跨进程 IPC

SpringBoard ↔ backboardd 通过文件 + Darwin notification：
- SpringBoard 写 `STTouchCmd` 到 `/var/jb/tmp/simtouch-cmd`
- 发 Darwin notification `page.0x01.simtouch.cmd`
- backboardd 读取 cmd 文件并执行

特殊 phase 值复用同一通道：`0xF0`=录制开始、`0xF1`=停止、`0xF2`=回放。

### 边缘手势 event_mask 位

从录制分析中发现：
- `0x40000` (bit 18) = 通用边缘手势标志
- `0x1000000` (bit 24) = 底部边缘（Home 手势）
- `0x2000000` (bit 25) = 顶部边缘（通知中心）

### 当前状态（v0.0.1-24）

- **已验证**：tap、swipe、longpress、截图、录制
- **待解决**：回放事件不产生可见效果（基本 tap 有效但录制回放无效）
- **待实现**：边缘手势 mask 应用到 dispatchTouch
