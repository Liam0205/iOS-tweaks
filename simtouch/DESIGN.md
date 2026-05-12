# SimTouch 设计文档

## 目标

通过 SSH 远程控制越狱 iOS 设备的触摸输入和屏幕截图，实现自动化测试。

## 架构

```
[Linux 构建机]                          [iOS 设备 SpringBoard 进程]
     |                                        |
  simtouch CLI ──── Unix Socket ────► SimTouch.dylib (tweak)
  (ssh -p 22xx)    /var/jb/tmp/              |
                   simtouch.sock        ├── TouchInjector (IOHIDEvent)
                                        ├── ScreenCapture (IOSurface)
                                        └── SocketServer (dispatch_source)
```

两个构建产物：

| 产物 | 类型 | 安装路径 | 注入目标 |
|------|------|----------|----------|
| `SimTouch.dylib` | Theos Tweak | `/var/jb/Library/MobileSubstrate/DynamicLibraries/` | `com.apple.springboard` |
| `simtouch` | C CLI 工具 | `/var/jb/usr/local/bin/` | N/A（独立进程） |

## 模块设计

### 1. SocketServer（IPC 层）

**职责**：监听 Unix domain socket，解析命令，分发到功能模块。

**实现**：
- 在 SpringBoard `applicationDidFinishLaunching:` 时**检查开关状态**，仅在启用时启动
- `socket(AF_UNIX, SOCK_STREAM, 0)` + `bind` 到 `/var/jb/tmp/simtouch.sock`
- `dispatch_source(DISPATCH_SOURCE_TYPE_READ)` 异步监听，不阻塞 SpringBoard 主线程
- 每个连接分配独立 dispatch_source 处理读写
- bind 前 `unlink()` 清理旧 socket 文件
- `chmod(0666)` 确保 mobile/root 用户都能连接

**协议**：
- 文本行协议，每条命令一行，`\n` 分隔
- 响应格式：`OK [payload]\n` 或 `ERR [message]\n`

```
# 命令格式
tap <x> <y>                        # 点按（屏幕坐标，像素）
swipe <x1> <y1> <x2> <y2> [ms]    # 滑动（默认 300ms）
longpress <x> <y> [ms]            # 长按 / HapticTouch（默认 500ms）
screenshot [path]                   # 截图（默认 /var/jb/tmp/simtouch/screen_<ts>.jpg）
keyinput <text>                     # 文本输入（未来）
info                                # 返回屏幕尺寸、scale、senderID 状态
enable                              # 运行时启用（CLI 直接写偏好 + Darwin 通知）
disable                             # 运行时禁用（CLI 直接写偏好 + Darwin 通知）

# 响应格式
OK                                  # tap/swipe/longpress/enable/disable 成功
OK /var/jb/tmp/simtouch/screen.jpg 1170x2532  # screenshot 成功
OK 390x844 @3x senderID=ready      # info 响应
ERR no senderID                     # senderID 未捕获
ERR invalid command                 # 解析失败
```

### 2. TouchInjector（触摸注入层）

**职责**：构造并注入 IOHIDEvent 触摸事件。

**核心 API**（IOKit 私有，需自行声明头文件）：

```c
// 系统客户端（tweak 生命周期内持有）
IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef);
void IOHIDEventSystemClientDispatchEvent(IOHIDEventSystemClientRef, IOHIDEventRef);

// 事件构造
IOHIDEventRef IOHIDEventCreateDigitizerEvent(allocator, timestamp,
    transducerType, index, identity, eventMask, buttonMask,
    x, y, z, tipPressure, barrelPressure, range, touch, options);
IOHIDEventRef IOHIDEventCreateDigitizerFingerEvent(allocator, timestamp,
    index, identity, eventMask,
    x, y, z, tipPressure, barrelPressure, range, touch, options);
void IOHIDEventAppendEvent(parent, child);
void IOHIDEventSetSenderID(event, senderID);
```

**senderID 捕获**：
- 注册 `IOHIDEventSystemClientRegisterEventCallback` 回调
- 监听真实触摸事件（type == kIOHIDEventTypeDigitizer）
- 提取 senderID 并持久化到 `/var/jb/var/mobile/.simtouch/senderid`
- **设备重启后需用户触摸屏幕一次**以重新捕获

**触摸序列**：

```
tap(x, y):
  1. finger down event (range=1, touch=1, identity=2)
  2. 50ms delay
  3. finger up event (range=0, touch=0, identity=2)

longpress(x, y, duration):    # HapticTouch
  1. finger down event (range=1, touch=1, identity=2)
  2. hold for duration ms（默认 500ms，iOS HapticTouch 阈值约 350-500ms）
  3. finger up event (range=0, touch=0, identity=2)

swipe(x1, y1, x2, y2, duration):
  1. finger down at (x1, y1)
  2. N 个 finger move 事件（线性插值，~16ms 间隔 ≈ 60fps）
  3. finger up at (x2, y2)
```

**坐标系**：
- IOHIDEvent 使用归一化坐标 [0.0, 1.0]
- CLI 传入屏幕像素坐标
- 转换：`normalized_x = pixel_x / screen_width_pixels`
- 需要获取 `[UIScreen mainScreen].bounds.size` 和 `scale` 来计算

### 3. ScreenCapture（截图层）

**职责**：静默截取当前屏幕，保存为图片。

**实现方案**：`_UICreateScreenUIImage()`（UIKit 私有 API，weak_import）

```objc
// 私有 API 声明
extern UIImage *_UICreateScreenUIImage(void) __attribute__((weak_import));

// 流程
1. 必须在主线程调用（dispatch_sync(dispatch_get_main_queue(), ...)）
2. _UICreateScreenUIImage() → CIImage-backed UIImage
3. 重绘到 bitmap context（CIImage 不含 CGImage，UIImageJPEGRepresentation 会返回 nil）
   UIGraphicsBeginImageContextWithOptions(size, YES, 1.0)
   [image drawAtPoint:CGPointZero]
   UIImage *bitmapImage = UIGraphicsGetImageFromCurrentImageContext()
4. JPEG 编码（quality 0.8）或 PNG（按文件后缀）
5. 写入指定路径
```

**废弃方案**：CARenderServerRenderDisplay + IOSurface（在测试中产生全白截图，已放弃）

**格式选择**：
- 默认 JPEG（quality 0.8），~646KB（1170x2532）
- `.png` 后缀时自动使用 PNG，~7MB（同分辨率）
- JPEG 更适合自动化场景：文件小、50MB 配额可存约 77 张

**截图存储管理**：

截图默认保存到 `/var/jb/tmp/simtouch/`。每次保存后**立即触发清理**（reactive，无定时任务）：

```
saveScreenshot(path)
  ↓
写入 JPEG/PNG 文件
  ↓
scanDirectory(/var/jb/tmp/simtouch/)
  ↓
Phase 1: 删除超龄文件（默认 > 1 小时）
  ↓
Phase 2: 计算剩余文件总体积
         若 > maxSize（默认 50MB），按 mtime 从旧到新删除，直到 ≤ maxSize
```

- 清理只在 screenshot 命令触发时执行——不截图就不清理，零开销
- 只管理 `/var/jb/tmp/simtouch/` 目录内的文件，用户指定自定义路径的不清理
- 默认阈值可通过 Settings 面板调整（`maxAge`、`maxSize`）

### 5. 开关控制

**机制**：PreferenceBundle（设置面板）+ Darwin notification 通知 tweak。

```
设置 APP                              SpringBoard (SimTouch.dylib)
    |                                        |
  [SimTouch 开关]                     ctor: 读 preference, 若 enabled 则启动
    |                                        |
  写 NSUserDefaults                    监听 Darwin notification
  (page.0x01.simtouch/enabled)        "page.0x01.simtouch.prefsChanged"
    |                                        |
  CFNotificationCenterPostNotification ──►  回调: 重新读 preference
                                             ├── enabled → 启动 socket server
                                             └── disabled → 停止 socket server + 注销回调
```

**PreferenceBundle 配置项**：

| 键 | 类型 | 默认值 | 说明 |
|-----|------|--------|------|
| `enabled` | BOOL | NO | 总开关 |
| `maxScreenshotAge` | Number | 3600 | 截图超龄阈值（秒） |
| `maxScreenshotSize` | Number | 50 | 截图总体积上限（MB） |

**资源开销**（关闭时）：
- dylib 加载到 SpringBoard 内存（~100KB）
- 无 socket、无 IOHIDEvent 回调、无定时器
- 接近零 CPU 开销

**CLI 也可控制**：`simtouch enable` / `simtouch disable` 写 preference + 发 notification，效果等同设置面板。

### 6. CLI 工具（simtouch）

**职责**：连接 Unix socket 发送命令，或直接操作偏好（enable/disable）。

**实现**：C + CoreFoundation。enable/disable 通过 CFPreferences + CFNotificationCenter 直接写偏好并发 Darwin 通知，无需 socket 连接（server 关闭时也能工作）。其他命令通过 Unix socket 转发到 tweak。

```
用法：
  simtouch enable                      # 启用（写偏好 + Darwin 通知）
  simtouch disable                     # 禁用（写偏好 + Darwin 通知）
  simtouch tap <x> <y>
  simtouch swipe <x1> <y1> <x2> <y2> [duration_ms]
  simtouch longpress <x> <y> [ms]      # HapticTouch 长按（默认 500ms）
  simtouch screenshot [output_path]
  simtouch info

通过 SSH 远程调用：
  ssh -p 2215 mobile@localhost "simtouch tap 200 400"
  ssh -p 2215 mobile@localhost "simtouch screenshot /tmp/s.jpg"
  scp -P 2215 mobile@localhost:/tmp/s.jpg ./screen.jpg
```

退出码：0 = 成功，1 = 错误（ERR 响应或连接失败）

## 文件结构

```
simtouch/
├── DESIGN.md              # 本文档
├── Makefile               # Theos：同时构建 tweak + tool + prefs
├── control                # Debian 包元数据
├── SimTouch.plist          # 注入 SpringBoard 的过滤器
├── icon.svg               # 设置图标源文件（紫色触摸涟漪）
├── Tweak.x                # SpringBoard tweak 入口（ctor + 开关监听 + 命令注册）
├── TouchInjector.h        # 触摸注入接口（Phase 2）
├── TouchInjector.m        # IOHIDEvent 触摸注入实现（Phase 2）
├── ScreenCapture.h        # 截图接口
├── ScreenCapture.m        # _UICreateScreenUIImage 截图 + JPEG/PNG + 自动清理
├── SocketServer.h         # socket server 接口
├── SocketServer.m         # Unix socket IPC 实现（dispatch_source 异步）
├── headers/
│   ├── IOHIDEvent.h       # IOHIDEvent 私有 API 声明（Phase 2）
│   └── IOHIDEventSystemClient.h
├── tools/
│   └── simtouch.c         # CLI 客户端（C + CoreFoundation）
├── layout/
│   └── Library/PreferenceLoader/Preferences/
│       └── SimTouch.plist # PreferenceLoader 注册
└── simtouchprefs/
    ├── STRootListController.h
    ├── STRootListController.m  # PreferenceBundle 控制器
    ├── entry.plist             # PreferenceLoader 注册（源文件）
    └── Resources/
        ├── Root.plist          # 设置面板布局
        ├── Info.plist
        ├── icon@2x.png         # 58x58 设置图标
        └── icon@3x.png         # 87x87 设置图标
```

## Theos 构建配置

```makefile
# Tweak（注入 SpringBoard）
TWEAK_NAME = SimTouch
SimTouch_FILES = Tweak.x ScreenCapture.m SocketServer.m  # Phase 2 加 TouchInjector.m
SimTouch_FRAMEWORKS = Foundation UIKit
SimTouch_LIBRARIES = substrate  # ellekit 要求链接 CydiaSubstrate
SimTouch_CFLAGS = -fobjc-arc
ARCHS = arm64 arm64e            # iPhone 13 Pro A15 SpringBoard 需要 arm64e

# CLI 工具
TOOL_NAME = simtouch
simtouch_FILES = tools/simtouch.c
simtouch_FRAMEWORKS = CoreFoundation  # enable/disable 用 CFPreferences + CFNotificationCenter
simtouch_INSTALL_PATH = /usr/bin      # rootless → /var/jb/usr/bin

# PreferenceBundle（设置面板）
BUNDLE_NAME = SimTouchPrefs
SimTouchPrefs_FILES = simtouchprefs/STRootListController.m
SimTouchPrefs_FRAMEWORKS = UIKit
SimTouchPrefs_PRIVATE_FRAMEWORKS = Preferences
SimTouchPrefs_INSTALL_PATH = /Library/PreferenceBundles
SimTouchPrefs_RESOURCE_DIRS = simtouchprefs/Resources
SimTouchPrefs_CFLAGS = -fobjc-arc
```

## senderID 生命周期

```
设备开机
    ↓
SpringBoard 启动 → SimTouch.dylib 加载
    ↓
检查 /var/jb/var/mobile/.simtouch/senderid
    ├── 存在且有效 → senderID ready
    └── 不存在 → 注册 IOHIDEvent 回调等待真实触摸
                     ↓
              用户触摸屏幕（任意触摸）
                     ↓
              回调捕获 senderID → 持久化 → ready
```

**注意**：senderID 在设备重启后失效（硬件随机化），需重新捕获。正常使用中用户总会先触摸屏幕再通过 SSH 发命令，所以这不是实际问题。

## 分阶段实现

### Phase 1：截图（MVP）✅ 已完成
- SocketServer + ScreenCapture + CLI + PreferenceBundle
- 支持 `screenshot`、`info`、`enable`、`disable` 命令
- `_UICreateScreenUIImage` 截图，JPEG 默认（0.8 quality）
- PreferenceBundle 设置面板（开关 + 清理参数）
- CLI enable/disable 通过 CoreFoundation 绕过 socket
- 已在 iPhone 13 Pro / iOS 15.4.1 上验证

### Phase 2：触摸注入
- TouchInjector + senderID 捕获
- 支持 `tap`、`swipe`、`longpress`（HapticTouch）命令
- 完成通用自动化能力

### Phase 3：增强
- `keyinput` 文本输入（GSEvent 或 WebClip 注入）
- 多点触控（pinch/zoom）
- 录制/回放宏

## 兼容性

| 组件 | iOS 15.4.1 | iOS 16.3.1 | 备注 |
|------|------------|------------|------|
| IOHIDEventSystemClient | ✅ | ✅ | 私有 API，一直存在 |
| IOHIDEventCreateDigitizerFingerEvent | ✅ | ✅ | 同上 |
| _UICreateScreenUIImage | ✅ 已验证 | ✅ | UIKit 私有 |
| Unix domain socket | ✅ 已验证 | ✅ | POSIX 标准 |
| SpringBoard 注入 | ✅ 已验证 | ✅ | ellekit/substrate |
| PreferenceBundle | ✅ 已验证 | ✅ | PreferenceLoader |

## 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| senderID API 签名变化 | 触摸注入失效 | 回退到旧版 iolate/SimulateTouch 的 Mach port 方式 |
| _UICreateScreenUIImage 移除 | 截图失败 | weak_import + 运行时检查，回退到 drawViewHierarchyInRect |
| SpringBoard crash | 设备 respring | socket server 不阻塞主线程；IOHIDEvent 操作在 @try 内 |
| Socket 权限问题 | CLI 连不上 | chmod 0666 + 路径 /var/jb/tmp/（已验证） |
| arm64e 架构遗漏 | tweak 不加载 | Makefile 固定 `ARCHS = arm64 arm64e` |
