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
screenshot [path]                   # 截图（默认 /var/jb/tmp/simtouch/screen.png）
keyinput <text>                     # 文本输入（未来）
info                                # 返回屏幕尺寸、scale、senderID 状态
enable                              # 运行时启用（启动 socket server）
disable                             # 运行时禁用（停止 socket server）

# 响应格式
OK                                  # tap/swipe/enable/disable 成功
OK /var/jb/tmp/simtouch/screen.png 1170x2532  # screenshot 成功
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

**职责**：静默截取当前屏幕，保存为 PNG。

**实现方案**：IOSurface + CARenderServerRenderDisplay

```objc
// 私有 API 声明
extern void CARenderServerRenderDisplay(
    kern_return_t, CFStringRef, IOSurfaceRef, int, int);
extern CGImageRef UICreateCGImageFromIOSurface(IOSurfaceRef);

// 流程
1. 获取屏幕尺寸（pixels = points × scale）
2. IOSurfaceCreate({width, height, bytesPerRow=width*4, pixelFormat=BGRA})
3. IOSurfaceLock()
4. CARenderServerRenderDisplay(0, CFSTR("LCD"), surface, 0, 0)
5. IOSurfaceUnlock()
6. UICreateCGImageFromIOSurface() → UIImage → PNG data
7. 写入指定路径
8. CFRelease(surface)
```

**备选方案**：`_UICreateScreenUIImage()`（一行调用，但线程安全性不确定）

**截图存储管理**：

截图默认保存到 `/var/jb/tmp/simtouch/`。每次保存后**立即触发清理**（reactive，无定时任务）：

```
saveScreenshot(path)
  ↓
写入 PNG 文件
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
- 默认阈值：`maxAge = 3600s`，`maxSize = 50MB`

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

**职责**：连接 Unix socket，发送命令，输出结果。

**实现**：纯 C，无框架依赖。

```
用法：
  simtouch tap <x> <y>
  simtouch swipe <x1> <y1> <x2> <y2> [duration_ms]
  simtouch screenshot [output_path]
  simtouch info

通过 SSH 远程调用：
  ssh -p 2216 mobile@localhost "simtouch tap 200 400"
  ssh -p 2216 mobile@localhost "simtouch screenshot /tmp/s.png"
  scp -P 2216 mobile@localhost:/tmp/s.png ./screen.png
```

退出码：0 = 成功，1 = 错误（ERR 响应或连接失败）

## 文件结构

```
simtouch/
├── DESIGN.md              # 本文档
├── Makefile               # Theos：同时构建 tweak + tool + prefs
├── control                # Debian 包元数据
├── SimTouch.plist          # 注入 SpringBoard 的过滤器
├── Tweak.x                # SpringBoard tweak 入口（ctor + 开关监听）
├── TouchInjector.h        # 触摸注入接口
├── TouchInjector.m        # IOHIDEvent 触摸注入实现
├── ScreenCapture.h        # 截图接口
├── ScreenCapture.m        # IOSurface 截图实现
├── SocketServer.h         # socket server 接口
├── SocketServer.m         # Unix socket IPC 实现
├── headers/
│   ├── IOHIDEvent.h       # IOHIDEvent 私有 API 声明
│   └── IOHIDEventSystemClient.h
├── tools/
│   └── simtouch.c         # CLI 客户端
└── simtouchprefs/
    ├── STRootListController.h
    ├── STRootListController.m  # PreferenceBundle 控制器
    ├── Resources/
    │   ├── Root.plist          # 设置面板布局
    │   └── Info.plist
    └── entry.plist             # PreferenceLoader 注册
```

## Theos 构建配置

```makefile
# Tweak（注入 SpringBoard）
TWEAK_NAME = SimTouch
SimTouch_FILES = Tweak.x TouchInjector.m ScreenCapture.m SocketServer.m
SimTouch_FRAMEWORKS = UIKit IOKit IOSurface CoreGraphics QuartzCore
SimTouch_CFLAGS = -fobjc-arc -Iheaders
SimTouch_LDFLAGS = -lIOKit

# CLI 工具
TOOL_NAME = simtouch
simtouch_FILES = tools/simtouch.c
simtouch_INSTALL_PATH = /usr/local/bin

# PreferenceBundle（设置面板）
BUNDLE_NAME = SimTouchPrefs
SimTouchPrefs_FILES = simtouchprefs/STRootListController.m
SimTouchPrefs_FRAMEWORKS = UIKit
SimTouchPrefs_PRIVATE_FRAMEWORKS = Preferences
SimTouchPrefs_INSTALL_PATH = /Library/PreferenceBundles
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

### Phase 1：截图（MVP）
- SocketServer + ScreenCapture + CLI
- 支持 `screenshot` 和 `info` 命令
- 不含触摸功能
- 对 ABCBypass 测试立即有用

### Phase 2：触摸注入
- TouchInjector + senderID 捕获
- 支持 `tap` 和 `swipe` 命令
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
| CARenderServerRenderDisplay | ✅ | ✅ | QuartzCore 私有 |
| IOSurface | ✅ | ✅ | 公开框架 |
| Unix domain socket | ✅ | ✅ | POSIX 标准 |
| SpringBoard 注入 | ✅ | ✅ | ellekit/substrate |

## 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| senderID 变了 API 签名 | 触摸注入失效 | 回退到旧版 iolate/SimulateTouch 的 Mach port 方式 |
| CARenderServerRenderDisplay 参数变化 | 截图失败 | 回退到 `_UICreateScreenUIImage()` |
| SpringBoard crash | 设备 respring | 所有 IOHIDEvent 操作在 @try 内；socket server 不阻塞主线程 |
| Socket 权限问题 | CLI 连不上 | chmod 0666 + 路径选择 /var/jb/tmp/ |
