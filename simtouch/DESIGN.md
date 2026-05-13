# SimTouch 设计文档

## 目标

通过 SSH 远程控制越狱 iOS 设备的触摸输入和屏幕截图，实现自动化测试。

## 架构

```
[Linux 构建机]
     |
  simtouch CLI ── Unix Socket ──► SpringBoard (SimTouch.dylib)
  (ssh -p 22xx)  /var/jb/tmp/         │
                 simtouch.sock    ├── SocketServer (命令分发)
                                  ├── ScreenCapture (截图)
                                  ├── TouchInjector (触摸 IPC 中继)
                                  │      │
                                  │      │ 文件写入 /var/jb/tmp/simtouch-cmd
                                  │      │ + Darwin notification
                                  │      ▼
                                  │   backboardd (SimTouch.dylib)
                                  │      ├── _BKHandleIOHIDEventFromSender hook
                                  │      ├── 事件捕获 + 克隆注入
                                  │      ├── swipe 轨迹生成 (performSwipe)
                                  │      └── 录制/回放引擎
                                  ├── 系统手势 (SpringBoard 私有 API, 进程内直接调用)
                                  │      ├── home → SBUIController
                                  │      ├── cc → SBControlCenterController
                                  │      ├── notif → SBCoverSheetPresentationManager
                                  │      └── switcher → SBMainSwitcherViewController
                                  └── Tweak.x (ctor + 命令注册)
```

构建产物：

| 产物 | 类型 | 注入目标 |
|------|------|----------|
| `SimTouch.dylib` | Theos Tweak | SpringBoard + backboardd |
| `simtouch` | C CLI 工具 | N/A（独立进程） |
| `SimTouchPrefs.bundle` | PreferenceBundle | Settings.app |

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
tap <x> <y>                        # 点按（屏幕像素坐标）
swipe <x1> <y1> <x2> <y2> [ms] [curve]  # 滑动（默认 300ms，可选曲线）
                                        #   curve: linear, easein, easeout, easeinout
                                        #   bezier:cx1,cy1,cx2,cy2 (自定义 cubic-bezier)
longpress <x> <y> [ms]            # 长按（默认 500ms）
keyinput <key>                     # 单键注入（enter/tab/backspace/esc/space/delete/arrows/a-z/0-9）
keyinput text <string>             # 文本输入（剪贴板 + Cmd+V 粘贴）
pinch <cx> <cy> <scale> [ms]       # 多指缩放（scale>1 放大, <1 缩小，默认 300ms）
home                               # 返回主屏幕（SpringBoard API）
cc                                 # 打开控制中心（SpringBoard API）
notif                              # 打开通知中心（SpringBoard API）
switcher                           # 打开任务切换器（SpringBoard API）
screenshot [path]                   # 截图（默认 /var/jb/tmp/simtouch/screen_<ts>.jpg）
info                                # 屏幕尺寸、scale、backboardd 连接状态
bbstatus                            # ping backboardd 并返回 hook 状态
diag                                # 列出可用的 IOHIDEvent API 和 UIKit 内部类
record <start [name]|stop|list|dump [name]|delete <name>>  # 多录制管理
replay [name] [speed]               # 回放（可指定录制名 + 速度倍率）
enable                              # 运行时启用（CLI 直接写偏好 + Darwin 通知）
disable                             # 运行时禁用（CLI 直接写偏好 + Darwin 通知）

# 响应格式
OK                                  # 成功
OK 390x844 @3x conn=connected hook=captured  # info 响应
OK springboard-api                  # home/系统手势响应
OK cc presented                     # cc 响应
OK notif presented                  # notif 响应
OK switcher toggled                 # switcher 响应
OK stopped test1, 42 events, 1234ms  # record stop 响应（含名称）
OK replaying 42 events over 1234ms (speed=2.0x)  # replay 响应
OK recordings:\n  test1 - 42 events, 6426 bytes  # record list 响应
ERR no senderID                     # backboardd 未捕获事件
ERR invalid command                 # 解析失败
```

### 2. BackboardHook（触摸注入核心）

**职责**：在 backboardd 进程中 hook HID 事件管道，捕获真实触摸事件并注入合成事件。

**Hook 目标**：`_BKHandleIOHIDEventFromSender(IOHIDEventRef event, void *sender, void *, void *)`
- backboardd 的 HID 事件入口函数，所有触摸/按键事件经此进入 iOS 事件系统
- 通过 `MSHookFunction` 安装 hook

**事件捕获**：
- 首次收到 digitizer 类型（type=11）事件时，捕获 `sender` 指针和 `senderID`
- 首次收到有 touch 属性的事件时，通过 `IOHIDEventCreateCopy` 克隆并保存为模板
- 后续注入都基于此模板克隆，确保保留 BKS 内部属性

**注入流程**：
```
SpringBoard 写命令结构体到 /var/jb/tmp/simtouch-cmd
    → Darwin notification (BB_CMD_NOTIFY)
        → backboardd onTouchCommand 回调
            → 读取 cmd 文件，按 phase 字段分发：
                phase=0/1/2 → dispatchTouch(phase, x, y)
                phase=3     → performSwipe(x1, y1, x2, y2, duration, curve)
                phase=4     → performKeySequence(keys)
                phase=5     → performPinch(cx, cy, scale, duration)
                phase=0xF0  → 开始录制
                phase=0xF1  → 停止录制
                phase=0xF2  → 回放
            → dispatchTouch:
                → IOHIDEventCreateCopy（克隆捕获的模板）
                → 修改坐标、phase、mask、timestamp
                → orig_HandleFromSender（注入到原始管道）
```

**Swipe 轨迹生成**（`performSwipe`）：
- SpringBoard 发送单个 `STSwipeCmd`（起点、终点、时长）
- backboardd 内部生成 N 步线性插值（16ms 间隔），通过 `dispatch_after` 调度
- 消除了旧方案中逐步跨进程 IPC 导致的 Darwin notification 合并竞态

**关键发现**：
- 单指触摸：从零创建 IOHIDEvent 不起作用（缺少 BKS 内部属性），必须克隆真实事件再修改字段
- 多指触摸（pinch）：必须从零创建 IOHIDEventCreateDigitizerEvent(type=Hand) + Finger children。克隆单指模板的 parent type 错误，且子事件结构不可控

**坐标系**：
- IOHIDEvent 使用归一化坐标 [0.0, 1.0]
- CLI/socket 传入屏幕像素坐标
- TouchInjector 转换：`normalized = pixel / screen_pixels`
- iPhone 13 Pro：1170x2532 px，390x844 pt，@3x

### 3. TouchInjector（IPC 中继层）

**职责**：接收 SpringBoard 侧的触摸命令，通过文件 + Darwin notification 转发给 backboardd。

**IPC 协议**：
```c
#pragma pack(push, 1)
typedef struct {
    uint8_t phase;  // kSTPhaseDown=0, kSTPhaseMove=1, kSTPhaseUp=2
    float x;        // 归一化 X [0,1]
    float y;        // 归一化 Y [0,1]
    uint32_t edge_mask; // 保留
} STTouchCmd;       // 13 bytes

typedef struct {
    uint8_t phase;       // = kSTPhaseSwipe (3)
    float x1, y1;        // 归一化起点
    float x2, y2;        // 归一化终点
    uint32_t duration_ms;
    uint32_t edge_mask;  // 保留
    uint8_t curve_type;  // 0=linear, 1=easein, 2=easeout, 3=easeinout, 4=bezier
    float bz_x1, bz_y1, bz_x2, bz_y2;  // cubic-bezier 控制点（curve_type=4 时使用）
} STSwipeCmd;       // 46 bytes

typedef struct {
    uint8_t phase;       // = kSTPhaseKeyboard (4)
    uint8_t key_count;   // 按键事件数（down+up 序列，最多 8）
    struct {
        uint16_t usage;  // USB HID usage code (page 0x07)
        uint8_t down;    // 1=down, 0=up
    } keys[8];
} STKeyCmd;         // 26 bytes

typedef struct {
    uint8_t phase;       // = kSTPhasePinch (5)
    float cx, cy;        // 归一化中心点
    float scale;         // >1 放大, <1 缩小
    uint32_t duration_ms;
} STPinchCmd;       // 17 bytes
#pragma pack(pop)
```

**特殊 phase 值**（复用同一 IPC 通道）：
- `3` = 完整 swipe（含曲线参数）
- `4` = 键盘事件序列
- `5` = pinch/zoom 多指触摸
- `0xF0` = 开始录制
- `0xF1` = 停止录制
- `0xF2` = 回放

**触摸序列**：
```
tap(x, y):
  1. phase=Down at (x, y)
  2. 80ms delay
  3. phase=Up at (x, y)

longpress(x, y, ms):
  1. phase=Down at (x, y)
  2. hold for ms（默认 500ms）
  3. phase=Up at (x, y)

swipe(x1, y1, x2, y2, ms):
  单次 IPC：发送 STSwipeCmd（phase=3）
  backboardd 内部：Down → N 个 Move（16ms 间隔线性插值）→ Up
```

### 3b. 系统手势（SpringBoard 私有 API）

**职责**：触发 iOS 系统手势（Home、控制中心、通知中心、App 切换器），绕过 gesture arbiter。

**实现**：直接在 SpringBoard 进程内调用私有 API（不经过 backboardd IPC）。

| 命令 | API 调用 | 目标类 |
|------|----------|--------|
| `home` | `handleHomeButtonSinglePressUp` / `clickedMenuButton` | `SBUIController` |
| `cc` | `presentAnimated:` | `SBControlCenterController` |
| `notif` | `setCoverSheetPresented:animated:withCompletion:` | `SBCoverSheetPresentationManager` |
| `switcher` | `toggleMainSwitcherNoninteractivelyWithSource:animated:` | `SBMainSwitcherViewController` |

**平台限制**：iOS gesture arbiter 验证 HID 事件的投递路径（delivery path），而非事件数据。通过 `_BKHandleIOHIDEventFromSender` 注入的事件无法触发系统手势，无论 edge mask 设置如何。常规触摸（tap/swipe/longpress）不受此限制。

### 4. 录制/回放引擎

**录制**（在 backboardd 的 hook 中内联执行）：
- 拦截所有 digitizer type=11 事件，记录到命名文件
- 文件路径：`/tmp/simtouch-record-<name>.bin`（无名称则 `/tmp/simtouch-record.bin`）
- 录制时不录制注入的合成事件（`_injecting` 标志）
- 时间戳用 `mach_absolute_time()` 相对值，精度到毫秒

**多录制管理**：
```
record start [name]    → 开始录制到命名文件
record stop            → 停止当前录制
record list            → 列出所有录制（名称 + 事件数 + 文件大小）
record dump [name]     → 导出事件详情（最多 200 条）
record delete <name>   → 删除指定录制文件
```

**录制格式**：
```c
#define ST_MAX_CHILDREN 5
typedef struct {
    uint32_t time_ms;
    uint32_t phase;
    float x, y;
    uint32_t event_mask;    // 边缘手势标志位
    int32_t touch, range;
    float pressure;
    uint8_t child_count;
    struct {
        float x, y, pressure;
        int32_t touch, range;
        uint32_t phase;
    } children[ST_MAX_CHILDREN];
} STRecordEntry;  // 153 bytes packed
```

**录制/回放 IPC**：
```c
typedef struct {
    uint8_t phase;      // 0xF0 (start) or 0xF2 (replay)
    float speed;        // 回放速度倍率（1.0 = 原速）
    char name[32];      // 录制名称
} STRecordCmd;          // 37 bytes
```

**边缘手势 mask 位**（从真实事件录制中发现）：
- `0x40000`（bit 18）= 通用边缘手势标志
- `0x1000000`（bit 24）= 底部边缘（Home 手势）
- `0x2000000`（bit 25）= 顶部边缘（通知中心）

**回放**：
- 主线程 `dispatch_after` 调度（按录制时间戳间隔 ÷ 速度倍率）
- 使用 `dispatchTouch()` 路径注入（与 tap 相同路径）
- 录制数据中的 touch/range 字段用于推断 phase 状态转换
- **速度控制**：`replay [name] [speed]`，delay = 原始间隔 / speed
- **边缘手势智能替换**：检测 `event_mask & 0x40000`，跳过触摸注入，改为发送 Darwin notification 给 SpringBoard 调用系统手势 API（home/notif）

**文件路径约束**：
- 录制文件必须写到 `/tmp/`（→ `/private/var/tmp/`），不能写到 `/var/jb/tmp/`
- 原因：backboardd 沙箱禁止写入 preboot 分区（`/var/jb/` → `/private/preboot/.../procursus/`）
- 命令文件 `/var/jb/tmp/simtouch-cmd` 可读不可写（由 SpringBoard 写入）

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
  simtouch swipe <x1> <y1> <x2> <y2> [duration_ms] [curve]
  simtouch longpress <x> <y> [ms]      # HapticTouch 长按（默认 500ms）
  simtouch keyinput <key>              # 单键（enter/tab/backspace/arrows/a-z/0-9）
  simtouch keyinput text <string>      # 文本粘贴
  simtouch pinch <cx> <cy> <scale> [ms]  # 多指缩放
  simtouch home                         # 返回主屏幕
  simtouch cc                           # 打开控制中心
  simtouch notif                        # 打开通知中心
  simtouch switcher                     # 打开任务切换器
  simtouch screenshot [output_path]
  simtouch info
  simtouch record start [name]          # 开始命名录制
  simtouch record stop                  # 停止录制
  simtouch record list                  # 列出所有录制
  simtouch record dump [name]           # 导出事件详情
  simtouch record delete <name>         # 删除录制
  simtouch replay [name] [speed]        # 回放（可指定名称 + 速度倍率）

通过 SSH 远程调用：
  ssh -p 2215 mobile@localhost "simtouch tap 200 400"
  ssh -p 2215 mobile@localhost "simtouch home"
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
├── Tweak.x                # SpringBoard tweak 入口（ctor + 命令注册 + 录制/回放命令）
├── BackboardHook.x        # backboardd hook（_BKHandleIOHIDEventFromSender + 录制/回放引擎）
├── TouchInjector.h        # 触摸 IPC 中继接口
├── TouchInjector.m        # Darwin notification + 文件 IPC 到 backboardd
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
# Tweak（注入 SpringBoard + backboardd）
TWEAK_NAME = SimTouch
SimTouch_FILES = Tweak.x BackboardHook.x SocketServer.m ScreenCapture.m TouchInjector.m
SimTouch_FRAMEWORKS = Foundation UIKit IOKit
SimTouch_LIBRARIES = substrate
SimTouch_CFLAGS = -fobjc-arc
ARCHS = arm64 arm64e

# 注入过滤器（SimTouch.plist）
{ Filter = { Executables = ( "SpringBoard", "backboardd" ); }; }

INSTALL_TARGET_PROCESSES = SpringBoard backboardd

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

## backboardd 事件捕获生命周期

```
设备开机
    ↓
backboardd 启动 → SimTouch.dylib 加载
    ↓
hook _BKHandleIOHIDEventFromSender
    ↓
等待首个 digitizer 事件（type=11）
    ├── 捕获 sender 指针 → CFRetain → 发 diag "sender.captured"
    └── 捕获有 touch 属性的事件 → IOHIDEventCreateCopy → 保存为模板
    ↓
后续注入：clone 模板 → 修改字段 → 调用 orig_HandleFromSender
```

**注意**：捕获需要用户先触摸一次屏幕。backboardd 重启后需重新捕获。

## 分阶段实现

### Phase 1：截图（MVP）✅ 已完成
- SocketServer + ScreenCapture + CLI + PreferenceBundle
- 支持 `screenshot`、`info`、`enable`、`disable` 命令
- `_UICreateScreenUIImage` 截图，JPEG 默认（0.8 quality）
- 已在 iPhone 13 Pro / iOS 15.4.1 上验证

### Phase 2：触摸注入 ✅ 核心完成
- BackboardHook + TouchInjector + 录制/回放 + 系统手势
- `_BKHandleIOHIDEventFromSender` hook + 事件克隆注入
- **已验证**：tap、swipe、longpress 在主屏幕和 App 内生效
- **已验证**：单次 IPC swipe（STSwipeCmd），消除 notification 合并竞态
- **已验证**：系统手势（home/cc/notif/switcher）通过 SpringBoard 私有 API
- **已验证**：录制基础设施——录制真实触摸事件到二进制文件
- **已确认**：edge mask 位仅用于诊断，不能注入系统手势（arbiter 验证投递路径）
- **已清理**：移除死代码（edge gesture injection、旧 swipe 逐步 IPC）
- **回放**：使用 dispatchTouch 路径，基本可用

### Phase 3：增强 ✅ 已完成
- 自定义 swipe 曲线（cubic-bezier easing，CSS 兼容）
- `keyinput` 文本输入（HID keyboard + 剪贴板粘贴）
- 多点触控 `pinch`（从零创建 IOHIDDigitizerEvent Hand type + 双 Finger children）
- **已验证**：easeinout 和自定义 bezier 曲线在主屏幕滑动
- **已验证**：文本粘贴（"hello世界"）和特殊键（backspace）在 Spotlight
- **已验证**：pinch zoom in/out 在高德地图
- **关键发现**：多指触摸必须从零创建事件（type=Hand），不能克隆单指模板
- **部署要求**：更新 backboardd hook 需 `killall backboardd`，sbreload 不够

### Phase 4：录制回放增强 ✅ 已完成
- 多录制管理（命名录制、列表、删除）
- 回放速度控制（任意倍率）
- 边缘手势智能替换（回放时检测 edge mask → 调用 SpringBoard API）
- **已验证**：命名录制文件创建/删除/列表
- **已验证**：速度倍率计算正确（2x=半时长, 0.5x=倍时长）
- **已验证**：录制中 Home 手势回放时自动触发 SpringBoard home API
- **未实现（记录供后续）**：多指手势录制回放（需要在回放时重建 Hand+Finger 事件结构）

## 兼容性

| 组件 | iOS 15.4.1 | iOS 16.3.1 | 备注 |
|------|------------|------------|------|
| IOHIDEventSystemClient | ✅ | ✅ | 私有 API，一直存在 |
| IOHIDEventCreateCopy | ✅ 已验证 | ✅ | backboardd 中克隆事件 |
| _BKHandleIOHIDEventFromSender | ✅ 已验证 | ✅ | backboardd HID 入口 |
| MSHookFunction | ✅ 已验证 | ✅ | backboardd hook |
| Unix domain socket | ✅ 已验证 | ✅ | POSIX 标准 |
| SpringBoard 注入 | ✅ 已验证 | ✅ | ellekit/substrate |
| backboardd 注入 | ✅ 已验证 | ✅ | ellekit/substrate |

## 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| 事件克隆模板过时 | 注入失效 | 捕获的是 touch-down 事件，结构稳定；如失效可重新触摸捕获 |
| backboardd 沙箱 | 文件 I/O 受限 | 录制文件写 `/tmp/`（可写），命令文件由 SpringBoard 写到 `/var/jb/tmp/`（backboardd 可读） |
| _UICreateScreenUIImage 移除 | 截图失败 | weak_import + 运行时检查 |
| SpringBoard/backboardd crash | respring | hook 内 @try 保护；`_injecting` 标志防递归 |
| arm64e 架构遗漏 | tweak 不加载 | Makefile 固定 `ARCHS = arm64 arm64e` |
| gesture arbiter 投递路径验证 | 系统手势无法通过 HID 注入 | 已用 SpringBoard 私有 API 绕过（已解决） |
| SpringBoard 私有 API 版本变化 | 系统手势命令失败 | 多 selector 降级（如 `handleHomeButtonSinglePressUp` → `clickedMenuButton`） |
| Darwin notification 合并 | swipe 步骤丢失 | 已用单次 STSwipeCmd IPC 解决（backboardd 内部生成轨迹） |
