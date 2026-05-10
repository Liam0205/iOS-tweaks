# DevLog — 共享开发日志库

## 目标

为仓库内所有 tweak 提供统一的开发日志采集与上传能力。仅在开发构建中启用，正式发版完全禁用。

## 设计

### Tweak 端（静态编入各 tweak）

- 头文件 `DevLog.h`，实现 `DevLog.m`
- 编译开关 `DEVLOG_ENABLED`（0/1），由 Makefile 或 dev-deploy 控制
- 禁用时所有 API 编译为空宏，零运行时开销

### API

```objc
// 初始化，传入上报地址。应在 %ctor 中调用。
void DevLogInit(NSString *serverURL);

// 写日志（线程安全）。tag 用于分类，如 "HOOK", "FREEZE", "ALERT"。
void DevLog(NSString *tag, NSString *fmt, ...);

// 立即上传（通常由定时器自动触发，也可手动调用）。
void DevLogFlush(void);
```

### 设备标识

- `UIDevice.currentDevice.identifierForVendor.UUIDString` 作为设备 ID
- `UIDevice.currentDevice.name` 作为可读名称
- 通过 HTTP header `X-Device-ID` 和 `X-Device-Name` 传递

### 上传策略

- 本地写入 `Documents/devlog.txt`（追加模式）
- 每 30 秒定时上传（后台 dispatch timer）
- 上传成功后清空本地日志
- 上传失败不丢弃，下次重试

### 服务端（Python 脚本）

- `devlog/server.py`：监听 HTTP POST
- 日志按设备 ID 分目录存储：`logs/<device-id>/latest.log`
- 支持 `tail -f` 实时查看
- 可选：终端 TUI 展示多设备实时日志流

### 集成方式

各 tweak 的 Makefile 中：

```makefile
<TweakName>_FILES += ../devlog/DevLog.m
<TweakName>_CFLAGS += -I../devlog -DDEVLOG_ENABLED=1
```

dev-deploy.py 构建时自动传入 `DEVLOG_ENABLED=1` 和 `DEVLOG_SERVER_URL`。

## 文件结构

```
devlog/
├── PLAN.md         # 本文件
├── DevLog.h        # 头文件（API + 条件编译宏）
├── DevLog.m        # 实现
└── server.py       # 日志接收服务端
```
