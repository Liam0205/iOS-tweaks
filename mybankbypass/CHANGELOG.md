# Changelog

## 1.1.1

- 修正 Sileo 中包分类显示（从"插件"改为"反检测"）

## 1.1.0

适配网商银行 4.7.36 版本。

### 新增

- 中和 `MAJailbreakChecker` 内置越狱检测库（含 filesystem / DYLD / fork / URL scheme / ObjC class / symlink 等多维度检测）
- 中和 `MYBLauncherController.checkJailbroken`，防止检测触发 exit 导致主线程死锁
- 中和 `MASecurityUtil` 风险标记与内存扫描
- 中和 `RDSSecurityCheck` dylib/tweak 检测与反调试检查
- 新增 `DTDeviceInfo` 越狱相关方法 hook 与 C 函数 `DTDeviceInfo_isJailbreak` hook
- 新增 `RVPBridgeExtension4Jailbroken` H5/RPC bridge 越狱状态中和
- 新增 BinAOP hook detection 全面中和（APBinAOPDrill / Config / GlobalStatusUtils 等）
- 新增 `statfs` / `statvfs` hook，隐藏文件系统可写状态
- 新增 `getppid` hook
- 扩充越狱路径指纹列表与 dylib 隐藏列表

### 修复

- 修复 `_dyld_image_count` / `_dyld_get_image_name` 过滤一致性 bug（此前导致 watchdog 崩溃）
- 改进 exit/\_exit/abort hook：后台线程使用 `pthread_exit` 替代 `sleep(INT_MAX)` 避免线程池阻塞

### 移除

- 移除大部分 `NSFileManager` ObjC 层 hook（避免被 BinAOP 直接检测），改由底层 C hook 覆盖

## 1.0.0

初始版本，支持网商银行 4.6.4。
