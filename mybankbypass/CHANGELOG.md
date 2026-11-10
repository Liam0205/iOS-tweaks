# Changelog

## 1.2.2

适配网商银行 4.7.48。

### 修复

- 4.7.48 在启动检查失败时会直接调用 `exit(0)`。原来的 `exit` 钩子在主线程用死循环
  runloop 把它吞掉，那次调用永远不返回，启动流程停在半路：界面能出来、能滚动、能切
  tab，但中间内容点击没有反应。现在改为在 4.7.48 里把这次退出之前的分支改成不跳转
  （偏移 `0x3c2ac30`，`cbnz w19` 换成 `nop`），让检查结束时正常返回，启动流程走完。
- 定位主程序镜像改用可执行文件路径匹配。注入之后 `_dyld_get_image_header(0)`
  不一定是主程序，按索引取会把补丁写到空洞里。
- 打完补丁后把代码页权限还原成可读可执行。iOS 不允许一页同时可写可执行，
  不还原的话同页其它函数一执行就 `SIGBUS`。

### 已知限制

- 这个偏移是按 4.7.48 写死的。其它版本必须重新定位，程序里只对已知版本生效，
  遇到未知版本不做修改。

## 1.2.1

- 补充验证信息：在网商银行 4.7.36 版本验证可用（支持 4.6.4 ~ 4.7.36）

## 1.2.0

- 更换包名为 page.0x01.mybankbypass
- 已安装用户可无缝升级

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
