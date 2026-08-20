# Changelog

## 0.1.0

- 完全绕过链家 9.86.91 与贝壳找房 3.06.21 的越狱检测（两 App 共用 JGBSDK + a.framework 检测引擎）
- 层 1 文件检测：hook stat/lstat/access/opendir/dlopen，拦截越狱路径返回 ENOENT，dladdr 伪装镜像来源
- 层 2 dyld 镜像枚举：作用域限定重排 _dyld_image_count/_dyld_get_image_name，隐藏越狱镜像并用 vis-map 缓存避免 O(n²) 卡死主线程
- 层 3 注入检测：MSHookFunction a.framework 的 _isInjectedWithDynamicLibrary 恒返回未注入
- 层 4 自杀退出：运行时 patch JGBSDK 内联的 29 处直接 exit syscall（svc #0x80）改为 ret
- NSFileManager 目录枚举过滤，隐藏 DynamicLibraries 类目录中的越狱项
- 链家与贝壳找房主界面均验证通过，无秒退、无冻结
