# AIABypass 更新日志

## 0.0.1

- 首个版本，**尚未解决**。目标是友邦友享（`com.aia.china.YoubangHealthRelease`）在 rootless 越狱设备上打开即闪退的问题。
- 已确认闪退来自 App 内置的 `JMCodeProtectKit.framework` RASP，不是普通越狱判定。
- 已排除：镜像路径检测、多装载一个 tweak 触发、`brk #0xdead` 陷阱桩。
- 已确认检测对象是越狱注入基座（`systemhook.dylib`、`libinjector.dylib`、`libellekit.dylib`），移除所有 tweak 后仍然闪退。
