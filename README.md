# iOS Tweaks

iOS 越狱 Tweak 仓库，基于 Theos 构建，面向 rootless 越狱环境（Dopamine 等）。

## Tweaks

| 包名 | 目标 App | 支持版本 | 说明 |
|------|----------|----------|------|
| `page.0x01.mybankbypass` | 网商银行 | 4.6.4 ~ 4.7.36 | 绕过越狱环境检测，使其在越狱设备上正常运行 |
| `page.0x01.bankcommbypass` | 交通银行 | 10.3.0 | 绕过越狱环境检测，使其在越狱设备上正常运行 |
| `page.0x01.icbcbypass` | 工商银行 | 3.0.80 ~ 3.0.90 | 绕过越狱检测三层防御（检测+冻结+退出弹窗） |
| `page.0x01.abcbypass` | 农业银行 | 11.1.0 | 绕过越狱检测（开发中） |
| `page.0x01.lianjiabypass` | 链家、贝壳找房 | 链家 9.86.91 / 贝壳 3.06.21 | 绕过越狱检测四层防御（文件检测+镜像枚举+注入检测+自杀退出） |

## Tools

| 包名 | 类型 | 说明 |
|------|------|------|
| `page.0x01.sshtunnel` | Application | SSH 反向隧道管理器 (v1.3.2)，用于远程调试越狱设备 |
| `page.0x01.simtouch` | Tweak + Tool | 远程触控模拟与截屏 (v0.1.0)，用于自动化测试越狱设备 |

## 安装

添加 Sileo 软件源：

```
https://tweaks.0x01.page
```

## 从源码构建

需要 [Theos](https://theos.dev) 环境。

```bash
cd <tweak目录>
make clean && make package FINALPACKAGE=1
```

产物在 `<tweak目录>/packages/` 下。

部分 tweak（如 `simtouch`）依赖私有框架（Preferences 等）。官方 Xcode 的 iOS SDK 不含这些私有框架的链接期 stub，构建会报 `framework not found`。需从 [theos/sdks](https://github.com/theos/sdks) 获取带私有框架 stub 的 patched SDK，放入 `$THEOS/sdks/` 并在构建时用 `SYSROOT` 指定。CI 已自动处理这一步。

部署到设备（需配置 `THEOS_DEVICE_IP`）：

```bash
make install
```

## License

Private repository. All rights reserved.
