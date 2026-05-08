# DEV-iOS

iOS 越狱 Tweak 仓库，基于 Theos 构建，面向 rootless 越狱环境（Dopamine 等）。

## Tweaks

| 包名 | 目标 App | 支持版本 | 说明 |
|------|----------|----------|------|
| `com.liam.mybankbypass` | 网商银行 | 4.6.4 ~ 4.7.36 | 绕过越狱环境检测，使其在越狱设备上正常运行 |

## 安装

添加 Sileo 软件源：

```
https://tweaks.0x01.page
```

## 从源码构建

需要 [Theos](https://theos.dev) 环境。

```bash
cd mybankbypass
make clean && make package FINALPACKAGE=1
```

产物在 `mybankbypass/packages/` 目录下。

部署到设备（需配置 `THEOS_DEVICE_IP`）：

```bash
make install
```

## 项目结构

```
mybankbypass/           # MYBankBypass tweak 源码
├── Tweak.x            # Hook 实现
├── Makefile           # Theos 构建配置
├── control            # Debian 包元数据
├── MYBankBypass.plist # 注入过滤（仅目标 App）
└── CHANGELOG.md       # 版本更新日志
repo/                  # Sileo 软件源（GitHub Pages 托管）
├── depictions/        # Native depiction JSON
├── debs/              # 已发布 deb 包
├── Packages           # 包索引
└── Release            # 源元数据
.github/workflows/     # CI/CD
├── build.yml          # 自动构建（push/PR 触发）
├── release.yml        # 自动发版（tag 触发）
└── pages.yml          # 软件源部署到 GitHub Pages
```

## 发版流程

1. 更新 `control` 中的版本号
2. 更新 tweak 目录下的 `CHANGELOG.md`
3. 推送 tag，格式为 `<tweak目录名>_<版本号>`（如 `mybankbypass_1.1.0`）
4. CI 自动完成：构建 → GitHub Release → 更新软件源 → 部署 Pages

## License

Private repository. All rights reserved.
