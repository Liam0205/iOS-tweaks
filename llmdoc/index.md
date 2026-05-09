# llmdoc 索引

本目录保存 DEV-iOS 项目的稳定文档，按”启动必读、项目概览、架构、参考、操作指南”组织，便于在后续分析、构建、回归测试和适配新版本时快速定位信息。

## 启动入口

- `llmdoc/startup.md`：新会话启动时的阅读顺序，只列出建议优先阅读的文档。

## overview/

- `llmdoc/overview/project-overview.md`：项目目标（多 tweak 仓库）、目标环境、当前工作状态、软件源与 CI/CD 架构。

## architecture/

- `llmdoc/architecture/tweak-architecture.md`：绕过 tweak 的核心执行模型、Hook 分层、业务层 launcher 中和与关键实现约束。

## reference/

- `llmdoc/reference/detection-vectors.md`：目标 App 已知越狱检测向量、4.7.36 新增检测点、调试经验与当前覆盖情况。

## guides/

- `llmdoc/guides/build-deploy.md`：构建、安装、发版 tag 规则、CI Release workflow 与 gh-pages 部署流程。
- `llmdoc/guides/reverse-engineering-methodology.md`：逆向分析与反检测对抗的实验方法论、诊断顺序与 analysis.md 记录纪律。
