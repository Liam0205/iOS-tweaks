# llmdoc 索引

本目录保存 DEV-iOS 项目的稳定文档，按”启动必读、项目概览、架构、参考、操作指南”组织，便于在后续分析、构建、回归测试和适配新版本时快速定位信息。

## 启动入口

- `llmdoc/startup.md`：新会话启动时的阅读顺序，只列出建议优先阅读的文档。

## overview/

- `llmdoc/overview/project-overview.md`：项目目标（多 tweak 仓库 + 设备端开发工具）、目标环境、当前工作状态、软件源与 CI/CD 架构。

## architecture/

- `llmdoc/architecture/tweak-architecture.md`：mybankbypass 的核心执行模型、Hook 分层、业务层 launcher 中和与关键实现约束。
- `llmdoc/architecture/icbc-architecture.md`：icbcbypass 的架构——fishhook + Logos 组合、三层防御对抗（检测+冻结+弹窗退出）、CALayer 速率限制策略、解冻定时器永久运行与降频机制、已知性能考量、与 mybankbypass 的关键差异。

## reference/

- `llmdoc/reference/detection-vectors.md`：网商银行已知越狱检测向量、4.7.36 新增检测点、调试经验与当前覆盖情况。
- `llmdoc/reference/icbc-detection-vectors.md`：工商银行检测框架（SecureUtilityPlus）、冻结机制（持续 freeze 循环及版本间时序差异）、弹窗退出链路、版本适配记录（3.0.80、3.0.90）与覆盖情况。

## guides/

- `llmdoc/guides/build-deploy.md`：构建、安装、发版 tag 规则、CI Release workflow 与 gh-pages 部署流程。
- `llmdoc/guides/reverse-engineering-methodology.md`：逆向分析与反检测对抗的实验方法论、诊断顺序与 analysis.md 记录纪律。

## memory/reflections/

- `llmdoc/memory/reflections/hsbc-methodology-lesson.md`：HSBC 分析经验反思。
- `llmdoc/memory/reflections/icbcbypass-v1.0.0-release.md`：icbcbypass v1.0.0 发布反思——嵌套 RunLoop 死锁教训、fishhook 替代 MSHookFunction 约束、semaphore 区分策略。
- `llmdoc/memory/reflections/icbc-3090-adaptation.md`：ICBC 3.0.90 适配反思——全局阻断框架方法的隐性退化、速率限制优于时间门控、sched_yield 缓解忙循环。
- `llmdoc/memory/reflections/anti-detection-deep-analysis.md`：MSHookFunction 风险决策、inline SVC 对抗哲学、fishhook 被禁极端场景分析、发版配置教训。
- `llmdoc/memory/reflections/linux-cross-compile-setup.md`：Linux 无 sudo 环境搭建 Theos 交叉编译的完整踩坑记录。
- `llmdoc/memory/reflections/deploy-via-reverse-tunnel.md`：反向隧道部署踩坑——端口号/用户名缺失导致试错、root vs mobile 约束、SSHTunnel 自举问题。
