# llmdoc Startup

开始处理本项目时，按以下顺序阅读：

1. `llmdoc/overview/project-overview.md` — 了解项目目标、设备环境与当前已验证状态
2. `llmdoc/architecture/tweak-architecture.md` — 了解绕过实现的核心结构与关键实现约束
3. `llmdoc/reference/detection-vectors.md` — 查阅目标 App 的检测面与当前 Hook 覆盖
4. `llmdoc/guides/build-deploy.md` — 执行构建、安装、测试与回归验证
5. `llmdoc/guides/reverse-engineering-methodology.md` — 逆向分析方法论，面对新目标时优先阅读

以上 2、3 步列出的是网商银行（mybankbypass）的文档。其他每个 tweak 都有各自独立的 `architecture/<tweak>-architecture.md` 与 `reference/<tweak>-detection-vectors.md`，处理某个具体 tweak 时改读对应文档，完整列表见 `llmdoc/index.md`。
