# iOS 越狱检测绕过插件开发计划

## 背景

- 设备：iPhone 14 Pro Max, iOS 16.3.1, 已越狱
- 目标：绕过某 APP 的越狱检测（APP 打开后 3-5 秒自动退出）
- 参考：该 APP 4.6.4 版本曾有可用插件（已停止维护）

---

## 整体思路

iOS APP 的越狱检测通常通过以下方式实现：
1. 检查越狱相关文件路径是否存在（如 `/Applications/Cydia.app`, `/usr/sbin/sshd`）
2. 检查是否能打开越狱相关 URL scheme（如 `cydia://`）
3. 检查文件系统是否可写（沙盒外）
4. 检查是否存在越狱相关动态库（通过 `_dyld_image_count` 等）
5. 调用 `fork()` 等系统调用测试沙盒完整性
6. 使用 `stat()` / `access()` / `open()` 等检查特定路径
7. 检查环境变量（如 `DYLD_INSERT_LIBRARIES`）

绕过方式是编写 Tweak（动态库），通过 **Method Swizzling** 和 **函数 Hook** 拦截上述检测逻辑，返回"未越狱"的结果。

---

## 操作步骤

### 阶段一：环境准备

- [ ] **Step 1**: 确认越狱工具和包管理器（Cydia/Sileo/Zebra）
- [ ] **Step 2**: 在 Mac 上安装 Theos（越狱插件开发工具链）
- [ ] **Step 3**: 确认 SSH 可连接到手机

### 阶段二：获取和分析目标 APP

- [ ] **Step 4**: 确认 APP 名称和 Bundle ID
- [ ] **Step 5**: 从手机上提取 APP 的二进制文件（已解密）
- [ ] **Step 6**: 使用逆向工具（class-dump / Hopper / IDA）分析二进制文件
- [ ] **Step 7**: 定位越狱检测相关代码

### 阶段三：分析旧插件

- [ ] **Step 8**: 获取旧插件文件（.deb 或 .dylib）
- [ ] **Step 9**: 反编译/反汇编旧插件，理解其 Hook 策略
- [ ] **Step 10**: 记录旧插件 Hook 了哪些方法/函数

### 阶段四：开发新插件

- [ ] **Step 11**: 创建 Theos Tweak 项目
- [ ] **Step 12**: 编写 Hook 代码（基于旧插件分析 + 新版本适配）
- [ ] **Step 13**: 编译并安装到手机测试
- [ ] **Step 14**: 迭代调试（如果 APP 仍然退出，增加更多 Hook 点）

### 阶段五：完善

- [ ] **Step 15**: 确认 APP 核心功能正常
- [ ] **Step 16**: 打包为 .deb 方便后续安装

---

## 当前需要你提供的信息

在开始 Step 1 之前，请告诉我：

1. **APP 名称**是什么？（或 Bundle ID）
2. **你的越狱方式**是什么？（unc0ver / checkra1n / palera1n / Dopamine 等）
3. **包管理器**用的哪个？（Cydia / Sileo / Zebra）
4. **旧插件**你是否还能获取到？（名称、来源 repo 等）
5. **Mac 上是否已有 Theos**？（终端输入 `which theos` 或 `ls ~/theos` 看看）

---

## 技术栈说明

| 工具 | 用途 |
|------|------|
| **Theos** | 越狱插件开发框架（类似 Makefile + SDK） |
| **Logos** | Theos 的 Hook 语法（`%hook`, `%orig` 等宏） |
| **class-dump** | 从二进制文件导出 ObjC 头文件 |
| **Hopper/IDA/Ghidra** | 反汇编/反编译工具 |
| **frida** | 动态分析工具（可实时 Hook 和调试） |
| **SSH + scp** | 与越狱手机通信 |
