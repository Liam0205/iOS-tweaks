# Changelog

## 1.0.0

- 完全绕过工商银行 3.0.80 的越狱检测三层防御
- 对抗 SecureUtilityPlus 检测框架的文件/路径/环境变量检查
- 解除主线程持续冻结循环（RunLoop freeze）
- 拦截退出弹窗链路，防止强制退出
- 使用 fishhook + Logos 组合方案，绕过 MSHookFunction 限制
- 登录与正常使用均已验证通过
