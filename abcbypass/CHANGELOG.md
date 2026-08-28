# Changelog

## 1.0.1

- 补充验证信息：在农业银行 11.1.0 版本验证可用

## 1.0.0

- 完全绕过中国农业银行的越狱检测与检测后 exit 杀进程链路
- 核心方案：swizzle `-[DTFrameworkInterface initRiskManage]` 从源头消除检测退出，纯 ObjC swizzle 不触发完整性自检
- 中和 SecureUtilityPlus / SmAntiFraud / IOSSecuritySuite 及农行专有越狱检测方法
- 隐藏越狱文件路径、屏蔽越狱 App URL scheme、抑制越狱弹窗、清理注入环境变量
- 已验证：农行 11.1.0 / iPhone 13 Pro / iOS 15.4.1，农行 11.2.0 / iPhone 14 Pro Max / iOS 16.3.1，均进入首页且交互正常
