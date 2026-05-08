# Changelog

## 0.1.2

- 修正 CI 发版流程（自动生成 index.html、修复 Pages 部署）

## 0.1.0

- 初始版本
- 绕过交通银行 10.3.0 越狱环境检测
- Hook BangcleCheck、SecureUtilityPlus、CWDeviceStatusManager 等安全类
- Hook C 层文件检测（stat/lstat/access/fopen）
- Hook dyld 枚举、sysctl 调试检测、fork
- 拦截越狱提示弹窗与 exit/abort 退出调用
- 隐藏越狱相关 URL Scheme 和环境变量
