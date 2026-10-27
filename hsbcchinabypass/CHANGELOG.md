# HSBCChinaBypass 更新日志

## 1.0.1

改包名，功能与 1.0.0 完全一致。

1.0.0 叫 `page.0x01.hsbcbypass`，filter 同时包含汇丰中国和汇丰香港两个 bundle id。
实测名称与覆盖面不符：这套手段只对汇丰中国的 ZDefend 生效，汇丰香港 3.69.12 是另一套
技术栈，补丁在那儿不起任何作用，那条 filter 唯一的效果是多留一条注入痕迹。

- 包名改为 `page.0x01.hsbcchinabypass`，tweak 名与安装后的 dylib 改为 `HSBCChinaBypass`。
- filter 只保留 `cn.com.hsbc.hsbcchina`。
- 通过 `Conflicts` / `Replaces: page.0x01.hsbcbypass` 接替旧包，安装时由包管理器自行替换。
- 日志文件改名为 `hsbcchinabypass.log`（仅 debug 构建会写）。
- 汇丰香港另立 `hsbchkbypass` 项目，目前仍在排查，没有可用版本。

## 1.0.0

首个发布版。目标 App 汇丰中国（`cn.com.hsbc.hsbcchina`）3.75.0（build 129890），在 rootless 越狱
（Dopamine + ElleKit）环境下不再一打开就闪退，也不再显示「抱歉，您无法在此设备上使用此应用程序」的
拦截页。首页 → 隐私政策 → 用户条款 → 新功能引导 → 位置/通知授权 → 首页 → 去注册/登录 →
跨境传输授权 → 数字证书授权 → 设置您的手机银行，全程可交互，连续三次冷启动各 40 秒、再持续
运行 3 分钟以上都稳定。

- **检测栈换代**：3.75.0 把判定引擎从 Promon SHIELD 换成了 ZDefend（Zimperium），
  `ShieldSDK.framework` 已从包里移除，可执行文件也从 `Frameworks/hsbcchinax.framework/hsbcchinax`
  换成了主二进制 `China.app/China`。早期版本的所有地址对 3.75.0 都失效。
- **闪退根因**：ZDefend 判定后起一条线程收拾后事，`ZDefend+0x23a3c8 → +0x23a380 → +0x1e569c`
  调用 `exit(0)`，启动约 2.8 秒进程消失。把 `exit` 拦下它会改用 `pthread_kill(SIGABRT)` 重试。
- **主要手段是改掉那条线程的入口**：`ZDefend+0x23a380` 第一条指令换成 `ret`（`0xD65F03C0`）。
  这个入口没有直接调用者，地址被写进结构体后由 `pthread_create` 进入，所以改一条指令即可。
  改 `+0x1e569c` 里那条 `b.eq` 反而更糟：App 多活十秒后变成 `SIGILL`。
- **辅助手段是清空威胁列表**：`+[ZDefend getAllThreats]`、`+[ZDefendImpl getAllThreats]`、
  `-[ZDeviceStatus allThreats/activeThreats/activeNewThreats]` 返回空数组。PlatformRASP
  拿不到威胁就不渲染拦截页。
- **判定本身没有被消除**：ZDefend 照样认为设备不安全，实测 11 条威胁——八条来自它比对自己导入的
  libc 函数指针与实际实现是否一致（`_dlsym`、`_fopen`、`_getenv`、`_sysctl`、`_sysctlbyname`、
  `_access`、`_lstat`、`_open`），一条来自 `_dlopen` 指向 `/usr/lib/systemhook.dylib`，
  两条来自 `statfs("/usr/lib")` 返回的 `bindfs`。前两类只要还注入就消不掉。
- **发布版不再留日志**：日志开关改为编译期判断，`make package` 走 debug 构建带日志，
  `make package FINALPACKAGE=1` 走 release 构建，所有日志调用被编译掉，不会在 App 容器里创建
  `hsbcchinabypass.log`。需要排查时把 `Tweak.x` 里的 `HSBC_DUMP_THREATS` 改成 1，可以在 App 起来后
  把 ZDefend 的 11 条威胁连证据一起打印出来。

## 0.0.1 – 0.0.2

> 诊断迭代，未发布。过程记录在 `analysis.md`。
