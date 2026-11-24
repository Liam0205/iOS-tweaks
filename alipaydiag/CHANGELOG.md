# AlipayDiag 更新日志

只读诊断插件，不改任何返回值。每个版本对应 `analysis.md` 里的一轮实验。

## 0.0.8

- 新增 MTOP/openapi/mdap/anx 出站摘要：只记命中的字段名与 `isPrisonBreak` 的值，
  query 与 cookie/token/session/sign 一律 redacted，不记 body 原文。
- 结论：本次会话只有一条 mtop 走 `NSURLSession`，无设备字段；核身四条请求都没有 Cookie。

## 0.0.7

- 改用 `method_copyReturnType` / `method_copyArgumentType` 判断签名，`B` 与 `@` 两种形态都挂。
- 结论：`isPrisonBreak` 一系列入口本次会话零调用；APDID cookie 被设置 7 次。

## 0.0.6

- 新增 `aluDeviceInfoManager`、`MOBILEAPPGwCommonReq`、`ANXRuntimeConfig`、
  `ANXBusVerifyServiceModel`、`aluSDK`、`AUGUnifyLoginReq`、`AntUserDefaultDelegate` 的
  `isPrisonBreak` 类型编码打印。
- 类型编码判断写成了字面量，未挂上钩子；只拿到编码。

## 0.0.5

- 新增 `AccountAuthFrameworkServiceImp getUmidToken` / `getApdidToken`、
  `NativeUmidTokenProvider getUmidToken` 的取值记录，用于验证「空 UMID 是否是环境异常」。
- 结论：UMID 生成正常，`getMetaInfo` 本身不返回该字段，假设排除。

## 0.0.4

- 新增 ZimJSApi / Tecla / SSAuth / RVP 的越狱判定入口记录。
- 新增请求体关键字扫描（`jailbreak` / `isroot` 等）。
- 结论：这条链路上本地越狱判定入口零调用，请求体无明文标记。

## 0.0.3

- 新增 `NSURLSession` 发请求入口的记录，按 `custweb` / `certify` 过滤，打印 URL、请求头和请求体。
- 拿到 `module/query`、`module/auth` 的完整 JSON body。

## 0.0.2

- 新增 `AlipayVIAdapter getBioInfo`、`TeclaZimIdentityAbilityImpl verify:params:callback:` 的记录。
- 结论：这两个入口没有命中，不是这条链路的取数点。

## 0.0.1

- 首个版本：SecurityGuard（RootDetect / SimulatorDetect / Manager）、DTCTUInfo、
  ZOLOZ（IdentityManager / BiometricCPUService）、BioAuthFacade、APBToygerFacade 的入口记录。
- 移除 `TBSDKSecurity` 的 WUA / factorSign hook：它们会让启动阶段 SIGABRT。
