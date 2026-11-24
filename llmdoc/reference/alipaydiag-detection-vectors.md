# 支付宝刷脸核身（open-certify）链路

目标：`com.alipay.iphoneclient`（支付宝 12.12.56.6000）。
诊断插件：`alipaydiag`（只读，不改返回值、不改请求）。

## 入口与失败点

北京实名的刷脸走开放平台核身（open-certify），页面是 `render.alipay.com` 上的 H5，
请求由 **App 主进程自己的网络栈**发出（响应缓存在
`Library/Caches/com.alipay.iphoneclient/Cache.db`，不是 WebKit 的 NetworkCache）。

顺序：

1. `GET custweb.alipay.com/certify/open/personal/dispatch/`、`…/entrance?certifyId=…&sign=…`
2. `POST custweb.alipay.com/certify/open/module/query`
   → `{"success":false,"errorCode":"OPEN_CERTIFY_NEED_AUTHORIZE",…,"action_names":["FA_PHOTO","FA"]}`
3. 用户同意协议后 `POST custweb.alipay.com/certify/open/module/auth`
   → `{"success":false,"errorCode":"DEVICE_NOT_SUPPORT",…}`

`DEVICE_NOT_SUPPORT` 的文案来自下载的 i18n 表（`fengdie_custweb_i18n_error_openCertify/zh_CN.json`），
「因兼容性问题，当前手机暂不能使用刷脸功能。请更换手机后重试；或确保当前手机使用手机厂商
原生系统，且不要开启应用分身功能，并只安装厂商官方应用市场下载的支付宝App后重试」。

## auth 请求体（完整字段）

```json
{
  "clientInfo": {
    "clientAppName": "ALIPAY", "clientType": "mobile",
    "clientAppVersion": "12.12.56.6000",
    "noBioAuth": false, "isiOS": true,
    "bioInfo": {
      "zimVer": "3.0.0", "appVersion": "12.12.56.6000",
      "bioMetaInfo": "4.12.0:<ts>,32774,<uid>",
      "appName": "com.alipay.iphoneclient", "deviceType": "ios",
      "osVersion": "iOS 16.3.1", "apdidToken": "<40 字节 base64>",
      "deviceModel": "iPhone15,3"
    },
    "apdidToken": "<同上>", "umidToken": "", "deviceType": "ios"
  },
  "params": { "certifyId": "<id>", "sign": "<RSA 签名>" }
}
```

请求头只有 Nebula 的常规项：`Origin: https://render.alipay.com`、
`X-Biz-Scope: NebulaMD`、`X-Alipay-Client-Session: check`、`X-CDN-Safeguard: afts` 和 UA
（`… AliApp(AP/12.12.56.6000) Nebula WK RVKType(0) AlipayDefined(nt:WIFI,…) …`）。

`clientInfo` 不是 JS 现拼的：页面用 pre-request 机制（`window.__promo_pre_request__`）
提前算好，`bioInfo` 就是 `-[ZimJSApiHandler getMetaInfo]` 返回的 `actionResult`
原样透传；`noBioAuth` 取决于 UA 里有没有 `nobioauth`。

## 已确认的排除项

- 请求体与请求头里没有明文的越狱 / root / 调试标记。
- 空 `umidToken` 不是环境异常：`-[AccountAuthFrameworkServiceImp getUmidToken]` 返回正常
  token，`getMetaInfo` 本来就不含该键。
- 这条链路上零调用的本地入口：SecurityGuard（Manager/RootDetect/SimulatorDetect）、
  `DTCTUInfo setJailbreaked:`、`TeclaDeviceInfoAbilityImpl isJailbroken`、
  `SSAuthServiceImpl isJailbroken`、`RVPBridgeExtension4Jailbroken isJailbroken`。
- ZOLOZ / Toyger 从未启动（`ZolozIdentityManager`、`ZolozBiometricCPServiceImpl`、
  `BioAuthFacade`、`APBToygerFacade` 全部零调用），所以改任何本地刷脸布尔值都影响不到这一步。
- 核身的四条请求（dispatch / entrance / query / auth）都没有 Cookie 头。
- `module/query` 与 `module/auth` 的 `clientInfo` 逐字段相同，前者被正常处理
  （业务错误 `OPEN_CERTIFY_NEED_AUTHORIZE`），后者被拒绝。判定不是这几个字段的纯函数。

## 客户端确实有越狱标记通道，但本次会话没有走

方法表里存在一整族 `isPrisonBreak` / `prisonBreak`：

| 类 | 类型 | 备注 |
|---|---|---|
| `aluDeviceInfoManager` | BOOL | 同时提供 `apdidToken`、`apdidTokenByMode:`、`setApdidTokenCookie:`、`umid`、`utdid`、`tid` |
| `MOBILEAPPGwCommonReq`（MTOP 网关公共请求） | NSNumber | 同族还有 `apdId`、`utdid`、`tid`、`ttid`、`umidToken`、`IMEI`/`IMSI`、`userAgent`、`mobileBrand`/`mobileModel` |
| `ANXRuntimeConfig` | NSNumber | 另有 `isTrojan` |
| `aluSDK`、`AUGUnifyLoginReq`、`ANXBusVerifyServiceModel`、`AntUserDefaultDelegate`、`MOBILEAPPCOMMONClientUpgradeReq`、`UnifyRegisterAllReqPb` | 混合 | 登录/风控/升级通道 |

`isPrisonBreak` / `prisonBreak` 也作为字符串存在于主二进制，说明是会被序列化的字段名。
但在「已登录、直接走核身」的会话里，上述 getter/setter 全部零调用；`NSURLSession` 可见的
出站流量里只有一条 `mobilegw.alipay.com/mgw.htm`，body 中没有任何设备字段标记。
`setApdidTokenCookie:` 被调 7 次（同一个 APDID token），但那四条核身请求上没有 Cookie。

覆盖面限制：支付宝原生 RPC 大部分不经过 `NSURLSession`，对原生传输层的结论仍然开口。

## 唯一具备设备唯一性的字段是 apdidToken

40 字节：前 32 字节像摘要，其后 4 字节 `a2 01 00 00` + `00 00`。它由
`AccountAuthFrameworkServiceImp getApdidToken` 提供，可能来自 SecurityGuard 的 APDID。
服务端可以拿它查自己的设备画像，客户端看不到画像内容。

`bioMetaInfo` 的第二个字段 `32774`（0x8006）含义未查明，若它是能力位掩码，也可能参与判定。

与网商银行的差别：支付宝没有 `ma_jbcheck_use_new`、`kerXbsLCpwutSJRB`、
`_MASecurityUtilImpl` 这一套路径 + unlink 检查；两家同属 SecurityGuard + ZOLOZ 体系，
但集成方式不同。

## 现状

2026-11-24：诊断插件已卸载，设备上的日志与安装包已删除；结论停在「服务端判定、客户端本会话未上报明文标记、判定不是 clientInfo 的纯函数」。12.12.56 里生物识别、生物支付、实名认证、安全中心等备选入口都唤不起人脸认证，入口已收敛到 open-certify 这一条链路。要继续推进只有两条路：退出登录抓登录链路的 `isPrisonBreak`，或换一台未越狱设备做对照。

## 详见

- `alipaydiag/analysis.md`：逐轮实验（假设 / 验证 / 观察 / 推论）
- `llmdoc/memory/doc-gaps.md`：服务端判定依据未定位这一条
