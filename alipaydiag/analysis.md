# AlipayDiag 实验记录

目标：`com.alipay.iphoneclient`（支付宝 12.12.56.6000）。
设备：iPhone 14 Pro Max（iPhone15,3）/ iOS 16.3.1 / rootless Dopamine + ElleKit。

原始症状：支付宝大部分功能正常，但进入北京实名的刷脸核身入口后，页面提示
「因兼容性问题，当前手机暂不能使用刷脸功能」。

本目录是**只读诊断插件**，不改任何返回值、不拦截请求，只把关键调用和请求内容写进
App 容器的 `Documents/alipaydiag.log`。

## 0. 静态：检测栈身份

主二进制里的相关组件（全部静态链入，无独立 framework 镜像）：

| 组件 | 关键方法 | 备注 |
|------|----------|------|
| SecurityGuardManager / RootDetect / SimulatorDetect | `getRootDetectComp`、`isRoot`、`isSimulator` | 与网商银行同族的 SecurityGuard |
| DTCTUInfo | `setJailbreaked:`、`isJailbreaked` | UT 设备信息里的越狱标记 |
| TBSDKSecurity | `getMiddleTierWua:`、`getAvmpWua:`、`factorSign:…` | x-sign / WUA |
| ZolozIdentityManager / ZolozBiometricCPServiceImpl | `verifyWith:extParams:onCompletion:`、`getBioMetaInfo` | ZOLOZ 刷脸 |
| BioAuthFacade、APBToygerFacade | `authWithRequest:withCallback:`、`initWithRequest:` | Toyger 刷脸 UI |
| AlipayVIAdapter、TeclaZimIdentityAbilityImpl、ZimJSApiHandler | `getBioInfo`、`getMetaInfo` | H5 核身链路的信息出口 |
| APSecurityUtilityServiceImpl、SSAuthServiceImpl、TeclaDeviceInfoAbilityImpl、RVPBridgeExtension4Jailbroken | `MADetectJailbroken`、`isJailbroken`、`isSystemRoot:…` | App 自带的越狱判定入口 |

与网商银行（`mybankbypass`）的共同点：同为 SecurityGuard + ZOLOZ 体系。
不同点：支付宝这边没有网商银行 4.7.48 起那套「路径 + unlink」检查
（`ma_jbcheck_use_new` / `kerXbsLCpwutSJRB` / `_MASecurityUtilImpl` 在支付宝里不存在）。

## 1. 0.0.1：复现时本地组件在做什么

- **假设**：刷脸失败是本地某个检测布尔（SecurityGuard 越狱/模拟器、DTCTUInfo、ZOLOZ）取值异常导致的。
- **验证**：装 0.0.1（只 hook 上述组件的入口并记日志），重启 App，重走刷脸入口。
- **观察**：日志里只有 `%ctor` 打的 class 地址，**没有任何一次方法调用命中**。
  同一时段，App 容器 `Library/Caches/com.alipay.iphoneclient/Cache.db` 新增两条记录：
  `POST custweb.alipay.com/certify/open/module/query` 返回
  `{"success":false,"errorCode":"OPEN_CERTIFY_NEED_AUTHORIZE",…,"action_names":["FA_PHOTO","FA"]}`；
  随后 `POST …/module/auth` 返回 `{"success":false,"errorCode":"DEVICE_NOT_SUPPORT",…}`。
- **推论**：失败来自服务端对 `module/auth` 的响应，不是本地组件给出的结论。ZOLOZ 从未启动，
  改任何一个本地布尔都不可能影响这条链路。
- **副作用记录**：0.0.1 首版还 hook 了 `TBSDKSecurity` 的 `getMiddleTierWua:` / `factorSign:…`，
  导致启动阶段 SIGABRT（故障线程在 `mtop.common.getTimestamp` 队列）。移除这两组 hook
  后启动稳定。这是自己造成的崩溃，不是目标检测。

## 2. 静态：页面脚本里的请求构造

从设备 WebKit NetworkCache 里取出 open-certify 页面的 pre-request 脚本（21881 字节，
内联在 HTML 里）和页面主 bundle（572660 字节）。关键代码（去混淆后）：

```js
function R() {                       // ClientInfo
  return new Promise(function (t) {
    f("zimIdentity", { action: "getBioInfo" }).then(function (n) {
      var e = n.actionResult || {};
      e.appVersion ? t({
        clientAppName: "ALIPAY", clientType: "mobile",
        clientAppVersion: e.appVersion, noBioAuth: B() || false,
        isiOS: e.deviceType === "ios" || false,
        bioInfo: e,                       // 整个 actionResult 原样带走
        apdidToken: e.apdidToken || "", umidToken: e.umidToken || "",
        deviceType: e.deviceType
      }) : t({});
    });
  });
}
// auth：POST /certify/open/module/auth，body = {clientInfo, params:{certifyId, sign}}
```

`ClientInfo` 由容器的 pre-request 机制（`window.__promo_pre_request__`）提前算好；
`noBioAuth` 直接看 UA 里有没有 `nobioauth`。

## 3. Frida 抓包尝试（失败，记录避免重蹈）

- **假设**：请求由 WebKit 网络进程发出，可以在那里抓请求体。
- **验证**：附着 `com.apple.WebKit.Networking`，hook `NSURLSession` 的发请求方法。
- **观察**：该 XPC 进程按需拉起、空闲即退出，轮询 attach 连续得到
  `the connection is closed`；改用 spawn gating 后，`Spawn` 对象没有 `name` 属性，
  脚本在放行环节抛异常，所有新进程都没被 resume，**表现为页面一直转圈**。
- **推论**：这条路既不稳定又会改变设备状态（暂停进程），放弃。改在 App 进程内 hook。
  教训：观测手段不能改变被测对象的状态；spawn gating 属于高风险工具，没有可靠放行
  逻辑不要开。

## 4. 0.0.3：在 App 进程内抓请求体

- **假设**：如果请求由 App 主进程发出，`NSURLSession` hook 就能拿到完整 body。
- **验证**：hook `-[NSURLSession dataTaskWithRequest:]` 等入口，按 URL 关键字过滤。
- **观察**：命中。`module/query` 与 `module/auth` 都带完整 JSON body，请求头里有
  `X-Biz-Scope: NebulaMD`、`X-Alipay-Client-Session: check` 和 Nebula 的 UA。
  body 原文（token 已截断）：

```json
{
  "clientInfo": {
    "clientAppName": "ALIPAY", "clientType": "mobile",
    "clientAppVersion": "12.12.56.6000", "noBioAuth": false, "isiOS": true,
    "bioInfo": {
      "zimVer": "3.0.0", "appVersion": "12.12.56.6000",
      "bioMetaInfo": "4.12.0:1628342034496,32774,<uid>",
      "appName": "com.alipay.iphoneclient", "deviceType": "ios",
      "osVersion": "iOS 16.3.1", "apdidToken": "JLI/VU4a…AAA==",
      "deviceModel": "iPhone15,3"
    },
    "apdidToken": "JLI/VU4a…AAA==", "umidToken": "", "deviceType": "ios"
  },
  "params": { "certifyId": "<id>", "sign": "<sign>" }
}
```

- **推论**：客户端交给服务端的设备信息就这些——一个设备级 token（`apdidToken`，
  40 字节，前 32 字节像摘要）、机型、系统版本、App 版本、ZOLOZ 元信息、UA。
  **没有明文的越狱/root 标记**。请求落在 `com.alipay.iphoneclient/Cache.db`，
  说明是 App 主进程自己的网络栈发的，不是 WebKit 网络进程。

## 5. 0.0.4：本地越狱判定入口是否被调用

- **假设**：客户端会在这条链路上做本地越狱判定，并把结果编码进上面那些字段。
- **验证**：hook `ZimJSApiHandler getMetaInfo`、`TeclaDeviceInfoAbilityImpl isJailbroken`、
  `SSAuthServiceImpl isJailbroken`、`RVPBridgeExtension4Jailbroken isJailbroken`、
  `DTCTUInfo setJailbreaked:`；同时对每个请求体做 `jailbreak` / `isroot` 关键字扫描。
- **观察**：`ZimJSApi.getMetaInfo` 命中，返回值与请求体里的 `bioInfo` 逐字段一致；
  其余越狱判定入口**零调用**；关键字扫描零命中。
- **推论**：至少在这条链路上，客户端不查询本机越狱状态，也不上报明文标记。
  `bioInfo` 就是 `getMetaInfo` 的全部输出，没有隐藏字段。

## 6. 0.0.5：UMID 假设

- **假设**：请求里 `umidToken` 为空，可能是越狱环境导致 UMID 生成失败，服务端据此拒绝。
- **验证**：hook `AccountAuthFrameworkServiceImp getUmidToken` / `getApdidToken`、
  `NativeUmidTokenProvider getUmidToken`。
- **观察**：`getUmidToken` 返回了正常长度的 token（`AwUHAfKezFKAMgpCsBvesMcJNgDvQetq`）；
  但 `getMetaInfo` 的返回里根本没有 `umidToken` 键，页面按 `e.umidToken || ""` 补空。
- **推论**：空 UMID 是这个接口的固定构造，不是环境异常。假设排除。

## 7. 0.0.6：越狱标记的取值与上传（进行中）

第 6 节的结论被推翻了一半：certify 的 POST 确实不带越狱标记，但**客户端另有通道**。
静态方法表里可以看到：

| 类 | 相关方法 |
|---|---|
| `aluDeviceInfoManager` | `isPrisonBreak`、`setIsPrisonBreak:`、`apdidToken`、`apdidTokenByMode:`、`setApdidTokenCookie:`、`umid`、`utdid`、`tid`、`imei`/`imsi`、`idfa` |
| `MOBILEAPPGwCommonReq`（MTOP 网关公共请求） | `apdId`、`utdid`、`tid`、`ttid`、`umidToken`、`IMEI`/`IMSI`、`userAgent`、`mobileBrand`/`mobileModel`、`isPrisonBreak` |
| `ANXRuntimeConfig` | `isPrisonBreak`、`isTrojan` |
| `ANXBusVerifyServiceModel`、`aluSDK`、`AUGUnifyLoginReq`、`AntUserDefaultDelegate`、`MOBILEAPPCOMMONClientUpgradeReq`、`UnifyRegisterAllReqPb` | 各自的 `isPrisonBreak` / `prisonBreak` |

`isPrisonBreak` / `prisonBreak` 也作为字符串出现在主二进制里，说明它是会被序列化的字段名，
不是纯内部状态。也就是说：设备是否越狱，客户端会算，并且会随 MTOP 网关请求上传；
certify 的 POST 只是没带它，服务端仍然可以在同一账号、同一 UDID/APDID 的画像里读到。

另外，`setApdidTokenCookie:` 说明 APDID 也走 Cookie。`fetch(..., credentials:"include")`
会带上 Cookie，而我们的抓包读的是 `NSURLRequest.allHTTPHeaderFields`，Cookie 通常是
CFNetwork 在发送前才补的，所以第 4 节的头里看不到它。

- **假设**：`aluDeviceInfoManager isPrisonBreak` 在本机返回 YES，并经
  `MOBILEAPPGwCommonReq setIsPrisonBreak:` 进入发往服务端的请求；certify 那一步只是
  没重复携带，服务端早已从别的请求里知道这台设备越狱。
- **验证**：0.0.6 先按类型编码校验再挂钩（`c@:`/`B@:` 才挂 getter，`v@:c`/`v@:B` 才挂
  setter，其余只打印编码不挂），记录 `aluDeviceInfoManager`、`MOBILEAPPGwCommonReq`、
  `ANXRuntimeConfig` 等类的取值与赋值时机，并记录 `setApdidTokenCookie:` 的参数。
- **观察（0.0.6，只看类型编码）**：实际编码带偏移，不是字面的 `B@:`：
  `aluDeviceInfoManager isPrisonBreak` = `B16@0:8`（BOOL），`setIsPrisonBreak:` = `v20@0:8B16`；
  `MOBILEAPPGwCommonReq isPrisonBreak` = `@16@0:8`（**NSNumber 对象**），`setIsPrisonBreak:` = `v24@0:8@16`；
  `ANXRuntimeConfig isPrisonBreak`/`isTrojan` 同样是 `@`；`aluSDK`、`AntUserDefaultDelegate`
  的是 `B`；`ANXBusVerifyServiceModel`、`AUGUnifyLoginReq` 的是 `@`。
  0.0.6 的比较写成了字面量，全部没挂上，只有编码打印——这一轮等于没测到值。
- **0.0.7**：改用 `method_copyReturnType` / `method_copyArgumentType` 判断，`B`/`c` 与 `@`
  两种形态分别挂钩，重新测取值与时机。
- **观察（0.0.7）**：`setApdidTokenCookie:` 命中 9 次，参数始终是同一个 APDID token
  （`JLI/VU4a…AAA==`），说明 APDID 会以 Cookie 形式随请求发出。但
  `aluDeviceInfoManager.isPrisonBreak` / `setIsPrisonBreak:`、
  `MOBILEAPPGwCommonReq.isPrisonBreak` / `setIsPrisonBreak:`、`ANXRuntimeConfig` 的
  `isPrisonBreak`/`isTrojan`，以及 `ANXBusVerifyServiceModel`、`aluSDK`、`AUGUnifyLoginReq`、
  `AntUserDefaultDelegate` 的 `isPrisonBreak`，**全部零调用**。
- **推论**：在「已登录、直接走核身」这段稳态里，客户端没有读取或写入 `isPrisonBreak`。
  携带该字段的类集中在登录与风控通道（`aluSDK loginAsync:`、`AUGUnifyLoginReq`、
  `ANXRuntimeConfig`），这些路径本次没有走。MTOP 网关请求模型上的 getter 零调用还不足以
  证明字段没被发送（protobuf 序列化可能直接读成员），但 setter 也没被调用，说明本次会话
  里这个字段根本没有被赋值。
- **另一个关键观察**：`module/query` 与 `module/auth` 的请求体里 `clientInfo` **逐字段相同**
  （同一个 apdidToken、同一份 bioInfo）。query 被服务端正常处理（返回业务错误
  `OPEN_CERTIFY_NEED_AUTHORIZE`），auth 才返回 `DEVICE_NOT_SUPPORT`。所以这个判定不是
  这几个客户端字段的纯函数，order 状态或账号/设备的历史状态参与了判断。

## 结论与仍未解决的问题

已确认：

1. 刷脸失败发生在 `POST /certify/open/module/auth` 这一步，服务端返回 `DEVICE_NOT_SUPPORT`；
   `module/query` 是成功的，订单和商户信息都正常。
2. 客户端在 `module/auth` 这一条请求里交给服务端的设备信息是完整可枚举的（见第 4 节），
   其中没有任何越狱标记；但客户端另有通道（MTOP 网关公共请求）携带 `isPrisonBreak`，
   见第 7 节。
3. 这条链路上，本地 SecurityGuard / DTCTUInfo / ZOLOZ / Toyger / Tecla 越狱判定入口
   都没有被调用；ZOLOZ 从未启动。

未知：

- 服务端依据哪一项判定「设备不支持」。唯一具备设备唯一性的是 `apdidToken`；
  服务端可以拿它查自己的设备画像（该画像是否含越狱/环境结论，客户端看不到）。
  其余字段（机型、系统版本、App 版本、`bioMetaInfo`）更像能力矩阵的输入。
- `bioMetaInfo` 的第二个字段 `32774` 含义未知。若是能力位掩码，也可能直接参与判定。
- 尚未对照的实验：同一账号在未越狱设备上走同一入口；或抓 mtop 侧设备信息上报
  （请求体通常加密/压缩，本轮没做）。

## 复现方式

```bash
make package                                  # 需要 THEOS；Linux 下先 env -u PERL5LIB
scp -P <port> packages/<deb> mobile@localhost:/var/jb/tmp/
ssh -p <port> mobile@localhost "sudo dpkg -i /var/jb/tmp/<deb>"
# 重启支付宝，走一次北京实名的刷脸入口
ssh -p <port> mobile@localhost "cat /var/mobile/Containers/Data/Application/<UUID>/Documents/alipaydiag.log"
```

注意：新装的 dylib 需要 Choicy 的按 App 允许列表放行才能注入（本项目设备上
支付宝的允许列表在 bootstrap 侧
`/var/jb/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist`）。

静态分析用到的两个脚本在 `tools/`：`findstr.py` 按 Mach-O section 定位 UTF-8 /
UTF-16LE 字符串，`parse_objc.py` 解析 `__objc_classlist` → `class_ro_t` → 相对方法表，
输出「类名 + 方法名」清单。
