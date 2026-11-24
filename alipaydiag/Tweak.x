#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <fcntl.h>
#import <unistd.h>
#import <time.h>
#import <string.h>
#import <zlib.h>

// 只读诊断：不改任何返回值，只把关键安全组件的行为写进 App 容器的
// Documents/alipaydiag.log。

static void dlog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!dir) {
        return;
    }
    NSString *path = [dir stringByAppendingPathComponent:@"alipaydiag.log"];

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

    NSString *line = [NSString stringWithFormat:@"[%s] %@\n", ts, msg];
    const char *c = line.UTF8String;
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    write(fd, c, strlen(c));
    close(fd);
}

#pragma mark - 取值转字符串（限制长度，避免日志过大）

static NSString *jdump(id obj) {
    if (!obj) {
        return @"(nil)";
    }
    @try {
        if ([obj isKindOfClass:[NSDictionary class]] || [obj isKindOfClass:[NSArray class]]) {
            NSError *err = nil;
            NSData *d = [NSJSONSerialization dataWithJSONObject:obj options:0 error:&err];
            if (d) {
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (s.length > 2000) {
                    s = [[s substringToIndex:2000] stringByAppendingString:@"...[truncated]"];
                }
                return s;
            }
        }
        NSString *s = [obj description];
        if (s.length > 2000) {
            s = [[s substringToIndex:2000] stringByAppendingString:@"...[truncated]"];
        }
        return s;
    } @catch (NSException *e) {
        return @"(dump exception)";
    }
}

#pragma mark - SecurityGuard 组件

%hook SecurityGuardManager
- (id)getRootDetectComp {
    dlog(@"SG.getRootDetectComp");
    return %orig;
}
- (id)getSimulatorDetectComp {
    dlog(@"SG.getSimulatorDetectComp");
    return %orig;
}
%end

%hook SecurityGuardRootDetect
- (BOOL)isRoot {
    BOOL r = %orig;
    dlog(@"SG.root.isRoot -> %d", (int)r);
    return r;
}
+ (BOOL)isRoot {
    BOOL r = %orig;
    dlog(@"SG.root.+isRoot -> %d", (int)r);
    return r;
}
%end

%hook SecurityGuardSimulatorDetect
- (BOOL)isSimulator {
    BOOL r = %orig;
    dlog(@"SG.simulator.isSimulator -> %d", (int)r);
    return r;
}
+ (BOOL)isSimulator {
    BOOL r = %orig;
    dlog(@"SG.simulator.+isSimulator -> %d", (int)r);
    return r;
}
%end

#pragma mark - UT 设备信息里的越狱标记

%hook DTCTUInfo
- (void)setJailbreaked:(BOOL)v {
    dlog(@"DTCTUInfo.setJailbreaked(%d)", (int)v);
    %orig;
}
- (BOOL)isJailbreaked {
    BOOL r = %orig;
    dlog(@"DTCTUInfo.isJailbreaked -> %d", (int)r);
    return r;
}
%end

#pragma mark - 刷脸链路上报的请求体

static NSString *safeURLString(NSURL *url) {
    if (!url) {
        return @"(nil)";
    }
    NSMutableString *s = [NSMutableString string];
    if (url.scheme.length) {
        [s appendFormat:@"%@://", url.scheme];
    }
    if (url.host.length) {
        [s appendString:url.host];
    }
    if (url.path.length) {
        [s appendString:url.path];
    }
    if (url.query.length) {
        [s appendString:@"?<redacted>"];
    }
    return s;
}

static NSString *safeHeaders(NSDictionary *h) {
    if (!h) {
        return @"(nil)";
    }
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *k in h) {
        NSString *lk = k.lowercaseString;
        if ([lk isEqualToString:@"cookie"] || [lk containsString:@"token"] ||
            [lk containsString:@"session"] || [lk containsString:@"sign"] ||
            [lk containsString:@"auth"]) {
            out[k] = @"<redacted>";
            continue;
        }
        NSString *v = [h[k] description];
        out[k] = v.length > 200 ? [[v substringToIndex:200] stringByAppendingString:@"..."] : v;
    }
    return jdump(out);
}

static void logWebReq(NSURLRequest *req) {
    if (!req) {
        return;
    }
    NSString *u = safeURLString(req.URL);
    if (!req.URL) {
        return;
    }
    BOOL hit = NO;
    NSString *raw = req.URL.absoluteString ?: @"";
    for (NSString *k in @[@"custweb", @"certify", @"module/auth", @"module/query"]) {
        if ([raw rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) {
            hit = YES;
            break;
        }
    }
    if (!hit) {
        return;
    }
    NSData *body = req.HTTPBody;
    NSString *bs = @"(none)";
    if (body.length) {
        bs = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (!bs) {
            bs = [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)body.length];
        } else if (bs.length > 4000) {
            bs = [[bs substringToIndex:4000] stringByAppendingString:@"...[truncated]"];
        }
    }
    dlog(@"REQ %@ %@\n  hdr=%@\n  body=%@", req.HTTPMethod, u, safeHeaders(req.allHTTPHeaderFields), bs);
}

static NSData *gunzipData(NSData *in) {
    if (in.length < 4) {
        return nil;
    }
    const uint8_t *b = in.bytes;
    if (!(b[0] == 0x1f && b[1] == 0x8b)) {
        return in;   // 不是 gzip，原样返回
    }
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 + 16) != Z_OK) {
        return nil;
    }
    NSUInteger cap = 1 << 20;
    NSMutableData *out = [NSMutableData dataWithLength:cap];
    zs.next_in = (Bytef *)b;
    zs.avail_in = (uInt)in.length;
    zs.next_out = (Bytef *)out.mutableBytes;
    zs.avail_out = (uInt)cap;
    int ret = inflate(&zs, Z_FINISH);
    NSUInteger produced = cap - zs.avail_out;
    inflateEnd(&zs);
    if (ret != Z_STREAM_END) {
        return nil;
    }
    [out setLength:produced];
    return out;
}

// 只记摘要：命中哪些字段名、isPrisonBreak 的值；不记 body 原文、query、token
static void mtopSummary(NSURLRequest *req) {
    static int count = 0;
    if (count > 80 || !req.URL) {
        return;
    }
    NSString *host = req.URL.host.lowercaseString;
    if (!host.length) {
        return;
    }
    BOOL hit = [host containsString:@"mobilegw"] || [host containsString:@"mgw"] ||
               [host containsString:@"openapi"] || [host containsString:@"mdap"] ||
               [host containsString:@"anx"];
    if (!hit) {
        return;
    }
    NSData *body = req.HTTPBody;
    if (!body.length) {
        return;
    }
    NSData *plain = gunzipData(body);
    NSString *s = plain ? [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding] : nil;
    if (!s.length) {
        count++;
        dlog(@"MTOP %@ %@ bin len=%lu", req.HTTPMethod, safeURLString(req.URL), (unsigned long)body.length);
        return;
    }
    if (s.length > 200000) {
        s = [s substringToIndex:200000];
    }
    NSString *low = s.lowercaseString;
    NSMutableArray *keys = [NSMutableArray array];
    for (NSString *k in @[@"isprisonbreak", @"prisonbreak", @"istrojan", @"apdid",
                          @"utdid", @"umidtoken", @"devicemodel", @"osversion", @"systemversion"]) {
        if ([low containsString:k]) {
            [keys addObject:k];
        }
    }
    NSString *val = @"-";
    NSRange r = [low rangeOfString:@"isprisonbreak"];
    if (r.location != NSNotFound) {
        NSUInteger start = NSMaxRange(r);
        NSUInteger len = MIN((NSUInteger)40, s.length - start);
        val = [s substringWithRange:NSMakeRange(start, len)];
        val = [val stringByReplacingOccurrencesOfString:@"\"" withString:@"'"];
        val = [val stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    }
    count++;
    dlog(@"MTOP %@ %@ keys=[%@] isPrisonBreak=%@", req.HTTPMethod,
         safeURLString(req.URL), [keys componentsJoinedByString:@","], val);
}

static void scanJailbreak(NSData *body, NSString *where) {
    if (!body.length || body.length > 300000) {
        return;
    }
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!s.length) {
        return;
    }
    NSString *low = s.lowercaseString;
    for (NSString *k in @[@"jailbreak", @"jailbroken", @"isroot", @"jail_break"]) {
        NSRange r = [low rangeOfString:k];
        if (r.location != NSNotFound) {
            NSUInteger start = r.location;
            NSRange ctx = NSMakeRange(start, MIN((NSUInteger)60, s.length - start));
            dlog(@"JBHIT %@ %@\n  %@", where, k, [s substringWithRange:ctx]);
            return;
        }
    }
}

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    logWebReq(request);
    scanJailbreak(request.HTTPBody, safeURLString(request.URL));
    mtopSummary(request);
    return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(id)handler {
    logWebReq(request);
    scanJailbreak(request.HTTPBody, safeURLString(request.URL));
    mtopSummary(request);
    return %orig;
}
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)data {
    logWebReq(request);
    scanJailbreak(data, safeURLString(request.URL));
    mtopSummary(request);
    return %orig;
}
%end

#pragma mark - 设备信息（刷脸链路上报给服务端的那份）

%hook AlipayVIAdapter
- (id)getBioInfo {
    id r = %orig;
    dlog(@"VI.getBioInfo -> %@", jdump(r));
    return r;
}
%end

%hook TeclaZimIdentityAbilityImpl
- (void)verify:(id)a params:(id)b callback:(id)c {
    dlog(@"ZimIdentityAbility.verify params=%@", jdump(b));
    %orig;
}
%end

#pragma mark - 本地越狱判定入口（看它们在这条链路上是否被调用）

%hook ZimJSApiHandler
- (void)handler:(id)a contextInfo:(id)b callback:(id)c {
    dlog(@"ZimJSApi.handler ctx=%@", jdump(b));
    %orig;
}
- (id)getMetaInfo {
    id r = %orig;
    dlog(@"ZimJSApi.getMetaInfo -> %@", jdump(r));
    return r;
}
%end

%hook ZimJSApiAdapter
- (void)handler:(id)a context:(id)b callback:(id)c {
    dlog(@"ZimJSApiAdapter.handler ctx=%@", jdump(b));
    %orig;
}
%end

%hook TeclaDeviceInfoAbilityImpl
- (BOOL)isJailbroken {
    BOOL r = %orig;
    dlog(@"TeclaDeviceInfo.isJailbroken -> %d", (int)r);
    return r;
}
%end

%hook AccountAuthFrameworkServiceImp
- (id)getUmidToken {
    id r = %orig;
    dlog(@"AccountAuth.getUmidToken -> %@", jdump(r));
    return r;
}
- (id)getApdidToken {
    id r = %orig;
    dlog(@"AccountAuth.getApdidToken -> %@", jdump(r));
    return r;
}
%end

%hook NativeUmidTokenProvider
- (id)getUmidToken {
    id r = %orig;
    dlog(@"NativeUmid.getUmidToken -> %@", jdump(r));
    return r;
}
%end

%hook SSAuthServiceImpl
- (BOOL)isJailbroken {
    BOOL r = %orig;
    dlog(@"SSAuthService.isJailbroken -> %d", (int)r);
    return r;
}
%end

%hook RVPBridgeExtension4Jailbroken
- (BOOL)isJailbroken {
    BOOL r = %orig;
    dlog(@"RVPBridgeJailbroken.isJailbroken -> %d", (int)r);
    return r;
}
%end

#pragma mark - 越狱标记的取值与落点（先校验类型编码再挂钩）

static void jbHookGetter(Class cls, const char *name) {
    if (!cls) {
        dlog(@"JB 缺类：%s", name);
        return;
    }
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        dlog(@"JB 无方法：%s", name);
        return;
    }
    char *rt = method_copyReturnType(m);
    dlog(@"JB 类型 %s = %s", name, method_getTypeEncoding(m));
    if (!rt) {
        return;
    }
    IMP orig = method_getImplementation(m);
    if (rt[0] == 'B' || rt[0] == 'c') {
        IMP repl = imp_implementationWithBlock(^BOOL(id self) {
            BOOL r = ((BOOL (*)(id, SEL))orig)(self, sel);
            dlog(@"JB %s -> %d", name, (int)r);
            return r;
        });
        MSHookMessageEx(cls, sel, repl, NULL);
    } else if (rt[0] == '@') {
        IMP repl = imp_implementationWithBlock(^id(id self) {
            id r = ((id (*)(id, SEL))orig)(self, sel);
            dlog(@"JB %s -> %@", name, jdump(r));
            return r;
        });
        MSHookMessageEx(cls, sel, repl, NULL);
    }
    free(rt);
}

static void jbHookSetter(Class cls, const char *name) {
    if (!cls) {
        return;
    }
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        dlog(@"JB 无方法：%s", name);
        return;
    }
    char *at = method_copyArgumentType(m, 2);
    dlog(@"JB 类型 %s = %s", name, method_getTypeEncoding(m));
    if (!at) {
        return;
    }
    IMP orig = method_getImplementation(m);
    if (at[0] == 'B' || at[0] == 'c') {
        IMP repl = imp_implementationWithBlock(^(id self, BOOL v) {
            dlog(@"JB %s(%d)", name, (int)v);
            ((void (*)(id, SEL, BOOL))orig)(self, sel, v);
        });
        MSHookMessageEx(cls, sel, repl, NULL);
    } else if (at[0] == '@') {
        IMP repl = imp_implementationWithBlock(^(id self, id v) {
            dlog(@"JB %s(%@)", name, jdump(v));
            ((void (*)(id, SEL, id))orig)(self, sel, v);
        });
        MSHookMessageEx(cls, sel, repl, NULL);
    }
    free(at);
}

static void jbHookObjArg(Class cls, const char *name) {
    if (!cls) {
        return;
    }
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        dlog(@"JB 无方法：%s", name);
        return;
    }
    char *at = method_copyArgumentType(m, 2);
    dlog(@"JB 类型 %s = %s", name, method_getTypeEncoding(m));
    if (!at || at[0] != '@') {
        free(at);
        return;
    }
    free(at);
    IMP orig = method_getImplementation(m);
    IMP repl = imp_implementationWithBlock(^(id self, id arg) {
        dlog(@"JB %s(%@)", name, jdump(arg));
        ((void (*)(id, SEL, id))orig)(self, sel, arg);
    });
    MSHookMessageEx(cls, sel, repl, NULL);
}

#pragma mark - 刷脸链路入口

%hook ZolozIdentityManager
- (void)verifyWith:(id)a extParams:(id)b onCompletion:(id)c {
    dlog(@"Zoloz.verifyWith called ext=%p", (void *)(__bridge void *)b);
    %orig;
}
- (void)ossentry_verifyWith:(id)a extParams:(id)b onCompletion:(id)c {
    dlog(@"Zoloz.ossentry_verifyWith called ext=%p", (void *)(__bridge void *)b);
    %orig;
}
%end

%hook ZolozBiometricCPServiceImpl
- (void)verifyWith:(id)a extParams:(id)b onCompletion:(id)c {
    dlog(@"ZolozBiometric.verifyWith called ext=%p", (void *)(__bridge void *)b);
    %orig;
}
%end

%hook BioAuthFacade
- (void)authWithRequest:(id)req withCallback:(id)cb {
    dlog(@"BioAuthFacade.authWithRequest called req=%p", (void *)(__bridge void *)req);
    %orig;
}
%end

%hook APBToygerFacade
- (id)initWithRequest:(id)req {
    dlog(@"APBToygerFacade.initWithRequest called req=%p", (void *)(__bridge void *)req);
    return %orig;
}
%end

%ctor {
    dlog(@"=== AlipayDiag loaded pid=%d ver=%@",
         getpid(),
         [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

    NSArray *names = @[
        @"SecurityGuardManager", @"SecurityGuardRootDetect", @"SecurityGuardSimulatorDetect",
        @"DTCTUInfo", @"TBSDKSecurity", @"ZolozIdentityManager", @"ZolozBiometricCPServiceImpl",
        @"BioAuthFacade", @"APBToygerFacade", @"AlipayVIAdapter", @"TeclaZimIdentityAbilityImpl",
        @"ZimJSApiHandler", @"ZimJSApiAdapter", @"TeclaDeviceInfoAbilityImpl",
        @"SSAuthServiceImpl", @"RVPBridgeExtension4Jailbroken", @"AccountAuthFrameworkServiceImp", @"NativeUmidTokenProvider",
        @"aluDeviceInfoManager", @"MOBILEAPPGwCommonReq", @"ANXRuntimeConfig",
        @"ANXBusVerifyServiceModel", @"aluSDK", @"AUGUnifyLoginReq", @"AntUserDefaultDelegate"
    ];
    for (NSString *n in names) {
        dlog(@"class %@ = %p", n, NSClassFromString(n));
    }

    Class alu = NSClassFromString(@"aluDeviceInfoManager");
    jbHookGetter(alu, "isPrisonBreak");
    jbHookSetter(alu, "setIsPrisonBreak:");
    jbHookObjArg(alu, "setApdidTokenCookie:");

    Class gw = NSClassFromString(@"MOBILEAPPGwCommonReq");
    jbHookGetter(gw, "isPrisonBreak");
    jbHookSetter(gw, "setIsPrisonBreak:");

    Class anx = NSClassFromString(@"ANXRuntimeConfig");
    jbHookGetter(anx, "isPrisonBreak");
    jbHookSetter(anx, "setIsPrisonBreak:");
    jbHookGetter(anx, "isTrojan");

    jbHookGetter(NSClassFromString(@"ANXBusVerifyServiceModel"), "isPrisonBreak");
    jbHookGetter(NSClassFromString(@"aluSDK"), "isPrisonBreak");
    jbHookGetter(NSClassFromString(@"AUGUnifyLoginReq"), "isPrisonBreak");
    jbHookGetter(NSClassFromString(@"AntUserDefaultDelegate"), "isPrisonBreak");
}
