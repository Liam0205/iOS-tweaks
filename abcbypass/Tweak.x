#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <pthread.h>
#import <signal.h>
#import <setjmp.h>
#import <string.h>
#import <dirent.h>
#import <malloc/malloc.h>
#import <execinfo.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>
#import <mach/thread_act.h>
#import <mach/arm/thread_status.h>
#import "fishhook.h"

#define ABC_DEBUG_LOG 1

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

// ========== Logging ==========

static char g_log_path[512];
static CFAbsoluteTime g_start;

static void abc_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void abc_log(const char *fmt, ...) {
#if ABC_DEBUG_LOG
    FILE *f = fopen(g_log_path, "a");
    if (!f) return;
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    fprintf(f, "[%6.2f] ", elapsed);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
#endif
}

// ========== Path lists ==========

static const char *jb_paths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app",
    "/Library/MobileSubstrate", "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/PreferenceBundles", "/Library/PreferenceLoader",
    "/Library/Themes", "/Library/dpkg",
    "/usr/sbin/sshd", "/usr/bin/sshd", "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server", "/usr/bin/cycript",
    "/usr/local/bin/cycript", "/usr/lib/libcycript.dylib",
    "/bin/bash", "/bin/sh", "/bin/zsh",
    "/usr/bin/ssh", "/usr/bin/scp",
    "/etc/apt", "/etc/ssh/sshd_config",
    "/var/cache/apt", "/var/lib/apt", "/var/lib/dpkg",
    "/var/lib/cydia", "/var/log/syslog",
    "/var/mobile/Library/SBSettings", "/var/stash",
    "/private/var/lib/apt", "/private/var/lib/cydia",
    "/private/var/stash", "/private/var/tmp/cydia.log",
    "/private/var/mobileLibrary/SBSettingsThemes",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/private/etc/dpkg/origins/debian",
    "/var/jb", "/var/binpack",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cycript", "frida", "Frida",
    "MobileSubstrate", "DynamicLibraries", "TweakInject",
    "Cydia", "Sileo", "jailbreak", "Jailbreak",
    "injection", "libhooker", "ellekit",
    NULL
};

static int is_jb_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; jb_paths[i]; i++) {
        if (strcmp(path, jb_paths[i]) == 0) return 1;
    }
    for (int i = 0; jb_substrings[i]; i++) {
        if (strstr(path, jb_substrings[i])) return 1;
    }
    return 0;
}

// ========== ObjC hook setup ==========

static BOOL isSecuritySelector(NSString *selName) {
    return [selName containsString:@"jailb"] || [selName containsString:@"Jailb"] ||
        [selName containsString:@"JailB"] || [selName containsString:@"amI"] ||
        [selName containsString:@"check"] || [selName containsString:@"Check"] ||
        [selName containsString:@"detect"] || [selName containsString:@"Detect"] ||
        [selName containsString:@"hook"] || [selName containsString:@"Hook"] ||
        [selName containsString:@"debug"] || [selName containsString:@"Debug"] ||
        [selName containsString:@"inject"] || [selName containsString:@"Inject"] ||
        [selName containsString:@"tamper"] || [selName containsString:@"Tamper"] ||
        [selName containsString:@"root"] || [selName containsString:@"Root"] ||
        [selName containsString:@"emulat"] || [selName containsString:@"Emulat"] ||
        [selName containsString:@"reverse"] || [selName containsString:@"Reverse"] ||
        [selName containsString:@"frida"] || [selName containsString:@"Frida"] ||
        [selName containsString:@"proxy"] || [selName containsString:@"Proxy"] ||
        [selName containsString:@"integrity"] || [selName containsString:@"Integrity"];
}

static void hookSecureUtilityPlusClass(const char *className) {
    Class cls = objc_getClass(className);
    if (!cls) return;
    for (int pass = 0; pass < 2; pass++) {
        Class target = (pass == 0) ? object_getClass(cls) : cls;
        unsigned int mc = 0;
        Method *methods = class_copyMethodList(target, &mc);
        for (unsigned int i = 0; i < mc; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if (!isSecuritySelector(selName)) continue;
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c')
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            else if (retType[0] == '@')
                method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s, ...) { return @[]; }));
        }
        if (methods) free(methods);
    }
}

static void hookSecureUtilityPlus(void) {
    static const char *classes[] = {
        "_TtC17SecureUtilityPlus16JailbreakChecker",
        "_TtC17SecureUtilityPlus16IOSSecuritySuite",
        "_TtC17SecureUtilityPlus21MSHookFunctionChecker",
        "_TtC17SecureUtilityPlus18RuntimeHookChecker",
        "_TtC17SecureUtilityPlus30ReverseEngineeringToolsChecker",
        "_TtC17SecureUtilityPlus15EmulatorChecker",
        "_TtC17SecureUtilityPlus12ModesChecker",
        "_TtC17SecureUtilityPlus16IntegrityChecker",
        "_TtC17SecureUtilityPlus12ProxyChecker",
        "_TtC17SecureUtilityPlus15DebuggerChecker",
        "_TtC17SecureUtilityPlus12CheckAllCall",
        "_TtC17SecureUtilityPlus11FileChecker",
        "_TtC17SecureUtilityPlus15FishHookChecker",
        NULL
    };
    for (int i = 0; classes[i]; i++)
        hookSecureUtilityPlusClass(classes[i]);
}

static void hookIOSSecuritySuite(void) {
    Class cls = objc_getClass("IOSSecuritySuite.IOSSecuritySuite");
    if (!cls) cls = objc_getClass("IOSSecuritySuite");
    if (!cls) return;
    SEL sels[] = {
        NSSelectorFromString(@"amIJailbroken"),
        NSSelectorFromString(@"amIRunInEmulator"),
        NSSelectorFromString(@"amIDebugged"),
        NSSelectorFromString(@"amIReverseEngineered"),
        NSSelectorFromString(@"amIProxied"),
        NSSelectorFromString(@"amITampered:"),
    };
    for (int i = 0; i < 6; i++) {
        Method m = class_getClassMethod(cls, sels[i]);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
    }
    SEL failSel = NSSelectorFromString(@"amIJailbrokenWithFailedChecks");
    Method m = class_getClassMethod(cls, failSel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^id(id s) {
        return @{@"jailbroken": @NO, @"failedChecks": @[]};
    }));
}

static void hookABCJailbreakMethods(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        const char *cname = class_getName(cls);
        if (!cname) continue;
        // Only scan classes likely from the app binary (skip system frameworks)
        if (strncmp(cname, "NS", 2) == 0 || strncmp(cname, "UI", 2) == 0 ||
            strncmp(cname, "BS", 2) == 0 || strncmp(cname, "BK", 2) == 0 ||
            strncmp(cname, "WK", 2) == 0 || strncmp(cname, "CA", 2) == 0 ||
            strncmp(cname, "AV", 2) == 0 || strncmp(cname, "CT", 2) == 0 ||
            strncmp(cname, "CK", 2) == 0 || strncmp(cname, "RB", 2) == 0 ||
            strncmp(cname, "_UI", 3) == 0 || strncmp(cname, "__NS", 4) == 0 ||
            strncmp(cname, "OS_", 3) == 0 || strncmp(cname, "CF", 2) == 0)
            continue;
        for (int pass = 0; pass < 2; pass++) {
            Class target = (pass == 0) ? cls : object_getClass(cls);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(target, &mc);
            for (unsigned int i = 0; i < mc; i++) {
                NSString *sel = NSStringFromSelector(method_getName(methods[i]));
                BOOL match = [sel isEqualToString:@"isJailBreak"] ||
                    [sel isEqualToString:@"isJailbroken"] ||
                    [sel isEqualToString:@"isJailBreaked"] ||
                    [sel isEqualToString:@"jailbroken"] ||
                    [sel isEqualToString:@"phoneIsJailBreak"] ||
                    [sel isEqualToString:@"checkIsJailBreak"] ||
                    [sel isEqualToString:@"isDeviceJailBreak"] ||
                    [sel hasPrefix:@"isJailBreak"] ||
                    [sel isEqualToString:@"checkRootStatusWithUserLocalScenario:"];
                if (!match) continue;
                abc_log("hookABCJailbreak: %s -> %s", cname, sel.UTF8String);
                char rt[8];
                method_getReturnType(methods[i], rt, sizeof(rt));
                if (rt[0] == 'B' || rt[0] == 'c')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                else if (rt[0] == 'i' || rt[0] == 'l' || rt[0] == 'q')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
            }
            if (methods) free(methods);
        }
    }
    if (allClasses) free(allClasses);
}

// 源头阻断 (纯 ObjC swizzle, 安全, 不触发完整性校验):
// -[DTFrameworkInterface initRiskManage] 内创建并投递那个检测 block
// (invoke=MbapMPaaS+0x8dad68), block 在越狱时判定 [receiver action]==3 -> exit(0)。
// swizzle initRiskManage 直接 return, 使风险管理不初始化 -> 检测 block 永不创建/投递。
static void hookInitRiskManage(void) {
    Class cls = objc_getClass("DTFrameworkInterface");
    if (!cls) { abc_log("DTFrameworkInterface not found — initRiskManage hook skipped"); return; }
    SEL sel = sel_registerName("initRiskManage");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { abc_log("initRiskManage method not found"); return; }
    char rt[8] = {0};
    method_getReturnType(m, rt, sizeof(rt));
    // 返回类型为 void (v) — 替换为空实现
    method_setImplementation(m, imp_implementationWithBlock(^void(id self) {
        abc_log("initRiskManage NEUTRALIZED (risk manager init skipped — detection block never scheduled)");
    }));
    abc_log("initRiskManage swizzled (rettype=%c)", rt[0] ? rt[0] : '?');
}

static void hookAuthorityJailBreakFlag(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        for (int pass = 0; pass < 2; pass++) {
            Class target = (pass == 0) ? cls : object_getClass(cls);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(target, &mc);
            for (unsigned int i = 0; i < mc; i++) {
                if (sel_isEqual(method_getName(methods[i]), @selector(authorityWithJailBreakFlag:))) {
                    IMP origIMP = method_getImplementation(methods[i]);
                    method_setImplementation(methods[i], imp_implementationWithBlock(^(id self, BOOL flag) {
                        ((void (*)(id, SEL, BOOL))origIMP)(self, @selector(authorityWithJailBreakFlag:), NO);
                    }));
                }
            }
            if (methods) free(methods);
        }
    }
    if (allClasses) free(allClasses);
}

static void hookShowJailBrokenAlert(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        for (int pass = 0; pass < 2; pass++) {
            Class target = (pass == 0) ? cls : object_getClass(cls);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(target, &mc);
            for (unsigned int i = 0; i < mc; i++) {
                if (sel_isEqual(method_getName(methods[i]), @selector(showJailBrokenAlertIfNeeded))) {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^(id s) {}));
                }
            }
            if (methods) free(methods);
        }
    }
    if (allClasses) free(allClasses);
}

static void hookSmAntiFraud(void) {
    // Disable SmAntiFraud initialization entirely
    Class smClass = objc_getClass("SmAntiFraud");
    if (smClass) {
        SEL initSel = NSSelectorFromString(@"initWithCheckRoot:checkRiskFrame:checkFrida:");
        Method m = class_getInstanceMethod(smClass, initSel);
        if (m) {
            method_setImplementation(m, imp_implementationWithBlock(^id(id self, BOOL root, BOOL riskFrame, BOOL frida) {
                abc_log("SmAntiFraud init disabled");
                return self;
            }));
        }
        SEL sharedSel = NSSelectorFromString(@"sharedInstance");
        Method sm = class_getClassMethod(smClass, sharedSel);
        if (sm) {
            method_setImplementation(sm, imp_implementationWithBlock(^id(id cls) { return nil; }));
        }
    }

    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        const char *name = class_getName(allClasses[c]);
        if (!name) continue;
        if (strncmp(name, "Sm", 2) != 0 && !strstr(name, "AntiFraud")) continue;
        Class cls = allClasses[c];
        for (int pass = 0; pass < 2; pass++) {
            Class target = (pass == 0) ? cls : object_getClass(cls);
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(target, &mc);
            for (unsigned int i = 0; i < mc; i++) {
                NSString *sel = NSStringFromSelector(method_getName(methods[i]));
                if ([sel containsString:@"checkRoot"] || [sel containsString:@"checkDylib"] ||
                    [sel containsString:@"checkInject"] || [sel containsString:@"checkFrida"] ||
                    [sel containsString:@"isRoot"] || [sel containsString:@"foundFlexInject"] ||
                    [sel containsString:@"checkRisk"] || [sel containsString:@"getDeviceRisk"]) {
                    char rt[8];
                    method_getReturnType(methods[i], rt, sizeof(rt));
                    if (rt[0] == 'B' || rt[0] == 'c')
                        method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                    else if (rt[0] == 'i' || rt[0] == 'l' || rt[0] == 'q')
                        method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
                    else if (rt[0] == '@')
                        method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s, ...) { return nil; }));
                }
            }
            if (methods) free(methods);
        }
    }
    if (allClasses) free(allClasses);
}

// ========== ObjC exception handler ==========

static void abc_exception_handler(NSException *exception) {
    abc_log("EXCEPTION caught: %s — %s", exception.name.UTF8String, exception.reason.UTF8String);
    NSArray *symbols = [exception callStackSymbols];
    for (NSUInteger i = 0; i < MIN(symbols.count, 10); i++)
        abc_log("  [%lu] %s", (unsigned long)i, [symbols[i] UTF8String]);
}

// ========== Logos hooks ==========

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && is_jb_path(path.UTF8String)) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && is_jb_path(path.UTF8String)) return NO;
    return %orig;
}
- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (path && is_jb_path(path.UTF8String)) return NO;
    return %orig;
}
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSArray *contents = %orig;
    if (!contents) return contents;
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!is_jb_path(fullPath.UTF8String)) [filtered addObject:item];
    }
    return filtered;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSString *s = url.scheme.lowercaseString;
    if ([s isEqualToString:@"cydia"] || [s isEqualToString:@"sileo"] ||
        [s isEqualToString:@"zbra"] || [s isEqualToString:@"filza"]) return NO;
    return %orig;
}
- (void)terminateWithSuccess {
    abc_log("terminateWithSuccess blocked");
}
- (void)_terminateWithStatus:(int)status {
    // 安全网: 源头阻断 (initRiskManage 中和) 后检测退出通常不再触发, 但保留此拦截
    // 以防其它早期退出路径。<30s 视为检测退出, 直接拦下不 %orig。
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    if (elapsed < 30.0) {
        abc_log("_terminateWithStatus:%d blocked (%.1fs after launch, likely detection)", status, elapsed);
        return;
    }
    abc_log("_terminateWithStatus:%d allowed (%.1fs after launch, likely lifecycle)", status, elapsed);
    %orig;
}
%end

static const char kABCSuppressedKey;

%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)message preferredStyle:(UIAlertControllerStyle)style {
    NSString *combined = [NSString stringWithFormat:@"%@ %@", title ?: @"", message ?: @""];
    NSString *lower = [combined lowercaseString];
    if ([lower containsString:@"越狱"] || [lower containsString:@"jailbr"] ||
        [lower containsString:@"安全"] || [lower containsString:@"root"]) {
        abc_log("ALERT suppressed: %s", combined.UTF8String);
        NSArray *bt = [NSThread callStackSymbols];
        for (NSUInteger i = 0; i < MIN(bt.count, 15); i++)
            abc_log("  BT[%lu] %s", (unsigned long)i, [bt[i] UTF8String]);
        UIAlertController *dummy = %orig(@"", @"", style);
        objc_setAssociatedObject(dummy, &kABCSuppressedKey, @YES, OBJC_ASSOCIATION_RETAIN);
        return dummy;
    }
    return %orig;
}
%end

%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)flag completion:(void (^)(void))completion {
    if ([vc isKindOfClass:[UIAlertController class]] &&
        objc_getAssociatedObject(vc, &kABCSuppressedKey)) {
        abc_log("suppressed alert presentation blocked");
        if (completion) completion();
        return;
    }
    %orig;
}
%end

%hook NSProcessInfo
- (NSDictionary *)environment {
    NSDictionary *orig = %orig;
    NSMutableDictionary *env = [orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"_MSSafeMode"];
    return env;
}
%end

// ========== Constructor ==========

%ctor {
    g_start = CFAbsoluteTimeGetCurrent();

    // Try /var/jb/tmp first, fall back to app container Documents
    snprintf(g_log_path, sizeof(g_log_path), "/var/jb/tmp/abcbypass.log");
    FILE *f = fopen(g_log_path, "w");
    if (!f) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (docs) {
            snprintf(g_log_path, sizeof(g_log_path), "%s/abcbypass.log", docs.UTF8String);
            f = fopen(g_log_path, "w");
        }
    }

#if ABC_DEBUG_LOG
    if (f) {
        NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        fprintf(f, "[  0.00] [INIT] ABCBypass v0.1.0-116 / ABC %s ctor started\n",
                appVer ? appVer.UTF8String : "?");
        fclose(f);
    }
#else
    if (f) fclose(f);
#endif

    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"kUPWHomePageJailBrokenToastNotAgainKey"];
    [[NSUserDefaults standardUserDefaults] synchronize];

    NSSetUncaughtExceptionHandler(abc_exception_handler);
    abc_log("NSSetUncaughtExceptionHandler installed");

    // 有效方案 (纯 ObjC swizzle, 不触发 ABC 完整性自检):
    // 越狱检测方法中和 + 关键: hookInitRiskManage 从源头消除 native exit
    // (检测退出 block 定义在 -[DTFrameworkInterface initRiskManage] 内)。
    hookSecureUtilityPlus();
    hookSmAntiFraud();
    hookIOSSecuritySuite();
    hookABCJailbreakMethods();
    hookInitRiskManage();
    hookAuthorityJailBreakFlag();
    hookShowJailBrokenAlert();
    abc_log("all ObjC jailbreak hooks armed (ctor)");
}
