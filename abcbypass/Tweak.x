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

static int is_jb_dylib(const char *name) {
    if (!name) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") ||
        strstr(name, "libhooker") || strstr(name, "cycript") ||
        strstr(name, "frida") || strstr(name, "pspawn") ||
        strstr(name, "ABCBypass") || strstr(name, "abcbypass") ||
        strstr(name, "/var/jb/") || strstr(name, "Shadow") ||
        strstr(name, "Choicy") || strstr(name, "systemhook")) {
        return 1;
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

static NSUncaughtExceptionHandler *orig_exception_handler;

static void abc_exception_handler(NSException *exception) {
    abc_log("EXCEPTION caught: %s — %s", exception.name.UTF8String, exception.reason.UTF8String);
    NSArray *symbols = [exception callStackSymbols];
    for (NSUInteger i = 0; i < MIN(symbols.count, 10); i++)
        abc_log("  [%lu] %s", (unsigned long)i, [symbols[i] UTF8String]);
}

static void (*orig_objc_exception_throw)(id);
static void hooked_objc_exception_throw(id exception) {
    if ([exception isKindOfClass:[NSException class]]) {
        NSException *ex = (NSException *)exception;
        NSString *reason = ex.reason ?: @"(nil)";
        abc_log("objc_exception_throw intercepted: %s — %s", ex.name.UTF8String, reason.UTF8String);
    } else {
        abc_log("objc_exception_throw intercepted: non-NSException object");
    }
    // Swallow: do NOT call orig — this prevents std::terminate → abort
}

// ========== Forward declarations for counters used in trampoline heartbeat ==========
static volatile int g_dispatch_redirect_count;
static volatile int g_dispatch_sync_inline;
static volatile int g_dispatch_sync_dropped;
static volatile int g_dispatch_async_dropped;
static volatile int g_pthread_blocked;
static volatile int g_pthread_allowed;

// ========== CFRunLoopAddTimer tracking ==========

static volatile int g_exit_blocked = 0;
static volatile int g_exit_recovered = 0;

#define MAX_TRACKED_TIMERS 64
static CFRunLoopTimerRef g_tracked_timers[MAX_TRACKED_TIMERS];
static volatile int g_tracked_timer_count = 0;
static volatile int g_timers_invalidated = 0;

static void (*orig_CFRunLoopAddTimer)(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFStringRef mode);
static void hooked_CFRunLoopAddTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFStringRef mode) {
    if (rl == CFRunLoopGetMain() && timer && !g_exit_recovered) {
        CFTimeInterval interval = CFRunLoopTimerGetInterval(timer);
        if (interval == 0) {
            CFAbsoluteTime fireDate = CFRunLoopTimerGetNextFireDate(timer);
            CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
            CFTimeInterval delay = fireDate - now;
            if (delay > 5.0 && delay < 60.0) {
                abc_log("TIMER DEFUSED: one-shot delay=%.1fs (potential SDK kill timer)", delay);
                return;
            }
        }

        int idx = g_tracked_timer_count;
        if (idx < MAX_TRACKED_TIMERS) {
            CFRetain(timer);
            g_tracked_timers[idx] = timer;
            g_tracked_timer_count = idx + 1;
        }
    }
    orig_CFRunLoopAddTimer(rl, timer, mode);
}

static void invalidate_sdk_timers(void) {
    int count = g_tracked_timer_count;
    int invalidated = 0;
    for (int i = 0; i < count; i++) {
        CFRunLoopTimerRef t = g_tracked_timers[i];
        if (t && CFRunLoopTimerIsValid(t)) {
            CFRunLoopTimerInvalidate(t);
            invalidated++;
        }
        if (t) CFRelease(t);
        g_tracked_timers[i] = NULL;
    }
    g_tracked_timer_count = 0;
    g_timers_invalidated = invalidated;
    abc_log("TIMER SWEEP: invalidated %d pre-exit timers", invalidated);
}

// ========== Dispatch drain hook (clean exit neutralization) ==========

static jmp_buf g_drain_jmp;
static volatile int g_drain_jmp_ready = 0;
static volatile int g_drain_exit_count = 0;

static void (*orig_dispatch_drain)(void *);
static void hooked_dispatch_drain(void *context) {
    if (pthread_main_np()) {
        int val = setjmp(g_drain_jmp);
        if (val == 0) {
            g_drain_jmp_ready = 1;
            orig_dispatch_drain(context);
            g_drain_jmp_ready = 0;
        } else {
            g_drain_jmp_ready = 0;
            g_drain_exit_count++;
            abc_log("DRAIN ESCAPE #%d: exit(%d) neutralized — app state clean, no blocking needed", g_drain_exit_count, val);
        }
    } else {
        orig_dispatch_drain(context);
    }
}

// ========== longjmp escape from exit() (fallback) ==========

static jmp_buf g_exit_jmp;
static volatile int g_exit_jmp_ready = 0;

extern SInt32 CFRunLoopRunSpecific(CFRunLoopRef rl, CFStringRef modeName, CFTimeInterval seconds, Boolean returnAfterSourceHandled);

static SInt32 (*orig_CFRunLoopRunSpecific)(CFRunLoopRef rl, CFStringRef modeName, CFTimeInterval seconds, Boolean returnAfterSourceHandled);

static void install_ui_recovery_timer(void);

static SInt32 hooked_CFRunLoopRunSpecific(CFRunLoopRef rl, CFStringRef modeName, CFTimeInterval seconds, Boolean returnAfterSourceHandled) {
    if (pthread_main_np() && !g_exit_recovered && rl == CFRunLoopGetMain()) {
        int val = setjmp(g_exit_jmp);
        g_exit_jmp_ready = 1;
        if (val != 0) {
            g_exit_recovered = 1;
            g_exit_jmp_ready = 0;
            abc_log("RUNLOOP FALLBACK: recovered from exit(%d), invalidating %d tracked timers", val, g_tracked_timer_count);
            invalidate_sdk_timers();
            install_ui_recovery_timer();
            abc_log("RUNLOOP FALLBACK: re-entering RunLoop");
            return orig_CFRunLoopRunSpecific(CFRunLoopGetMain(), kCFRunLoopDefaultMode, 1e10, false);
        }
    }
    return orig_CFRunLoopRunSpecific(rl, modeName, seconds, returnAfterSourceHandled);
}

// ========== Crash recovery ==========

#include <sys/ucontext.h>

static volatile int g_crash_count = 0;
static volatile int g_trampoline_count = 0;
static volatile int g_exit_call_count = 0;
static uintptr_t g_cf_base = 0, g_cf_end = 0;
static uintptr_t g_dispatch_base = 0, g_dispatch_end = 0;
static uintptr_t g_libc_base = 0, g_libc_end = 0;
static uintptr_t g_malloc_base = 0, g_malloc_end = 0;
static uintptr_t g_pthread_base = 0, g_pthread_end = 0;
static uintptr_t g_kernel_base = 0, g_kernel_end = 0;
static uintptr_t g_main_stack_top = 0;
static mach_port_t g_main_thread_id = 0;

static int is_system_thread_pc(thread_act_t thread) {
#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64,
                                         (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS) return 0;
    uintptr_t pc = (uintptr_t)(state.__pc & 0x0000007FFFFFFFFFULL);
    Dl_info info;
    if (dladdr((void *)pc, &info) && info.dli_fname) {
        return (strncmp(info.dli_fname, "/usr/lib/", 9) == 0 ||
                strncmp(info.dli_fname, "/System/", 8) == 0);
    }
#endif
    return 0;
}

static void (*g_force_unlock_fn)(malloc_zone_t *) = NULL;
static malloc_zone_t *g_saved_zones[32];
static unsigned g_saved_zone_count = 0;
static void (*g_dispatch_drain_fn)(void *) = NULL;

static void install_crash_recovery(void);
static void install_ui_recovery_timer(void);

static volatile int g_drain_count = 0;

static void manual_drain_timer_cb(CFRunLoopTimerRef timer, void *info) {
    g_drain_count++;
    if (g_drain_count <= 5)
        abc_log("drain timer #%d firing", g_drain_count);
    if (orig_dispatch_drain)
        orig_dispatch_drain(NULL);
    else if (g_dispatch_drain_fn)
        g_dispatch_drain_fn(NULL);
    if (g_drain_count <= 5)
        abc_log("drain timer #%d returned", g_drain_count);
}

static int is_safe_thread(const char *name) {
    if (!name || name[0] == '\0') return 0;
    return (strstr(name, "com.apple.") != NULL ||
            strcmp(name, "APFileLog") == 0 ||
            strcmp(name, "PowerGetThread") == 0 ||
            strcmp(name, "longLinkThread") == 0 ||
            strcmp(name, "MASS_Net") == 0);
}

static void suspend_and_log_threads(int log_detail) {
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    task_threads(mach_task_self(), &threads, &count);
    mach_port_t main_thread = mach_thread_self();
    int suspended = 0, resumed = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (threads[i] == main_thread) {
            mach_port_deallocate(mach_task_self(), threads[i]);
            continue;
        }
        char name[64] = {0};
        pthread_t pt = pthread_from_mach_thread_np(threads[i]);
        if (pt) pthread_getname_np(pt, name, sizeof(name));

        if (is_safe_thread(name)) {
            thread_resume(threads[i]);
            resumed++;
            if (log_detail)
                abc_log("  kept thread '%s'", name);
        } else {
            thread_suspend(threads[i]);
            suspended++;
            if (log_detail && suspended <= 20)
                abc_log("  suspended '%s'", name[0] ? name : "(unnamed)");
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
    if (log_detail)
        abc_log("TRAMPOLINE: suspended %d, kept %d (of %d threads)", suspended, resumed, count);
    mach_port_deallocate(mach_task_self(), main_thread);
}

static volatile int g_patrol_run = 0;
static void thread_patrol_timer_cb(CFRunLoopTimerRef timer, void *info) {
    suspend_and_log_threads(0);
}

static void abort_recovery_trampoline(void) {
    g_trampoline_count++;
    abc_log("TRAMPOLINE entry #%d", g_trampoline_count);

    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);

    if (g_force_unlock_fn) {
        for (unsigned i = 0; i < g_saved_zone_count; i++)
            g_force_unlock_fn(g_saved_zones[i]);
    }
    install_crash_recovery();

    suspend_and_log_threads(1);

    // Invalidate all SDK timers registered before exit was blocked.
    // These include the ~25s kill timer that fires svc #0x80.
    invalidate_sdk_timers();

    // Patrol timer: catch new detection threads spawned via direct pthread_create calls
    // (fishhook only catches PLT/GOT; SDK may use internal branches)
    {
        CFRunLoopTimerContext ctx = {0};
        CFRunLoopTimerRef patrol = CFRunLoopTimerCreate(
            kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + 0.3, 0.3, 0, 0,
            thread_patrol_timer_cb, &ctx);
        CFRunLoopAddTimer(CFRunLoopGetMain(), patrol, kCFRunLoopCommonModes);
        CFRelease(patrol);
        abc_log("TRAMPOLINE: patrol timer installed (0.3s)");
    }

    install_ui_recovery_timer();

    abc_log("TRAMPOLINE: entering CFRunLoopRun (entry #%d)", g_trampoline_count);
    int hb = 0;
    while (1) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, false);
        hb++;
        if (hb <= 10 || hb % 30 == 0)
            abc_log("TRAMPOLINE: heartbeat #%d (redir=%d, async_drop=%d, sync_inline=%d, sync_drop=%d, pt_block=%d, tmr_kill=%d)",
                    hb, g_dispatch_redirect_count, g_dispatch_async_dropped, g_dispatch_sync_inline, g_dispatch_sync_dropped, g_pthread_blocked, g_timers_invalidated);
    }
}

static void init_dylib_ranges(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *hdr = _dyld_get_image_header(i);
        uintptr_t base = (uintptr_t)hdr;
        if (!name) continue;
        if (strstr(name, "CoreFoundation") && !g_cf_base) {
            g_cf_base = base; g_cf_end = base + 0x800000;
        } else if (strstr(name, "libdispatch") && !g_dispatch_base) {
            g_dispatch_base = base; g_dispatch_end = base + 0x200000;
        } else if (strstr(name, "libsystem_c.dylib") && !g_libc_base) {
            g_libc_base = base; g_libc_end = base + 0x200000;
        } else if (strstr(name, "libsystem_malloc") && !g_malloc_base) {
            g_malloc_base = base; g_malloc_end = base + 0x100000;
        } else if (strstr(name, "libsystem_pthread") && !g_pthread_base) {
            g_pthread_base = base; g_pthread_end = base + 0x100000;
        } else if (strstr(name, "libsystem_kernel") && !g_kernel_base) {
            g_kernel_base = base; g_kernel_end = base + 0x100000;
        }
    }
}

#define PAC_STRIP(x) ((uint64_t)(x) & 0x0000007FFFFFFFFF)
#define VALID_FP(x) ((x) > 0x10000 && (x) < 0x0000008000000000 && ((x) & 0xF) == 0)
#define VALID_PC(x) (PAC_STRIP(x) >= 0x100000000ULL && (PAC_STRIP(x) & 0x3) == 0)

static volatile int g_sigsegv_count = 0;
static volatile int g_sigabrt_count = 0;

static void crash_recovery_handler(int sig, siginfo_t *info, void *uap) {
    if (!g_exit_blocked) {
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
        return;
    }
    g_crash_count++;

#if defined(__arm64__) || defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)uap;

    if (sig == SIGABRT) {
        g_sigabrt_count++;
        abc_log("=== SIGABRT HANDLER #%d: PC=%p FP=%p SP=%p ===", g_sigabrt_count,
                (void *)uc->uc_mcontext->__ss.__pc,
                (void *)uc->uc_mcontext->__ss.__fp,
                (void *)uc->uc_mcontext->__ss.__sp);
        // Always use trampoline for SIGABRT. Skipping to existing frames fails
        // because __stack_chk_fail → __abort resets handler to SIG_DFL before raise.
        if (g_main_stack_top) {
            install_crash_recovery();
            uc->uc_mcontext->__ss.__pc = (uint64_t)abort_recovery_trampoline;
            uc->uc_mcontext->__ss.__sp = g_main_stack_top - 256;
            uc->uc_mcontext->__ss.__fp = 0;
            uc->uc_mcontext->__ss.__lr = 0;
            uc->uc_mcontext->__ss.__x[0] = 0;
            return;
        }
        install_crash_recovery();
        return;
    }

    // SIGSEGV/SIGBUS: one-frame skip to keep dispatch drain functional.
    g_sigsegv_count++;
    if (g_sigsegv_count <= 10)
        abc_log("SIGSEGV #%d: PC=%p FP=%p LR=%p", g_sigsegv_count,
                (void *)uc->uc_mcontext->__ss.__pc,
                (void *)uc->uc_mcontext->__ss.__fp,
                (void *)PAC_STRIP(uc->uc_mcontext->__ss.__lr));
    else if (g_sigsegv_count == 100 || g_sigsegv_count == 1000 || g_sigsegv_count == 10000)
        abc_log("SIGSEGV count reached %d", g_sigsegv_count);
    uint64_t fp = uc->uc_mcontext->__ss.__fp;
    uint64_t lr = PAC_STRIP(uc->uc_mcontext->__ss.__lr);

    if (VALID_FP(fp)) {
        uint64_t saved_fp = PAC_STRIP(*(uint64_t *)(fp));
        uint64_t saved_lr = PAC_STRIP(*(uint64_t *)(fp + 8));
        uc->uc_mcontext->__ss.__pc = lr;
        uc->uc_mcontext->__ss.__lr = saved_lr;
        uc->uc_mcontext->__ss.__fp = saved_fp;
        uc->uc_mcontext->__ss.__x[0] = 0;
    } else {
        // FP chain broken — trampoline on clean stack (manual dispatch drain).
        abc_log("SIGSEGV FP broken (0x%llx) → trampoline", (unsigned long long)fp);
        if (g_main_stack_top) {
            uc->uc_mcontext->__ss.__pc = (uint64_t)abort_recovery_trampoline;
            uc->uc_mcontext->__ss.__sp = g_main_stack_top - 256;
            uc->uc_mcontext->__ss.__fp = 0;
            uc->uc_mcontext->__ss.__lr = 0;
            uc->uc_mcontext->__ss.__x[0] = 0;
            return;
        }
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
    }
#endif
}

static void install_crash_recovery(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_recovery_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

// ========== Stack jump for exit recovery ==========

#if defined(__arm64__) || defined(__aarch64__)
__attribute__((naked, noreturn))
static void jump_to_frame(uint64_t fp, uint64_t lr, uint64_t sp) {
    __asm__ volatile (
        "mov x29, x0\n"
        "mov x30, x1\n"
        "mov sp, x2\n"
        "mov x0, #0\n"
        "ret\n"
    );
}

__attribute__((naked, noreturn))
static void jump_to_frame_regs(uint64_t fp, uint64_t lr, uint64_t sp,
                                uint64_t x19_val, uint64_t x20_val) {
    __asm__ volatile (
        "mov x19, x3\n"
        "mov x20, x4\n"
        "mov x29, x0\n"
        "mov x30, x1\n"
        "mov sp, x2\n"
        "mov x0, #0\n"
        "ret\n"
    );
}
#endif

// ========== Exit hooks (fishhook) ==========

static void force_reenable_ui(CFRunLoopTimerRef timer, void *info) {
    UIWindow *w = [UIApplication sharedApplication].keyWindow;
    if (w) w.userInteractionEnabled = YES;
    while ([UIApplication sharedApplication].isIgnoringInteractionEvents)
        [[UIApplication sharedApplication] endIgnoringInteractionEvents];
}

static void install_ui_recovery_timer(void) {
    CFRunLoopTimerContext ctx = {0};
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + 0.5, 2.0, 0, 0,
        force_reenable_ui, &ctx);
    CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
    CFRelease(timer);
}

static void (*orig_exit)(int);
static void hooked_exit(int code) {
    g_exit_call_count++;

    void *caller = __builtin_return_address(0);
    Dl_info dli = {0};
    dladdr(caller, &dli);
    abc_log("EXIT blocked: exit(%d) thread=%s call#%d caller=%p (%s+%ld)",
            code, pthread_main_np() ? "main" : "bg", g_exit_call_count,
            caller, dli.dli_fname ?: "?",
            (long)((uintptr_t)caller - (uintptr_t)dli.dli_fbase));

    if (pthread_main_np()) {
        if (g_drain_jmp_ready) {
            abc_log("  longjmp to drain level (clean path)");
            longjmp(g_drain_jmp, code ? code : 1);
        }
        if (g_exit_jmp_ready) {
            abc_log("  longjmp to RunLoop level (fallback)");
            longjmp(g_exit_jmp, code ? code : 1);
        }
    }

    abc_log("  no longjmp available, spinning forever");
    while (1) sleep(60);
}

static void (*orig__exit)(int);
static void hooked__exit(int code) {
    abc_log("EXIT blocked: _exit(%d) — returning", code);
}

static void (*orig_abort)(void);
static void hooked_abort(void) {
    abc_log("EXIT blocked: abort() — returning");
}

static int (*orig_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *);
// counters declared above (forward decl for trampoline heartbeat)
static int hooked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*start_routine)(void *), void *arg) {
    if (g_exit_blocked) {
        Dl_info info = {0};
        int is_system = 0;
        if (dladdr((void *)start_routine, &info) && info.dli_fname) {
            is_system = (strncmp(info.dli_fname, "/usr/lib/", 9) == 0 ||
                         strncmp(info.dli_fname, "/System/", 8) == 0);
        }
        if (is_system) {
            g_pthread_allowed++;
            if (g_pthread_allowed <= 5)
                abc_log("pthread_create ALLOWED (system: %s)", info.dli_fname ?: "?");
            return orig_pthread_create(thread, attr, start_routine, arg);
        }
        g_pthread_blocked++;
        if (g_pthread_blocked <= 5)
            abc_log("pthread_create BLOCKED (app: %s fn=%p)", info.dli_fname ?: "?", start_routine);
        if (thread) *thread = pthread_self();
        return 0;
    }
    return orig_pthread_create(thread, attr, start_routine, arg);
}

// g_dispatch_redirect_count declared above (forward decl for trampoline heartbeat)
static int block_invoke_in_shared_cache(dispatch_block_t block);

static void (*orig_dispatch_async)(dispatch_queue_t, dispatch_block_t);
static void hooked_dispatch_async(dispatch_queue_t queue, dispatch_block_t block) {
    if (g_exit_blocked && queue == dispatch_get_main_queue()) {
        if (!block_invoke_in_shared_cache(block)) {
            g_dispatch_async_dropped++;
            return;
        }
        g_dispatch_redirect_count++;
        if (g_dispatch_redirect_count <= 5)
            abc_log("dispatch_async REDIRECT #%d to CFRunLoop", g_dispatch_redirect_count);
        CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, block);
        CFRunLoopWakeUp(CFRunLoopGetMain());
        return;
    }
    orig_dispatch_async(queue, block);
}

static void (*orig_dispatch_async_f)(dispatch_queue_t, void *, void (*)(void *));
static void hooked_dispatch_async_f(dispatch_queue_t queue, void *context, void (*work)(void *)) {
    if (g_exit_blocked && queue == dispatch_get_main_queue()) {
        uintptr_t fn = PAC_STRIP((uintptr_t)work);
        if (fn < 0x180000000ULL) {
            g_dispatch_async_dropped++;
            return;
        }
        g_dispatch_redirect_count++;
        if (g_dispatch_redirect_count <= 5)
            abc_log("dispatch_async_f REDIRECT #%d to CFRunLoop", g_dispatch_redirect_count);
        void *ctx_copy = context;
        void (*work_copy)(void *) = work;
        CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, ^{
            work_copy(ctx_copy);
        });
        CFRunLoopWakeUp(CFRunLoopGetMain());
        return;
    }
    orig_dispatch_async_f(queue, context, work);
}

static volatile int g_dispatch_sync_inline = 0;
static volatile int g_dispatch_sync_dropped = 0;

static int block_invoke_in_shared_cache(dispatch_block_t block) {
    uintptr_t fn = PAC_STRIP(*(uintptr_t *)((uint8_t *)(__bridge void *)block + 16));
    return fn >= 0x180000000ULL;
}

static void (*orig_dispatch_sync)(dispatch_queue_t, dispatch_block_t);
static void hooked_dispatch_sync(dispatch_queue_t queue, dispatch_block_t block) {
    if (g_exit_blocked && pthread_main_np() && queue != dispatch_get_main_queue()) {
        if (block_invoke_in_shared_cache(block)) {
            g_dispatch_sync_inline++;
            block();
        } else {
            g_dispatch_sync_dropped++;
        }
        return;
    }
    orig_dispatch_sync(queue, block);
}

static void (*orig_dispatch_sync_f)(dispatch_queue_t, void *, void (*)(void *));
static void hooked_dispatch_sync_f(dispatch_queue_t queue, void *context, void (*work)(void *)) {
    if (g_exit_blocked && pthread_main_np() && queue != dispatch_get_main_queue()) {
        uintptr_t fn = PAC_STRIP((uintptr_t)work);
        if (fn >= 0x180000000ULL) {
            g_dispatch_sync_inline++;
            work(context);
        } else {
            g_dispatch_sync_dropped++;
        }
        return;
    }
    orig_dispatch_sync_f(queue, context, work);
}

// ========== dispatch_after diagnostic hook ==========

static void (*orig_dispatch_after_block)(dispatch_time_t, dispatch_queue_t, dispatch_block_t);
static int g_dispatch_after_app_count = 0;
static volatile int g_dispatch_after_dropped = 0;

static void hooked_dispatch_after_block(dispatch_time_t when, dispatch_queue_t queue, dispatch_block_t block) {
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    if (elapsed < 30.0 && !block_invoke_in_shared_cache(block)) {
        g_dispatch_after_app_count++;
        Dl_info info = {0};
        uintptr_t fn = PAC_STRIP(*(uintptr_t *)((uint8_t *)(__bridge void *)block + 16));
        dladdr((void *)fn, &info);

        // Calculate delay: dispatch_time is absolute (DISPATCH_TIME_NOW-based)
        int64_t delta_ns = (int64_t)(when - dispatch_time(DISPATCH_TIME_NOW, 0));
        double delay_s = (double)delta_ns / 1e9;

        // Drop app blocks with long delays during early startup (kill timers)
        if (delay_s > 5.0 && queue == dispatch_get_main_queue()) {
            g_dispatch_after_dropped++;
            abc_log("DISPATCH_AFTER DROPPED #%d: app block fn=%p (%s+%ld) delay=%.1fs at t=%.2f",
                    g_dispatch_after_dropped, (void *)fn,
                    info.dli_fname ?: "?", (long)(fn - (uintptr_t)info.dli_fbase),
                    delay_s, elapsed);
            return;
        }

        abc_log("DISPATCH_AFTER DIAG #%d: app block fn=%p (%s+%ld) at t=%.2f delay=%.1fs queue=%s",
                g_dispatch_after_app_count, (void *)fn,
                info.dli_fname ?: "?", (long)(fn - (uintptr_t)info.dli_fbase),
                elapsed, delay_s, queue == dispatch_get_main_queue() ? "main" : "bg");
    }
    orig_dispatch_after_block(when, queue, block);
}

static int (*orig_kill)(pid_t, int);
static int hooked_kill(pid_t pid, int sig) {
    if (pid == getpid() || pid == 0) {
        abc_log("EXIT blocked: kill(self, %d)", sig);
        return 0;
    }
    return orig_kill(pid, sig);
}

#import <signal.h>

typedef void (*sig_t_fn)(int);

static sig_t_fn (*orig_signal)(int, sig_t_fn);
static sig_t_fn hooked_signal(int sig, sig_t_fn handler) {
    if (sig == SIGTERM || sig == SIGKILL) return (sig_t_fn)SIG_DFL;
    return orig_signal(sig, handler);
}

static int (*orig_pthread_kill)(pthread_t, int);
static int hooked_pthread_kill(pthread_t thread, int sig) {
    if (sig == SIGABRT || sig == SIGKILL || sig == SIGTERM) {
        abc_log("EXIT blocked: pthread_kill(sig=%d)", sig);
        return 0;
    }
    return orig_pthread_kill(thread, sig);
}

static void (*orig_stack_chk_fail)(void);
static void hooked_stack_chk_fail(void) {
    abc_log("EXIT blocked: __stack_chk_fail — returning (skip canary check)");
}

static int (*orig_sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static int hooked_sigaction_fn(int sig, const struct sigaction *act, struct sigaction *oact) {
    if (g_exit_blocked && sig == SIGABRT && act && act->sa_handler == SIG_DFL) {
        abc_log("sigaction(SIGABRT, SIG_DFL) blocked — preventing abort() from resetting handler");
        return 0;
    }
    return orig_sigaction_fn(sig, act, oact);
}

// ========== File hooks (fishhook) ==========

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int (*orig_open)(const char *, int, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    return orig_open(path, flags, mode);
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static char *(*orig_realpath)(const char *, char *);
static char *hooked_realpath(const char *path, char *resolved) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_realpath(path, resolved);
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hooked_readlink(const char *path, char *buf, size_t bufsiz) {
    if (is_jb_path(path)) { errno = EINVAL; return -1; }
    return orig_readlink(path, buf, bufsiz);
}

// ========== Dyld hooks ==========

static uint32_t g_real_image_count;
static uint32_t *g_safe_map;
static uint32_t g_safe_count;

static void build_dyld_map(void) {
    g_real_image_count = _dyld_image_count();
    g_safe_map = calloc(g_real_image_count, sizeof(uint32_t));
    g_safe_count = 0;
    for (uint32_t i = 0; i < g_real_image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!is_jb_dylib(name))
            g_safe_map[g_safe_count++] = i;
    }
}

static uint32_t (*orig_dyld_image_count)(void);
static uint32_t hooked_dyld_image_count(void) {
    return g_safe_count;
}

static const char *(*orig_dyld_get_image_name)(uint32_t);
static const char *hooked_dyld_get_image_name(uint32_t idx) {
    if (idx < g_safe_count) return orig_dyld_get_image_name(g_safe_map[idx]);
    return orig_dyld_get_image_name(idx);
}

static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static const struct mach_header *hooked_dyld_get_image_header(uint32_t idx) {
    if (idx < g_safe_count) return orig_dyld_get_image_header(g_safe_map[idx]);
    return orig_dyld_get_image_header(idx);
}

static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);
static intptr_t hooked_dyld_get_image_vmaddr_slide(uint32_t idx) {
    if (idx < g_safe_count) return orig_dyld_get_image_vmaddr_slide(g_safe_map[idx]);
    return orig_dyld_get_image_vmaddr_slide(idx);
}

// ========== Sysctl hook ==========

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                         void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && name[3] == getpid() && oldp) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

// ========== Env / fork / dlopen hooks ==========

static char *(*orig_getenv)(const char *);
static char *hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "DYLD_LIBRARY_PATH") == 0))
        return NULL;
    return orig_getenv(name);
}

static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) {
    errno = ENOSYS;
    return -1;
}

static int (*orig_posix_spawn)(pid_t *, const char *, void *, void *, char *const [], char *const []);
static int hooked_posix_spawn(pid_t *pid, const char *path, void *file_actions,
                               void *attrp, char *const argv[], char *const envp[]) {
    if (path && is_jb_path(path)) return ENOENT;
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_path(path)) { return NULL; }
    return orig_dlopen(path, mode);
}

static void *(*orig_dlsym)(void *, const char *);
static void *hooked_dlsym(void *handle, const char *symbol) {
    if (symbol && (strstr(symbol, "MSHookFunction") || strstr(symbol, "MSHookMessageEx") ||
                   strstr(symbol, "substrate") || strstr(symbol, "Substrate") ||
                   strstr(symbol, "fishhook") || strstr(symbol, "rebind_symbols")))
        return NULL;
    return orig_dlsym(handle, symbol);
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
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    if (elapsed < 30.0) {
        abc_log("_terminateWithStatus:%d blocked (%.1fs after launch, likely detection)", status, elapsed);
        g_exit_blocked = 1;
        install_crash_recovery();
        install_ui_recovery_timer();
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
    NSMutableDictionary *env = [%orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"_MSSafeMode"];
    return env;
}
%end

// ========== Binary offset hook for detection function ==========

#define DETECTION_OFFSET_1 0x8DC910  // MbapMPaaS: triggers jailbreak alert (ABC 11.1.0)

static void (*orig_detection_1)(void);
static void hooked_detection_1(void) {
    abc_log("DETECTION INTERCEPT: MbapMPaaS+0x%X — calling original with protections active", DETECTION_OFFSET_1);
    orig_detection_1();
}

static void hookDetectionByOffset(void) {
    const struct mach_header *mbap = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "MbapMPaaS")) {
            mbap = _dyld_get_image_header(i);
            abc_log("MbapMPaaS base: %p", (void *)mbap);
            break;
        }
    }
    if (!mbap) {
        abc_log("MbapMPaaS not found — offset hook skipped");
        return;
    }

    uintptr_t target1 = (uintptr_t)mbap + DETECTION_OFFSET_1;
    MSHookFunction((void *)target1, (void *)hooked_detection_1, (void **)&orig_detection_1);
    abc_log("OFFSET HOOK: MbapMPaaS+0x%X -> hooked_detection_1 (%p)", DETECTION_OFFSET_1, (void *)target1);
}

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
        fprintf(f, "[  0.00] [INIT] ABCBypass v0.1.0-114 / ABC %s ctor started\n",
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

    init_dylib_ranges();
    g_main_stack_top = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    g_main_thread_id = mach_thread_self();

    // Pre-resolve force_unlock from the zone's introspect table.
    // dlsym("malloc_zone_force_unlock") returns NULL on iOS (not exported).
    // Read directly from the zone struct using raw memory access to avoid
    // any compiler issues with __ptrauth-annotated fields.
    // Layout: malloc_zone_t.introspect at offset 96 (13th pointer field)
    //         malloc_introspection_t.force_unlock at offset 48 (7th fn ptr)
    {
        malloc_zone_t *dz = malloc_default_zone();
        if (dz) {
            uintptr_t intro_raw = *(uintptr_t *)((char *)dz + 96);
            intro_raw = PAC_STRIP(intro_raw);
            if (intro_raw) {
                uintptr_t fn_raw = *(uintptr_t *)((char *)intro_raw + 48);
                fn_raw = PAC_STRIP(fn_raw);
                if (fn_raw > 0x100000000ULL)
                    g_force_unlock_fn = (void (*)(malloc_zone_t *))(void *)fn_raw;
            }
        }

        vm_address_t *zones = NULL;
        unsigned zc = 0;
        if (malloc_get_all_zones(mach_task_self(), NULL, &zones, &zc) == KERN_SUCCESS) {
            if (zc > 32) zc = 32;
            for (unsigned i = 0; i < zc; i++)
                g_saved_zones[i] = (malloc_zone_t *)zones[i];
            g_saved_zone_count = zc;
        }
    }

    abc_log("dylib ranges: CF=%p-%p, dispatch=%p-%p, libc=%p-%p, malloc=%p-%p",
            (void *)g_cf_base, (void *)g_cf_end,
            (void *)g_dispatch_base, (void *)g_dispatch_end,
            (void *)g_libc_base, (void *)g_libc_end,
            (void *)g_malloc_base, (void *)g_malloc_end);
    abc_log("  pthread=%p-%p, kernel=%p-%p, main stack top=%p, tid=0x%x",
            (void *)g_pthread_base, (void *)g_pthread_end,
            (void *)g_kernel_base, (void *)g_kernel_end,
            (void *)g_main_stack_top, g_main_thread_id);
    abc_log("malloc zones: %u, force_unlock=%p", g_saved_zone_count, (void *)g_force_unlock_fn);

    g_dispatch_drain_fn = (void (*)(void *))dlsym(RTLD_DEFAULT, "_dispatch_main_queue_callback_4CF");
    abc_log("dispatch drain fn: %p", (void *)g_dispatch_drain_fn);

    if (g_dispatch_drain_fn) {
        MSHookFunction((void *)g_dispatch_drain_fn, (void *)hooked_dispatch_drain, (void **)&orig_dispatch_drain);
        abc_log("_dispatch_main_queue_callback_4CF hook armed (drain-level exit neutralization)");
    }

    // Arm file/dyld/sysctl hooks FIRST (MSHookFunction, not fishhook — avoids GOT modification).
    build_dyld_map();

    // Hook detection function at known binary offset BEFORE it can trigger
    // DISABLED: +0x8DC910 is a return address (mid-function), not an entry point.
    // MSHookFunction can't safely relocate instructions there.
    // hookDetectionByOffset();

    abc_log("arming ctor hooks (MSHookFunction — GOT-clean)");
    MSHookFunction((void *)stat, (void *)hooked_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)hooked_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)access, (void *)hooked_access, (void **)&orig_access);
    MSHookFunction((void *)open, (void *)hooked_open, (void **)&orig_open);
    MSHookFunction((void *)fopen, (void *)hooked_fopen, (void **)&orig_fopen);
    MSHookFunction((void *)realpath, (void *)hooked_realpath, (void **)&orig_realpath);
    MSHookFunction((void *)readlink, (void *)hooked_readlink, (void **)&orig_readlink);
    MSHookFunction((void *)_dyld_image_count, (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)hooked_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);
    MSHookFunction((void *)sysctl, (void *)hooked_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)getenv, (void *)hooked_getenv, (void **)&orig_getenv);
    MSHookFunction((void *)fork, (void *)hooked_fork, (void **)&orig_fork);
    MSHookFunction((void *)dlopen, (void *)hooked_dlopen, (void **)&orig_dlopen);
    MSHookFunction((void *)dlsym, (void *)hooked_dlsym, (void **)&orig_dlsym);
    abc_log("ctor inline hooks armed (16 functions, zero GOT modifications)");

    MSHookFunction((void *)CFRunLoopAddTimer, (void *)hooked_CFRunLoopAddTimer, (void **)&orig_CFRunLoopAddTimer);
    abc_log("CFRunLoopAddTimer hook armed (ctor)");

    MSHookFunction((void *)CFRunLoopRunSpecific, (void *)hooked_CFRunLoopRunSpecific, (void **)&orig_CFRunLoopRunSpecific);
    abc_log("CFRunLoopRunSpecific hook armed (longjmp recovery)");

    // dispatch_after hook MUST be in ctor — detection schedules kill block at t=0.88s
    MSHookFunction((void *)dispatch_after, (void *)hooked_dispatch_after_block, (void **)&orig_dispatch_after_block);
    abc_log("dispatch_after hook armed (ctor — intercept early kill timers)");

    // Now install ObjC jailbreak detection hooks
    hookSecureUtilityPlus();
    hookSmAntiFraud();
    hookIOSSecuritySuite();
    hookABCJailbreakMethods();
    hookAuthorityJailBreakFlag();
    hookShowJailBrokenAlert();
    abc_log("all ObjC jailbreak hooks armed (ctor)");

    // Delay exit/abort hooks + remaining swizzle to avoid BSXPCServiceConnection crash.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(200 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        abc_log("arming delayed hooks (MSHookFunction — GOT-clean)");

        MSHookFunction((void *)exit, (void *)hooked_exit, (void **)&orig_exit);
        MSHookFunction((void *)_exit, (void *)hooked__exit, (void **)&orig__exit);
        MSHookFunction((void *)abort, (void *)hooked_abort, (void **)&orig_abort);
        MSHookFunction((void *)kill, (void *)hooked_kill, (void **)&orig_kill);
        MSHookFunction((void *)signal, (void *)hooked_signal, (void **)&orig_signal);
        MSHookFunction((void *)pthread_kill, (void *)hooked_pthread_kill, (void **)&orig_pthread_kill);
        void *ps = dlsym(RTLD_DEFAULT, "posix_spawn");
        if (ps) MSHookFunction(ps, (void *)hooked_posix_spawn, (void **)&orig_posix_spawn);
        MSHookFunction((void *)sigaction, (void *)hooked_sigaction_fn, (void **)&orig_sigaction_fn);

        void *stack_chk = dlsym(RTLD_DEFAULT, "__stack_chk_fail");
        if (stack_chk) MSHookFunction(stack_chk, (void *)hooked_stack_chk_fail, (void **)&orig_stack_chk_fail);

        void *oet = dlsym(RTLD_DEFAULT, "objc_exception_throw");
        if (oet) MSHookFunction(oet, (void *)hooked_objc_exception_throw, (void **)&orig_objc_exception_throw);

        abc_log("delayed inline hooks armed (10 functions, zero GOT modifications)");

        MSHookFunction((void *)dispatch_async, (void *)hooked_dispatch_async, (void **)&orig_dispatch_async);
        MSHookFunction((void *)dispatch_async_f, (void *)hooked_dispatch_async_f, (void **)&orig_dispatch_async_f);
        MSHookFunction((void *)dispatch_sync, (void *)hooked_dispatch_sync, (void **)&orig_dispatch_sync);
        MSHookFunction((void *)dispatch_sync_f, (void *)hooked_dispatch_sync_f, (void **)&orig_dispatch_sync_f);
        // dispatch_after already hooked in ctor
        abc_log("dispatch hooks armed (async/sync — after already in ctor)");

        abc_log("all hooks armed (GOT-clean — zero rebind_symbols)");
    });
}
