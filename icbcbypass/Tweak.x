#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <mach-o/dyld.h>
#import <pthread.h>
#import <signal.h>
#import <string.h>
#import "fishhook.h"

#define ICBC_DEBUG_LOG 0

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

static const char *jb_paths[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/PreferenceBundles",
    "/Library/PreferenceLoader",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/sbin/frida-server",
    "/usr/lib/substrate",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/TweakInject",
    "/usr/lib/ellekit",
    "/usr/libexec/cydia",
    "/usr/libexec/cydia/firmware.sh",
    "/usr/local/bin/cycript",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/mobile/Library/SBSettings",
    "/var/jb",
    "/var/lib/cydia",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/var/lib/undecimus/apt",
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/tmp/frida-",
    "/jb/",
    "/.installed_unc0ver",
    "/.installed_dopamine",
    "/.bootstrapped",
    "/bootstrap/inject_criticald",
    "/procursus",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "Frida", "jailbreak", "cycript",
    "MobileSubstrate", "TweakInject", "ellekit",
    "libhooker", "substitute", "Substitute",
    "SBSettings", "pspawn", "libsubstitute",
    "procursus", "Dopamine", "dopamine",
    NULL
};

static int is_jb_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; jb_paths[i]; i++) {
        if (strncmp(path, jb_paths[i], strlen(jb_paths[i])) == 0) return 1;
    }
    for (int i = 0; jb_substrings[i]; i++) {
        if (strstr(path, jb_substrings[i])) return 1;
    }
    return 0;
}

static int is_jb_dylib(const char *name) {
    if (!name || (uintptr_t)name < 0x100000000ULL) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "substitute") || strstr(name, "Substitute") ||
        strstr(name, "frida") || strstr(name, "cycript") ||
        strstr(name, "libhooker") || strstr(name, "MobileSubstrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") ||
        strstr(name, "pspawn") || strstr(name, "rocketbootstrap") ||
        strstr(name, "ICBCBypass") || strstr(name, "icbcbypass") ||
        strstr(name, "/var/jb/") || strstr(name, "Shadow") ||
        strstr(name, "Choicy") || strstr(name, "systemhook")) {
        return 1;
    }
    return 0;
}

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

    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(object_getClass(cls), &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        if (!isSecuritySelector(selName)) continue;
        char retType[8];
        method_getReturnType(methods[i], retType, sizeof(retType));
        if (retType[0] == 'B' || retType[0] == 'c') {
            method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
        }
    }
    if (methods) free(methods);

    methods = class_copyMethodList(cls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        if (!isSecuritySelector(selName)) continue;
        char retType[8];
        method_getReturnType(methods[i], retType, sizeof(retType));
        if (retType[0] == 'B' || retType[0] == 'c') {
            method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
        } else if (retType[0] == '@') {
            method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s, ...) { return @[]; }));
        }
    }
    if (methods) free(methods);
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
    for (int i = 0; classes[i]; i++) {
        hookSecureUtilityPlusClass(classes[i]);
    }
}

static void hookIOSSecuritySuite(void) {
    Class cls = objc_getClass("IOSSecuritySuite.IOSSecuritySuite");
    if (!cls) cls = objc_getClass("IOSSecuritySuite");
    if (!cls) return;

    SEL sel = NSSelectorFromString(@"amIJailbroken");
    if (class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));
    }
    sel = NSSelectorFromString(@"amIJailbrokenWithFailedChecks");
    if (class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^id(id s) {
            return @{@"jailbroken": @NO, @"failedChecks": @[]};
        }));
    }
    sel = NSSelectorFromString(@"amIJailbrokenWithFailMessage");
    if (class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^id(id s) {
            return @{@"jailbroken": @NO, @"failMessage": @""};
        }));
    }
}

static void hookICBCJailbreakMethods(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];

        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            BOOL match = [selName isEqualToString:@"isJailBreak"] ||
                [selName isEqualToString:@"isJailbroken"] ||
                [selName isEqualToString:@"jailbroken"] ||
                [selName isEqualToString:@"jailbreaking"] ||
                [selName isEqualToString:@"phoneIsJailBreak"] ||
                [selName isEqualToString:@"MaxentJailBroken"] ||
                [selName isEqualToString:@"isJailBrokenOne"] ||
                [selName isEqualToString:@"isJailBrokenThree"] ||
                [selName isEqualToString:@"isJailBrokenFour"] ||
                [selName isEqualToString:@"isJailBrokenFive"] ||
                [selName isEqualToString:@"p_isJailBreak1"] ||
                [selName isEqualToString:@"p_isJailBreak2"] ||
                [selName hasPrefix:@"isJailBreak"];
            if (match) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
            }
        }
        if (methods) free(methods);

        Class metaCls = object_getClass(cls);
        methods = class_copyMethodList(metaCls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            BOOL match = [selName isEqualToString:@"isJailBreak"] ||
                [selName isEqualToString:@"isJailbroken"] ||
                [selName isEqualToString:@"jailbroken"] ||
                [selName isEqualToString:@"jailbreaking"] ||
                [selName isEqualToString:@"phoneIsJailBreak"] ||
                [selName isEqualToString:@"MaxentJailBroken"] ||
                [selName isEqualToString:@"isJailBrokenOne"] ||
                [selName isEqualToString:@"isJailBrokenThree"] ||
                [selName isEqualToString:@"isJailBrokenFour"] ||
                [selName isEqualToString:@"isJailBrokenFive"] ||
                [selName isEqualToString:@"p_isJailBreak1"] ||
                [selName isEqualToString:@"p_isJailBreak2"] ||
                [selName hasPrefix:@"isJailBreak"];
            if (match) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q')
                    method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
            }
        }
        if (methods) free(methods);
    }
    if (allClasses) free(allClasses);
}

static void hookAuthorityJailBreakFlag(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            if (sel_isEqual(method_getName(methods[i]), @selector(authorityWithJailBreakFlag:))) {
                IMP origIMP = method_getImplementation(methods[i]);
                method_setImplementation(methods[i], imp_implementationWithBlock(^(id self, BOOL flag) {
                    ((void (*)(id, SEL, BOOL))origIMP)(self, @selector(authorityWithJailBreakFlag:), NO);
                }));
            }
        }
        if (methods) free(methods);
        methods = class_copyMethodList(object_getClass(cls), &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            if (sel_isEqual(method_getName(methods[i]), @selector(authorityWithJailBreakFlag:))) {
                IMP origIMP = method_getImplementation(methods[i]);
                method_setImplementation(methods[i], imp_implementationWithBlock(^(id self, BOOL flag) {
                    ((void (*)(id, SEL, BOOL))origIMP)(self, @selector(authorityWithJailBreakFlag:), NO);
                }));
            }
        }
        if (methods) free(methods);
    }
    if (allClasses) free(allClasses);
}

static void hookShowJailBrokenAlert(void) {
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            if (sel_isEqual(method_getName(methods[i]), @selector(showJailBrokenAlertIfNeeded))) {
                method_setImplementation(methods[i], imp_implementationWithBlock(^(id s) {}));
            }
        }
        if (methods) free(methods);
        methods = class_copyMethodList(object_getClass(cls), &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            if (sel_isEqual(method_getName(methods[i]), @selector(showJailBrokenAlertIfNeeded))) {
                method_setImplementation(methods[i], imp_implementationWithBlock(^(id s) {}));
            }
        }
        if (methods) free(methods);
    }
    if (allClasses) free(allClasses);
}

static int g_fishhook_hit_count = 0;
static int g_freeze_indicator = 0;
static char g_log_path[512] = {0};
static CFAbsoluteTime g_ctor_time = 0;

static void log_fishhook_hit(const char *func, const char *path) {
    g_fishhook_hit_count++;
    if (g_fishhook_hit_count <= 200 && g_log_path[0]) {
        FILE *f = fopen(g_log_path, "a");
        if (f) { fprintf(f, "[HIT] %s: %s\n", func, path ? path : "(null)"); fclose(f); }
    }
}

static void log_fishhook_pass(const char *func, const char *path) {
    (void)func; (void)path;
}

static unsigned int (*orig_sleep)(unsigned int);
static unsigned int hooked_sleep(unsigned int seconds) {
    if (pthread_main_np() && seconds >= 1) {
        if (g_log_path[0]) {
            FILE *f = fopen(g_log_path, "a");
            if (f) { fprintf(f, "[FREEZE] sleep(%u) blocked on main thread\n", seconds); fclose(f); }
        }
        return 0;
    }
    return orig_sleep(seconds);
}

static int (*orig_usleep)(useconds_t);
static int hooked_usleep(useconds_t usec) {
    if (pthread_main_np() && usec > 100000) {
        if (g_log_path[0] && g_freeze_indicator > 0) {
            FILE *f = fopen(g_log_path, "a");
            if (f) { fprintf(f, "[FREEZE] usleep(%u) blocked on main thread\n", usec); fclose(f); }
        }
        return 0;
    }
    return orig_usleep(usec);
}

static int (*orig_nanosleep)(const struct timespec *, struct timespec *);
static int hooked_nanosleep(const struct timespec *req, struct timespec *rem) {
    if (pthread_main_np() && req && (req->tv_sec >= 1 || req->tv_nsec > 100000000)) {
        if (g_log_path[0] && g_freeze_indicator > 0) {
            FILE *f = fopen(g_log_path, "a");
            if (f) { fprintf(f, "[FREEZE] nanosleep(%ld.%09ld) blocked on main thread\n", req->tv_sec, req->tv_nsec); fclose(f); }
        }
        if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; }
        return 0;
    }
    return orig_nanosleep(req, rem);
}

typedef void (*dispatch_function_t)(void *);
static void (*orig_dispatch_suspend)(dispatch_object_t);
static void hooked_dispatch_suspend(dispatch_object_t obj) {
    if (obj == dispatch_get_main_queue()) {
        if (g_log_path[0]) {
            FILE *f = fopen(g_log_path, "a");
            if (f) { fprintf(f, "[FREEZE] dispatch_suspend(main_queue) blocked!\n"); fclose(f); }
        }
        return;
    }
    orig_dispatch_suspend(obj);
}

static int (*orig_pthread_kill)(pthread_t, int);
static int hooked_pthread_kill(pthread_t thread, int sig) {
    if (pthread_equal(thread, pthread_self()) && pthread_main_np() && (sig == SIGSTOP || sig == SIGTSTP)) {
        if (g_log_path[0]) {
            FILE *f = fopen(g_log_path, "a");
            if (f) { fprintf(f, "[FREEZE] pthread_kill(main, %d) blocked!\n", sig); fclose(f); }
        }
        return 0;
    }
    return orig_pthread_kill(thread, sig);
}

static void (*orig_CFRunLoopStop)(CFRunLoopRef);
static void hooked_CFRunLoopStop(CFRunLoopRef rl) {
    orig_CFRunLoopStop(rl);
}

static long (*orig_dispatch_group_wait)(dispatch_group_t, dispatch_time_t);
static long hooked_dispatch_group_wait(dispatch_group_t group, dispatch_time_t timeout) {
    if (pthread_main_np()) {
        CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
        if (elapsed > 8.0 && timeout != DISPATCH_TIME_NOW) {
            int64_t diff = 0;
            if (timeout == DISPATCH_TIME_FOREVER) {
                diff = INT64_MAX;
            } else {
                dispatch_time_t now = dispatch_time(DISPATCH_TIME_NOW, 0);
                diff = (int64_t)(timeout - now);
            }
            if (diff > 2000000000LL) { // > 2 seconds
                if (g_log_path[0]) {
                    FILE *f = fopen(g_log_path, "a");
                    if (f) { fprintf(f, "[FREEZE2] dispatch_group_wait(timeout=%s) BLOCKED on main, elapsed=%.1f\n",
                                     timeout == DISPATCH_TIME_FOREVER ? "FOREVER" : "long", elapsed); fclose(f); }
                }
                return 0;
            }
        }
    }
    return orig_dispatch_group_wait(group, timeout);
}

static void *(*orig_dispatch_semaphore_wait)(dispatch_semaphore_t, dispatch_time_t);
static int g_sema_block_count = 0;
static void *hooked_dispatch_semaphore_wait(dispatch_semaphore_t sema, dispatch_time_t timeout) {
    if (pthread_main_np()) {
        CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
        if (elapsed > 3.0) {
            if (timeout == DISPATCH_TIME_FOREVER) {
                g_sema_block_count++;
                if (g_sema_block_count <= 10 && g_log_path[0]) {
                    FILE *f = fopen(g_log_path, "a");
                    if (f) { fprintf(f, "[BLOCK] semaphore_wait #%d elapsed=%.1f timeout=FOREVER\n",
                                     g_sema_block_count, elapsed); fclose(f); }
                }
                return (void *)0;
            }
            if (elapsed < 10.0 && timeout != DISPATCH_TIME_NOW) {
                int64_t diff = 0;
                dispatch_time_t now = dispatch_time(DISPATCH_TIME_NOW, 0);
                diff = (int64_t)(timeout - now);
                if (diff > 2000000000LL) { // > 2 seconds, only in first 10s
                    g_sema_block_count++;
                    return (void *)0;
                }
            }
        }
    }
    return orig_dispatch_semaphore_wait(sema, timeout);
}

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { log_fishhook_hit("stat", path); errno = ENOENT; return -1; }
    log_fishhook_pass("stat", path);
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { log_fishhook_hit("lstat", path); errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path(path)) { log_fishhook_hit("access", path); errno = ENOENT; return -1; }
    log_fishhook_pass("access", path);
    return orig_access(path, mode);
}

static int (*orig_open)(const char *, int, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode_t mode = va_arg(args, int); va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static char *(*orig_realpath)(const char *, char *);
static char *hooked_realpath(const char *path, char *resolved) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    char *result = orig_realpath(path, resolved);
    if (result && is_jb_path(result)) { errno = ENOENT; return NULL; }
    return result;
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hooked_readlink(const char *path, char *buf, size_t bufsize) {
    if (is_jb_path(path)) { errno = EINVAL; return -1; }
    ssize_t ret = orig_readlink(path, buf, bufsize);
    if (ret > 0) {
        char tmp[PATH_MAX];
        size_t len = (size_t)ret < PATH_MAX - 1 ? (size_t)ret : PATH_MAX - 1;
        memcpy(tmp, buf, len); tmp[len] = '\0';
        if (is_jb_path(tmp)) { errno = EINVAL; return -1; }
    }
    return ret;
}

static int (*orig_statfs)(const char *, struct statfs *);
static int hooked_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs(path, buf);
    if (ret == 0 && buf && path &&
        (strcmp(path, "/") == 0 || strncmp(path, "/var", 4) == 0 ||
         strncmp(path, "/private", 8) == 0 || strncmp(path, "/System", 7) == 0)) {
        buf->f_flags |= MNT_RDONLY | MNT_NOSUID;
    }
    return ret;
}

static int (*orig_statvfs)(const char *, struct statvfs *);
static int hooked_statvfs(const char *path, struct statvfs *buf) {
    int ret = orig_statvfs(path, buf);
    if (ret == 0 && buf && path &&
        (strcmp(path, "/") == 0 || strncmp(path, "/var", 4) == 0 ||
         strncmp(path, "/private", 8) == 0 || strncmp(path, "/System", 7) == 0)) {
        buf->f_flag |= ST_RDONLY | ST_NOSUID;
    }
    return ret;
}

static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) { errno = ENOSYS; return -1; }

static char *(*orig_getenv)(const char *);
static char *hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
                 strcmp(name, "DYLD_FRAMEWORK_PATH") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "_SafeMode") == 0)) return NULL;
    return orig_getenv(name);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && oldp) {
        struct kinfo_proc *proc = (struct kinfo_proc *)oldp;
        proc->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strcmp(name, "security.mac.amfi.developer_mode_status") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) { *(int *)oldp = 1; return 0; }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);

static uint32_t g_clean_count = 0;
static uint32_t *g_clean_map = NULL;

static void buildDyldMap(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        uint32_t n = orig_dyld_image_count();
        g_clean_map = (uint32_t *)calloc(n, sizeof(uint32_t));
        if (!g_clean_map) return;
        for (uint32_t i = 0; i < n; i++) {
            const char *name = orig_dyld_get_image_name(i);
            if (!name || (uintptr_t)name < 0x100000000ULL || is_jb_dylib(name)) continue;
            g_clean_map[g_clean_count++] = i;
        }
    });
}

static uint32_t hooked_dyld_image_count(void) {
    buildDyldMap();
    return g_clean_count;
}

static const char *hooked_dyld_get_image_name(uint32_t idx) {
    buildDyldMap();
    if (idx >= g_clean_count) return NULL;
    return orig_dyld_get_image_name(g_clean_map[idx]);
}

static const struct mach_header *hooked_dyld_get_image_header(uint32_t idx) {
    buildDyldMap();
    if (idx >= g_clean_count) return NULL;
    return orig_dyld_get_image_header(g_clean_map[idx]);
}

static intptr_t hooked_dyld_get_image_vmaddr_slide(uint32_t idx) {
    buildDyldMap();
    if (idx >= g_clean_count) return 0;
    return orig_dyld_get_image_vmaddr_slide(g_clean_map[idx]);
}

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_path(path)) return NULL;
    return orig_dlopen(path, mode);
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && is_jb_dylib(info->dli_fname)) {
        info->dli_fname = "/usr/lib/system/libsystem_c.dylib";
        info->dli_sname = NULL;
        info->dli_saddr = NULL;
    }
    return ret;
}

#include <sys/syscall.h>
#include <stdarg.h>
#include <dirent.h>

static DIR *(*orig_opendir)(const char *);
static DIR *hooked_opendir(const char *path) {
    if (path && is_jb_path(path)) {
        log_fishhook_hit("opendir", path);
        errno = ENOENT;
        return NULL;
    }
    if (path && (strstr(path, "preboot") || strstr(path, "DynamicLibraries") ||
                 strstr(path, "TweakInject"))) {
        log_fishhook_hit("opendir", path);
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir(path);
}

static struct dirent *(*orig_readdir)(DIR *);
static struct dirent *hooked_readdir(DIR *dirp) {
    struct dirent *entry = orig_readdir(dirp);
    while (entry) {
        if (entry->d_name[0] && is_jb_dylib(entry->d_name)) {
            entry = orig_readdir(dirp);
            continue;
        }
        break;
    }
    return entry;
}

static int (*orig_syscall)(int, ...);
static int hooked_syscall(int number, ...) {
    va_list args;
    va_start(args, number);

    switch (number) {
        case SYS_stat64:
        case SYS_lstat64: {
            const char *path = va_arg(args, const char *);
            struct stat *buf = va_arg(args, struct stat *);
            va_end(args);
            if (path && is_jb_path(path)) {
                log_fishhook_hit("syscall_stat64", path);
                errno = ENOENT;
                return -1;
            }
            return orig_syscall(number, path, buf);
        }
        case SYS_access: {
            const char *path = va_arg(args, const char *);
            int mode = va_arg(args, int);
            va_end(args);
            if (path && is_jb_path(path)) {
                log_fishhook_hit("syscall_access", path);
                errno = ENOENT;
                return -1;
            }
            return orig_syscall(number, path, mode);
        }
        case SYS_open: {
            const char *path = va_arg(args, const char *);
            int flags = va_arg(args, int);
            int mode = va_arg(args, int);
            va_end(args);
            if (path && is_jb_path(path)) {
                log_fishhook_hit("syscall_open", path);
                errno = ENOENT;
                return -1;
            }
            return orig_syscall(number, path, flags, mode);
        }
        default:
            break;
    }
    va_end(args);

    va_start(args, number);
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    long a6 = va_arg(args, long);
    va_end(args);
    return orig_syscall(number, a1, a2, a3, a4, a5, a6);
}

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

static int g_send_event_count = 0;
static int g_app_send_event_count = 0;

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSString *s = url.scheme.lowercaseString;
    if ([s isEqualToString:@"cydia"] || [s isEqualToString:@"sileo"] ||
        [s isEqualToString:@"zbra"] || [s isEqualToString:@"filza"] ||
        [s isEqualToString:@"undecimus"] || [s isEqualToString:@"activator"]) return NO;
    return %orig;
}
- (void)terminateWithSuccess {}
- (void)beginIgnoringInteractionEvents {
    if (g_log_path[0]) {
        FILE *f = fopen(g_log_path, "a");
        if (f) { fprintf(f, "[UI-FREEZE] beginIgnoringInteractionEvents blocked!\n"); fclose(f); }
    }
}
- (void)_beginIgnoringInteractionEvents {
    if (g_log_path[0]) {
        FILE *f = fopen(g_log_path, "a");
        if (f) { fprintf(f, "[UI-FREEZE] _beginIgnoringInteractionEvents blocked!\n"); fclose(f); }
    }
}
- (void)sendEvent:(UIEvent *)event {
    g_app_send_event_count++;
    %orig;
}
%end

%hook ICBCMotionRecognizingWindow
- (void)sendEvent:(UIEvent *)event {
    g_send_event_count++;
    struct objc_super superInfo = {
        .receiver = self,
        .super_class = [UIWindow class]
    };
    ((void (*)(struct objc_super *, SEL, UIEvent *))objc_msgSendSuper)(&superInfo, @selector(sendEvent:), event);
}
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    struct objc_super superInfo = {
        .receiver = self,
        .super_class = [UIWindow class]
    };
    return ((UIView *(*)(struct objc_super *, SEL, CGPoint, UIEvent *))objc_msgSendSuper)(&superInfo, @selector(hitTest:withEvent:), point, event);
}
%end

%hook UIAlertController
+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)message preferredStyle:(UIAlertControllerStyle)style {
    UIAlertController *alert = %orig;
    BOOL blocked = NO;
    if (title && ([title containsString:@"越狱"] || [title containsString:@"Jailbreak"] ||
        [title containsString:@"jailbreak"])) {
        blocked = YES;
    }
    if (message && ([message containsString:@"越狱"] || [message containsString:@"Jailbreak"] ||
        [message containsString:@"jailbreak"] || [message containsString:@"已越狱"])) {
        blocked = YES;
    }
    if (!blocked && title && [title containsString:@"安全"]) {
        if (!message || [message containsString:@"风险"] || [message containsString:@"检测"] ||
            [message containsString:@"设备"] || [message containsString:@"root"] ||
            [message containsString:@"异常"] || [message containsString:@"威胁"]) {
            blocked = YES;
        }
    }
    if (blocked) {
        objc_setAssociatedObject(alert, "jb_blocked", @YES, OBJC_ASSOCIATION_RETAIN);
    }
    return alert;
}
%end

%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)flag completion:(void (^)(void))completion {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        if (objc_getAssociatedObject(vc, "jb_blocked")) {
            UIAlertController *alert = (UIAlertController *)vc;
            if (g_log_path[0]) {
                FILE *f = fopen(g_log_path, "a");
                if (f) {
                    fprintf(f, "[ALERT-BLOCKED] title=%s msg=%s actions=%d\n",
                            alert.title ? alert.title.UTF8String : "nil",
                            alert.message ? [alert.message substringToIndex:MIN(alert.message.length, 60)].UTF8String : "nil",
                            (int)alert.actions.count);
                    for (UIAlertAction *a in alert.actions) {
                        fprintf(f, "[ALERT-BLOCKED]   action: '%s' style=%ld\n",
                                a.title ? a.title.UTF8String : "nil", (long)a.style);
                    }
                    fclose(f);
                }
            }
            if (completion) completion();
            return;
        }
    }
    %orig;
}
%end

%hook NSProcessInfo
- (NSDictionary *)environment {
    NSMutableDictionary *env = [%orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"DYLD_LIBRARY_PATH"];
    [env removeObjectForKey:@"DYLD_FRAMEWORK_PATH"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"_SafeMode"];
    return env;
}
%end

%hook UIView
+ (void)setAnimationsEnabled:(BOOL)enabled {
    if (!enabled) {
        g_freeze_indicator++;
        CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
        if (elapsed > 3.0) {
            return;
        }
    }
    %orig;
}
- (void)setUserInteractionEnabled:(BOOL)enabled {
    if (!enabled) {
        CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
        if (elapsed > 3.0) {
            return;
        }
    }
    %orig;
}
%end

%hook CALayer
- (void)removeAllAnimations {
    CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
    if (elapsed > 3.0) {
        return;
    }
    %orig;
}
- (void)removeAnimationForKey:(NSString *)key {
    CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - g_ctor_time;
    if (elapsed > 3.0) {
        return;
    }
    %orig;
}
%end

%ctor {
    @autoreleasepool {
        %init;

        g_ctor_time = CFAbsoluteTimeGetCurrent();

        NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:docs withIntermediateDirectories:YES attributes:nil error:nil];
#if ICBC_DEBUG_LOG
        NSString *logPath = [docs stringByAppendingPathComponent:@"icbc_fishhook.log"];
        strncpy(g_log_path, logPath.UTF8String, sizeof(g_log_path) - 1);

        FILE *f = fopen(g_log_path, "w");
        if (f) { fprintf(f, "[INIT] ICBCBypass v1.0.0 ctor started\n"); fclose(f); }
#endif

        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"kUPWHomePageJailBrokenToastNotAgainKey"];
        [[NSUserDefaults standardUserDefaults] synchronize];

        hookSecureUtilityPlus();
        hookIOSSecuritySuite();
        hookICBCJailbreakMethods();
        hookAuthorityJailBreakFlag();
        hookShowJailBrokenAlert();

        rebind_symbols((struct rebinding[]){
            {"stat", (void *)hooked_stat, (void **)&orig_stat},
            {"lstat", (void *)hooked_lstat, (void **)&orig_lstat},
            {"access", (void *)hooked_access, (void **)&orig_access},
            {"open", (void *)hooked_open, (void **)&orig_open},
            {"fopen", (void *)hooked_fopen, (void **)&orig_fopen},
            {"realpath", (void *)hooked_realpath, (void **)&orig_realpath},
            {"readlink", (void *)hooked_readlink, (void **)&orig_readlink},
            {"statfs", (void *)hooked_statfs, (void **)&orig_statfs},
            {"statvfs", (void *)hooked_statvfs, (void **)&orig_statvfs},
            {"fork", (void *)hooked_fork, (void **)&orig_fork},
            {"getenv", (void *)hooked_getenv, (void **)&orig_getenv},
            {"sysctl", (void *)hooked_sysctl, (void **)&orig_sysctl},
            {"sysctlbyname", (void *)hooked_sysctlbyname, (void **)&orig_sysctlbyname},
            {"dlopen", (void *)hooked_dlopen, (void **)&orig_dlopen},
            {"dladdr", (void *)hooked_dladdr, (void **)&orig_dladdr},
            {"_dyld_image_count", (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count},
            {"_dyld_get_image_name", (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
            {"_dyld_get_image_header", (void *)hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
            {"_dyld_get_image_vmaddr_slide", (void *)hooked_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide},
            {"syscall", (void *)hooked_syscall, (void **)&orig_syscall},
            {"opendir", (void *)hooked_opendir, (void **)&orig_opendir},
            {"readdir", (void *)hooked_readdir, (void **)&orig_readdir},
            {"sleep", (void *)hooked_sleep, (void **)&orig_sleep},
            {"usleep", (void *)hooked_usleep, (void **)&orig_usleep},
            {"nanosleep", (void *)hooked_nanosleep, (void **)&orig_nanosleep},
            {"dispatch_suspend", (void *)hooked_dispatch_suspend, (void **)&orig_dispatch_suspend},
            {"pthread_kill", (void *)hooked_pthread_kill, (void **)&orig_pthread_kill},
            {"dispatch_semaphore_wait", (void *)hooked_dispatch_semaphore_wait, (void **)&orig_dispatch_semaphore_wait},
            {"dispatch_group_wait", (void *)hooked_dispatch_group_wait, (void **)&orig_dispatch_group_wait},
            {"CFRunLoopStop", (void *)hooked_CFRunLoopStop, (void **)&orig_CFRunLoopStop},
        }, 30);

#if ICBC_DEBUG_LOG
        // Watchdog: background thread checks if main thread is responsive
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
            __block BOOL mainResponded = NO;
            dispatch_async(dispatch_get_main_queue(), ^{ mainResponded = YES; });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                FILE *lf = fopen(g_log_path, "a");
                if (lf) {
                    fprintf(lf, "[WATCHDOG] t=5s main_responsive=%d\n", mainResponded);
                    fclose(lf);
                }
            });
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
            __block BOOL mainResponded = NO;
            dispatch_async(dispatch_get_main_queue(), ^{ mainResponded = YES; });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                FILE *lf = fopen(g_log_path, "a");
                if (lf) {
                    fprintf(lf, "[WATCHDOG] t=10s main_responsive=%d\n", mainResponded);
                    fclose(lf);
                }
            });
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
            __block BOOL mainResponded = NO;
            dispatch_async(dispatch_get_main_queue(), ^{ mainResponded = YES; });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                FILE *lf = fopen(g_log_path, "a");
                if (lf) {
                    fprintf(lf, "[WATCHDOG] t=14s main_responsive=%d sema_blocked=%d freeze_indicator=%d sendEvent=%d appEvent=%d\n",
                            mainResponded, g_sema_block_count, g_freeze_indicator, g_send_event_count, g_app_send_event_count);
                    fclose(lf);
                }
            });
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(18.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
            __block BOOL mainResponded = NO;
            dispatch_async(dispatch_get_main_queue(), ^{ mainResponded = YES; });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                FILE *lf = fopen(g_log_path, "a");
                if (lf) {
                    fprintf(lf, "[WATCHDOG] t=20s main_responsive=%d sema_blocked=%d freeze_indicator=%d sendEvent=%d appEvent=%d isIgnoring=%d\n",
                            mainResponded, g_sema_block_count, g_freeze_indicator, g_send_event_count, g_app_send_event_count,
                            (int)[[UIApplication sharedApplication] isIgnoringInteractionEvents]);
                    fclose(lf);
                }
            });
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(28.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
            __block BOOL mainResponded = NO;
            dispatch_async(dispatch_get_main_queue(), ^{ mainResponded = YES; });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                FILE *lf = fopen(g_log_path, "a");
                if (lf) {
                    fprintf(lf, "[WATCHDOG] t=30s main_responsive=%d sema_blocked=%d freeze_indicator=%d sendEvent=%d appEvent=%d isIgnoring=%d\n",
                            mainResponded, g_sema_block_count, g_freeze_indicator, g_send_event_count, g_app_send_event_count,
                            (int)[[UIApplication sharedApplication] isIgnoringInteractionEvents]);
                    fclose(lf);
                }
            });
        });
#endif

        // Periodic unfreezer: re-enable interaction every 2s
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), 2.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
        __block int unfreezeCount = 0;
        dispatch_source_set_event_handler(timer, ^{
            unfreezeCount++;
            UIApplication *app = [UIApplication sharedApplication];
            while (app.isIgnoringInteractionEvents) {
                [app endIgnoringInteractionEvents];
            }
            for (UIWindow *win in app.windows) {
                win.userInteractionEnabled = YES;
                if (win.rootViewController.view) {
                    win.rootViewController.view.userInteractionEnabled = YES;
                }
                if (win.windowLevel >= 1999 && ![win isKindOfClass:NSClassFromString(@"ICBCMotionRecognizingWindow")]) {
                    win.hidden = YES;
                }
                win.layer.speed = 1.0;
                if (win.rootViewController.view) {
                    win.rootViewController.view.layer.speed = 1.0;
                }
            }
            [UIView setAnimationsEnabled:YES];

#if ICBC_DEBUG_LOG
            // Deep diagnostic at count 3 (~9s after launch)
            if (unfreezeCount == 3 && g_log_path[0]) {
                FILE *df = fopen(g_log_path, "a");
                if (df) {
                    fprintf(df, "[DIAG] === Deep UI Dump ===\n");
                    UIWindow *mainWin = nil;
                    for (UIWindow *win in app.windows) {
                        if ([win isKindOfClass:NSClassFromString(@"ICBCMotionRecognizingWindow")]) {
                            mainWin = win;
                            break;
                        }
                    }
                    if (mainWin) {
                        UIViewController *rootVC = mainWin.rootViewController;
                        UIViewController *topVC = rootVC;
                        UINavigationController *navVC = nil;
                        if ([rootVC isKindOfClass:[UINavigationController class]]) {
                            navVC = (UINavigationController *)rootVC;
                            topVC = [navVC topViewController];
                            fprintf(df, "[DIAG] topVC: %s\n", [NSStringFromClass([topVC class]) UTF8String]);
                        }
                        if (topVC.view) {
                            // Check button targets
                            for (UIView *sub in topVC.view.subviews) {
                                if ([sub isKindOfClass:[UIButton class]]) {
                                    UIButton *btn = (UIButton *)sub;
                                    NSArray *targets = btn.allTargets.allObjects;
                                    NSArray *actions = [btn actionsForTarget:targets.firstObject forControlEvent:UIControlEventTouchUpInside];
                                    fprintf(df, "[DIAG] Button targets=%lu actions=%s\n",
                                            (unsigned long)targets.count,
                                            actions ? [[actions description] UTF8String] : "nil");
                                }
                            }
                        }
                        // Try to auto-skip: if topVC is Guide, pop it
                        if (navVC && [[NSStringFromClass([topVC class]) lowercaseString] containsString:@"guide"]) {
                            fprintf(df, "[DIAG] Attempting auto-skip of guide page...\n");
                            fclose(df);
                            // Try multiple skip strategies
                            // 1. Try calling skipGuide / skipBtn / enterApp methods
                            SEL skipSels[] = {
                                NSSelectorFromString(@"skipGuide"),
                                NSSelectorFromString(@"skipBtnClicked:"),
                                NSSelectorFromString(@"skipBtnClick:"),
                                NSSelectorFromString(@"skipAction:"),
                                NSSelectorFromString(@"skip:"),
                                NSSelectorFromString(@"enterApp"),
                                NSSelectorFromString(@"enterMainPage"),
                                NSSelectorFromString(@"dismissGuide"),
                                NSSelectorFromString(@"goToMainPage"),
                                NSSelectorFromString(@"finishGuide"),
                            };
                            BOOL skipped = NO;
                            for (int s = 0; s < 10; s++) {
                                if ([topVC respondsToSelector:skipSels[s]]) {
                                    FILE *sf = fopen(g_log_path, "a");
                                    if (sf) { fprintf(sf, "[SKIP] Found selector: %s — calling it\n", [NSStringFromSelector(skipSels[s]) UTF8String]); fclose(sf); }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                                    [topVC performSelector:skipSels[s] withObject:nil];
#pragma clang diagnostic pop
                                    skipped = YES;
                                    break;
                                }
                            }
                            if (!skipped) {
                                // 2. Fallback: pop the guide VC
                                FILE *sf = fopen(g_log_path, "a");
                                if (sf) { fprintf(sf, "[SKIP] No skip selector found, trying popViewController\n"); fclose(sf); }
                                [navVC popViewControllerAnimated:NO];
                            }
                        } else {
                            fclose(df);
                        }
                    } else {
                        fprintf(df, "[DIAG] mainWin not found\n");
                        fclose(df);
                    }
                }
            }
#endif

            if (unfreezeCount >= 15) dispatch_source_cancel(timer);
        });
        dispatch_resume(timer);
    }
}
