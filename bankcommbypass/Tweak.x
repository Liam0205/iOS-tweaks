#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <pthread.h>

// ============================================================
// MARK: Jailbreak path / substring lists
// ============================================================

static const char *jb_paths[] = {
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/MobileSubstrate/DynamicLibraries/Flex.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/SubstrateLoader.dylib",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/cydia/firmware.sh",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/jailbreak_test.txt",
    "/var/cache/apt",
    "/var/lib/apt",
    "/var/lib/cydia/",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/var/log/apt",
    "/var/jb",
    "/var/jb/usr/sbin/frida-server",
    "/jb/",
    "/jb/lzma",
    "/TweakInject/",
    "/Bangcle/",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "SBSettings", "pspawn", "libsubstitute", "procursus",
    "sileo", "zebra", "Dopamine",
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
    if (strstr(path, "/var/jb")) return 1;
    return 0;
}

static int is_jb_dylib(const char *name) {
    if (!name) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "substitute") || strstr(name, "Substitute") ||
        strstr(name, "frida") || strstr(name, "cycript") ||
        strstr(name, "libhooker") || strstr(name, "MobileSubstrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") ||
        strstr(name, "pspawn") || strstr(name, "rocketbootstrap") ||
        strstr(name, "BankcommBypass") || strstr(name, "bankcommbypass") ||
        strstr(name, "/var/jb/") ||
        strstr(name, "AWZ.dylib") || strstr(name, "axjj.dylib") ||
        strstr(name, "ALS.dylib") || strstr(name, "rstweak.dylib") ||
        strstr(name, "zorro") || strstr(name, "zorrod")) {
        return 1;
    }
    return 0;
}

// ============================================================
// MARK: C function hooks
// ============================================================

// --- stat / lstat / access ---
static int (*orig_stat)(const char *path, struct stat *buf);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *path, int mode);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

// --- fopen ---
static FILE *(*orig_fopen)(const char *path, const char *mode);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

// --- statfs / statvfs (hide writable filesystem) ---
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int hooked_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs(path, buf);
    if (ret == 0 && buf) {
        if (path && (strcmp(path, "/") == 0 || strncmp(path, "/var", 4) == 0 ||
                     strncmp(path, "/private", 8) == 0 || strncmp(path, "/System", 7) == 0)) {
            buf->f_flags |= MNT_RDONLY | MNT_NOSUID;
        }
    }
    return ret;
}

static int (*orig_statvfs)(const char *path, struct statvfs *buf);
static int hooked_statvfs(const char *path, struct statvfs *buf) {
    int ret = orig_statvfs(path, buf);
    if (ret == 0 && buf) {
        if (path && (strcmp(path, "/") == 0 || strncmp(path, "/var", 4) == 0 ||
                     strncmp(path, "/private", 8) == 0 || strncmp(path, "/System", 7) == 0)) {
            buf->f_flag |= ST_RDONLY | ST_NOSUID;
        }
    }
    return ret;
}

// --- fork ---
static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) {
    errno = ENOSYS;
    return -1;
}

// --- getppid ---
static pid_t (*orig_getppid)(void);
static pid_t hooked_getppid(void) {
    return 1;
}

// --- dyld image filtering (cached) ---
static uint32_t *dyld_remap = NULL;
static uint32_t dyld_visible_count = 0;
static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t idx);

static void rebuild_dyld_cache(void) {
    uint32_t count = orig_dyld_image_count();
    uint32_t *new_remap = (uint32_t *)malloc(count * sizeof(uint32_t));
    uint32_t visible = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (!is_jb_dylib(name)) {
            new_remap[visible++] = i;
        }
    }
    uint32_t *old = dyld_remap;
    dyld_remap = new_remap;
    dyld_visible_count = visible;
    if (old) free(old);
}

static uint32_t hooked_dyld_image_count(void) {
    if (!dyld_remap) rebuild_dyld_cache();
    return dyld_visible_count;
}

static const char *hooked_dyld_get_image_name(uint32_t idx) {
    if (!dyld_remap) rebuild_dyld_cache();
    if (idx < dyld_visible_count) {
        return orig_dyld_get_image_name(dyld_remap[idx]);
    }
    return "";
}

// --- exit / _exit / abort: block the calling thread instead of killing it ---
static dispatch_semaphore_t _block_forever_sema;

static void (*orig_exit)(int code);
static void hooked_exit(int code) {
    if ([NSThread isMainThread]) {
        [[NSRunLoop currentRunLoop] run];
    } else {
        dispatch_semaphore_wait(_block_forever_sema, DISPATCH_TIME_FOREVER);
    }
    __builtin_unreachable();
}

static void (*orig__exit)(int code);
static void hooked__exit(int code) {
    if ([NSThread isMainThread]) {
        [[NSRunLoop currentRunLoop] run];
    } else {
        dispatch_semaphore_wait(_block_forever_sema, DISPATCH_TIME_FOREVER);
    }
    __builtin_unreachable();
}

static void (*orig_abort)(void);
static void hooked_abort(void) {
    if ([NSThread isMainThread]) {
        [[NSRunLoop currentRunLoop] run];
    } else {
        dispatch_semaphore_wait(_block_forever_sema, DISPATCH_TIME_FOREVER);
    }
    __builtin_unreachable();
}

// --- sysctl (hide debugger / process info) ---
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info) {
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// ============================================================
// MARK: ObjC hooks - BangcleCheck
// ============================================================

%hook BangcleCheck

- (void)showJailbreakAlert {
    // No-op
}

- (void)showNPHandlerAlert {
    // No-op
}

- (BOOL)isJailbreaked {
    return NO;
}

- (void)setIsJailbreaked:(BOOL)v {
    // No-op - never set to YES
}

- (BOOL)jailbreakAlerting {
    return NO;
}

- (void)setJailbreakAlerting:(BOOL)v {
    // No-op
}

- (BOOL)jailbreakAlertShowed {
    return YES; // Pretend already showed so it won't try again
}

- (BOOL)shouldInterruptRouter {
    return NO;
}

- (void)initializeBangcleSecureUtiltil {
    // No-op - prevent SecureUtilityPlus from running integrity/hook checks
}

- (void)startNPHandlerCheck:(id)arg {
    // No-op
}

- (NSString *)enableBangcleCheck {
    return @"0";
}

%end

// ============================================================
// MARK: ObjC hooks - CWDeviceStatusManager
// ============================================================

%hook CWDeviceStatusManager

+ (BOOL)isDeviceJailbroken {
    return NO;
}

+ (BOOL)isDeviceEscape {
    return NO;
}

+ (BOOL)isFileSystemWritable {
    return NO;
}

+ (BOOL)isEnvironmentVariablePresent {
    return NO;
}

%end

// ============================================================
// MARK: ObjC hooks - UPWHomePageUtils
// ============================================================

%hook UPWHomePageUtils

+ (void)showJailBrokenAlertIfNeeded {
    // No-op
}

%end

// ============================================================
// MARK: ObjC hooks - UIDevice (bcm_isJailbreak category)
// ============================================================

%hook UIDevice

+ (BOOL)bcm_isJailbreak {
    return NO;
}

+ (BOOL)getYueYu {
    return NO;
}

+ (BOOL)printDYLD {
    return NO;
}

%end

// ============================================================
// MARK: ObjC hooks - UIAlertController (block jailbreak alert)
// ============================================================

%hook UIViewController

- (void)presentViewController:(UIViewController *)vc animated:(BOOL)flag completion:(void (^)(void))completion {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title = alert.title ?: @"";
        NSString *msg = alert.message ?: @"";
        NSString *combined = [NSString stringWithFormat:@"%@%@", title, msg];
        if ([combined containsString:@"越狱"] || [combined containsString:@"jailbreak"] ||
            [combined containsString:@"Jailbreak"] || [combined containsString:@"安全"] ||
            [combined containsString:@"退出应用"]) {
            if (completion) completion();
            return;
        }
    }
    %orig;
}

%end

// ============================================================
// MARK: Hook SecureUtilityPlus (Swift classes)
// ============================================================

static void hookSecureUtilityPlus(void) {
    // Hook JailbreakChecker
    Class cls = objc_getClass("SecureUtilityPlus.JailbreakChecker");
    if (!cls) cls = objc_getClass("_TtC17SecureUtilityPlus16JailbreakChecker");
    if (cls) {
        // Hook all class methods that return Bool
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook FileChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus11FileChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook DebuggerChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus15DebuggerChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook FishHookChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus15FishHookChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook MSHookFunctionChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus21MSHookFunctionChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook RuntimeHookChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus18RuntimeHookChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook ReverseEngineeringToolsChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus30ReverseEngineeringToolsChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook IntegrityChecker
    cls = objc_getClass("_TtC17SecureUtilityPlus16IntegrityChecker");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }

    // Hook IOSSecuritySuite
    cls = objc_getClass("_TtC17SecureUtilityPlus16IOSSecuritySuite");
    if (cls) {
        Class metaCls = object_getClass(cls);
        unsigned int count = 0;
        Method *methods = class_copyMethodList(metaCls, &count);
        for (unsigned int i = 0; i < count; i++) {
            char retType[8];
            method_getReturnType(methods[i], retType, sizeof(retType));
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        }
        if (methods) free(methods);
    }
}

// ============================================================
// MARK: Hook canOpenURL (hide jailbreak URL schemes)
// ============================================================

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    NSString *scheme = url.scheme.lowercaseString;
    if ([scheme isEqualToString:@"cydia"] || [scheme isEqualToString:@"sileo"] ||
        [scheme isEqualToString:@"zbra"] || [scheme isEqualToString:@"filza"] ||
        [scheme hasPrefix:@"undecimus"]) {
        return NO;
    }
    return %orig;
}

%end

// NSFileManager hook removed - bottom-level C hooks (stat/access/fopen) already cover these paths
// Keeping ObjC layer clean avoids performance overhead on frequent file operations

// ============================================================
// MARK: Hook NSProcessInfo (hide environment variables)
// ============================================================

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSDictionary *orig = %orig;
    NSMutableDictionary *env = [orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"_SafeMode"];
    return env;
}

%end

// ============================================================
// MARK: Constructor
// ============================================================

%ctor {
    @autoreleasepool {
        _block_forever_sema = dispatch_semaphore_create(0);

        // Hook C functions
        MSHookFunction((void *)stat, (void *)hooked_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hooked_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)access, (void *)hooked_access, (void **)&orig_access);
        MSHookFunction((void *)fopen, (void *)hooked_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)statfs, (void *)hooked_statfs, (void **)&orig_statfs);
        MSHookFunction((void *)statvfs, (void *)hooked_statvfs, (void **)&orig_statvfs);
        MSHookFunction((void *)fork, (void *)hooked_fork, (void **)&orig_fork);
        MSHookFunction((void *)getppid, (void *)hooked_getppid, (void **)&orig_getppid);
        MSHookFunction((void *)_dyld_image_count, (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        rebuild_dyld_cache();

        // exit/abort hooks
        MSHookFunction((void *)exit, (void *)hooked_exit, (void **)&orig_exit);
        MSHookFunction((void *)_exit, (void *)hooked__exit, (void **)&orig__exit);
        MSHookFunction((void *)abort, (void *)hooked_abort, (void **)&orig_abort);

        // sysctl
        void *sysctl_ptr = dlsym(RTLD_DEFAULT, "sysctl");
        if (sysctl_ptr) {
            MSHookFunction(sysctl_ptr, (void *)hooked_sysctl, (void **)&orig_sysctl);
        }

        // Hook SecureUtilityPlus Swift classes
        hookSecureUtilityPlus();

        // Delayed retry for classes loaded later
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            hookSecureUtilityPlus();
        });
    }
}
