#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <signal.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <string.h>

// ============================================================
// Pure C path checking (no ObjC, safe for low-level hooks)
// ============================================================

static const char *jb_paths[] = {
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/lib/substrate",
    "/usr/lib/libjailbreak.dylib",
    "/usr/libexec/sftp-server",
    "/usr/sbin/frida-server",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings",
    "/var/jb",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/var/lib/undecimus/apt",
    "/tmp/frida-",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/private/jailbreak.txt",
    "/private/umTest_Jailbreak.txt",
    "/usr/share/jailbreak/injectme.plist",
    "/var/mobile/Library/Caches/cy-",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/usr/libexec/cydia",
    "/usr/local/bin/cycript",
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/Library/PreferenceBundles",
    "/Library/PreferenceLoader",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "SBSettings", "pspawn",
    NULL
};

// Pure C check - no ObjC allocation, safe in any context
static int is_jb_path_c(const char *path) {
    if (!path) return 0;

    for (int i = 0; jb_paths[i]; i++) {
        if (strncmp(path, jb_paths[i], strlen(jb_paths[i])) == 0) {
            return 1;
        }
    }

    for (int i = 0; jb_substrings[i]; i++) {
        if (strstr(path, jb_substrings[i])) {
            return 1;
        }
    }

    return 0;
}

// Thread-local reentrance guard for ObjC hooks
static _Thread_local int g_reentrant = 0;

// ============================================================
// ObjC-level path check (used only in ObjC hooks)
// ============================================================

static BOOL isJailbreakPath(NSString *path) {
    if (!path || path.length == 0) return NO;
    return is_jb_path_c(path.UTF8String) ? YES : NO;
}

static BOOL isJailbreakURL(NSURL *url) {
    if (!url) return NO;
    NSString *scheme = url.scheme.lowercaseString;
    NSArray *schemes = @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator"];
    return [schemes containsObject:scheme];
}

static int is_jb_dylib(const char *name) {
    if (!name) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "substitute") || strstr(name, "Substitute") ||
        strstr(name, "frida") || strstr(name, "cycript") ||
        strstr(name, "libhooker") || strstr(name, "MobileSubstrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") ||
        strstr(name, "pspawn") || strstr(name, "rocketbootstrap") ||
        strstr(name, "MYBankBypass") || strstr(name, "mybankNoJb") ||
        strstr(name, "/var/jb/")) {
        return 1;
    }
    return 0;
}

// ============================================================
// MARK: Hook NSFileManager
// ============================================================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if (isJailbreakPath(path)) return NO;
    return %orig;
}

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (g_reentrant) return %orig;
    g_reentrant = 1;
    NSArray *contents = %orig;
    g_reentrant = 0;
    if (!contents) return contents;

    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!isJailbreakPath(fullPath)) {
            [filtered addObject:item];
        }
    }
    return filtered;
}

- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (isJailbreakPath(path)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    return %orig;
}

%end

// ============================================================
// MARK: Hook UIApplication canOpenURL
// ============================================================

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (isJailbreakURL(url)) return NO;
    return %orig;
}

%end

// ============================================================
// MARK: Hook NSProcessInfo
// ============================================================

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSMutableDictionary *env = [%orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"DYLD_LIBRARY_PATH"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"_SafeMode"];
    return env;
}

%end

// ============================================================
// MARK: C function hooks (pure C checks only!)
// ============================================================

// --- stat / lstat ---
static int (*orig_stat)(const char *path, struct stat *buf);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

// --- access ---
static int (*orig_access)(const char *path, int mode);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

// --- open ---
static int (*orig_open)(const char *path, int flags, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

// --- fopen ---
static FILE *(*orig_fopen)(const char *path, const char *mode);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

// --- realpath ---
static char *(*orig_realpath)(const char *path, char *resolved);
static char *hooked_realpath(const char *path, char *resolved) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    char *result = orig_realpath(path, resolved);
    if (result && is_jb_path_c(result)) { errno = ENOENT; return NULL; }
    return result;
}

// --- readlink ---
static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsize);
static ssize_t hooked_readlink(const char *path, char *buf, size_t bufsize) {
    if (is_jb_path_c(path)) { errno = EINVAL; return -1; }
    ssize_t ret = orig_readlink(path, buf, bufsize);
    if (ret > 0 && buf) {
        char tmp[PATH_MAX];
        size_t len = (size_t)ret < PATH_MAX - 1 ? (size_t)ret : PATH_MAX - 1;
        memcpy(tmp, buf, len);
        tmp[len] = '\0';
        if (is_jb_path_c(tmp)) { errno = EINVAL; return -1; }
    }
    return ret;
}

// --- fork ---
static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) {
    errno = ENOSYS;
    return -1;
}

// --- getenv ---
static char *(*orig_getenv)(const char *name);
static char *hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
                 strcmp(name, "DYLD_FRAMEWORK_PATH") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "_SafeMode") == 0)) {
        return NULL;
    }
    return orig_getenv(name);
}

// --- sysctl (hide P_TRACED flag) ---
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
        if (ret == 0 && oldp) {
            struct kinfo_proc *proc = (struct kinfo_proc *)oldp;
            proc->kp_proc.p_flag &= ~P_TRACED;
        }
        return ret;
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// --- sysctlbyname ---
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int hooked_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && strcmp(name, "security.mac.amfi.developer_mode_status") == 0) {
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = 1;
            return 0;
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// ============================================================
// MARK: Hook _dyld functions
// ============================================================

static uint32_t (*orig_dyld_image_count)(void);
static uint32_t hooked_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (is_jb_dylib(name)) hidden++;
    }
    return count - hidden;
}

static const char *(*orig_dyld_get_image_name)(uint32_t idx);
static const char *hooked_dyld_get_image_name(uint32_t idx) {
    uint32_t count = orig_dyld_image_count();
    uint32_t visibleIdx = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (!is_jb_dylib(name)) {
            if (visibleIdx == idx) return name;
            visibleIdx++;
        }
    }
    return NULL;
}

// --- dlopen ---
static void *(*orig_dlopen)(const char *path, int mode);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_path_c(path)) return NULL;
    return orig_dlopen(path, mode);
}

// --- dladdr ---
static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && is_jb_dylib(info->dli_fname)) {
        info->dli_fname = "/usr/lib/system/libsystem_c.dylib";
        info->dli_sname = NULL;
        info->dli_saddr = NULL;
    }
    return ret;
}

// ============================================================
// MARK: Block sandbox write test
// ============================================================

static int (*orig_creat)(const char *path, mode_t mode);
static int hooked_creat(const char *path, mode_t mode) {
    if (path && (strstr(path, "jailbreak") || strstr(path, "Jailbreak"))) {
        errno = EACCES;
        return -1;
    }
    return orig_creat(path, mode);
}

// ============================================================
// MARK: Hook IOSSecuritySuite at runtime
// ============================================================

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

// ============================================================
// MARK: Hook SecurityGuard RootDetect
// ============================================================

static void hookSecurityGuard(void) {
    NSArray *classNames = @[
        @"SecurityGuardRootDetect",
        @"SecurityGuardSimulatorDetect",
        @"OpenSecurityGuardManager",
    ];

    for (NSString *className in classNames) {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) continue;

        // Instance methods
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"isRoot"] ||
                [selName containsString:@"isJail"] ||
                [selName containsString:@"rootDetect"] ||
                [selName containsString:@"jailbreak"] ||
                [selName containsString:@"checkEnv"]) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                } else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
                }
            }
        }
        if (methods) free(methods);

        // Class methods
        Class metaClass = object_getClass(cls);
        methods = class_copyMethodList(metaClass, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"isRoot"] ||
                [selName containsString:@"isJail"] ||
                [selName containsString:@"rootDetect"] ||
                [selName containsString:@"jailbreak"] ||
                [selName containsString:@"checkEnv"]) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                } else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^int(id s, ...) { return 0; }));
                }
            }
        }
        if (methods) free(methods);
    }
}

// ============================================================
// MARK: Block app termination
// ============================================================

// exit/abort are __attribute__((noreturn)) - we MUST NOT return from hooks
// Instead, suspend the calling thread forever

static void (*orig_exit)(int status);
static void hooked_exit(int status) {
    // If on main thread, just spin the run loop to keep app alive
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    // Background thread: sleep forever
    while (1) { sleep(INT_MAX); }
    __builtin_unreachable();
}

static void (*orig__exit)(int status);
static void hooked__exit(int status) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    while (1) { sleep(INT_MAX); }
    __builtin_unreachable();
}

static void (*orig_abort)(void);
static void hooked_abort(void) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    while (1) { sleep(INT_MAX); }
    __builtin_unreachable();
}

// Hook kill() to prevent self-kill (SIGKILL, SIGTERM, SIGABRT)
static int (*orig_kill)(pid_t pid, int sig);
static int hooked_kill(pid_t pid, int sig) {
    if (pid == getpid() || pid == 0) {
        return 0;
    }
    return orig_kill(pid, sig);
}

// Hook raise() to prevent signal-based exit
static int (*orig_raise)(int sig);
static int hooked_raise(int sig) {
    if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGTRAP) {
        return 0;
    }
    return orig_raise(sig);
}

// ============================================================
// MARK: Constructor
// ============================================================

%ctor {
    @autoreleasepool {
        // FIRST: Block all exit mechanisms
        MSHookFunction((void *)exit, (void *)hooked_exit, (void **)&orig_exit);
        MSHookFunction((void *)_exit, (void *)hooked__exit, (void **)&orig__exit);
        MSHookFunction((void *)abort, (void *)hooked_abort, (void **)&orig_abort);
        MSHookFunction((void *)kill, (void *)hooked_kill, (void **)&orig_kill);
        MSHookFunction((void *)raise, (void *)hooked_raise, (void **)&orig_raise);

        // File system hooks (pure C checks)
        MSHookFunction((void *)stat, (void *)hooked_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hooked_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)access, (void *)hooked_access, (void **)&orig_access);
        MSHookFunction((void *)open, (void *)hooked_open, (void **)&orig_open);
        MSHookFunction((void *)fopen, (void *)hooked_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)realpath, (void *)hooked_realpath, (void **)&orig_realpath);
        MSHookFunction((void *)readlink, (void *)hooked_readlink, (void **)&orig_readlink);
        MSHookFunction((void *)creat, (void *)hooked_creat, (void **)&orig_creat);

        // Process hooks
        MSHookFunction((void *)fork, (void *)hooked_fork, (void **)&orig_fork);
        MSHookFunction((void *)getenv, (void *)hooked_getenv, (void **)&orig_getenv);
        MSHookFunction((void *)sysctl, (void *)hooked_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)sysctlbyname, (void *)hooked_sysctlbyname, (void **)&orig_sysctlbyname);

        // Dyld hooks
        MSHookFunction((void *)_dyld_image_count, (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dlopen, (void *)hooked_dlopen, (void **)&orig_dlopen);
        MSHookFunction((void *)dladdr, (void *)hooked_dladdr, (void **)&orig_dladdr);

        // ObjC runtime hooks
        hookIOSSecuritySuite();
        hookSecurityGuard();
    }
}
