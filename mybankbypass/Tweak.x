#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <signal.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <string.h>
#import <pthread.h>

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
    "/usr/lib/libsubstitute.dylib",
    "/usr/libexec/sftp-server",
    "/usr/sbin/frida-server",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/etc/profile",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings",
    "/var/jb",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/var/lib/undecimus/apt",
    "/var/lib/cydia",
    "/tmp/frida-",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/private/jailbreak.txt",
    "/private/umTest_Jailbreak.txt",
    "/usr/share/jailbreak/injectme.plist",
    "/var/mobile/Library/Caches/cy-",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/usr/libexec/cydia",
    "/usr/local/bin/cycript",
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/Library/PreferenceBundles",
    "/Library/PreferenceLoader",
    "/bootstrap/inject_criticald",
    "/var/binpack/loaderd_hook",
    "/.installed_unc0ver",
    "/.installed_yaluX",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/dhpdaemon.plist",
    "/usr/bin/DHPDaemon",
    "/Library/MobileSubstrate/DynamicLibraries/AWZ.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/axjj.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/ALS.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/rstweak.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zorro.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zorrod.dylib",
    "/usr/bin/zorrodaemon.dylib",
    "/var/jb/usr/sbin/frida-server",
    "/bin/ssh",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "SBSettings", "pspawn", "libsubstitute",
    NULL
};

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
        strstr(name, "/var/jb/") ||
        strstr(name, "AWZ.dylib") || strstr(name, "axjj.dylib") ||
        strstr(name, "ALS.dylib") || strstr(name, "rstweak.dylib") ||
        strstr(name, "zorro") || strstr(name, "zorrod")) {
        return 1;
    }
    return 0;
}

// ============================================================
// MARK: Hook MYBLauncherController (prevent jailbreak check from calling exit)
// ============================================================

%hook MYBLauncherController

- (void)checkJailbroken {
    // No-op: prevent detection flow that leads to exit()
}

%end

// ============================================================
// MARK: Hook NSFileManager
// ============================================================

%hook NSFileManager

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
    [env removeObjectForKey:@"DYLD_FRAMEWORK_PATH"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"_SafeMode"];
    return env;
}

%end

// ============================================================
// MARK: C function hooks (pure C checks only!)
// ============================================================

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

static int (*orig_access)(const char *path, int mode);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

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

static FILE *(*orig_fopen)(const char *path, const char *mode);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static char *(*orig_realpath)(const char *path, char *resolved);
static char *hooked_realpath(const char *path, char *resolved) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    char *result = orig_realpath(path, resolved);
    if (result && is_jb_path_c(result)) { errno = ENOENT; return NULL; }
    return result;
}

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

static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) {
    errno = ENOSYS;
    return -1;
}

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

// --- getppid (hide injection parent) ---
static pid_t (*orig_getppid)(void);
static pid_t hooked_getppid(void) {
    return 1;
}

// ============================================================
// MARK: Hook _dyld functions
// ============================================================

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t idx);

static uint32_t hooked_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (name && is_jb_dylib(name)) hidden++;
    }
    return count - hidden;
}
static const char *hooked_dyld_get_image_name(uint32_t idx) {
    uint32_t count = orig_dyld_image_count();
    uint32_t visibleIdx = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (!name) continue;
        if (!is_jb_dylib(name)) {
            if (visibleIdx == idx) return name;
            visibleIdx++;
        }
    }
    return orig_dyld_get_image_name(0);
}

static void *(*orig_dlopen)(const char *path, int mode);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_path_c(path)) return NULL;
    return orig_dlopen(path, mode);
}

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

// --- statfs / statvfs: hide writable root filesystem ---
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int hooked_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs(path, buf);
    if (ret == 0 && buf) {
        // Force MNT_RDONLY on root and other restricted paths
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
// MARK: Hook MAJailbreakChecker (app's built-in detection)
// ============================================================

static void hookMAJailbreakChecker(void) {
    Class cls = objc_getClass("MAJailbreakChecker");
    if (!cls) return;

    Class metaCls = object_getClass(cls);
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(metaCls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        char retType[8];
        method_getReturnType(methods[i], retType, sizeof(retType));

        if ([selName isEqualToString:@"amIJailbroken"] ||
            [selName hasPrefix:@"check"] ||
            [selName isEqualToString:@"amIRunInEmulator"]) {
            if (retType[0] == 'B' || retType[0] == 'c') {
                method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
            }
        } else if ([selName isEqualToString:@"amIJailbrokenWithFailMessage"]) {
            method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s) {
                return @{@"jailbroken": @NO, @"failMessage": @""};
            }));
        } else if ([selName isEqualToString:@"amIJailbrokenWithFailedChecks"]) {
            method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s) {
                return @{@"jailbroken": @NO, @"failedChecks": @[]};
            }));
        } else if ([selName isEqualToString:@"performChecks"]) {
            method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s) {
                return @NO;
            }));
        } else if ([selName isEqualToString:@"getResultFromCheckType:"]) {
            method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s, int type) {
                return @NO;
            }));
        }
    }
    if (methods) free(methods);
}

// ============================================================
// MARK: Hook MASecurityUtil (risk flag)
// ============================================================

static void hookMASecurityUtil(void) {
    Class cls = objc_getClass("MASecurityUtil");
    if (!cls) return;

    SEL sel = NSSelectorFromString(@"existRisk");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

    sel = NSSelectorFromString(@"setExistRisk:");
    m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, BOOL v) {}));

    sel = NSSelectorFromString(@"isInstalledViaTrollStore");
    m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

    sel = NSSelectorFromString(@"searchMemContent");
    m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s) {}));

    sel = NSSelectorFromString(@"startCheckTimer:");
    m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, ...) {}));
}

// ============================================================
// MARK: Hook RDSSecurityCheck (dylib/tweak detection)
// ============================================================

static void hookRDSSecurityCheck(void) {
    Class cls = objc_getClass("RDSSecurityCheck");
    if (!cls) return;

    SEL sel = NSSelectorFromString(@"checkDylibTweak");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

    sel = NSSelectorFromString(@"checkAntiDebugStauts");
    m = class_getInstanceMethod(cls, sel);
    if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));
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
// MARK: Hook DTDeviceInfo (new in 4.7.x)
// ============================================================

static void hookDTDeviceInfo(void) {
    Class cls = objc_getClass("DTDeviceInfo");
    if (!cls) return;

    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        if ([selName containsString:@"isJail"] ||
            [selName containsString:@"isJailBreak"] ||
            [selName containsString:@"isJailbreak"] ||
            [selName containsString:@"jailbreaked"] ||
            [selName containsString:@"checkJailbroken"]) {
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

    Class metaClass = object_getClass(cls);
    methods = class_copyMethodList(metaClass, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        NSString *selName = NSStringFromSelector(method_getName(methods[i]));
        if ([selName containsString:@"isJail"] ||
            [selName containsString:@"isJailBreak"] ||
            [selName containsString:@"isJailbreak"] ||
            [selName containsString:@"jailbreaked"] ||
            [selName containsString:@"checkJailbroken"]) {
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

// ============================================================
// MARK: Hook DTDeviceInfo_isJailbreak C function
// ============================================================

static BOOL (*orig_DTDeviceInfo_isJailbreak)(void);
static BOOL hooked_DTDeviceInfo_isJailbreak(void) {
    return NO;
}

// ============================================================
// MARK: Hook RVPBridgeExtension4Jailbroken (H5/RPC bridge)
// ============================================================

static void hookJailbreakBridge(void) {
    Class cls = objc_getClass("RVPBridgeExtension4Jailbroken");
    if (!cls) return;

    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        char retType[8];
        method_getReturnType(methods[i], retType, sizeof(retType));
        if (retType[0] == 'B' || retType[0] == 'c') {
            method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
        } else if (retType[0] == '@') {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"jailb"] || [selName containsString:@"Jailb"] ||
                [selName containsString:@"Jail"]) {
                method_setImplementation(methods[i], imp_implementationWithBlock(^id(id s, ...) {
                    return @{@"isJailBroken": @NO, @"jailbroken": @NO};
                }));
            }
        }
    }
    if (methods) free(methods);

    Class metaCls = object_getClass(cls);
    methods = class_copyMethodList(metaCls, &methodCount);
    for (unsigned int i = 0; i < methodCount; i++) {
        char retType[8];
        method_getReturnType(methods[i], retType, sizeof(retType));
        if (retType[0] == 'B' || retType[0] == 'c') {
            method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
        }
    }
    if (methods) free(methods);
}

// Force _jailbreaked ivar to NO on DTDeviceInfo singleton
static void forceDTDeviceInfoClean(void) {
    Class cls = objc_getClass("DTDeviceInfo");
    if (!cls) return;

    SEL sharedSel = NSSelectorFromString(@"sharedDTDeviceInfo");
    if (!class_respondsToSelector(object_getClass(cls), sharedSel)) return;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    id instance = [cls performSelector:sharedSel];
#pragma clang diagnostic pop
    if (!instance) return;

    Ivar ivar = class_getInstanceVariable(cls, "_jailbreaked");
    if (ivar) {
        ((void (*)(id, Ivar, BOOL))object_setIvar)(instance, ivar, NO);
    }
}

static void hookBinAOPDetection(void) {
    // APBinAOPDrill - the main detection orchestrator
    Class drillClass = objc_getClass("APBinAOPDrill");
    if (drillClass) {
        // startHookDetect: - entry point for hook detection
        SEL sel = NSSelectorFromString(@"startHookDetect:");
        Method m = class_getInstanceMethod(drillClass, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, ...) {}));

        // pollingCheckHook - periodic re-check
        sel = NSSelectorFromString(@"pollingCheckHook");
        m = class_getInstanceMethod(drillClass, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s) {}));

        // checkHookDetectState - state query
        sel = NSSelectorFromString(@"checkHookDetectState");
        m = class_getInstanceMethod(drillClass, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

        // checkHookMethodStr:andBundlePath: - individual method check
        sel = NSSelectorFromString(@"checkHookMethodStr:andBundlePath:");
        m = class_getInstanceMethod(drillClass, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s, id str, id path) { return NO; }));

        // Also try class methods
        SEL sel2 = NSSelectorFromString(@"startHookDetect:");
        Method m2 = class_getClassMethod(drillClass, sel2);
        if (m2) method_setImplementation(m2, imp_implementationWithBlock(^(id s, ...) {}));

        sel2 = NSSelectorFromString(@"pollingCheckHook");
        m2 = class_getClassMethod(drillClass, sel2);
        if (m2) method_setImplementation(m2, imp_implementationWithBlock(^(id s) {}));
    }

    // Neutralize hook detection on ALL possible classes that might carry it
    NSArray *possibleClasses = @[
        @"APBinAOPDrill", @"APBinAOPConfig", @"APBinAOPConfig_v2",
        @"APBinAOPEntry", @"APBinAOPLifeCycle", @"APBinAOPGlobalStatusUtils",
        @"APBinAOPReportActiveManager",
    ];
    for (NSString *className in possibleClasses) {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) continue;

        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"hookDetect"] ||
                [selName containsString:@"HookDetect"] ||
                [selName containsString:@"hookDetection"] ||
                [selName containsString:@"hookedDetection"] ||
                [selName containsString:@"pollingCheck"] ||
                [selName containsString:@"reportBINAOPHook"] ||
                [selName containsString:@"startHookDetect"]) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                } else if (retType[0] == 'v') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^(id s, ...) {}));
                }
            }
        }
        if (methods) free(methods);

        // Same for class methods
        Class metaCls = object_getClass(cls);
        methods = class_copyMethodList(metaCls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"hookDetect"] ||
                [selName containsString:@"HookDetect"] ||
                [selName containsString:@"hookDetection"] ||
                [selName containsString:@"hookedDetection"] ||
                [selName containsString:@"pollingCheck"] ||
                [selName containsString:@"reportBINAOPHook"] ||
                [selName containsString:@"startHookDetect"]) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                } else if (retType[0] == 'v') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^(id s, ...) {}));
                }
            }
        }
        if (methods) free(methods);
    }

    // Neutralize hookDetectionEnable / hookCheck properties on config classes
    NSArray *configClasses = @[@"APBinAOPConfig", @"APBinAOPConfig_v2", @"APBinAOPDrill"];
    for (NSString *className in configClasses) {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) continue;

        SEL sel = NSSelectorFromString(@"hookDetectionEnable");
        Method m = class_getInstanceMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

        sel = NSSelectorFromString(@"hookCheck");
        m = class_getInstanceMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { return NO; }));

        sel = NSSelectorFromString(@"setHookDetectionEnable:");
        m = class_getInstanceMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, BOOL v) {}));

        sel = NSSelectorFromString(@"setHookCheck:");
        m = class_getInstanceMethod(cls, sel);
        if (m) method_setImplementation(m, imp_implementationWithBlock(^(id s, BOOL v) {}));
    }

    // Neutralize microPageHookDetect (triggered by mini-program/webview loads)
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = allClasses[c];
        const char *cname = class_getName(cls);
        if (!cname) continue;
        if (!strstr(cname, "BinAOP") && !strstr(cname, "binaop") && !strstr(cname, "Binaop")) continue;

        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            NSString *selName = NSStringFromSelector(method_getName(methods[i]));
            if ([selName containsString:@"microPageHookDetect"] ||
                [selName containsString:@"hookDetectHaveEnd"] ||
                [selName containsString:@"RESULT_HOOKED"]) {
                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));
                if (retType[0] == 'B' || retType[0] == 'c') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^BOOL(id s, ...) { return NO; }));
                } else if (retType[0] == 'v') {
                    method_setImplementation(methods[i], imp_implementationWithBlock(^(id s, ...) {}));
                }
            }
        }
        if (methods) free(methods);
    }
    if (allClasses) free(allClasses);
}

// ============================================================
// MARK: Block app termination
// ============================================================

static void (*orig_exit)(int status);
static void hooked_exit(int status) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    pthread_exit(NULL);
    __builtin_unreachable();
}

static void (*orig__exit)(int status);
static void hooked__exit(int status) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    pthread_exit(NULL);
    __builtin_unreachable();
}

static void (*orig_abort)(void);
static void hooked_abort(void) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    pthread_exit(NULL);
    __builtin_unreachable();
}

static int (*orig_kill)(pid_t pid, int sig);
static int hooked_kill(pid_t pid, int sig) {
    if (pid == getpid() || pid == 0) {
        return 0;
    }
    return orig_kill(pid, sig);
}

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
        // Install Logos ObjC hooks
        %init;

        // Block all exit mechanisms FIRST
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
        MSHookFunction((void *)statfs, (void *)hooked_statfs, (void **)&orig_statfs);
        MSHookFunction((void *)statvfs, (void *)hooked_statvfs, (void **)&orig_statvfs);

        // Process hooks
        MSHookFunction((void *)fork, (void *)hooked_fork, (void **)&orig_fork);
        MSHookFunction((void *)getenv, (void *)hooked_getenv, (void **)&orig_getenv);
        MSHookFunction((void *)sysctl, (void *)hooked_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)sysctlbyname, (void *)hooked_sysctlbyname, (void **)&orig_sysctlbyname);
        MSHookFunction((void *)getppid, (void *)hooked_getppid, (void **)&orig_getppid);

        // Dyld hooks
        MSHookFunction((void *)_dyld_image_count, (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dlopen, (void *)hooked_dlopen, (void **)&orig_dlopen);
        MSHookFunction((void *)dladdr, (void *)hooked_dladdr, (void **)&orig_dladdr);

        // ObjC runtime hooks for security frameworks
        hookIOSSecuritySuite();
        hookMAJailbreakChecker();
        hookMASecurityUtil();
        hookRDSSecurityCheck();
        hookSecurityGuard();
        hookDTDeviceInfo();
        hookJailbreakBridge();
        hookBinAOPDetection();

        // Hook DTDeviceInfo_isJailbreak C function
        void *sym = dlsym(RTLD_DEFAULT, "DTDeviceInfo_isJailbreak");
        if (sym) {
            MSHookFunction(sym, (void *)hooked_DTDeviceInfo_isJailbreak, (void **)&orig_DTDeviceInfo_isJailbreak);
        }

        // Force DTDeviceInfo singleton clean
        forceDTDeviceInfoClean();

        // Delayed retry: some classes may load after our ctor
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            hookMAJailbreakChecker();
            hookMASecurityUtil();
            hookRDSSecurityCheck();
            hookDTDeviceInfo();
            hookJailbreakBridge();
            hookBinAOPDetection();
            forceDTDeviceInfoClean();
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            hookMAJailbreakChecker();
            hookMASecurityUtil();
            hookRDSSecurityCheck();
            hookDTDeviceInfo();
            hookJailbreakBridge();
            hookBinAOPDetection();
            forceDTDeviceInfoClean();
        });
    }
}
