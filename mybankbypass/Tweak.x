#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <dirent.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#import <objc/runtime.h>

// ============================================================
// Jailbreak paths to hide
// ============================================================

static NSArray<NSString *> *jailbreakPaths() {
    static NSArray *paths;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        paths = @[
            @"/Applications/Cydia.app",
            @"/Library/MobileSubstrate",
            @"/Library/MobileSubstrate/DynamicLibraries",
            @"/Library/MobileSubstrate/CydiaSubstrate.dylib",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            @"/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
            @"/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist",
            @"/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist",
            @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            @"/bin/bash",
            @"/bin/sh",
            @"/usr/sbin/sshd",
            @"/usr/bin/ssh",
            @"/usr/bin/sshd",
            @"/usr/lib/substrate",
            @"/usr/lib/libjailbreak.dylib",
            @"/usr/libexec/sftp-server",
            @"/usr/sbin/frida-server",
            @"/etc/apt",
            @"/etc/apt/sources.list.d",
            @"/etc/apt/sources.list.d/electra.list",
            @"/etc/apt/sources.list.d/sileo.sources",
            @"/etc/apt/undecimus/undecimus.list",
            @"/private/var/lib/apt",
            @"/private/var/lib/apt/",
            @"/private/var/lib/cydia",
            @"/private/var/mobile/Library/SBSettings/Themes",
            @"/var/jb",
            @"/var/jb/",
            @"/var/jb/usr",
            @"/var/jb/Library",
            @"/var/jb/usr/sbin/frida-server",
            @"/var/jb/Library/MobileSubstrate",
            @"/var/lib/dpkg/info/mobilesubstrate.md5sums",
            @"/var/lib/undecimus/apt",
            @"/tmp/frida-",
            @"/jb/jailbreakd.plist",
            @"/jb/libjailbreak.dylib",
            @"/private/jailbreak.txt",
            @"/private/umTest_Jailbreak.txt",
            @"/usr/share/jailbreak/injectme.plist",
            @"/var/mobile/Library/Caches/cy-",
            @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            @"/usr/libexec/cydia",
            @"/usr/local/bin/cycript",
            @"/var/checkra1n.dmg",
            @"/var/binpack",
            @"/Library/PreferenceBundles/",
            @"/Library/PreferenceLoader/",
        ];
    });
    return paths;
}

static BOOL isJailbreakPath(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jbPath in jailbreakPaths()) {
        if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
            return YES;
        }
    }
    if ([path containsString:@"substrate"] ||
        [path containsString:@"Substrate"] ||
        [path containsString:@"cydia"] ||
        [path containsString:@"Cydia"] ||
        [path containsString:@"frida"] ||
        [path containsString:@"jailbreak"] ||
        [path containsString:@"cycript"] ||
        [path containsString:@"SBSettings"] ||
        [path containsString:@"MobileSubstrate"] ||
        [path containsString:@"TweakInject"] ||
        [path containsString:@"ellekit"] ||
        [path containsString:@"libhooker"] ||
        [path containsString:@"substitute"]) {
        return YES;
    }
    return NO;
}

static BOOL isJailbreakCPath(const char *path) {
    if (!path) return NO;
    return isJailbreakPath([NSString stringWithUTF8String:path]);
}

// ============================================================
// Jailbreak URL schemes to block
// ============================================================

static BOOL isJailbreakURL(NSURL *url) {
    if (!url) return NO;
    NSString *scheme = url.scheme.lowercaseString;
    NSArray *schemes = @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator"];
    return [schemes containsObject:scheme];
}

// ============================================================
// Dylib names to hide
// ============================================================

static BOOL isJailbreakDylib(const char *name) {
    if (!name) return NO;
    NSString *dylib = [NSString stringWithUTF8String:name];
    if ([dylib containsString:@"substrate"] ||
        [dylib containsString:@"Substrate"] ||
        [dylib containsString:@"substitute"] ||
        [dylib containsString:@"Substitute"] ||
        [dylib containsString:@"frida"] ||
        [dylib containsString:@"cycript"] ||
        [dylib containsString:@"libhooker"] ||
        [dylib containsString:@"MobileSubstrate"] ||
        [dylib containsString:@"TweakInject"] ||
        [dylib containsString:@"ellekit"] ||
        [dylib containsString:@"pspawn"] ||
        [dylib containsString:@"rocketbootstrap"] ||
        [dylib containsString:@"MYBankBypass"] ||
        [dylib containsString:@"mybankNoJb"] ||
        [dylib containsString:@"/var/jb/"]) {
        return YES;
    }
    return NO;
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
    NSArray *contents = %orig;
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
// MARK: Block exit/abort - prevent app from killing itself
// ============================================================

static void (*orig_exit)(int status);
static void hooked_exit(int status) {
    // Don't let the app exit
    return;
}

static void (*orig__exit)(int status);
static void hooked__exit(int status) {
    return;
}

static void (*orig_abort)(void);
static void hooked_abort(void) {
    return;
}

// Also hook atexit-registered termination
static int (*orig_atexit)(void (*func)(void));
static int hooked_atexit(void (*func)(void)) {
    return 0;
}

// ============================================================
// MARK: Hook C functions
// ============================================================

// --- stat / lstat ---
static int (*orig_stat)(const char *path, struct stat *buf);
static int hooked_stat(const char *path, struct stat *buf) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

// --- access ---
static int (*orig_access)(const char *path, int mode);
static int hooked_access(const char *path, int mode) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

// --- open ---
static int (*orig_open)(const char *path, int flags, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return -1;
    }
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
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen(path, mode);
}

// --- opendir ---
static DIR *(*orig_opendir)(const char *path);
static DIR *hooked_opendir(const char *path) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir(path);
}

// --- realpath ---
static char *(*orig_realpath)(const char *path, char *resolved);
static char *hooked_realpath(const char *path, char *resolved) {
    if (isJailbreakCPath(path)) {
        errno = ENOENT;
        return NULL;
    }
    char *result = orig_realpath(path, resolved);
    if (result && isJailbreakCPath(result)) {
        errno = ENOENT;
        return NULL;
    }
    return result;
}

// --- readlink (critical for Dopamine symlinks) ---
static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsize);
static ssize_t hooked_readlink(const char *path, char *buf, size_t bufsize) {
    if (isJailbreakCPath(path)) {
        errno = EINVAL;
        return -1;
    }
    ssize_t ret = orig_readlink(path, buf, bufsize);
    if (ret > 0 && buf) {
        char tmp[PATH_MAX];
        memcpy(tmp, buf, ret);
        tmp[ret] = '\0';
        if (isJailbreakCPath(tmp)) {
            errno = EINVAL;
            return -1;
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

// --- getenv ---
static char *(*orig_getenv)(const char *name);
static char *hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0 ||
                 strcmp(name, "_SafeMode") == 0 ||
                 strcmp(name, "DYLD_FRAMEWORK_PATH") == 0)) {
        return NULL;
    }
    return orig_getenv(name);
}

// --- sysctl (hide jailbreak-related processes) ---
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // Block P_TRACED detection (anti-debug)
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
        // Return developer mode enabled
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            *(int *)oldp = 1;
            return 0;
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

// --- statfs (detect jailbreak filesystem modifications) ---
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int hooked_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs(path, buf);
    if (ret == 0 && buf) {
        // Remove MNT_NOSUID and MNT_RDONLY flags that might indicate modification
        // Some jailbreaks remount / as read-write
        buf->f_flags |= MNT_RDONLY;
        buf->f_flags |= MNT_NOSUID;
    }
    return ret;
}

// ============================================================
// MARK: Hook _dyld_get_image_name / _dyld_image_count
// ============================================================

static uint32_t (*orig_dyld_image_count)(void);
static uint32_t hooked_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (isJailbreakDylib(name)) hidden++;
    }
    return count - hidden;
}

static const char *(*orig_dyld_get_image_name)(uint32_t idx);
static const char *hooked_dyld_get_image_name(uint32_t idx) {
    uint32_t count = orig_dyld_image_count();
    uint32_t visibleIdx = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (!isJailbreakDylib(name)) {
            if (visibleIdx == idx) return name;
            visibleIdx++;
        }
    }
    return NULL;
}

// ============================================================
// MARK: Hook dlopen / dladdr
// ============================================================

static void *(*orig_dlopen)(const char *path, int mode);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && isJailbreakCPath(path)) {
        return NULL;
    }
    return orig_dlopen(path, mode);
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hooked_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && isJailbreakDylib(info->dli_fname)) {
        info->dli_fname = "/usr/lib/system/libsystem_c.dylib";
        info->dli_sname = NULL;
        info->dli_saddr = NULL;
    }
    return ret;
}

// ============================================================
// MARK: Hook sandbox write test
// ============================================================

static int (*orig_creat)(const char *path, mode_t mode);
static int hooked_creat(const char *path, mode_t mode) {
    if (path) {
        NSString *p = [NSString stringWithUTF8String:path];
        if ([p isEqualToString:@"/private/jailbreak.txt"] ||
            [p isEqualToString:@"/private/umTest_Jailbreak.txt"] ||
            ([p hasPrefix:@"/private/"] && [p containsString:@"jailbreak"])) {
            errno = EACCES;
            return -1;
        }
    }
    return orig_creat(path, mode);
}

// --- write test via symlink ---
static int (*orig_symlink)(const char *target, const char *linkpath);
static int hooked_symlink(const char *target, const char *linkpath) {
    if (linkpath) {
        NSString *p = [NSString stringWithUTF8String:linkpath];
        if ([p hasPrefix:@"/private/"] || [p hasPrefix:@"/var/"] || [p hasPrefix:@"/tmp/"]) {
            if ([p containsString:@"jailbreak"] || [p containsString:@"test"]) {
                errno = EACCES;
                return -1;
            }
        }
    }
    return orig_symlink(target, linkpath);
}

// ============================================================
// MARK: Hook IOSSecuritySuite (Swift class with ObjC bridge)
// ============================================================

// IOSSecuritySuite uses class methods - we'll try runtime hooks
static void hookIOSSecuritySuite() {
    Class cls = objc_getClass("IOSSecuritySuite.IOSSecuritySuite");
    if (!cls) cls = objc_getClass("IOSSecuritySuite");
    if (!cls) return;

    // Hook amIJailbroken
    SEL sel = NSSelectorFromString(@"amIJailbroken");
    if (sel && class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^BOOL(id self_) { return NO; });
            method_setImplementation(m, newImp);
        }
    }

    // Hook amIJailbrokenWithFailedChecks
    sel = NSSelectorFromString(@"amIJailbrokenWithFailedChecks");
    if (sel && class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^id(id self_) { return @{@"jailbroken": @NO, @"failedChecks": @[]}; });
            method_setImplementation(m, newImp);
        }
    }

    // Hook amIJailbrokenWithFailMessage
    sel = NSSelectorFromString(@"amIJailbrokenWithFailMessage");
    if (sel && class_respondsToSelector(object_getClass(cls), sel)) {
        Method m = class_getClassMethod(cls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^id(id self_) { return @{@"jailbroken": @NO, @"failMessage": @""}; });
            method_setImplementation(m, newImp);
        }
    }
}

// ============================================================
// MARK: Hook SecurityGuard RootDetect
// ============================================================

static void hookSecurityGuard() {
    // Try to find and hook the SecurityGuard root detection
    NSArray *classNames = @[
        @"SecurityGuardRootDetect",
        @"SecurityGuardOpenSecurityBody",
        @"SecurityGuardSimulatorDetect",
        @"OpenSecurityGuardManager",
    ];

    for (NSString *className in classNames) {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) continue;

        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);

            // Hook methods that check for root/jailbreak
            if ([selName containsString:@"isRoot"] ||
                [selName containsString:@"isJail"] ||
                [selName containsString:@"rootDetect"] ||
                [selName containsString:@"jailbreak"] ||
                [selName containsString:@"checkEnv"]) {

                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));

                if (retType[0] == 'B' || retType[0] == 'c') { // BOOL or char
                    IMP newImp = imp_implementationWithBlock(^BOOL(id self_, ...) { return NO; });
                    method_setImplementation(methods[i], newImp);
                } else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q') { // int/long
                    IMP newImp = imp_implementationWithBlock(^int(id self_, ...) { return 0; });
                    method_setImplementation(methods[i], newImp);
                }
            }
        }
        if (methods) free(methods);

        // Also check class methods
        Class metaClass = object_getClass(cls);
        methods = class_copyMethodList(metaClass, &methodCount);
        for (unsigned int i = 0; i < methodCount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);

            if ([selName containsString:@"isRoot"] ||
                [selName containsString:@"isJail"] ||
                [selName containsString:@"rootDetect"] ||
                [selName containsString:@"jailbreak"] ||
                [selName containsString:@"checkEnv"]) {

                char retType[8];
                method_getReturnType(methods[i], retType, sizeof(retType));

                if (retType[0] == 'B' || retType[0] == 'c') {
                    IMP newImp = imp_implementationWithBlock(^BOOL(id self_, ...) { return NO; });
                    method_setImplementation(methods[i], newImp);
                } else if (retType[0] == 'i' || retType[0] == 'l' || retType[0] == 'q') {
                    IMP newImp = imp_implementationWithBlock(^int(id self_, ...) { return 0; });
                    method_setImplementation(methods[i], newImp);
                }
            }
        }
        if (methods) free(methods);
    }
}

// ============================================================
// MARK: Constructor - apply all hooks
// ============================================================

%ctor {
    @autoreleasepool {
        // C function hooks
        MSHookFunction((void *)stat, (void *)hooked_stat, (void **)&orig_stat);
        MSHookFunction((void *)lstat, (void *)hooked_lstat, (void **)&orig_lstat);
        MSHookFunction((void *)access, (void *)hooked_access, (void **)&orig_access);
        MSHookFunction((void *)open, (void *)hooked_open, (void **)&orig_open);
        MSHookFunction((void *)fopen, (void *)hooked_fopen, (void **)&orig_fopen);
        MSHookFunction((void *)opendir, (void *)hooked_opendir, (void **)&orig_opendir);
        MSHookFunction((void *)realpath, (void *)hooked_realpath, (void **)&orig_realpath);
        MSHookFunction((void *)readlink, (void *)hooked_readlink, (void **)&orig_readlink);
        MSHookFunction((void *)fork, (void *)hooked_fork, (void **)&orig_fork);
        MSHookFunction((void *)getenv, (void *)hooked_getenv, (void **)&orig_getenv);
        MSHookFunction((void *)sysctl, (void *)hooked_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)sysctlbyname, (void *)hooked_sysctlbyname, (void **)&orig_sysctlbyname);
        MSHookFunction((void *)statfs, (void *)hooked_statfs, (void **)&orig_statfs);
        MSHookFunction((void *)symlink, (void *)hooked_symlink, (void **)&orig_symlink);
        MSHookFunction((void *)creat, (void *)hooked_creat, (void **)&orig_creat);

        // Dyld hooks
        MSHookFunction((void *)_dyld_image_count, (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count);
        MSHookFunction((void *)_dyld_get_image_name, (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        MSHookFunction((void *)dlopen, (void *)hooked_dlopen, (void **)&orig_dlopen);
        MSHookFunction((void *)dladdr, (void *)hooked_dladdr, (void **)&orig_dladdr);

        // Block app termination
        MSHookFunction((void *)exit, (void *)hooked_exit, (void **)&orig_exit);
        MSHookFunction((void *)_exit, (void *)hooked__exit, (void **)&orig__exit);
        MSHookFunction((void *)abort, (void *)hooked_abort, (void **)&orig_abort);
        MSHookFunction((void *)atexit, (void *)hooked_atexit, (void **)&orig_atexit);

        // ObjC runtime hooks for security SDKs
        hookIOSSecuritySuite();
        hookSecurityGuard();
    }
}
