// CCTVBypass — 绕过央视频（com.cctv.yangshipin.app.iphone / CCTVVideo）的越狱检测秒退
//
// 检测面（见 llmdoc/reference/cctvbypass-detection-vectors.md）：
// - 路径型文件检测：/Applications/Cydia.app、/Library/MobileSubstrate、/usr/sbin/frida-server、
//   /var/checkra1n.dmg、/bin/bash 等；友盟 UMeng 另查 /private/umTest_Jailbreak.txt。
// - ObjC selector `isJailbreak` 等布尔判定；cydia:// 等 URL scheme 探测。
// - 未发现商业 RASP，未发现二进制完整性自检 / 内联 svc（integrity/checksum 字符串来自
//   Bugly/QAPM 崩溃上报的 SQLite integrity_check 与 HMAC，非 text 段自检），故 inline-hook 安全。
//
// 方案：沿用 mybankbypass 验证过的做法 —— 纯 C 路径检查 + C 函数 inline-hook（stat 族/open/
// dlopen/dyld 镜像枚举）遮蔽越狱痕迹；ObjC 层中和 isJailbreak 类判定与 NSFileManager/
// canOpenURL；exit/abort/kill/raise 兜底拦截，防止早期检测直接终止进程。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <signal.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <string.h>
#import <pthread.h>
#import <execinfo.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <libkern/OSCacheControl.h>

// 诊断日志开关：发布版关闭。日志写 App 数据容器（沙箱内可写），不写 /tmp 或 /var/jb/tmp。
#ifndef CCTV_DEBUG_LOG
#define CCTV_DEBUG_LOG 0
#endif

#if CCTV_DEBUG_LOG
#import <stdio.h>
static void cctvlog(const char *fmt, ...) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"cctvbypass.log"];
    });
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}
#else
#define cctvlog(...) do {} while (0)
#endif

// ============================================================
// MARK: 纯 C 路径检查（不含 ObjC，供低层 C 函数 hook 使用）
// ============================================================

static const char *jb_paths[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Library/MobileSubstrate",
    "/Library/PreferenceBundles",
    "/Library/PreferenceLoader",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/lib/substrate",
    "/usr/lib/substitute",
    "/usr/lib/TweakInject",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/libexec/sftp-server",
    "/usr/libexec/cydia",
    "/usr/sbin/frida-server",
    "/usr/local/bin/cycript",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/jailbreak.txt",
    "/private/umTest_Jailbreak.txt",
    "/var/jb",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/var/lib/dpkg/info/mobilesubstrate.md5sums",
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/.installed_unc0ver",
    "/.bootstrapped_electra",
    "/jb/jailbreakd.plist",
    NULL
};

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "Jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "checkra1n", "unc0ver", "Dopamine", "roothide",
    NULL
};

static int is_jb_path_c(const char *path) {
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
    if (!name) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "substitute") || strstr(name, "Substitute") ||
        strstr(name, "frida") || strstr(name, "cycript") ||
        strstr(name, "libhooker") || strstr(name, "MobileSubstrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") ||
        strstr(name, "pspawn") || strstr(name, "rocketbootstrap") ||
        strstr(name, "CCTVBypass") || strstr(name, "/var/jb/")) {
        return 1;
    }
    return 0;
}

static _Thread_local int g_reentrant = 0;

// ============================================================
// MARK: ObjC 层路径 / URL 判定（仅供 ObjC hook 使用）
// ============================================================

static BOOL isJailbreakPath(NSString *path) {
    if (!path || path.length == 0) return NO;
    return is_jb_path_c(path.UTF8String) ? YES : NO;
}

static BOOL isJailbreakURL(NSURL *url) {
    if (!url) return NO;
    NSString *scheme = url.scheme.lowercaseString;
    NSArray *schemes = @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator", @"apt-repo"];
    return [schemes containsObject:scheme];
}

// ============================================================
// MARK: C 函数 hook（只用纯 C 检查！）
// ============================================================

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
#if CCTV_DEBUG_LOG
    static int once = 0; if (!once) { once = 1; cctvlog("[CCTVBypass] hooked_stat LIVE first=%s", path ? path : "(null)"); }
#endif
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int (*orig_open)(const char *, int, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (is_jb_path_c(path)) { errno = ENOENT; return -1; }
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode_t mode = va_arg(args, int); va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static char *(*orig_realpath)(const char *, char *);
static char *hooked_realpath(const char *path, char *resolved) {
    if (is_jb_path_c(path)) { errno = ENOENT; return NULL; }
    char *result = orig_realpath(path, resolved);
    if (result && is_jb_path_c(result)) { errno = ENOENT; return NULL; }
    return result;
}

static ssize_t (*orig_readlink)(const char *, char *, size_t);
static ssize_t hooked_readlink(const char *path, char *buf, size_t bufsize) {
    if (is_jb_path_c(path)) { errno = EINVAL; return -1; }
    ssize_t ret = orig_readlink(path, buf, bufsize);
    if (ret > 0 && buf) {
        char tmp[PATH_MAX];
        size_t len = (size_t)ret < PATH_MAX - 1 ? (size_t)ret : PATH_MAX - 1;
        memcpy(tmp, buf, len); tmp[len] = '\0';
        if (is_jb_path_c(tmp)) { errno = EINVAL; return -1; }
    }
    return ret;
}

// 注意：不 hook statfs / statvfs。强行给 "/" 及 /var、/private 前缀返回 MNT_RDONLY
// 会把 App 自己的数据容器（/var/mobile/Containers…）也标成只读，可能影响视频缓存与下载；
// 且 rootfs 可写检测只是遥测向量、非闪退门禁，得不偿失，故不做。

// ============================================================
// MARK: 进程 / 环境 / dyld hook
// ============================================================

static pid_t (*orig_fork)(void);
static pid_t hooked_fork(void) { errno = ENOSYS; return -1; }

static pid_t (*orig_getppid)(void);
static pid_t hooked_getppid(void) { return 1; }

static char *(*orig_getenv)(const char *);
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

// sysctl：清除 P_TRACED（反调试）标志
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && oldp && namelen == 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *proc = (struct kinfo_proc *)oldp;
        proc->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

// 注意：不 hook _dyld_image_count / _dyld_get_image_name。
// 逐调用重算可见镜像列表是 O(N²) 且每镜像多次 strstr，App 按索引遍历镜像时会把
// 主线程拖到近乎冻结（见 lianjiabypass 反思的同类教训）。而央视频的越狱判定是遥测、
// 无枚举镜像触发的杀进程门禁，隐藏注入库并非必需，故不做镜像枚举对抗。

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_path_c(path)) return NULL;
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

// ============================================================
// MARK: 终止拦截（兜底，防早期检测直接杀进程）
// ============================================================

static void spin_main_or_park(void) {
    if ([NSThread isMainThread]) {
        while (1) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]];
        }
    }
    pthread_exit(NULL);
    __builtin_unreachable();
}

static void (*orig_exit)(int);
static void hooked_exit(int status) { cctvlog("[CCTVBypass] exit(%d) blocked", status); spin_main_or_park(); }
static void (*orig__exit)(int);
static void hooked__exit(int status) { cctvlog("[CCTVBypass] _exit(%d) blocked", status); spin_main_or_park(); }
static void (*orig_abort)(void);
static void hooked_abort(void) { cctvlog("[CCTVBypass] abort() blocked"); spin_main_or_park(); }

static int (*orig_kill)(pid_t, int);
static int hooked_kill(pid_t pid, int sig) {
    if (pid == getpid() || pid == 0) return 0;
    return orig_kill(pid, sig);
}

static int (*orig_raise)(int);
static int hooked_raise(int sig) {
    if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGTRAP) return 0;
    return orig_raise(sig);
}

// ============================================================
// MARK: 诊断——定位终止路径（仅 CCTV_DEBUG_LOG 生效）
// ============================================================
#if CCTV_DEBUG_LOG
static void cctv_log_backtrace(const char *tag) {
    void *cb[64];
    int n = backtrace(cb, 64);
    char **syms = backtrace_symbols(cb, n);
    cctvlog("[CCTVBypass] BT(%s) frames=%d", tag, n);
    if (syms) {
        for (int i = 0; i < n; i++) cctvlog("  %s", syms[i]);
        free(syms);
    }
}

static void cctv_fatal_signal(int sig) {
    cctvlog("[CCTVBypass] !!! fatal signal %d main=%d", sig, (int)[NSThread isMainThread]);
    cctv_log_backtrace("signal");
    signal(sig, SIG_DFL);
    raise(sig);
}

// exit_group 直接系统调用（绕开 libc exit 符号的路径）
static void (*orig_exit_group)(int);
static void hooked_exit_group(int status) {
    cctvlog("[CCTVBypass] exit_group(%d)", status);
    cctv_log_backtrace("exit_group");
    spin_main_or_park();
}

static void (*orig_pthread_exit)(void *);
static void hooked_pthread_exit(void *v) {
    cctvlog("[CCTVBypass] pthread_exit main=%d", (int)[NSThread isMainThread]);
    cctv_log_backtrace("pthread_exit");
    if ([NSThread isMainThread]) spin_main_or_park();
    orig_pthread_exit(v);
    __builtin_unreachable();
}

static void (*orig_abort_with_payload)(uint32_t, uint64_t, void *, uint32_t, const char *, uint64_t);
static void hooked_abort_with_payload(uint32_t reason_namespace, uint64_t reason_code, void *payload,
                                      uint32_t payload_size, const char *reason_string, uint64_t reason_flags) {
    cctvlog("[CCTVBypass] abort_with_payload ns=%u code=%llu reason=%s", reason_namespace, reason_code,
            reason_string ? reason_string : "(null)");
    cctv_log_backtrace("abort_with_payload");
    spin_main_or_park();
}

// mach task_terminate(mach_task_self()) —— 无痕自杀路径
static int (*orig_task_terminate)(unsigned int);
static int hooked_task_terminate(unsigned int target) {
    cctvlog("[CCTVBypass] task_terminate(%u) blocked", target);
    cctv_log_backtrace("task_terminate");
    spin_main_or_park();
    return 0;
}

// __pthread_kill(mach_thread, sig) —— abort/raise 的底层，也可被直接调用
static int (*orig___pthread_kill)(unsigned long, int);
static int hooked___pthread_kill(unsigned long thread, int sig) {
    if (sig == SIGKILL || sig == SIGABRT || sig == SIGTERM || sig == SIGTRAP || sig == SIGSEGV) {
        cctvlog("[CCTVBypass] __pthread_kill(sig=%d) swallowed", sig);
        cctv_log_backtrace("__pthread_kill");
        return 0;
    }
    return orig___pthread_kill(thread, sig);
}

// raw syscall(SYS_exit=1 / SYS_exit_group) —— 绕开具名 exit 符号
static long (*orig_syscall)(long, ...);
static long hooked_syscall(long num, ...) {
    if (num == 1 /*SYS_exit*/) {
        cctvlog("[CCTVBypass] syscall(SYS_exit) blocked");
        cctv_log_backtrace("syscall_exit");
        spin_main_or_park();
        return 0;
    }
    va_list ap; va_start(ap, num);
    long a0 = va_arg(ap, long), a1 = va_arg(ap, long), a2 = va_arg(ap, long),
         a3 = va_arg(ap, long), a4 = va_arg(ap, long), a5 = va_arg(ap, long);
    va_end(ap);
    return orig_syscall(num, a0, a1, a2, a3, a4, a5);
}

static void cctv_install_diagnostics(void) {
    int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGTRAP, SIGSYS, SIGFPE };
    for (unsigned i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) signal(sigs[i], cctv_fatal_signal);

    void *eg = dlsym(RTLD_DEFAULT, "exit_group");
    if (eg) MSHookFunction(eg, (void *)hooked_exit_group, (void **)&orig_exit_group);
    MSHookFunction((void *)pthread_exit, (void *)hooked_pthread_exit, (void **)&orig_pthread_exit);
    void *awp = dlsym(RTLD_DEFAULT, "abort_with_payload");
    if (awp) MSHookFunction(awp, (void *)hooked_abort_with_payload, (void **)&orig_abort_with_payload);
    void *tt = dlsym(RTLD_DEFAULT, "task_terminate");
    if (tt) MSHookFunction(tt, (void *)hooked_task_terminate, (void **)&orig_task_terminate);
    void *pk = dlsym(RTLD_DEFAULT, "__pthread_kill");
    if (pk) MSHookFunction(pk, (void *)hooked___pthread_kill, (void **)&orig___pthread_kill);
    void *sc = dlsym(RTLD_DEFAULT, "syscall");
    if (sc) MSHookFunction(sc, (void *)hooked_syscall, (void **)&orig_syscall);

    // 心跳：确认 App 是否进入 applicationDidFinishLaunching 之后
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ cctvlog("[CCTVBypass] heartbeat +1s alive"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ cctvlog("[CCTVBypass] heartbeat +3s alive"); });
}
#endif

// ============================================================
// MARK: ObjC — NSFileManager / canOpenURL / NSProcessInfo
// ============================================================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (isJailbreakPath(path)) { if (isDir) *isDir = NO; return NO; }
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
        NSString *full = [path stringByAppendingPathComponent:item];
        if (!isJailbreakPath(full)) [filtered addObject:item];
    }
    return filtered;
}

%end

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (isJailbreakURL(url)) return NO;
    return %orig;
}

%end

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSDictionary *orig = %orig;
    if (![orig objectForKey:@"DYLD_INSERT_LIBRARIES"] &&
        ![orig objectForKey:@"_MSSafeMode"]) return orig;
    NSMutableDictionary *env = [orig mutableCopy];
    [env removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    [env removeObjectForKey:@"DYLD_LIBRARY_PATH"];
    [env removeObjectForKey:@"DYLD_FRAMEWORK_PATH"];
    [env removeObjectForKey:@"_MSSafeMode"];
    [env removeObjectForKey:@"_SafeMode"];
    return env;
}

%end

// ============================================================
// MARK: ObjC — 中和越狱判定 selector（isJailbreak 等）
// ============================================================

// 保守匹配：仅命中明确的越狱判定 selector，避免误伤无关方法。
static BOOL isJailbreakSelectorName(NSString *sel) {
    NSString *s = sel.lowercaseString;
    return [s isEqualToString:@"isjailbreak"] ||
           [s isEqualToString:@"isjailbroken"] ||
           [s isEqualToString:@"is_jailbreak"] ||
           [s isEqualToString:@"is_jailbroken"] ||
           [s isEqualToString:@"isjailbroke"] ||
           [s isEqualToString:@"isdevicejailbreak"] ||
           [s isEqualToString:@"isdevicejailbroken"] ||
           [s isEqualToString:@"jailbroken"] ||
           [s isEqualToString:@"checkjailbreak"] ||
           [s isEqualToString:@"checkjailbroken"] ||
           [s isEqualToString:@"deviceisjailbreak"];
}

static void neutralizeMethod(Method m) {
    char retType[8] = {0};
    method_getReturnType(m, retType, sizeof(retType));
    if (retType[0] == 'B' || retType[0] == 'c' || retType[0] == 'i' ||
        retType[0] == 's' || retType[0] == 'l' || retType[0] == 'q' ||
        retType[0] == 'C' || retType[0] == 'I' || retType[0] == 'Q') {
        method_setImplementation(m, imp_implementationWithBlock(^long(id s, ...) { return 0; }));
    }
}

static void sweepJailbreakSelectors(void) {
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    if (!classes) return;
    for (unsigned int c = 0; c < classCount; c++) {
        Class cls = classes[c];
        // 实例方法
        unsigned int n = 0;
        Method *ms = class_copyMethodList(cls, &n);
        for (unsigned int i = 0; i < n; i++) {
            NSString *sn = NSStringFromSelector(method_getName(ms[i]));
            if (isJailbreakSelectorName(sn)) {
                cctvlog("[CCTVBypass] neutralize -[%s %s]", class_getName(cls), sn.UTF8String);
                neutralizeMethod(ms[i]);
            }
        }
        if (ms) free(ms);
        // 类方法
        Class meta = object_getClass(cls);
        n = 0;
        ms = class_copyMethodList(meta, &n);
        for (unsigned int i = 0; i < n; i++) {
            NSString *sn = NSStringFromSelector(method_getName(ms[i]));
            if (isJailbreakSelectorName(sn)) {
                cctvlog("[CCTVBypass] neutralize +[%s %s]", class_getName(cls), sn.UTF8String);
                neutralizeMethod(ms[i]);
            }
        }
        if (ms) free(ms);
    }
    free(classes);
}

// ============================================================
// MARK: 核心——运行时中和内联 svc 退出桩
// ============================================================
//
// 央视频在启动早期检测到注入/调试后，跳到主二进制内的内联 exit 桩：
//     movz w0,#0 ; movz w16,#1 ; svc #0x80   → exit(0)
// 该路径绕开全部 libSystem 具名符号（stat/exit/abort 等），也不产生崩溃报告，
// 因此 ObjC swizzle 与 C 函数 hook 都拦不住。唯一办法是运行时把 svc 指令改成 nop：
// 干净路径本就通过 tbnz 跳到 svc 之后（0x51b8 / 0x522c），命中路径 nop 掉 svc 后
// 自然并入正常流程，不会破坏控制流（第二处 svc 后紧跟 `b +8` 更印证这一合并设计）。
//
// 手法沿用 lianjiabypass 的运行时 __text patch：vm_protect 开可写 → 改指令 →
// 恢复 R+X → sys_icache_invalidate 刷指令缓存（缺一步会 KERN_PROTECTION_FAILURE）。

#define AARCH64_NOP        0xd503201fu
#define AARCH64_SVC_0x80   0xd4001001u
#define AARCH64_MOVZ_W16_1 0x52800030u   // movz w16, #1
#define AARCH64_MOVZ_X16_1 0xd2800030u   // movz x16, #1

// 返回主可执行镜像的索引（filetype == MH_EXECUTE），找不到则返回 0。
static uint32_t cctv_main_image_index(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) return i;
    }
    return 0;
}

static bool cctv_patch_word(uint32_t *addr, uint32_t val) {
    vm_address_t page = (vm_address_t)addr & ~((vm_address_t)vm_page_size - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, vm_page_size, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        cctvlog("[CCTVBypass] vm_protect(RW) failed kr=%d @%p", kr, addr);
        return false;
    }
    *addr = val;
    vm_protect(mach_task_self(), page, vm_page_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(addr, sizeof(uint32_t));
    return true;
}

// 扫描主镜像可执行段，把 `movz w16/x16,#1 ; svc #0x80` 的 svc 改成 nop。
static int cctv_neutralize_inline_exits(void) {
    uint32_t idx = cctv_main_image_index();
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(idx);
    if (!mh) return 0;
    intptr_t slide = _dyld_get_image_vmaddr_slide(idx);
    int patched = 0;

    const struct load_command *lc = (const struct load_command *)((const uint8_t *)mh + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            // 只扫可执行段（__TEXT 等）
            if (seg->initprot & VM_PROT_EXECUTE) {
                uint32_t *p   = (uint32_t *)(seg->vmaddr + slide);
                uint32_t *end = (uint32_t *)(seg->vmaddr + slide + seg->vmsize) - 1;
                for (; p < end; p++) {
                    if (p[1] == AARCH64_SVC_0x80 &&
                        (p[0] == AARCH64_MOVZ_W16_1 || p[0] == AARCH64_MOVZ_X16_1)) {
                        if (cctv_patch_word(&p[1], AARCH64_NOP)) {
                            patched++;
                            cctvlog("[CCTVBypass] neutralized inline exit @ %p (img+0x%lx)",
                                    &p[1], (unsigned long)((uintptr_t)&p[1] - (uintptr_t)mh));
                        }
                    }
                }
            }
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    cctvlog("[CCTVBypass] inline-exit neutralize done, patched=%d", patched);
    return patched;
}

// ============================================================
// MARK: Constructor
// ============================================================

%ctor {
    @autoreleasepool {
        cctvlog("[CCTVBypass] ==== ctor ====");

        // 最优先：中和内联 svc 退出桩（真正的闪退根因）
        cctv_neutralize_inline_exits();

        // 兜底：终止拦截，防止后续版本可能新增的、走具名符号的检测退出
        MSHookFunction((void *)exit,  (void *)hooked_exit,  (void **)&orig_exit);
        MSHookFunction((void *)_exit, (void *)hooked__exit, (void **)&orig__exit);
        MSHookFunction((void *)abort, (void *)hooked_abort, (void **)&orig_abort);
        MSHookFunction((void *)kill,  (void *)hooked_kill,  (void **)&orig_kill);
        MSHookFunction((void *)raise, (void *)hooked_raise, (void **)&orig_raise);

        // 文件系统 hook（纯 C 检查）
        MSHookFunction((void *)stat,     (void *)hooked_stat,     (void **)&orig_stat);
#if CCTV_DEBUG_LOG
        cctvlog("[CCTVBypass] hook-install check: orig_exit=%p orig_stat=%p (non-NULL => MSHookFunction works)",
                (void*)orig_exit, (void*)orig_stat);
#endif
        MSHookFunction((void *)lstat,    (void *)hooked_lstat,    (void **)&orig_lstat);
        MSHookFunction((void *)access,   (void *)hooked_access,   (void **)&orig_access);
        MSHookFunction((void *)open,     (void *)hooked_open,     (void **)&orig_open);
        MSHookFunction((void *)fopen,    (void *)hooked_fopen,    (void **)&orig_fopen);
        MSHookFunction((void *)realpath, (void *)hooked_realpath, (void **)&orig_realpath);
        MSHookFunction((void *)readlink, (void *)hooked_readlink, (void **)&orig_readlink);

        // 进程 / 环境 hook
        MSHookFunction((void *)fork,     (void *)hooked_fork,     (void **)&orig_fork);
        MSHookFunction((void *)getppid,  (void *)hooked_getppid,  (void **)&orig_getppid);
        MSHookFunction((void *)getenv,   (void *)hooked_getenv,   (void **)&orig_getenv);
        MSHookFunction((void *)sysctl,   (void *)hooked_sysctl,   (void **)&orig_sysctl);

        // dyld hook（不含镜像枚举，避免 O(N²) 冻结）
        MSHookFunction((void *)dlopen, (void *)hooked_dlopen, (void **)&orig_dlopen);
        MSHookFunction((void *)dladdr, (void *)hooked_dladdr, (void **)&orig_dladdr);

        // 安装 Logos ObjC hook
        %init;

#if CCTV_DEBUG_LOG
        cctv_install_diagnostics();
#endif

        // 中和越狱判定 selector（可能在启动后才注册的类，延迟重扫一次）
        sweepJailbreakSelectors();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ sweepJailbreakSelectors(); });
    }
}

