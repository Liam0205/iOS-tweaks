// LianJiaBypass v0.0.2 — A 闭环验证：对抗 DynamicLibraries 目录扫描检测
// 目标 App：链家 com.exmart.HomeLink 9.86.91（Flutter + JGBSDK 检测引擎）
// 第 3 轮静态分析确认：JGBSDK 用 NSFileManager 枚举 .../DynamicLibraries，
// 对文件名匹配 .dylib/.plist 判定越狱注入 —— 直接命中我方 tweak。
// 本轮策略（参考 mybankbypass）：过滤目录枚举结果，隐藏越狱相关项。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>
#import <sys/stat.h>

#define LJ_DEBUG_LOG 1

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

// ========== Logging（写沙箱内 NSTemporaryDirectory）==========

static char g_log_path[512];
static CFAbsoluteTime g_start;

// 用底层 open/write（不经被 hook 的 fopen），避免与 fopen hook 递归
static void lj_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void lj_log(const char *fmt, ...) {
#if LJ_DEBUG_LOG
    static _Thread_local int in_log = 0;
    if (in_log) return;   // 重入保护
    in_log = 1;
    char buf[1024];
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    int n = snprintf(buf, sizeof(buf), "[%6.2f] ", elapsed);
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
    va_end(ap);
    if (n < (int)sizeof(buf) - 1) { buf[n++] = '\n'; }
    int fd = open(g_log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) { write(fd, buf, n); close(fd); }
    in_log = 0;
#endif
}

// ========== 越狱路径/文件判定 ==========

// 明确的越狱特征子串（用于 C 层文件 hook，不含泛化的 .dylib/.plist 以免误伤）
static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "SBSettings", "pspawn", "libsubstitute", "rocketbootstrap",
    "LianJiaBypass", "lianjiabypass", "/var/jb",
    "Sileo.app", "Zebra.app", "Filza.app",
    "/var/lib/apt", "/var/lib/dpkg", "/var/lib/cydia",
    "/bin/bash", "/bin/sh", "/usr/sbin/sshd", "/etc/apt",
    NULL
};

static int is_jb_name_c(const char *name) {
    if (!name) return 0;
    for (int i = 0; jb_substrings[i]; i++) {
        if (strstr(name, jb_substrings[i])) return 1;
    }
    return 0;
}

// 目录枚举结果过滤专用：额外含 .dylib/.plist（仅在 DynamicLibraries 类目录里用）
static int is_jb_dylib_name(const char *name) {
    if (!name) return 0;
    if (is_jb_name_c(name)) return 1;
    if (strstr(name, ".dylib") || strstr(name, ".plist")) return 1;
    return 0;
}

// 仅在被扫描目录路径像 DynamicLibraries 时才按 .dylib/.plist 过滤，
// 避免误伤 App 自身正常的 .plist 读取
static int is_dylib_dir(const char *path) {
    if (!path) return 0;
    return strstr(path, "DynamicLibraries") || strstr(path, "MobileSubstrate")
        || strstr(path, "TweakInject") ? 1 : 0;
}

static _Thread_local int g_reentrant = 0;

// ========== C 层文件检测对抗 + 打点 ==========
// 命中越狱路径：先打日志（定位哪些检测真实触发），再返回“不存在”（对抗）
#import <dirent.h>
#import <fcntl.h>
#import <errno.h>
#import "fishhook.h"

static DIR *(*orig_opendir)(const char *);
static DIR *hooked_opendir(const char *name) {
    if (is_jb_name_c(name)) { lj_log("opendir BLOCK: %s", name); errno = ENOENT; return NULL; }
    return orig_opendir(name);
}

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_name_c(path)) { lj_log("stat BLOCK: %s", path); errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_name_c(path)) { lj_log("lstat BLOCK: %s", path); errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (is_jb_name_c(path)) { lj_log("access BLOCK: %s", path); errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int (*orig_open)(const char *, int, ...);
static int hooked_open(const char *path, int flags, ...) {
    if (is_jb_name_c(path)) { lj_log("open BLOCK: %s", path); errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hooked_fopen(const char *path, const char *mode) {
    if (is_jb_name_c(path)) { lj_log("fopen BLOCK: %s", path); errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

// ========== Hook NSFileManager 目录枚举 ==========

%hook NSFileManager

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (g_reentrant) return %orig;
    g_reentrant = 1;
    NSArray *contents = %orig;
    g_reentrant = 0;
    if (!contents) return contents;

    const char *cpath = path.UTF8String;
    BOOL dylibDir = is_dylib_dir(cpath);
    NSMutableArray *filtered = [NSMutableArray array];
    int removed = 0;
    for (NSString *item in contents) {
        const char *cname = item.UTF8String;
        // DynamicLibraries 类目录：连 .dylib/.plist 一起过滤；其他目录只过滤明确越狱项
        BOOL drop = dylibDir ? is_jb_dylib_name(cname) : is_jb_name_c(cname);
        if (drop) { removed++; continue; }
        [filtered addObject:item];
    }
    if (removed > 0) {
        lj_log("DIR FILTER: %s — removed %d jb items", cpath ? cpath : "?", removed);
    }
    return filtered;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url
    includingPropertiesForKeys:(NSArray *)keys options:(NSUInteger)mask error:(NSError **)error {
    if (g_reentrant) return %orig;
    g_reentrant = 1;
    NSArray<NSURL *> *contents = %orig;
    g_reentrant = 0;
    if (!contents) return contents;

    NSMutableArray *filtered = [NSMutableArray array];
    int removed = 0;
    for (NSURL *u in contents) {
        const char *cpath = u.path.UTF8String;
        if (is_jb_name_c(cpath)) { removed++; continue; }
        [filtered addObject:u];
    }
    if (removed > 0) {
        lj_log("DIR-URL FILTER: removed %d jb items", removed);
    }
    return filtered;
}

%end

// ========== ctor ==========

%ctor {
    g_start = CFAbsoluteTimeGetCurrent();
    NSString *dir = NSTemporaryDirectory();
    snprintf(g_log_path, sizeof(g_log_path), "%s/lianjiabypass.log",
             dir ? dir.UTF8String : "/tmp");
    FILE *f = fopen(g_log_path, "w");
    if (f) {
        NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        fprintf(f, "[  0.00] [INIT] LianJiaBypass v0.0.3 (C-file-hooks) / LianJia %s ctor started, pid=%d\n",
                appVer ? appVer.UTF8String : "?", getpid());
        fclose(f);
    }
    // C 层文件检测对抗 + 打点
    struct rebinding rebs[] = {
        {"opendir", (void *)hooked_opendir, (void **)&orig_opendir},
        {"stat",    (void *)hooked_stat,    (void **)&orig_stat},
        {"lstat",   (void *)hooked_lstat,   (void **)&orig_lstat},
        {"access",  (void *)hooked_access,  (void **)&orig_access},
        {"open",    (void *)hooked_open,    (void **)&orig_open},
        {"fopen",   (void *)hooked_fopen,   (void **)&orig_fopen},
    };
    // 诊断：rebind 前后各写一行（直接 fopen，此刻若 fopen 已 hook 也会走 orig）
    { FILE *ff = fopen(g_log_path, "a"); if (ff) { fprintf(ff, "[dbg] before rebind\n"); fclose(ff); } }
    int rr = rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
    { FILE *ff = fopen(g_log_path, "a"); if (ff) { fprintf(ff, "[dbg] after rebind rr=%d\n", rr); fclose(ff); } }

    lj_log("C-layer file hooks + NSFileManager dir-filter active");
}
