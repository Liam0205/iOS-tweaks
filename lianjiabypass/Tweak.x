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

static void lj_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void lj_log(const char *fmt, ...) {
#if LJ_DEBUG_LOG
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

// ========== 越狱路径/文件判定 ==========

static const char *jb_substrings[] = {
    "substrate", "Substrate", "cydia", "Cydia",
    "frida", "jailbreak", "cycript", "MobileSubstrate",
    "TweakInject", "ellekit", "libhooker", "substitute",
    "SBSettings", "pspawn", "libsubstitute", "rocketbootstrap",
    "LianJiaBypass", "lianjiabypass",
    ".dylib", ".plist",  // DynamicLibraries 目录里所有 tweak 产物
    NULL
};

static int is_jb_name_c(const char *name) {
    if (!name) return 0;
    for (int i = 0; jb_substrings[i]; i++) {
        if (strstr(name, jb_substrings[i])) return 1;
    }
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

// ========== 底层目录枚举打点（observe-only，定位检测到底走哪条路）==========
#import <dirent.h>
#import "fishhook.h"

static DIR *(*orig_opendir)(const char *);
static DIR *hooked_opendir(const char *name) {
    if (name && (strstr(name, "DynamicLibraries") || strstr(name, "MobileSubstrate")
                 || strstr(name, "Library") || strstr(name, "/var/jb"))) {
        lj_log("opendir: %s", name);
    }
    return orig_opendir(name);
}

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (path && (strstr(path, "DynamicLibraries") || strstr(path, "substrate")
                 || strstr(path, "cydia") || strstr(path, "Cydia")
                 || strstr(path, "/var/jb"))) {
        lj_log("stat: %s", path);
    }
    return orig_stat(path, buf);
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
        // 在 DynamicLibraries 类目录里，按越狱子串 + .dylib/.plist 过滤；
        // 其他目录只按明确越狱子串过滤（不动普通 .plist）
        BOOL drop = is_jb_name_c(cname);
        if (!dylibDir) {
            // 非 tweak 目录：不因 .dylib/.plist 后缀丢弃普通文件
            if (drop && (strstr(cname, ".dylib") || strstr(cname, ".plist"))
                && !strstr(cname, "substrate") && !strstr(cname, "Substrate")
                && !strstr(cname, "LianJiaBypass") && !strstr(cname, "ellekit")) {
                drop = NO;
            }
        }
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
        fprintf(f, "[  0.00] [INIT] LianJiaBypass v0.0.2 (dir-filter) / LianJia %s ctor started, pid=%d\n",
                appVer ? appVer.UTF8String : "?", getpid());
        fclose(f);
    }
    // 底层 opendir/stat 打点，定位检测扫描路径
    struct rebinding rebs[] = {
        {"opendir", (void *)hooked_opendir, (void **)&orig_opendir},
        {"stat",    (void *)hooked_stat,    (void **)&orig_stat},
    };
    rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));

    lj_log("NSFileManager dir-filter + opendir/stat probe hooks active");
}
