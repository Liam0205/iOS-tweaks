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
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import "fishhook.h"

// 判定加载镜像名是否为越狱/注入相关（用于隐藏 dylib 列表）
static int is_jb_dylib(const char *name) {
    if (!name) return 0;
    if (strstr(name, "substrate") || strstr(name, "Substrate") ||
        strstr(name, "substitute") || strstr(name, "Substitute") ||
        strstr(name, "frida") || strstr(name, "cycript") ||
        strstr(name, "libhooker") || strstr(name, "MobileSubstrate") ||
        strstr(name, "TweakInject") || strstr(name, "ellekit") || strstr(name, "ElleKit") ||
        strstr(name, "pspawn") || strstr(name, "rocketbootstrap") ||
        strstr(name, "LianJiaBypass") || strstr(name, "lianjiabypass") ||
        strstr(name, "/var/jb/")) {
        return 1;
    }
    return 0;
}

static DIR *(*orig_opendir)(const char *);
static DIR *hooked_opendir(const char *name) {
    if (is_jb_name_c(name)) { lj_log("opendir BLOCK: %s", name); errno = ENOENT; return NULL; }
    return orig_opendir(name);
}

#define LJ_TRACE_ALL_STAT 0   // 诊断：记录所有 /Applications 和可疑系统路径的 stat（噪音大，默认关）

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_name_c(path)) { lj_log("stat BLOCK: %s", path); errno = ENOENT; return -1; }
#if LJ_TRACE_ALL_STAT
    // 打点：应用/系统级敏感路径（越狱检测常查这些），不含 App 自身沙箱高频路径
    if (path && (strstr(path, "/Applications/") || strstr(path, "/usr/") ||
                 strstr(path, "/bin/") || strstr(path, "/etc/") ||
                 strstr(path, "/Library/") || path[0] == '/' ) &&
        !strstr(path, "/Containers/") && !strstr(path, ".app/")) {
        lj_log("stat: %s", path);
    }
#endif
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

// ========== dyld 镜像枚举对抗（作用域限定：只对 JGBSDK 的调用生效）==========
// 全局重排 _dyld_get_image_name 会污染 App/Flutter 自身按索引访问镜像的逻辑（导致冻结）。
// 改为：仅当调用来自 JGBSDK 模块地址范围内时，才隐藏/重排越狱镜像；其余透传。

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);

// 用 dladdr 判断返回地址所属模块是否为需要欺骗的检测框架
// （地址范围法不可靠：_dyld_get_image_header 的 base 与实际执行段地址不一致）
static inline int caller_is_detector(void *ret) {
    Dl_info info;
    if (dladdr(ret, &info) && info.dli_fname) {
        if (strstr(info.dli_fname, "JGBSDK") ||
            strstr(info.dli_fname, "/du.framework/") ||
            strstr(info.dli_fname, "senseid")) {
            return 1;
        }
    }
    return 0;
}

static uint32_t hooked_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    if (!caller_is_detector(__builtin_return_address(0))) return count;
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (name && is_jb_dylib(name)) hidden++;
    }
    return count - hidden;
}

static const char *hooked_dyld_get_image_name(uint32_t idx) {
    if (!caller_is_detector(__builtin_return_address(0))) {
        return orig_dyld_get_image_name(idx);  // App/Flutter：原样，保持索引不污染
    }
    // 检测框架调用：重排跳过越狱镜像
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

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_name_c(path)) { lj_log("dlopen BLOCK: %s", path); return NULL; }
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
        fprintf(f, "[  0.00] [INIT] LianJiaBypass v0.0.8 (scoped dyld dladdr) / LianJia %s ctor started, pid=%d\n",
                appVer ? appVer.UTF8String : "?", getpid());
        fclose(f);
    }
    // C 层文件检测对抗 + dyld 镜像枚举对抗（不含 open/fopen，避开 fishhook 卡死）
    struct rebinding rebs[] = {
        {"opendir",               (void *)hooked_opendir,          (void **)&orig_opendir},
        {"stat",                  (void *)hooked_stat,             (void **)&orig_stat},
        {"lstat",                 (void *)hooked_lstat,            (void **)&orig_lstat},
        {"access",                (void *)hooked_access,           (void **)&orig_access},
        {"_dyld_image_count",     (void *)hooked_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_name",  (void *)hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"dlopen",                (void *)hooked_dlopen,           (void **)&orig_dlopen},
        {"dladdr",                (void *)hooked_dladdr,           (void **)&orig_dladdr},
    };
    int rr = rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
    lj_log("hooks active rr=%d (scoped dyld via dladdr)", rr);
}
