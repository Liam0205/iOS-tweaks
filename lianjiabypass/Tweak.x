// LianJiaBypass — 绕过链家/贝壳系 App 的越狱检测
// 目标 App：链家 com.exmart.HomeLink、贝壳找房 com.lianjia.beike
//   （Flutter + JGBSDK 检测引擎 + a.framework 自研检测库，两 App 共用同一套检测）
//
// 四层对抗（详见 analysis.md 完整分析过程）：
//  1. 文件检测层：hook stat/lstat/access/opendir/dlopen，拦截越狱路径返回 ENOENT。
//  2. dyld 镜像枚举层：hook _dyld_image_count/_dyld_get_image_name，
//     作用域限定（仅对检测框架的调用）重排隐藏越狱镜像 + vis-map 缓存（防 O(n^2) 卡死）。
//  3. 注入检测层：MSHookFunction a.framework 的 _isInjectedWithDynamicLibrary 恒返回 0。
//  4. 自杀退出层：JGBSDK 内联 29 处 `mov w16,#1; svc #0x80`(exit) 绕过 libc，
//     运行时 patch 将这些 svc 就地改为 ret。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <string.h>
#import <sys/stat.h>
#import <dirent.h>
#import <fcntl.h>
#import <errno.h>
#import <dlfcn.h>
#import <pthread.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>
#import <substrate.h>
#import "fishhook.h"

// 调试日志开关：发布版设为 0（关闭日志写入，零开销）
#define LJ_DEBUG_LOG 0

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

// ========== 日志（可选，写沙箱内 NSTemporaryDirectory）==========

static char g_log_path[512];
static CFAbsoluteTime g_start;

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

static _Thread_local int g_reentrant = 0;

// ========== 层 1：C 层文件检测对抗 ==========

static DIR *(*orig_opendir)(const char *);
static DIR *hooked_opendir(const char *name) {
    if (is_jb_name_c(name)) { errno = ENOENT; return NULL; }
    return orig_opendir(name);
}

static int (*orig_stat)(const char *, struct stat *);
static int hooked_stat(const char *path, struct stat *buf) {
    if (is_jb_name_c(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, buf);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hooked_lstat(const char *path, struct stat *buf) {
    if (is_jb_name_c(path)) { errno = ENOENT; return -1; }
    return orig_lstat(path, buf);
}

static int (*orig_access)(const char *, int);
static int hooked_access(const char *path, int mode) {
    if (is_jb_name_c(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static void *(*orig_dlopen)(const char *, int);
static void *hooked_dlopen(const char *path, int mode) {
    if (path && is_jb_name_c(path)) { return NULL; }
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

// ========== 层 3：a.framework 注入检测函数 ==========
// _isInjectedWithDynamicLibrary 在主线程 dispatch 回调里大量 strstr 扫描已加载 dylib，
// 拖死主线程。直接 hook 恒返回“未注入”。（框架内部直接调用，只能用 MSHookFunction）
static int (*orig_isInjected)(void);
static int hooked_isInjected(void) {
    return 0;
}

// ========== 层 2：dyld 镜像枚举对抗（作用域限定，只对检测框架生效）==========
// 全局重排 _dyld_get_image_name 会污染 App/Flutter 自身按索引访问镜像的逻辑（导致冻结），
// 故用 dladdr 判断调用来源：仅当来自检测框架时才隐藏/重排越狱镜像，其余透传。

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);

// 判断返回地址所属模块是否为需要欺骗的检测框架
static inline int caller_is_detector(void *ret) {
    Dl_info info;
    if (dladdr(ret, &info) && info.dli_fname) {
        const char *f = info.dli_fname;
        if (strstr(f, "JGBSDK") || strstr(f, "/du.framework/") ||
            strstr(f, "senseid") || strstr(f, "/a.framework/")) {
            return 1;
        }
    }
    return 0;
}

// 缓存“可见镜像”映射：visibleIdx -> 原始 idx，避免每次调用 O(n×strstr) 重排。
// 检测框架常在紧循环里逐个 get_image_name(idx)，若每次重排则整体 O(n^2)，卡死主线程。
#define LJ_MAX_IMAGES 2048
static uint32_t g_vis_map[LJ_MAX_IMAGES];   // visibleIdx -> real idx
static uint32_t g_vis_count = 0;            // 可见镜像数
static uint32_t g_vis_cached_total = 0;     // 构建缓存时的原始 count（用作失效判断）
static pthread_mutex_t g_vis_lock = PTHREAD_MUTEX_INITIALIZER;

static void rebuild_vis_map_locked(uint32_t total) {
    g_vis_count = 0;
    for (uint32_t i = 0; i < total && g_vis_count < LJ_MAX_IMAGES; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (name && is_jb_dylib(name)) continue;  // 跳过越狱镜像
        g_vis_map[g_vis_count++] = i;
    }
    g_vis_cached_total = total;
}

static void ensure_vis_map(uint32_t total) {
    if (g_vis_cached_total == total && g_vis_count > 0) return;
    pthread_mutex_lock(&g_vis_lock);
    if (g_vis_cached_total != total || g_vis_count == 0) {
        rebuild_vis_map_locked(total);
    }
    pthread_mutex_unlock(&g_vis_lock);
}

static uint32_t hooked_dyld_image_count(void) {
    uint32_t count = orig_dyld_image_count();
    if (!caller_is_detector(__builtin_return_address(0))) return count;
    ensure_vis_map(count);
    return g_vis_count;
}

static const char *hooked_dyld_get_image_name(uint32_t idx) {
    if (!caller_is_detector(__builtin_return_address(0))) {
        return orig_dyld_get_image_name(idx);  // App/Flutter：O(1) 透传
    }
    uint32_t count = orig_dyld_image_count();
    ensure_vis_map(count);
    if (idx < g_vis_count) return orig_dyld_get_image_name(g_vis_map[idx]);
    return orig_dyld_get_image_name(0);
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
    for (NSString *item in contents) {
        const char *cname = item.UTF8String;
        // DynamicLibraries 类目录：连 .dylib/.plist 一起过滤；其他目录只过滤明确越狱项
        BOOL drop = dylibDir ? is_jb_dylib_name(cname) : is_jb_name_c(cname);
        if (drop) continue;
        [filtered addObject:item];
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
    for (NSURL *u in contents) {
        const char *cpath = u.path.UTF8String;
        if (is_jb_name_c(cpath)) continue;
        [filtered addObject:u];
    }
    return filtered;
}

%end

// ========== 层 4：运行时 patch JGBSDK 内联的直接 exit syscall ==========
// JGBSDK 散布 29 处 `mov w16,#1; svc #0x80`（exit(1)），绕过 libc（fishhook/信号均无效）。
// 扫描 JGBSDK __text，将 exit 序列的 `svc #0x80` 就地改为 `ret`，使检测失败分支返回而非自杀。
// 指令编码（小端）：mov w16,#1 = 0x52800030；svc #0x80 = 0xd4001001；ret = 0xd65f03c0
static int patch_jgb_exit_syscalls(void) {
    uint32_t n = _dyld_image_count();
    const struct mach_header_64 *mh = NULL;
    intptr_t slide = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "JGBSDK")) {
            mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!mh) { lj_log("patch: JGBSDK not found"); return -1; }

    // 遍历 load commands 找 __TEXT,__text 范围
    uintptr_t text_start = 0, text_size = 0;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            if (strcmp(sc->segname, "__TEXT") == 0) {
                const struct section_64 *sect = (const struct section_64 *)(sc + 1);
                for (uint32_t s = 0; s < sc->nsects; s++) {
                    if (strcmp(sect[s].sectname, "__text") == 0) {
                        text_start = sect[s].addr + slide;
                        text_size = sect[s].size;
                    }
                }
            }
        }
        p += lc->cmdsize;
    }
    if (!text_start) { lj_log("patch: __text not found"); return -2; }

    uint32_t *code = (uint32_t *)text_start;
    uint32_t count = (uint32_t)(text_size / 4);
    int patched = 0, failed = 0;
    for (uint32_t i = 1; i < count; i++) {
        if (code[i] == 0xd4001001 /* svc #0x80 */ &&
            code[i - 1] == 0x52800030 /* mov w16,#1 (exit) */) {
            // arm64 iOS 强制 W^X：改 RW → 写 → 恢复 RX → 刷 icache
            void *pg = (void *)((uintptr_t)&code[i] & ~0x3fffUL);
            size_t plen = 0x4000;
            kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)pg, plen,
                                          FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kr != KERN_SUCCESS) {
                kr = vm_protect(mach_task_self(), (vm_address_t)pg, plen, FALSE,
                                VM_PROT_READ | VM_PROT_WRITE);
            }
            if (kr != KERN_SUCCESS) { failed++; continue; }
            code[i] = 0xd65f03c0;  // ret
            vm_protect(mach_task_self(), (vm_address_t)pg, plen, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
            sys_icache_invalidate(&code[i], 4);
            patched++;
        }
    }
    lj_log("patch: neutralized %d JGBSDK exit syscalls (failed=%d)", patched, failed);
    return patched;
}

// ========== ctor ==========

%ctor {
    g_start = CFAbsoluteTimeGetCurrent();
#if LJ_DEBUG_LOG
    NSString *dir = NSTemporaryDirectory();
    snprintf(g_log_path, sizeof(g_log_path), "%s/lianjiabypass.log",
             dir ? dir.UTF8String : "/tmp");
    NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    lj_log("[INIT] LianJiaBypass / App %s pid=%d",
           appVer ? appVer.UTF8String : "?", getpid());
#endif

    // 层 1 + 层 2：fishhook 文件检测 + dyld 镜像枚举
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
    rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));

    // 层 3：MSHookFunction a.framework 的 _isInjectedWithDynamicLibrary
    void *sym = dlsym(RTLD_DEFAULT, "isInjectedWithDynamicLibrary");
    if (!sym) sym = dlsym(RTLD_DEFAULT, "_isInjectedWithDynamicLibrary");
    if (sym) {
        MSHookFunction(sym, (void *)hooked_isInjected, (void **)&orig_isInjected);
    }

    // 层 4：中和 JGBSDK 内联 exit syscall
    patch_jgb_exit_syscalls();
}
