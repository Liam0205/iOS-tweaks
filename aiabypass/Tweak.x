// AIABypass —— 友邦友享（com.aia.china.YoubangHealthRelease）越狱检测绕过
//
// 目标 App 6.9.33 内置 JMCodeProtectKit.framework（com.IPACodeProtectTwoSDk，v3.0.0.
// 20260903.1），这是一个带 RASP 的代码保护 SDK：
//   - 自带越狱 / hook / 调试 / 重签 / 完整性 / 代理 / VPN / 虚拟定位检测；
//   - 命中后不开弹窗，直接把线程 PC 置为非法地址，进程以 SIGSEGV 退出；
//   - 检测面来自其导入符号：dyld 镜像枚举、ObjC 方法表比对、stat/open/fopen 文件检查、
//     sysctl、dladdr/dlsym、SecTrust 证书链。
//
// 本文件当前是第一阶段实验版本：观测 + 隐藏注入库。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld_images.h>
#import <libkern/OSCacheControl.h>
extern int proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize);
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>
#import <execinfo.h>
#import <stdlib.h>
#import <signal.h>
#import <pthread.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <mach/exception_types.h>
#import <mach/thread_act.h>
#import <mach/ndr.h>

#ifndef AIA_DEBUG_LOG
#define AIA_DEBUG_LOG 1
#endif

// 实验开关：1 = 从 dyld 枚举里隐藏注入库；0 = 只观测不隐藏
#ifndef AIA_HIDE_IMAGES
#define AIA_HIDE_IMAGES 0
#endif

// 最小实验模式：只处理 _dyld_register_func_for_add_image，其余 hook 全部不装
#ifndef AIA_MINIMAL
#define AIA_MINIMAL 0
#endif

// ijm 混淆器的 VM 导入解析器在 0x7c5590 检查 x15；实验表明崩溃时 x15 被 VM 清 0，
// 但 x14 已经是有效的解析结果。打开这个开关把该检查改成 nop，让流程继续走 x14。
#ifndef AIA_PATCH_BINDER
#define AIA_PATCH_BINDER 0
#endif

// 把 dyld 镜像表里本 dylib 的 imageFilePath 指向一个无害路径，
// 用来验证 RASP 是否靠镜像路径判断注入。
#ifndef AIA_FAKE_PATH
#define AIA_FAKE_PATH 0
#endif

// 只装 dyld 枚举相关的 hook（含 dladdr），其余全不装，用来判断 RASP 是否走这些 API。
#ifndef AIA_DYLD_ONLY
#define AIA_DYLD_ONLY 0
#endif

// 隐身组合：dyld 枚举过滤 + dladdr 伪装，两者保持一致的镜像视图。
// 需要同时用 AIA_HIDE_IMAGES=1 编译。
#ifndef AIA_STEALTH
#define AIA_STEALTH 0
#endif

// 实验：只 hook dladdr，把落在越狱镜像里的地址伪装成系统库。
#ifndef AIA_DLADDR_MASK
#define AIA_DLADDR_MASK 0
#endif

// 实验：定期采样所有线程的 PC，用来定位空转位置。
#ifndef AIA_SAMPLE_THREADS
#define AIA_SAMPLE_THREADS 0
#endif

// 实验：安装自己的 Mach 异常处理器，抢在 ellekit 之前拿到故障线程的现场，
// 这样能看到"谁跳到了非法地址"。AIA_KILL_THREAD=1 时只终止故障线程，不杀整个进程。
#ifndef AIA_EXC_HANDLER
#define AIA_EXC_HANDLER 1
#endif
#ifndef AIA_KILL_THREAD
#define AIA_KILL_THREAD 0
#endif
// 1 = 收到 SIGUSR1 时把所有线程的 PC/LR 和主线程栈打到日志里，用来诊断卡死。
#ifndef AIA_DUMP_ON_SIGNAL
#define AIA_DUMP_ON_SIGNAL 0
#endif
// 1 = 后台线程每 50ms 重新设置一次异常端口，抢在 ellekit / Dynatrace KSCrash 之后。
#ifndef AIA_EXC_WATCHDOG
#define AIA_EXC_WATCHDOG 1
#endif
// 1 = 启动接收线程。0 = 只接管异常端口、不接收，让异常消息永久排队，
// 触发异常的线程会一直等在异常状态，JM 的处决线程随之阻塞。
#ifndef AIA_EXC_SERVER
#define AIA_EXC_SERVER 1
#endif
// 1 = 收到异常后不回复，让故障线程永久挂起（不交给 ellekit，也就不会有 exit(1)）
#ifndef AIA_EXC_NO_REPLY
#define AIA_EXC_NO_REPLY 1
#endif

// 实验：拦下 exit(1)/_exit(1)，验证是 JM 自己退出还是 ellekit 异常处理器退出。
#ifndef AIA_BLOCK_EXIT
#define AIA_BLOCK_EXIT 0
#endif

// 打印所有非系统镜像的路径，确认注入链路把哪些镜像带进了进程。
#ifndef AIA_LOG_IMAGES
#define AIA_LOG_IMAGES 0
#endif

// 真正什么都不做：不装信号处理器、不枚举模块，只写一行日志。
#ifndef AIA_TRULY_EMPTY
#define AIA_TRULY_EMPTY 0
#endif

// 空 tweak：只记录构造，不安装任何 hook，用来判断 RASP 是否只检测镜像存在。
#ifndef AIA_EMPTY
#define AIA_EMPTY 1
#endif

// 运行时把 0x7c54b0..0x7c5620 的字节和映射来源打出来，用来对比文件里的原始机器码。
#ifndef AIA_DUMP_CODE
#define AIA_DUMP_CODE 0
#endif

// 定时采样 0x7c5000 页的改动，判断这块代码是文件映射还是运行时生成。
#ifndef AIA_SAMPLE_CODE
#define AIA_SAMPLE_CODE 0
#endif

// 1 = 直接把 RASP 的 add_image 注册吞掉，不再转发给 dyld
#ifndef AIA_BLOCK_ADD_IMAGE
#define AIA_BLOCK_ADD_IMAGE 0
#endif

// 日志写 App 数据容器，不写 /tmp 或 /var/jb/tmp。
static void log_backtrace(const char *tag);
static const char *caller_desc(void *ra);
static __thread bool t_in_safe_read;
static bool caller_is_jb_infra(void *ra);
static void aialog(const char *fmt, ...) {
#if AIA_DEBUG_LOG
    static char path[PATH_MAX];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (!dir) dir = NSTemporaryDirectory();
        snprintf(path, sizeof(path), "%s/aiabypass.log", [dir fileSystemRepresentation]);
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "===== aiabypass start %s =====\n", [[NSDate date] description].UTF8String); fclose(f); }
    });
    FILE *f = fopen(path, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
#else
    (void)fmt;
#endif
}

// ============================================================
// MARK: 判定哪些镜像需要从枚举结果里隐藏
// ============================================================

static const char *const kHiddenPatterns[] = {
    "/var/jb/",
    "systemhook.dylib",
    "libinjector.dylib",
    "libsubstrate",
    "TweakInject",
    "ellekit",
    "CydiaSubstrate",
    "SubstrateLoader",
    "frida",
    "FridaGadget",
    "AIABypass",
    NULL,
};

static bool path_is_hidden(const char *p) {
    if (!p) return false;
    for (int i = 0; kHiddenPatterns[i]; i++) {
        if (strstr(p, kHiddenPatterns[i])) return true;
    }
    return false;
}

// ============================================================
// MARK: dyld 镜像枚举过滤
// ============================================================

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_slide)(uint32_t);

static uint32_t g_real_count;
static uint32_t *g_visible;
static uint32_t g_visible_count;
static uint32_t g_visible_cap;

static void rebuild_visible(void) {
    uint32_t n = orig_dyld_image_count();
    if (g_visible && n == g_real_count) return;
    if (g_visible_count && g_visible) {
        // 只增不减的常见情形：在旧表基础上增量补齐
    }
    if (n > g_visible_cap) {
        g_visible_cap = n + 32;
        free(g_visible);
        g_visible = (uint32_t *)malloc(sizeof(uint32_t) * g_visible_cap);
    }
    uint32_t vc = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (AIA_HIDE_IMAGES && path_is_hidden(name)) {
            aialog("[hide] image[%u] %s", i, name ? name : "(null)");
            continue;
        }
        g_visible[vc++] = i;
    }
    g_visible_count = vc;
    g_real_count = n;
}

static uint32_t my_dyld_image_count(void) {
    rebuild_visible();
    return g_visible_count;
}

static uint32_t visible_to_real(uint32_t idx) {
    rebuild_visible();
    if (idx >= g_visible_count) return UINT32_MAX;
    return g_visible[idx];
}

static const char *my_dyld_get_image_name(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_name(real);
}

static const struct mach_header *my_dyld_get_image_header(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_header(real);
}

static intptr_t my_dyld_get_image_slide(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return 0;
    return orig_dyld_get_image_slide(real);
}

// objc_copyImageNames
static CFArrayRef (*orig_objc_copyImageNames)(unsigned int *);
static CFArrayRef my_objc_copyImageNames(unsigned int *outCount) {
    CFArrayRef arr = orig_objc_copyImageNames(outCount);
    if (!arr) return arr;
    CFMutableArrayRef filtered = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFIndex n = CFArrayGetCount(arr);
    for (CFIndex i = 0; i < n; i++) {
        CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(arr, i);
        char buf[PATH_MAX];
        if (CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8) && path_is_hidden(buf)) {
            aialog("[hide] objc_copyImageNames %s", buf);
            continue;
        }
        CFArrayAppendValue(filtered, s);
    }
    if (outCount) *outCount = (unsigned int)CFArrayGetCount(filtered);
    return filtered;
}

// _dyld_register_func_for_add_image：把回调包一层，隐藏镜像不回调
typedef void (*add_image_cb_t)(const struct mach_header *, intptr_t);
static add_image_cb_t g_add_image_cbs[8];
static int g_add_image_cb_count;
static bool g_add_image_registered;

static void my_add_image_cb(const struct mach_header *mh, intptr_t slide) {
    aialog("+ add_image_cb(%p, %#lx)", mh, (unsigned long)slide);
    const char *name = NULL;
    if (orig_dyld_image_count && orig_dyld_get_image_header && orig_dyld_get_image_name) {
        uint32_t n = orig_dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (orig_dyld_get_image_header(i) == mh) { name = orig_dyld_get_image_name(i); break; }
        }
    } else {
        // 最小模式下没有接管 _dyld_image_count 等函数，orig_* 仍是空指针，
        // 这里退回系统（或 ellekit）提供的 _dyld_* 实现。
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (_dyld_get_image_header(i) == mh) { name = _dyld_get_image_name(i); break; }
        }
    }
    if (path_is_hidden(name)) {
        aialog("[hide] add_image cb skipped %s", name ? name : "(null)");
        return;
    }
    for (int i = 0; i < g_add_image_cb_count; i++) g_add_image_cbs[i](mh, slide);
}

static void (*orig_register_add_image)(add_image_cb_t);
static void my_register_add_image(add_image_cb_t cb) {
    aialog("+ _dyld_register_func_for_add_image(%p)", cb);
    if (g_add_image_cb_count < 8) g_add_image_cbs[g_add_image_cb_count++] = cb;
    if (AIA_BLOCK_ADD_IMAGE) { aialog("add_image registration swallowed"); return; }
    if (!g_add_image_registered) {
        g_add_image_registered = true;
        orig_register_add_image(my_add_image_cb);
    }
}

// dladdr：把隐藏库的路径抹掉
static int (*orig_dladdr)(const void *, Dl_info *);
static int my_dladdr(const void *addr, Dl_info *info) {
    int r = orig_dladdr(addr, info);
    if (r && info && info->dli_fname && path_is_hidden(info->dli_fname)) {
        aialog("[hide] dladdr(%p) %s base=%p sname=%s caller=%s", addr, info->dli_fname,
               info->dli_fbase, info->dli_sname ?: "-", caller_desc(__builtin_return_address(0)));
        info->dli_fname = "";
    }
    return r;
}

// ============================================================
// MARK: 文件检查（先只观测，命中的路径写日志）
// ============================================================

static bool path_is_suspicious(const char *p) {
    if (!p) return false;
    static const char *pat[] = {
        "/var/jb", "Cydia", "Sileo", "substrate", "Substrate", "frida",
        "/usr/sbin/sshd", "/bin/bash", "/bin/sh", "/etc/apt", "/private/var/lib/dpkg",
        "MobileSubstrate", "TweakInject", "ellekit", "libhooker", "checkra1n", "unc0ver",
        "dopamine", "Dopamine", "procursus", "jbroot", ".jbroot", NULL
    };
    for (int i = 0; pat[i]; i++) if (strstr(p, pat[i])) return true;
    return false;
}

static int (*orig_stat)(const char *, struct stat *);
static int my_stat(const char *p, struct stat *st) {
    if (path_is_suspicious(p) && !caller_is_jb_infra(__builtin_return_address(0))) aialog("stat(%s) caller=%s", p, caller_desc(__builtin_return_address(0)));
    return orig_stat(p, st);
}

static int (*orig_lstat)(const char *, struct stat *);
static int my_lstat(const char *p, struct stat *st) {
    if (path_is_suspicious(p)) aialog("lstat(%s)", p);
    return orig_lstat(p, st);
}

static int (*orig_access)(const char *, int);
static int my_access(const char *p, int mode) {
    if (path_is_suspicious(p)) aialog("access(%s,%d)", p, mode);
    return orig_access(p, mode);
}

static int (*orig_open)(const char *, int, ...);
static int my_open(const char *p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    if (path_is_suspicious(p)) aialog("open(%s,%d)", p, flags);
    return orig_open(p, flags, mode);
}

static int (*orig_readlink)(const char *, char *, size_t);
static int my_readlink(const char *p, char *buf, size_t sz) {
    if (path_is_suspicious(p)) aialog("readlink(%s)", p);
    return orig_readlink(p, buf, sz);
}

// ============================================================
// MARK: sysctl（观测）
// ============================================================

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2) {
        aialog("sysctl(mib=%d,%d,%d,%d namelen=%u)", name[0], name[1],
               namelen > 2 ? name[2] : -1, namelen > 3 ? name[3] : -1, namelen);
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}


// ============================================================
// MARK: 调用者定位（用于把检测行为归因到具体模块）
// ============================================================

static const char *caller_desc(void *ra) {
    static char buf[320];
    Dl_info info;
    if (ra && orig_dladdr && orig_dladdr(ra, &info) && info.dli_fname) {
        const char *slash = strrchr(info.dli_fname, '/');
        snprintf(buf, sizeof(buf), "%s+0x%lx", slash ? slash + 1 : info.dli_fname,
                 (unsigned long)((uintptr_t)ra - (uintptr_t)info.dli_fbase));
        return buf;
    }
    snprintf(buf, sizeof(buf), "%p", ra);
    return buf;
}

static bool caller_is_jb_infra(void *ra) {
    const char *d = caller_desc(ra);
    return strstr(d, "libinjector") || strstr(d, "systemhook") || strstr(d, "ellekit")
        || strstr(d, "Choicy") || strstr(d, "AIABypass");
}

// ============================================================
// MARK: VM 检测原语（观测 RASP 如何扫内存）
// ============================================================

static kern_return_t (*orig_vm_region_64)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t,
                                           vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
static kern_return_t my_vm_region_64(vm_map_t task, vm_address_t *address, vm_size_t *size,
                                     vm_region_flavor_t flavor, vm_region_info_t info,
                                     mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    kern_return_t kr = orig_vm_region_64(task, address, size, flavor, info, infoCnt, object_name);
    aialog("vm_region_64(addr=0x%lx size=0x%lx flavor=%d) -> %d caller=%s",
           address ? (unsigned long)*address : 0, size ? (unsigned long)*size : 0,
           (int)flavor, (int)kr, caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t, vm_address_t *, vm_size_t *, natural_t *,
                                                  vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t my_vm_region_recurse_64(vm_map_t task, vm_address_t *address, vm_size_t *size,
                                             natural_t *depth, vm_region_recurse_info_t info,
                                             mach_msg_type_number_t *infoCnt) {
    kern_return_t kr = orig_vm_region_recurse_64(task, address, size, depth, info, infoCnt);
    aialog("vm_region_recurse_64(addr=0x%lx size=0x%lx depth=%d) -> %d caller=%s",
           address ? (unsigned long)*address : 0, size ? (unsigned long)*size : 0,
           depth ? (int)*depth : -1, (int)kr, caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static kern_return_t my_vm_read_overwrite(vm_map_t task, vm_address_t address, vm_size_t size,
                                          vm_address_t data, vm_size_t *outsize) {
    kern_return_t kr = orig_vm_read_overwrite(task, address, size, data, outsize);
    if (t_in_safe_read) return kr;
    aialog("vm_read_overwrite(addr=0x%lx size=0x%lx) -> %d caller=%s",
           (unsigned long)address, (unsigned long)size, (int)kr,
           caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static kern_return_t my_vm_protect(vm_map_t task, vm_address_t address, vm_size_t size,
                                   boolean_t set_max, vm_prot_t prot) {
    kern_return_t kr = orig_vm_protect(task, address, size, set_max, prot);
    aialog("vm_protect(addr=0x%lx size=0x%lx prot=%d) -> %d caller=%s",
           (unsigned long)address, (unsigned long)size, (int)prot, (int)kr,
           caller_desc(__builtin_return_address(0)));
    return kr;
}

static uint8_t *(*orig_getsectiondata)(const struct mach_header *, const char *, const char *, unsigned long *);
static uint8_t *my_getsectiondata(const struct mach_header *mhp, const char *seg, const char *sect, unsigned long *size) {
    uint8_t *r = orig_getsectiondata(mhp, seg, sect, size);
    aialog("getsectiondata(%s,%s) -> %p size=%lu caller=%s", seg ? seg : "?", sect ? sect : "?",
           r, size ? *size : 0, caller_desc(__builtin_return_address(0)));
    return r;
}


// ============================================================
// MARK: RASP 查询面（类名 / 符号 / 环境变量）
// ============================================================

static Class (*orig_NSClassFromString)(NSString *);
static Class my_NSClassFromString(NSString *name) {
    Class c = orig_NSClassFromString(name);
    aialog("NSClassFromString(%s) -> %p caller=%s", name ? [name UTF8String] : "(nil)",
           c, caller_desc(__builtin_return_address(0)));
    return c;
}

static Class (*orig_objc_getClass)(const char *);
static Class my_objc_getClass(const char *name) {
    Class c = orig_objc_getClass(name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("objc_getClass(%s) -> %p caller=%s", name, c, caller_desc(__builtin_return_address(0)));
    return c;
}

static void *(*orig_dlsym)(void *, const char *);
static void *my_dlsym(void *handle, const char *name) {
    void *r = orig_dlsym(handle, name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("dlsym(%s) -> %p caller=%s", name, r, caller_desc(__builtin_return_address(0)));
    return r;
}

static char *(*orig_getenv)(const char *);
static char *my_getenv(const char *name) {
    char *r = orig_getenv(name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("getenv(%s) -> %s caller=%s", name, r ? r : "(null)",
               caller_desc(__builtin_return_address(0)));
    return r;
}

// ============================================================
// MARK: 崩溃现场记录（诊断用）
// ============================================================

static int g_logfd = -1;
static void log_raw(const char *s) {
    if (g_logfd >= 0) { ssize_t n = strlen(s); (void)!write(g_logfd, s, n); }
}

#define AIA_MAX_MODULES 1024
static struct { uintptr_t base; uintptr_t size; const char *name; } g_mods[AIA_MAX_MODULES];
static int g_mod_count;

static void snapshot_modules(void) {
    extern uint32_t (*orig_dyld_image_count)(void);
    extern const char *(*orig_dyld_get_image_name)(uint32_t);
    extern const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
    uint32_t (*cnt_fn)(void) = orig_dyld_image_count ? orig_dyld_image_count : _dyld_image_count;
    const char *(*name_fn)(uint32_t) = orig_dyld_get_image_name ? orig_dyld_get_image_name : _dyld_get_image_name;
    const struct mach_header *(*hdr_fn)(uint32_t) = orig_dyld_get_image_header ? orig_dyld_get_image_header : _dyld_get_image_header;
    if (!cnt_fn || !hdr_fn) return;
    uint32_t n = cnt_fn();
    if (n > AIA_MAX_MODULES) n = AIA_MAX_MODULES;
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = hdr_fn(i);
        if (!h) continue;
        uintptr_t base = (uintptr_t)h;
        uintptr_t size = 0;
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)h;
        if (h64->magic == MH_MAGIC_64) {
            const uint8_t *p = (const uint8_t *)h + sizeof(struct mach_header_64);
            for (uint32_t c = 0; c < h64->ncmds; c++) {
                const struct load_command *lc = (const struct load_command *)p;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                    if (strcmp(seg->segname, "__TEXT") == 0) size = seg->vmsize;
                }
                if (lc->cmdsize == 0) break;
                p += lc->cmdsize;
            }
        }
        g_mods[g_mod_count].base = base;
        g_mods[g_mod_count].size = size ? size : 0x1000;
        g_mods[g_mod_count].name = name_fn(i);
        g_mod_count++;
    }
}

static const char *module_for(uintptr_t addr, uintptr_t *offset) {
    for (int i = 0; i < g_mod_count; i++) {
        if (addr >= g_mods[i].base && addr < g_mods[i].base + g_mods[i].size) {
            *offset = addr - g_mods[i].base;
            return g_mods[i].name;
        }
    }
    *offset = 0;
    return NULL;
}

static __thread bool t_in_safe_read;
static bool safe_read(uintptr_t addr, uintptr_t *out) {
    vm_size_t got = 0;
    t_in_safe_read = true;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         sizeof(uintptr_t), (vm_address_t)out, &got);
    t_in_safe_read = false;
    return kr == KERN_SUCCESS && got == sizeof(uintptr_t);
}

static void crash_signal_handler(int sig, siginfo_t *si, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    char buf[512];
#if defined(__arm64__)
    uint64_t *x = uc->uc_mcontext->__ss.__x;
    uintptr_t pc = uc->uc_mcontext->__ss.__pc;
    uintptr_t lr = uc->uc_mcontext->__ss.__lr;
    uintptr_t fp = uc->uc_mcontext->__ss.__fp;
    uintptr_t off = 0;
    const char *m = module_for(pc, &off);
    snprintf(buf, sizeof(buf), "SIGNAL %d code=%d addr=%p pc=%p(%s+0x%lx) lr=%p sp=%p fp=%p\n",
             sig, si ? si->si_code : -1, si ? si->si_addr : NULL,
             (void *)pc, m ? m : "?", (unsigned long)off,
             (void *)lr, (void *)uc->uc_mcontext->__ss.__sp, (void *)fp);
    log_raw(buf);
    for (int i = 0; i < 29; i++) {
        uintptr_t voff = 0;
        const char *vm = module_for(x[i], &voff);
        if (vm) {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx %s+0x%lx\n", i, (unsigned long)x[i],
                     vm, (unsigned long)voff);
        } else {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx\n", i, (unsigned long)x[i]);
        }
        log_raw(buf);
    }
    snprintf(buf, sizeof(buf), "  cpsr=%#x\n", uc->uc_mcontext->__ss.__cpsr);
    log_raw(buf);
    {
        uint32_t insn = 0;
        if (safe_read(pc, (uintptr_t *)&insn)) {
            snprintf(buf, sizeof(buf), "  insn@pc=%08x\n", insn);
            log_raw(buf);
        }
    }
    // 运行时字节对比：文件里的桩和内存里的桩可能不同
    {
        uint8_t raw[0x80];
        vm_size_t got = 0;
        if (vm_read_overwrite(mach_task_self(), (vm_address_t)(pc - 0x40), sizeof(raw),
                              (vm_address_t)raw, &got) == KERN_SUCCESS && got == sizeof(raw)) {
            char line[256];
            for (int i = 0; i < 0x80; i += 16) {
                char *w = line;
                w += snprintf(w, 16, "  %c%03x: ", i >= 0x40 ? '+' : '-', i >= 0x40 ? i - 0x40 : 0x40 - i);
                for (int j = 0; j < 16; j++) w += snprintf(w, 4, "%02x", raw[i + j]);
                w += snprintf(w, 8, "  ");
                for (int j = 0; j < 16; j++) {
                    uint8_t c = raw[i + j];
                    *w++ = (c >= 0x20 && c < 0x7f) ? c : '.';
                }
                *w++ = '\n';
                *w = 0;
                log_raw(line);
            }
        }
    }
    // 原始栈扫描：找出落在已知模块里的返回地址
    {
        uintptr_t scan_sp = uc->uc_mcontext->__ss.__sp;
        int found = 0;
        for (int i = 0; i < 0x4000 / sizeof(uintptr_t) && found < 40; i++) {
            uintptr_t v = 0;
            if (!safe_read(scan_sp + i * sizeof(uintptr_t), &v)) break;
            uintptr_t voff = 0;
            const char *vm = module_for(v, &voff);
            if (vm && voff > 0) {
                snprintf(buf, sizeof(buf), "  stack[+0x%x] %p %s+0x%lx\n",
                         i * 8, (void *)v, vm, (unsigned long)voff);
                log_raw(buf);
                found++;
            }
        }
    }
    // fp 链展开
    uintptr_t frame = fp;
    for (int i = 0; i < 24 && frame; i++) {
        uintptr_t next = 0, ra = 0;
        if (!safe_read(frame, &next) || !safe_read(frame + sizeof(uintptr_t), &ra)) break;
        uintptr_t roff = 0;
        const char *rm = module_for(ra, &roff);
        snprintf(buf, sizeof(buf), "  #%d %p %s+0x%lx\n", i, (void *)ra,
                 rm ? rm : "?", (unsigned long)roff);
        log_raw(buf);
        if (next <= frame) break;
        frame = next;
    }
#else
    log_raw("SIGNAL (non-arm64)\n");
#endif
    signal(sig, SIG_DFL);
    raise(sig);
}

// ============================================================
// MARK: 终止原语（观测是谁在杀进程）
// ============================================================

static void log_backtrace(const char *tag) {
    void *frames[32];
    int n = backtrace(frames, 32);
    if (n <= 0) return;
    char **syms = backtrace_symbols(frames, n);
    if (!syms) return;
    aialog("%s bt(%d):", tag, n);
    for (int i = 0; i < n; i++) aialog("    %s", syms[i]);
    free(syms);
}

static void (*orig_exit)(int);
static void my_exit(int code) {
    aialog("EXIT(%d) pid=%d caller=%s", code, getpid(), caller_desc(__builtin_return_address(0)));
    log_backtrace("EXIT");
#if AIA_BLOCK_EXIT
    if (code == 1) { aialog("EXIT blocked"); return; }
#endif
    orig_exit(code);
}

static void (*orig_Exit)(int);
static void my_Exit(int code) {
    aialog("_EXIT(%d) pid=%d caller=%s", code, getpid(), caller_desc(__builtin_return_address(0)));
    log_backtrace("_EXIT");
#if AIA_BLOCK_EXIT
    if (code == 1) { aialog("_EXIT blocked"); return; }
#endif
    orig_Exit(code);
}

static void (*orig_abort)(void);
static void my_abort(void) {
    aialog("ABORT pid=%d", getpid());
    log_backtrace("ABORT");
    orig_abort();
}

static int (*orig_kill)(pid_t, int);
static int my_kill(pid_t pid, int sig) {
    aialog("KILL(pid=%d sig=%d) self=%d", pid, sig, getpid());
    if (pid == getpid()) log_backtrace("KILL");
    return orig_kill(pid, sig);
}

static void (*orig_pthread_exit)(void *);
static void my_pthread_exit(void *ret) {
    aialog("PTHREAD_EXIT");
    log_backtrace("PTHREAD_EXIT");
    orig_pthread_exit(ret);
}


// ============================================================
// MARK: 自建 Mach 异常处理器（抢占 ellekit 的异常端口）
// ============================================================

#if AIA_EXC_HANDLER

// EXCEPTION_STATE_IDENTITY + MACH_EXCEPTION_CODES 对应 mach_exception_raise_state_identity
// （msgh_id 2407）。消息里同时带 thread/task 端口和完整线程状态。
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[128];
} exc_req_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[128];
} exc_reply_t;

static mach_port_t g_exc_port = MACH_PORT_NULL;

// 消息线上 port descriptor 是 12 字节，和结构体里的 16 字节不一致，
// 所以这里全部按显式字节偏移解析，避免被编译器的对齐填充带偏。
// mach_exception_raise_state_identity 布局：
//   0 header(24) | 24 descriptor_count(4) | 28 thread(12) | 40 task(12)
//   52 NDR(8) | 60 exception(4) | 64 codeCnt(4) | 68 code[2](16)
//   84 flavor(4) | 88 old_stateCnt(4) | 92 old_state
#define EXC_HDR 0
#define EXC_THREAD_OFF 28
#define EXC_TASK_OFF 40
#define EXC_NDR_OFF 52
#define EXC_TYPE_OFF 60
#define EXC_CODECNT_OFF 64
#define EXC_CODE_OFF 68
#define EXC_FLAVOR_OFF 84
#define EXC_STATE_OFF 88
#define EXC_STATE_BODY_OFF 92

static void dump_fault_state(exc_req_t *req) {
    char buf[256];
    const uint8_t *b = (const uint8_t *)req;
    int64_t code0 = 0, code1 = 0;
    memcpy(&code0, b + EXC_CODE_OFF, 8);
    memcpy(&code1, b + EXC_CODE_OFF + 8, 8);
    uint32_t codeCnt = *(const uint32_t *)(b + EXC_CODECNT_OFF);
    uint32_t flavor = *(const uint32_t *)(b + EXC_FLAVOR_OFF);
    uint32_t stateCnt = *(const uint32_t *)(b + EXC_STATE_OFF);
    int etype = (int)*(const uint32_t *)(b + EXC_TYPE_OFF);
    mach_port_t thrPort = *(const uint32_t *)(b + EXC_THREAD_OFF);
    mach_port_t tskPort = *(const uint32_t *)(b + EXC_TASK_OFF);
    snprintf(buf, sizeof(buf),
             "EXCFAULT id=%d size=%u thr=%u task=%u type=%d codeCnt=%u code0=%lld code1=%lld flavor=%u stateCnt=%u\n",
             req->Head.msgh_id, req->Head.msgh_size, thrPort, tskPort, etype, codeCnt,
             (long long)code0, (long long)code1, flavor, stateCnt);
    log_raw(buf);
    if (flavor != 6 || stateCnt < 34) { log_raw("  (state 不可用)\n"); return; }
    arm_thread_state64_t st;
    memcpy(&st, b + EXC_STATE_BODY_OFF, sizeof(st));
    uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
    uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
    uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
    uintptr_t off = 0;
    const char *m = module_for(pc, &off);
    snprintf(buf, sizeof(buf), "  pc=%p(%s+0x%lx) lr=%p sp=%p\n", (void *)pc,
             m ? m : "?", (unsigned long)off, (void *)lr, (void *)sp);
    log_raw(buf);
    for (int i = 0; i < 29; i++) {
        uintptr_t v = (uintptr_t)st.__x[i];
        uintptr_t voff = 0;
        const char *vm = module_for(v, &voff);
        if (vm) {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx %s+0x%lx\n", i,
                     (unsigned long)v, vm, (unsigned long)voff);
        } else {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx\n", i, (unsigned long)v);
        }
        log_raw(buf);
    }
    int found = 0;
    for (int i = 0; i < 0x2000 / sizeof(uintptr_t) && found < 24; i++) {
        uintptr_t v = 0;
        if (!safe_read(sp + i * sizeof(uintptr_t), &v)) break;
        uintptr_t voff = 0;
        const char *vm = module_for(v, &voff);
        if (!vm || voff == 0) continue;
        if (!strstr(vm, "JMCodeProtectKit") && !strstr(vm, "KYHAppStore")) continue;
        snprintf(buf, sizeof(buf), "  stack[+0x%x] %p %s+0x%lx\n",
                 i * 8, (void *)v, vm, (unsigned long)voff);
        log_raw(buf);
        found++;
    }
}

__attribute__((unused)) static void *aia_exc_server(void *arg) {
    (void)arg;
    mach_msg_size_t rcv = 1024;
    exc_req_t *req = (exc_req_t *)calloc(1, rcv + 2048);
    exc_reply_t *rep = (exc_reply_t *)calloc(1, sizeof(exc_reply_t) + 256);
    if (!req || !rep) return NULL;
    while (1) {
        kern_return_t kr = mach_msg(&req->Head, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
                                    rcv, g_exc_port,
                                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == MACH_RCV_TOO_LARGE) {
            mach_msg_size_t need = 0;
            mach_msg(&req->Head, MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY,
                     0, 0, g_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            need = req->Head.msgh_size;
            if (need < 1024) need = 4096;
            rcv = need + 1024;
            req = (exc_req_t *)realloc(req, rcv + 2048);
            aialog("exc: rcv too large, resized to %u", rcv);
            continue;
        }
        if (kr != KERN_SUCCESS) {
            static int logged;
            if (logged < 5) { aialog("exc: recv failed %d", kr); logged++; }
            usleep(20000);
            continue;
        }
        dump_fault_state(req);
#if AIA_KILL_THREAD
        {
            mach_port_t tp = *(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF);
            kern_return_t tk = thread_terminate(tp);
            char b[96];
            snprintf(b, sizeof(b), "  terminate thread(%u) -> %d\n", tp, tk);
            log_raw(b);
        }
#endif
#if AIA_EXC_NO_REPLY
        // 不回复：故障线程留在异常状态，内核不会让它继续执行，JM 的处决也不会生效。
        memset(req, 0, rcv + 2048);
        continue;
#endif
        rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
        rep->Head.msgh_local_port = MACH_PORT_NULL;
        rep->Head.msgh_id = req->Head.msgh_id + 100;
        rep->NDR = NDR_record;
        rep->RetCode = KERN_SUCCESS;
        rep->new_stateCnt = req->old_stateCnt;
        memcpy(rep->new_state, req->old_state, req->old_stateCnt * sizeof(natural_t));
        rep->Head.msgh_size = 8 + 8 + 4 + 4 + req->old_stateCnt * sizeof(natural_t);
        mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    return NULL;
}

#if AIA_SAMPLE_THREADS
__attribute__((unused)) static void *aia_sampler(void *arg) {
    (void)arg;
    char buf[256];
    for (int round = 0; round < 30; round++) {
        sleep(2);
        thread_act_array_t list = NULL;
        mach_msg_type_number_t cnt = 0;
        if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) continue;
        snprintf(buf, sizeof(buf), "SAMPLE round=%d threads=%u\n", round, cnt);
        log_raw(buf);
        for (mach_msg_type_number_t i = 0; i < cnt && i < 24; i++) {
            struct thread_basic_info tb = {0};
            mach_msg_type_number_t tbc = THREAD_BASIC_INFO_COUNT;
            int cpu = -1;
            if (thread_info(list[i], THREAD_BASIC_INFO, (thread_info_t)&tb, &tbc) == KERN_SUCCESS)
                cpu = tb.cpu_usage;
            arm_thread_state64_t st;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            kern_return_t gs = thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc);
            if (gs != KERN_SUCCESS) {
                snprintf(buf, sizeof(buf), "  t%u cpu=%d getstate=%d\n", i, cpu, gs);
                log_raw(buf);
                continue;
            }
            uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
            uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
            uintptr_t voff = 0, loff = 0;
            const char *vm = module_for(pc, &voff);
            const char *lm = module_for(lr, &loff);
            snprintf(buf, sizeof(buf), "  t%u cpu=%d pc=%p %s+0x%lx lr=%p %s+0x%lx\n", i, cpu,
                     (void *)pc, vm ? vm : "?", (unsigned long)voff,
                     (void *)lr, lm ? lm : "?", (unsigned long)loff);
            log_raw(buf);
            if (i == 0) {
                uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
                int got = 0;
                for (int k = 0; k < 0x800 / 8 && got < 14; k++) {
                    uintptr_t v = 0;
                    if (!safe_read(sp + k * 8, &v)) break;
                    uintptr_t o2 = 0;
                    const char *m2 = module_for(v, &o2);
                    if (!m2 || o2 == 0) continue;
                    snprintf(buf, sizeof(buf), "    [%02d] %s+0x%lx\n", k, m2, (unsigned long)o2);
                    log_raw(buf);
                    got++;
                }
            }
        }
        vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    }
    return NULL;
}
static void start_sampler(void) {
    pthread_t th;
    pthread_create(&th, NULL, aia_sampler, NULL);
}
#endif

#if AIA_EXC_WATCHDOG
static void *aia_exc_watchdog(void *arg) {
    (void)arg;
    // 必须一直跑：JM 会在运行期间反复检测，端口一旦被别人抢回去就会再次触发处决。
    for (;;) {
        task_set_exception_ports(mach_task_self(),
                                 EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                                 g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64);
        usleep(50000);
    }
    return NULL;
}
#endif

#if AIA_DUMP_ON_SIGNAL
static void dump_view(UIView *v, int depth) {
    if (depth > 3) return;
    char buf[320];
    NSString *cls = NSStringFromClass([v class]);
    snprintf(buf, sizeof(buf), "    %*s%s fr=(%.0f,%.0f %.0fx%.0f) hidden=%d alpha=%.2f "
             "inter=%d clips=%d layer=%.2f\n", depth * 2, "", cls.UTF8String,
             v.frame.origin.x, v.frame.origin.y, v.frame.size.width, v.frame.size.height,
             (int)v.hidden, (double)v.alpha, (int)v.userInteractionEnabled,
             (int)v.clipsToBounds, (double)v.layer.opacity);
    log_raw(buf);
    for (UIView *sub in v.subviews) dump_view(sub, depth + 1);
}

static void dump_ui_main(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    UIApplication *app = [UIApplication sharedApplication];
    char buf[320];
    snprintf(buf, sizeof(buf), "=== UI: %u windows ===\n",
             (unsigned)app.windows.count);
    log_raw(buf);
    for (UIWindow *w in app.windows) {
        snprintf(buf, sizeof(buf), "  window %s level=%.0f hidden=%d alpha=%.2f inter=%d\n",
                 NSStringFromClass([w class]).UTF8String, (double)w.windowLevel,
                 (int)w.hidden, (double)w.alpha, (int)w.userInteractionEnabled);
        log_raw(buf);
        dump_view(w, 1);
        CGPoint c = CGPointMake(w.bounds.size.width / 2, w.bounds.size.height / 2);
        UIView *hit = [w hitTest:c withEvent:nil];
        snprintf(buf, sizeof(buf), "  hitTest(中心) -> %s inter=%d\n",
                 hit ? NSStringFromClass([hit class]).UTF8String : "(nil)",
                 hit ? (int)hit.userInteractionEnabled : -1);
        log_raw(buf);
    }
    log_raw("=== UI END ===\n");
#pragma clang diagnostic pop
}

static void dump_ui_signal(int sig) {
    (void)sig;
    dispatch_async(dispatch_get_main_queue(), ^{ dump_ui_main(); });
}

static void dump_all_threads(int sig) {
    (void)sig;
    char buf[256];
    log_raw("=== DUMP ALL THREADS ===\n");
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    for (mach_msg_type_number_t i = 0; i < cnt && i < 64; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS) continue;
        uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
        uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
        uintptr_t vo = 0, lo = 0;
        const char *vm = module_for(pc, &vo);
        const char *lm = module_for(lr, &lo);
        snprintf(buf, sizeof(buf), "  t%u pc=%p %s+0x%lx lr=%p %s+0x%lx\n", i,
                 (void *)pc, vm ? vm : "?", (unsigned long)vo,
                 (void *)lr, lm ? lm : "?", (unsigned long)lo);
        log_raw(buf);
        if (i == 0) {
            uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
            int got = 0;
            for (int k = 0; k < 0x1000 / 8 && got < 22; k++) {
                uintptr_t v = 0;
                if (!safe_read(sp + k * 8, &v)) break;
                uintptr_t o2 = 0;
                const char *m2 = module_for(v, &o2);
                if (!m2 || o2 == 0) continue;
                snprintf(buf, sizeof(buf), "    [%02d] %s+0x%lx\n", k, m2, (unsigned long)o2);
                log_raw(buf);
                got++;
            }
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    log_raw("=== DUMP END ===\n");
}
#endif

__attribute__((unused)) static void install_exc_handler(void) {
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) { aialog("exc: port_allocate %d", kr); return; }
    mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);
    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                                  g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                  ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { aialog("exc: set_exception_ports %d", kr); return; }
#if AIA_EXC_SERVER
    pthread_t th;
    pthread_create(&th, NULL, aia_exc_server, NULL);
    aialog("exc: handler installed port=%u (server on)", g_exc_port);
#else
    aialog("exc: handler installed port=%u (server off, exceptions will queue)", g_exc_port);
#endif
#if AIA_EXC_WATCHDOG
    pthread_t wt;
    pthread_create(&wt, NULL, aia_exc_watchdog, NULL);
#endif
}
#endif

// ============================================================
// MARK: 初始化
// ============================================================

// ellekit 会改写 _dyld_* 的编号，_dyld_get_image_header(0) 在这个进程里返回的是
// systemhook.dylib 而不是主程序。这里改为在模块表里按主可执行文件路径查找。
static uintptr_t app_base(void) {
    char exe[PATH_MAX] = {0};
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0) exe[0] = 0;
    if (exe[0]) {
        for (int i = 0; i < g_mod_count; i++) {
            if (g_mods[i].name && strcmp(g_mods[i].name, exe) == 0) return g_mods[i].base;
        }
    }
    for (int i = 0; i < g_mod_count; i++) {
        const char *nm = g_mods[i].name;
        if (!nm) continue;
        const char *slash = strrchr(nm, '/');
        const char *leaf = slash ? slash + 1 : nm;
        if (strncmp(leaf, "KYHAppStore", 11) == 0) return g_mods[i].base;
    }
    return (uintptr_t)_dyld_get_image_header(0);
}

__attribute__((unused)) static void patch_app_code(uintptr_t offset, uint32_t expect, uint32_t new_insn, const char *tag) {
    uintptr_t b = app_base();
    if (!b) { aialog("patch %s: no app base", tag); return; }
    uintptr_t addr = b + offset;
    uintptr_t page = addr & ~(uintptr_t)0x3fff;
    uint32_t old = *(volatile uint32_t *)addr;
    if (old != expect) {
        aialog("patch %s @%#lx: unexpected %08x (want %08x)", tag, (unsigned long)offset, old, expect);
        return;
    }
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { aialog("patch %s: vm_protect failed %d", tag, kr); return; }
    *(volatile uint32_t *)addr = new_insn;
    sys_icache_invalidate((void *)addr, 4);
    aialog("patch %s @%#lx: %08x -> %08x ok", tag, (unsigned long)offset, old, new_insn);
}

#if AIA_FAKE_PATH
static void fake_own_image_path(void) {
    Dl_info di = {0};
    if (!dladdr((void *)aialog, &di) || !di.dli_fbase) { aialog("fake_path: dladdr self failed"); return; }
    struct task_dyld_info td = {0};
    mach_msg_type_number_t tcount = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&td, &tcount) != KERN_SUCCESS ||
        !td.all_image_info_addr) {
        aialog("fake_path: task_info failed");
        return;
    }
    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)(uintptr_t)td.all_image_info_addr;
    if (!infos->infoArray) { aialog("fake_path: no all_image_infos"); return; }
    struct dyld_image_info *arr = (struct dyld_image_info *)(uintptr_t)infos->infoArray;
    static char fake[8][64];
    static const char *names[8] = {
        "/usr/lib/libz.1.dylib", "/usr/lib/libsqlite3.dylib", "/usr/lib/libxml2.2.dylib",
        "/usr/lib/libbz2.1.0.dylib", "/usr/lib/liblzma.5.dylib", "/usr/lib/libarchive.2.dylib",
        "/usr/lib/libcompression.dylib", "/usr/lib/libicucore.A.dylib",
    };
    int hit = 0;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)((uintptr_t)arr & ~0x3fffUL),
                                  ((infos->infoArrayCount * sizeof(*arr)) & ~0x3fffUL) + 0x4000,
                                  false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    aialog("fake_path: vm_protect=%d count=%u", kr, infos->infoArrayCount);
    for (uint32_t i = 0; i < infos->infoArrayCount && hit < 8; i++) {
        const char *old = arr[i].imageFilePath;
        if (!old) continue;
        if (!strstr(old, "/var/jb") && !strstr(old, "TweakInject") &&
            !strstr(old, "preboot") && !strstr(old, "basebin") &&
            !strstr(old, "procursus") && !strstr(old, "ellekit") &&
            !strstr(old, "libinjector") && !strstr(old, "systemhook")) continue;
        snprintf(fake[hit], sizeof(fake[hit]), "%s", names[hit]);
        aialog("fake_path: idx=%u %s -> %s%s", i, old, fake[hit],
               arr[i].imageLoadAddress == di.dli_fbase ? " (self)" : "");
        arr[i].imageFilePath = fake[hit];
        hit++;
    }
    aialog("fake_path: patched %d images", hit);
}
#endif

#if AIA_DLADDR_MASK || AIA_STEALTH
static void *g_orig_dladdr_fn;
static const char *g_mask_names[] = {
    "/usr/lib/libz.1.dylib", "/usr/lib/libsqlite3.dylib", "/usr/lib/libxml2.2.dylib",
    "/usr/lib/libbz2.1.0.dylib", "/usr/lib/liblzma.5.dylib", "/usr/lib/libcrypto.44.dylib",
    "/usr/lib/libcompression.dylib", "/usr/lib/libicucore.A.dylib",
};
static char g_mask_store[8][64];
static int g_mask_used;

static int my_dladdr_mask(const void *addr, Dl_info *info) {
    int (*orig)(const void *, Dl_info *) = (int (*)(const void *, Dl_info *))g_orig_dladdr_fn;
    int r = orig(addr, info);
    if (!r || !info || !info->dli_fname) return r;
    const char *p = info->dli_fname;
    if (!strstr(p, "/var/jb") && !strstr(p, "preboot") && !strstr(p, "basebin") &&
        !strstr(p, "procursus") && !strstr(p, "TweakInject") && !strstr(p, "ellekit") &&
        !strstr(p, "systemhook") && !strstr(p, "libinjector") && !strstr(p, "AIABypass")) {
        return r;
    }
    if (g_mask_used >= 8) { g_mask_used = 0; }
    strlcpy(g_mask_store[g_mask_used], g_mask_names[g_mask_used], sizeof(g_mask_store[0]));
    aialog("[mask] dladdr(%p) %s -> %s (caller %s)", addr, p,
           g_mask_store[g_mask_used], caller_desc(__builtin_return_address(0)));
    info->dli_fname = g_mask_store[g_mask_used];
    g_mask_used++;
    return r;
}

// 通过 __DATA_CONST 的懒绑定指针找到 dladdr 的真实实现
static void install_dladdr_mask(void) {
    void *fn = dlsym(RTLD_DEFAULT, "dladdr");
    if (!fn) { aialog("mask: dlsym dladdr failed"); return; }
    g_orig_dladdr_fn = fn;
    Dl_info di = {0};
    if (dladdr(fn, &di) && di.dli_fname) aialog("mask: dladdr impl in %s", di.dli_fname);
    MSHookFunction(fn, (void *)my_dladdr_mask, (void **)&g_orig_dladdr_fn);
    aialog("mask: dladdr hooked, orig=%p", g_orig_dladdr_fn);
}
#endif

__attribute__((constructor)) static void aiabypass_init(void) {
    aialog("===== ctor in %s =====", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
#if AIA_TRULY_EMPTY
    aialog("truly empty mode");
    return;
#endif

    {
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *lp = [dir stringByAppendingPathComponent:@"aiabypass.log"];
        g_logfd = open([lp fileSystemRepresentation], O_WRONLY | O_APPEND);
        struct sigaction sa = {0};
        sa.sa_sigaction = crash_signal_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sigaction(SIGTRAP, &sa, NULL);
    }
    snapshot_modules();
    aialog("module snapshot: %d", g_mod_count);
#if AIA_EXC_HANDLER
    install_exc_handler();
#endif
#if AIA_SAMPLE_THREADS
    start_sampler();
#endif
#if AIA_DUMP_ON_SIGNAL
    signal(SIGUSR1, dump_all_threads);
    signal(SIGUSR2, dump_ui_signal);
    aialog("dump-on-signal: SIGUSR1 已注册");
#endif
#if AIA_LOG_IMAGES
    for (int i = 0; i < g_mod_count; i++) {
        const char *nm = g_mods[i].name;
        if (!nm) continue;
        if (strncmp(nm, "/System/", 8) == 0 || strncmp(nm, "/usr/lib/", 9) == 0) continue;
        aialog("img[%d/%d] %s", i, g_mod_count, nm);
    }
#endif
#if AIA_FAKE_PATH
    fake_own_image_path();
#endif
#if AIA_STEALTH
    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    install_dladdr_mask();
    aialog("stealth mode: dyld filter + dladdr mask");
    return;
#endif
#if AIA_DLADDR_MASK
    install_dladdr_mask();
    aialog("dladdr-mask mode");
    return;
#endif
#if AIA_EMPTY
    aialog("empty mode: no hooks");
    return;
#endif

#if AIA_SAMPLE_CODE
    {
        const struct mach_header *h0 = _dyld_get_image_header(0);
        aialog("sample: image0=%p name=%s", h0, _dyld_get_image_name(0) ?: "?");
        for (int k = 0; k < 12; k++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(k * 100) * NSEC_PER_MSEC),
                           dispatch_get_global_queue(0, 0), ^{
                uintptr_t b = app_base();
                uint32_t w0 = *(volatile uint32_t *)(b + 0x7c5590);
                uint32_t w1 = *(volatile uint32_t *)(b + 0x7c55f8);
                uint64_t hsh = 0;
                const uint64_t *pg = (const uint64_t *)(b + 0x7c5000);
                for (int i = 0; i < 512; i++) hsh = hsh * 1099511628211ULL ^ pg[i];
                aialog("sample t=%d00ms w5590=%08x w55f8=%08x pagehash=%016llx",
                       k, w0, w1, (unsigned long long)hsh);
            });
        }
    }
#endif

#if AIA_DUMP_CODE
    {
        uintptr_t base = app_base();
        aialog("dump: app_base=%#lx image0=%s", (unsigned long)base,
               _dyld_get_image_name(0) ?: "?");
        char path[512] = {0};
        uint32_t rp = proc_regionfilename(getpid(), (uint64_t)(base + 0x7c5590), path, sizeof(path) - 1);
        aialog("region file for +0x7c5590: len=%u path=%s", rp, path);
        const uint8_t *p = (const uint8_t *)(base + 0x7c5490);
        char line[200];
        for (int i = 0; i < 0x190; i += 16) {
            char *w = line;
            w += snprintf(w, 24, "  +%05x: ", 0x7c5490 + i);
            for (int j = 0; j < 16; j++) w += snprintf(w, 4, "%02x", p[i + j]);
            *w++ = '\n'; *w = 0;
            log_raw(line);
        }
    }
#endif

#if AIA_PATCH_BINDER
    // 0x7c5590: cbz x15 -> nop
    patch_app_code(0x7c5590, 0xb400034f, 0xd503201f, "binder-x15");
#endif

#if AIA_DYLD_ONLY
    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    aialog("dyld-only mode");
    return;
#endif

#if AIA_MINIMAL
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    aialog("minimal mode: only add_image hook");
    return;
#endif

    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
    MSHookFunction((void *)open, (void *)my_open, (void **)&orig_open);
    MSHookFunction((void *)readlink, (void *)my_readlink, (void **)&orig_readlink);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&orig_exit);
    MSHookFunction((void *)_exit, (void *)my_Exit, (void **)&orig_Exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&orig_abort);
    MSHookFunction((void *)kill, (void *)my_kill, (void **)&orig_kill);
    MSHookFunction((void *)pthread_exit, (void *)my_pthread_exit, (void **)&orig_pthread_exit);
    MSHookFunction((void *)vm_region_64, (void *)my_vm_region_64, (void **)&orig_vm_region_64);
    MSHookFunction((void *)vm_region_recurse_64, (void *)my_vm_region_recurse_64, (void **)&orig_vm_region_recurse_64);
    MSHookFunction((void *)vm_read_overwrite, (void *)my_vm_read_overwrite, (void **)&orig_vm_read_overwrite);
    MSHookFunction((void *)vm_protect, (void *)my_vm_protect, (void **)&orig_vm_protect);
    MSHookFunction((void *)getsectiondata, (void *)my_getsectiondata, (void **)&orig_getsectiondata);
    MSHookFunction((void *)NSClassFromString, (void *)my_NSClassFromString, (void **)&orig_NSClassFromString);
    MSHookFunction((void *)objc_getClass, (void *)my_objc_getClass, (void **)&orig_objc_getClass);
    MSHookFunction((void *)dlsym, (void *)my_dlsym, (void **)&orig_dlsym);
    MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);

    aialog("hooks installed; image_count=%u", orig_dyld_image_count ? orig_dyld_image_count() : 0);
}
