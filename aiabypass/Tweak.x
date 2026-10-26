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
// 1 = hook UIApplication/UIWindow 的 sendEvent: 统计事件数量。
// 注意：App 自己在 sendEvent: 里做埋点，加这层 hook 会改变 swizzle 链，
// 实测会让主线程更早撞上 brk #0xdead，所以默认关闭，只在排查时打开。
#ifndef AIA_EVENT_PROBE
#define AIA_EVENT_PROBE 0
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
// 1 = 主线程遇到非法跳转时不挂起，而是把 PC 设成 LR，让这次调用"返回"后继续执行。
// 主线程一挂起，整个界面就再也收不到触摸事件（动画仍由 render server 合成）。
#ifndef AIA_EXC_RECOVER_MAIN
#define AIA_EXC_RECOVER_MAIN 1
#endif
// 1 = 真把主线程 PC 设成 LR（实验性：x0 现场无效时会二次崩溃）。
// 0 = 只记录、仍不回复，用来观察主线程挂住后的完整调用链。
#ifndef AIA_EXC_RECOVER_FAULT
#define AIA_EXC_RECOVER_FAULT 1
#endif
// 1 = 断点类异常（brk 断言桩）回复"PC 前进 4 字节"，让线程继续执行。
// 这是主线程不卡死的关键：主线程撞上 brk 后如果一直不回复，触摸就永久失效。
#ifndef AIA_EXC_SKIP_BRK
#define AIA_EXC_SKIP_BRK 1
#endif
// 1 = 收到非断点异常后不回复，让故障线程永久挂起（不交给 ellekit，也就不会有 exit(1)）。
// 处决跳转的 pc=0x8 如果被回复，线程会重跑同一条非法指令形成死循环，进程随即被杀。
#ifndef AIA_EXC_NO_REPLY
#define AIA_EXC_NO_REPLY 1
#endif
// 1 = 不挂起故障线程，而是把它送到 aia_thread_bail 让 pthread_exit 干净退出，
// 这样线程持有的锁和资源会被释放（挂起会导致后续触摸失效）。
#ifndef AIA_EXC_BAIL
#define AIA_EXC_BAIL 0
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

// 只装"安全子集"的观测 hook（不含 vm_region / vm_read 等高危项），
// 与异常接管同时开启，用来观察 JM 在判定前后调用了什么。
#ifndef AIA_OBSERVE_ONLY
#define AIA_OBSERVE_ONLY 0
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

// arm64e 的返回地址和帧指针带 PAC 签名，比较前要先剥掉高位。
__attribute__((unused)) static inline uintptr_t aia_strip_pac(uintptr_t v) {
    uintptr_t t = v & 0x0000FFFFFFFFFFFFULL;
    if (t & 0x0000800000000000ULL) t |= 0xFFFF000000000000ULL;
    return t;
}

static uint64_t g_main_tid;
static volatile int g_evt_count;      // UIWindow sendEvent: 累计调用次数
static volatile int g_evt_touch;      // 其中触摸事件
static volatile int g_exc_count;      // 收到的异常消息总数
static volatile int g_exc_noreply;    // 其中按"不回复"处理的数量

// 每 5 秒记录一次：异常数量、线程数、Mach 端口名称数。
// 目的：区分"触摸失效"是资源累积耗尽，还是 JM 状态机被卡住。
static uint64_t thread_id_of(mach_port_t th);

// 主线程的 Mach 端口：从 task_threads 里找 tid 等于 mainTid 的那个。
static mach_port_t main_thread_port(void) {
    thread_act_array_t l = NULL;
    mach_msg_type_number_t n = 0;
    mach_port_t r = 0;
    if (task_threads(mach_task_self(), &l, &n) != KERN_SUCCESS) return 0;
    for (mach_msg_type_number_t k = 0; k < n; k++) {
        if (thread_id_of(l[k]) == g_main_tid) { r = l[k]; }
        else mach_port_deallocate(mach_task_self(), l[k]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)l, n * sizeof(thread_t));
    return r;
}

static void dump_jm_swizzles(void);
#if AIA_EVENT_PROBE
static void my_app_sendEvent(id self, SEL _cmd, UIEvent *ev);
#endif

__attribute__((unused)) static void *aia_stats(void *arg) {
    (void)arg;
    char b[192];
    for (int i = 0; i < 240; i++) {
        sleep(5);
        thread_act_array_t list = NULL;
        mach_msg_type_number_t cnt = 0;
        int nthreads = -1;
        if (task_threads(mach_task_self(), &list, &cnt) == KERN_SUCCESS) {
            nthreads = (int)cnt;
            for (mach_msg_type_number_t k = 0; k < cnt; k++) mach_port_deallocate(mach_task_self(), list[k]);
            vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(mach_port_t));
        }
        mach_port_name_array_t names = NULL;
        mach_msg_type_number_t ncnt = 0, ntypes = 0;
        mach_port_type_array_t types = NULL;
        int nports = -1;
        if (mach_port_names(mach_task_self(), &names, &ncnt, &types, &ntypes) == KERN_SUCCESS) {
            nports = (int)ncnt;
            vm_deallocate(mach_task_self(), (vm_address_t)names, ncnt * sizeof(mach_port_name_t));
            vm_deallocate(mach_task_self(), (vm_address_t)types, ntypes * sizeof(mach_port_type_t));
        }
        snprintf(b, sizeof(b), "STATS t=%ds exc=%d noreply=%d evt=%d touch=%d threads=%d ports=%d\n",
                 i * 5, g_exc_count, g_exc_noreply, g_evt_count, g_evt_touch, nthreads, nports);
        log_raw(b);
        {
            // 直接读主线程 PC：判断"点不动"是不是主线程被阻塞。
            mach_port_t mt = main_thread_port();
            arm_thread_state64_t mst;
            mach_msg_type_number_t msc = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(mt, ARM_THREAD_STATE64, (thread_state_t)&mst, &msc) == KERN_SUCCESS) {
                uintptr_t mpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(mst);
                uintptr_t mlr = (uintptr_t)__darwin_arm_thread_state64_get_lr(mst);
                uintptr_t mo1 = 0, mo2 = 0;
                const char *m1 = module_for(mpc, &mo1);
                const char *m2 = module_for(mlr, &mo2);
                snprintf(b, sizeof(b), "  MAIN pc=%s+0x%lx lr=%s+0x%lx\n",
                         m1 ? m1 : "?", (unsigned long)mo1,
                         m2 ? m2 : "?", (unsigned long)mo2);
                log_raw(b);
            } else {
                log_raw("  MAIN getstate failed\n");
            }
        }
        if (i < 3 || i % 12 == 0) {
            // 事件入口是否还指着我们的实现；App 实际的 UIApplication 子类是什么。
            Class ac = objc_getClass("UIApplication");
            id app = ((id (*)(id, SEL))objc_msgSend)((id)ac, sel_registerName("sharedApplication"));
            Class realCls = app ? object_getClass(app) : Nil;
            Method m = ac ? class_getInstanceMethod(ac, sel_registerName("sendEvent:")) : NULL;
            IMP cur = m ? method_getImplementation(m) : NULL;
            uintptr_t mo = 0;
            const char *mn = cur ? module_for((uintptr_t)cur, &mo) : NULL;
            snprintf(b, sizeof(b), "  EVTCHK appCls=%s sendEventIMP=%s+0x%lx\n",
                     realCls ? class_getName(realCls) : "nil", mn ? mn : "?",
                     (unsigned long)mo);
            log_raw(b);
#if AIA_EVENT_PROBE
            if (i == 0) dump_jm_swizzles();
#endif
        }
    }
    return NULL;
}


// 观测事件入口：判断"点击无反应"时事件根本没送到 App，还是送到了但被丢弃。
static void (*orig_app_sendEvent)(id, SEL, UIEvent *);
__attribute__((unused)) static void my_app_sendEvent(id self, SEL _cmd, UIEvent *ev) {
    static int n;
    if (n < 200) {
        char b[160];
        snprintf(b, sizeof(b), "EVT UIApplication sendEvent type=%ld n=%d\n",
                 (long)ev.type, n + 1);
        log_raw(b);
        n++;
    }
    orig_app_sendEvent(self, _cmd, ev);
}

static void (*orig_win_sendEvent)(id, SEL, UIEvent *);
__attribute__((unused)) static void my_win_sendEvent(id self, SEL _cmd, UIEvent *ev) {
    static int n;
    g_evt_count++;
    if (ev && ev.type == UIEventTypeTouches) g_evt_touch++;
    if (n < 200) {
        char b[200];
        snprintf(b, sizeof(b), "EVT UIWindow sendEvent type=%ld win=%s n=%d\n",
                 (long)ev.type, object_getClassName(self), n + 1);
        log_raw(b);
        n++;
    }
    orig_win_sendEvent(self, _cmd, ev);
}

__attribute__((unused)) static void install_event_probe(void) {
    MSHookMessageEx(objc_getClass("UIApplication"),
                    @selector(sendEvent:), (IMP)my_app_sendEvent, (IMP *)&orig_app_sendEvent);
    MSHookMessageEx(objc_getClass("UIWindow"),
                    @selector(sendEvent:), (IMP)my_win_sendEvent, (IMP *)&orig_win_sendEvent);
    log_raw("event probe installed\n");
}

static void start_stats_thread(void) {
    static int started;
    if (started) return;
    started = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, aia_stats, NULL) == 0) pthread_detach(t);
}
#if AIA_EXC_BAIL
static void aia_thread_bail(void);
#endif
static uint64_t thread_id_of(mach_port_t th) {
    struct thread_identifier_info tii;
    mach_msg_type_number_t cnt = THREAD_IDENTIFIER_INFO_COUNT;
    if (thread_info(th, THREAD_IDENTIFIER_INFO, (thread_info_t)&tii, &cnt) != KERN_SUCCESS) return 0;
    return tii.thread_id;
}

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
    uint64_t ftid = thread_id_of(thrPort);
    snprintf(buf, sizeof(buf),
             "EXCFAULT main=%d thrId=%llu mainTid=%llu id=%d size=%u thr=%u task=%u type=%d codeCnt=%u code0=%lld code1=%lld flavor=%u stateCnt=%u\n",
             (int)(ftid && ftid == g_main_tid), (unsigned long long)ftid, (unsigned long long)g_main_tid,
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
    // 主线程故障时走一遍帧指针链：栈扫描会给出一堆陈旧值，帧链才是真实调用路径。
    if (ftid && ftid == g_main_tid) {
        uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(st));
        for (int d = 0; d < 64 && fp; d++) {
            uintptr_t prev = 0, ra = 0;
            if (!safe_read(fp, &prev) || !safe_read(fp + 8, &ra)) break;
            prev = aia_strip_pac(prev);
            ra = aia_strip_pac(ra);
            if (!ra) break;
            uintptr_t po = 0;
            const char *pm = module_for(ra, &po);
            if (pm) {
                snprintf(buf, sizeof(buf), "  FP#%02d %s+0x%lx\n", d, pm, (unsigned long)po);
                log_raw(buf);
            }
            if (prev <= fp) break;
            fp = prev;
        }
    }
    int found = 0;
    int main_thread = (ftid && ftid == g_main_tid);
    int limit = main_thread ? 64 : 24;
    size_t span = main_thread ? 0x4000 : 0x2000;
    for (size_t i = 0; i < span / sizeof(uintptr_t) && found < limit; i++) {
        uintptr_t v = 0;
        if (!safe_read(sp + i * sizeof(uintptr_t), &v)) break;
        uintptr_t voff = 0;
        const char *vm = module_for(v, &voff);
        if (!vm || voff == 0) continue;
        // 主线程多打印系统库：需要看清是哪条 App/系统调用路径进了 JM。
        if (!main_thread && !strstr(vm, "JMCodeProtectKit") && !strstr(vm, "KYHAppStore")) continue;
        if (main_thread && strstr(vm, "libsystem_") && voff == 0) continue;
        snprintf(buf, sizeof(buf), "  stack[+0x%zx] %p %s+0x%lx\n",
                 i * 8, (void *)v, vm, (unsigned long)voff);
        log_raw(buf);
        found++;
    }
}

#if AIA_EXC_BAIL
// 故障线程被重定向到这里：直接结束该线程，让 pthread 清理路径归还它持有的锁。
__attribute__((noinline, used)) static void aia_thread_bail(void) {
    pthread_exit(NULL);
    for (;;) { }
}
#endif

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
        g_exc_count++;
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
#if AIA_EXC_BAIL
        if (!(g_main_tid && thread_id_of(*(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF)) == g_main_tid)) {
            // 非主线程：送到一个只做 pthread_exit 的桩函数，让它正常结束。
            static char buf2[sizeof(arm_thread_state64_t) + 64];
            memcpy(buf2, (const char *)req + EXC_STATE_BODY_OFF,
                   sizeof(arm_thread_state64_t));
            arm_thread_state64_t *st = (arm_thread_state64_t *)buf2;
            uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*st);
            __darwin_arm_thread_state64_set_pc_fptr(*st, (void *)aia_thread_bail);
            __darwin_arm_thread_state64_set_lr_fptr(*st, (void *)0);
            st->__x[0] = 0;
            static int bail_logged;
            if (bail_logged < 20) {
                char b[128];
                snprintf(b, sizeof(b), "  bail: pc %#lx -> aia_thread_bail\n",
                         (unsigned long)oldpc);
                log_raw(b);
                bail_logged++;
            }
            rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
            rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
            rep->Head.msgh_local_port = MACH_PORT_NULL;
            rep->Head.msgh_id = req->Head.msgh_id + 100;
            rep->NDR = NDR_record;
            rep->RetCode = KERN_SUCCESS;
            rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
            memcpy(rep->new_state, buf2, sizeof(arm_thread_state64_t));
            rep->Head.msgh_size = 8 + 8 + 4 + 4 + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
            kern_return_t sk = mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                                        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (bail_logged < 20) {
                char b[96];
                snprintf(b, sizeof(b), "  bail: reply=%d size=%u\n", sk, rep->Head.msgh_size);
                log_raw(b);
            }
            memset(req, 0, rcv + 2048);
            continue;
        }
#endif
#if AIA_EXC_RECOVER_MAIN
        // 主线程的非法跳转：把 PC 改成 LR，模拟这次调用正常返回。
        // JM 破坏对象 isa 后发消息，最终 blr 到一个被截断的指针（例如 0x99ccd258），
        // 主线程如果一直不回复就永久挂起，界面从此失去响应。
        {
            const uint8_t *bb = (const uint8_t *)req;
            uint32_t flavor2 = *(const uint32_t *)(bb + EXC_FLAVOR_OFF);
            uint32_t sc2 = *(const uint32_t *)(bb + EXC_STATE_OFF);
            uint64_t ftid = thread_id_of(*(const uint32_t *)(bb + EXC_THREAD_OFF));
            if (g_main_tid && ftid == g_main_tid && flavor2 == 6 && sc2 >= 34) {
                memcpy(rep->new_state, bb + EXC_STATE_BODY_OFF, sizeof(arm_thread_state64_t));
                arm_thread_state64_t *nst = (arm_thread_state64_t *)rep->new_state;
                uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*nst);
                uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(*nst);
                static int rec_logged;
                if (rec_logged < 40) {
                    char b[192];
                    uintptr_t lo = 0;
                    const char *lm = module_for(lr, &lo);
                    snprintf(b, sizeof(b), "  RECOVERMAIN pc=%#lx -> lr=%s+0x%lx\n",
                             (unsigned long)oldpc, lm ? lm : "?", (unsigned long)lo);
                    log_raw(b);
                    rec_logged++;
                }
#if AIA_EXC_RECOVER_FAULT
                __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)lr);
#else
                memset(req, 0, rcv + 2048);
                continue;
#endif
                rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
                rep->Head.msgh_local_port = MACH_PORT_NULL;
                rep->Head.msgh_id = req->Head.msgh_id + 100;
                rep->NDR = NDR_record;
                rep->RetCode = KERN_SUCCESS;
                rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
                rep->Head.msgh_size = 8 + 8 + 4 + 4 + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
                mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                memset(req, 0, rcv + 2048);
                continue;
            }
        }
#endif
#if AIA_EXC_SKIP_BRK
        // 断点异常（brk / brk #0xdead 断言桩）：把 PC 推到下一条指令再回复，
        // 线程继续执行而不是被永久挂起。这是"能启动 + 主线程不卡死"的关键。
        {
            const uint8_t *bb = (const uint8_t *)req;
            int etype2 = (int)*(const uint32_t *)(bb + EXC_TYPE_OFF);
            uint32_t flavor2 = *(const uint32_t *)(bb + EXC_FLAVOR_OFF);
            uint32_t sc2 = *(const uint32_t *)(bb + EXC_STATE_OFF);
            if (etype2 == 6 && flavor2 == 6 && sc2 >= 34) {
                memcpy(rep->new_state, bb + EXC_STATE_BODY_OFF, sizeof(arm_thread_state64_t));
                arm_thread_state64_t *nst = (arm_thread_state64_t *)rep->new_state;
                uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*nst);
                __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)(oldpc + 4));
                static int skip_logged;
                if (skip_logged < 40) {
                    char b[160];
                    uintptr_t so = 0;
                    const char *sm = module_for(oldpc, &so);
                    snprintf(b, sizeof(b), "  SKIPBRK pc=%s+0x%lx -> +4\n",
                             sm ? sm : "?", (unsigned long)so);
                    log_raw(b);
                    skip_logged++;
                }
                rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
                rep->Head.msgh_local_port = MACH_PORT_NULL;
                rep->Head.msgh_id = req->Head.msgh_id + 100;
                rep->NDR = NDR_record;
                rep->RetCode = KERN_SUCCESS;
                rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
                rep->Head.msgh_size = 8 + 8 + 4 + 4 + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
                mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                memset(req, 0, rcv + 2048);
                continue;
            }
        }
#endif
#if AIA_EXC_NO_REPLY
        // 不回复：故障线程留在异常状态，内核不会让它继续执行，JM 的处决也不会生效。
        g_exc_noreply++;
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

// 判断某个地址是否落在 JMCodeProtectKit 里：JM 若 swizzle 了事件入口，
// 对应方法的 IMP 就会指向这个镜像。
static int jm_contains(uintptr_t a, uintptr_t *off) {
    uintptr_t lo = 0;
    const char *m = module_for(a, &lo);
    if (m && strstr(m, "JMCodeProtectKit")) { if (off) *off = lo; return 1; }
    return 0;
}

// 扫描一组与触摸/事件相关的类，列出 IMP 落在 JM 里的方法。
__attribute__((unused)) static void dump_jm_swizzles(void) {
    char buf[256];
    const char *names[] = {
        "UIApplication", "UIWindow", "UIView", "UIResponder", "UIControl",
        "UIEvent", "UITouch", "UIGestureRecognizer", "UIGestureEnvironment",
        "UIScreen", "UIWindowScene", "UIApplicationSceneSettings", NULL
    };
    int hits = 0;
    for (int i = 0; names[i]; i++) {
        Class c = objc_getClass(names[i]);
        if (!c) continue;
        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass((id)c) : c;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(target, &n);
            for (unsigned int k = 0; k < n; k++) {
                IMP imp = method_getImplementation(ms[k]);
                uintptr_t off = 0;
                if (!jm_contains((uintptr_t)imp, &off)) continue;
                snprintf(buf, sizeof(buf), "  SWZ %s%s%s -> JM+0x%lx\n",
                         meta ? "+" : "-", names[i],
                         sel_getName(method_getName(ms[k])), (unsigned long)off);
                log_raw(buf);
                hits++;
            }
            if (ms) free(ms);
        }
    }
    snprintf(buf, sizeof(buf), "  SWZ total=%d\n", hits);
    log_raw(buf);
}

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
    dump_jm_swizzles();
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
            // x29 帧链比栈扫描可靠：fp[0] 是上一帧 fp，fp[1] 是返回地址
            uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(st));
            for (int d = 0; d < 40 && fp; d++) {
                uintptr_t prev = 0, ra = 0;
                if (!safe_read(fp, &prev) || !safe_read(fp + 8, &ra)) break;
                prev = aia_strip_pac(prev);
                ra = aia_strip_pac(ra);
                uintptr_t o2 = 0;
                const char *m2 = module_for(ra, &o2);
                snprintf(buf, sizeof(buf), "    fp#%02d %s+0x%lx (%p)\n", d,
                         m2 ? m2 : "?", (unsigned long)o2, (void *)ra);
                log_raw(buf);
                if (prev <= fp) break;
                fp = prev;
            }
            snprintf(buf, sizeof(buf), "    x0=%#lx x1=%#lx x16=%#lx\n",
                     (unsigned long)st.__x[0], (unsigned long)st.__x[1],
                     (unsigned long)st.__x[16]);
            log_raw(buf);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    log_raw("=== DUMP END ===\n");
}
#endif

__attribute__((unused)) // 观测 task_info：JM 可能用 TASK_DYLD_INFO 直接读原始镜像表，绕过全部 _dyld_* hook。
static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static kern_return_t my_task_info(task_name_t target, task_flavor_t flavor, task_info_t info, mach_msg_type_number_t *cnt) {
    kern_return_t r = orig_task_info(target, flavor, info, cnt);
    const char *who = caller_desc(__builtin_return_address(0));
    if (flavor == TASK_DYLD_INFO) {
        aialog("task_info(TASK_DYLD_INFO) -> %d caller=%s", r, who);
    }
    return r;
}

// 记录接管之前谁持有异常端口。JM 若自己也装了处理器，抢走它可能破坏它的控制流。
__attribute__((unused)) static void log_exception_port_owners(const char *tag) {
    struct { const char *name; exception_mask_t mask; } items[] = {
        {"BAD_ACCESS", EXC_MASK_BAD_ACCESS},
        {"BAD_INSTRUCTION", EXC_MASK_BAD_INSTRUCTION},
        {"BREAKPOINT", EXC_MASK_BREAKPOINT},
        {"CORPSE_NOTIFY", EXC_MASK_CORPSE_NOTIFY},
        {"SYS", EXC_MASK_SYSCALL},
        {"GUARD", EXC_MASK_GUARD},
    };
    char b[192];
    for (unsigned i = 0; i < sizeof(items)/sizeof(items[0]); i++) {
        exception_mask_t masks[8] = {0};
        mach_msg_type_number_t cnt = 8;
        exception_handler_t handlers[8] = {0};
        exception_behavior_t behaviors[8] = {0};
        thread_state_flavor_t flavors[8] = {0};
        kern_return_t kr = task_get_exception_ports(mach_task_self(), items[i].mask,
                                                    masks, &cnt, handlers, behaviors, flavors);
        if (kr != KERN_SUCCESS) {
            snprintf(b, sizeof(b), "EXCPORT %s %s: query=%d\n", tag, items[i].name, kr);
            log_raw(b);
            continue;
        }
        snprintf(b, sizeof(b), "EXCPORT %s %s: cnt=%u", tag, items[i].name, (unsigned)cnt);
        log_raw(b);
        for (mach_msg_type_number_t k = 0; k < cnt && k < 8; k++) {
            snprintf(b, sizeof(b), "    port=%u beh=%d flavor=%d mask=%#x\n",
                     (unsigned)handlers[k], (int)behaviors[k], (int)flavors[k],
                     (unsigned)masks[k]);
            log_raw(b);
        }
    }
}


// ============================================================
// 阻断 Dynatrace 的 swizzle
// ============================================================
// Dynatrace 是纯埋点框架，它会 swizzle App 的方法去采集数据。被 swizzle 的
// App 方法如果由 JMCodeProtectKit 保护，调用会走 ijm 导入绑定器进 VM，
// 而 VM 在本进程里解出越界操作码直接跳飞（主线程一挂，界面就再没有触摸响应）。
// 这里把来源在 Dynatrace 里的 IMP 全部拒掉，让它的埋点装不上。
#ifndef AIA_BLOCK_DYNATRACE
#define AIA_BLOCK_DYNATRACE 1
#endif

#if AIA_BLOCK_DYNATRACE
static int imp_from_dynatrace(IMP imp) {
    if (!imp) return 0;
    uintptr_t off = 0;
    const char *m = module_for((uintptr_t)imp, &off);
    return m && strstr(m, "Dynatrace");
}

static IMP (*orig_method_setImplementation)(Method, IMP);
static IMP my_method_setImplementation(Method m, IMP imp) {
    if (imp_from_dynatrace(imp)) {
        char b[224];
        uintptr_t off = 0;
        const char *mod = module_for((uintptr_t)imp, &off);
        snprintf(b, sizeof(b), "  DT-BLOCK method_setImplementation %s %s+0x%lx\n",
                 m ? sel_getName(method_getName(m)) : "?", mod ? mod : "?",
                 (unsigned long)off);
        log_raw(b);
        return m ? method_getImplementation(m) : NULL;
    }
    return orig_method_setImplementation(m, imp);
}

static void (*orig_method_exchangeImplementations)(Method, Method);
static void my_method_exchangeImplementations(Method a, Method b) {
    if (a && b && (imp_from_dynatrace(method_getImplementation(a)) ||
                   imp_from_dynatrace(method_getImplementation(b)))) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK exchange %s <-> %s\n",
                 sel_getName(method_getName(a)), sel_getName(method_getName(b)));
        log_raw(buf);
        return;
    }
    orig_method_exchangeImplementations(a, b);
}

static BOOL (*orig_class_addMethod)(Class, SEL, IMP, const char *);
static BOOL my_class_addMethod(Class c, SEL sel, IMP imp, const char *types) {
    if (imp_from_dynatrace(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK class_addMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return NO;
    }
    return orig_class_addMethod(c, sel, imp, types);
}

static IMP (*orig_class_replaceMethod)(Class, SEL, IMP, const char *);
static IMP my_class_replaceMethod(Class c, SEL sel, IMP imp, const char *types) {
    if (imp_from_dynatrace(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK class_replaceMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return c ? (IMP)class_getMethodImplementation(c, sel) : (IMP)NULL;
    }
    return orig_class_replaceMethod(c, sel, imp, types);
}

__attribute__((unused)) static void install_dynatrace_block(void) {
    MSHookFunction((void *)method_setImplementation, (void *)my_method_setImplementation,
                   (void **)&orig_method_setImplementation);
    MSHookFunction((void *)method_exchangeImplementations, (void *)my_method_exchangeImplementations,
                   (void **)&orig_method_exchangeImplementations);
    MSHookFunction((void *)class_addMethod, (void *)my_class_addMethod,
                   (void **)&orig_class_addMethod);
    MSHookFunction((void *)class_replaceMethod, (void *)my_class_replaceMethod,
                   (void **)&orig_class_replaceMethod);
    aialog("dynatrace block installed");
}
#endif


static uintptr_t app_base(void);

// ============================================================
// 让 App 的 ijm 保护埋点方法直接返回 nil
// ============================================================
// App 在埋点里调用 requstQueryTaskStateInfo / requstQueryUserOtherInfo 这类方法，
// 它们的实现由 JMCodeProtectKit 的 ijm VM 接管。VM 在本进程里把导入绑定器的代码区
// 当成字节码解释，解出越界的跳转表项后跳飞。这些方法只是埋点，直接返回 nil 即可。
#ifndef AIA_NEUTER_IJM
#define AIA_NEUTER_IJM 1
#endif

#if AIA_NEUTER_IJM
static id aia_return_nil(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return nil;
}

static BOOL aia_return_no(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return NO;
}

// 一个方法的实现是否落在 ijm 保护桩区域（KYHAppStore 里那段导入绑定器）。
static int imp_is_ijm_stub(IMP imp, uintptr_t *off_out) {
    uintptr_t a = (uintptr_t)imp;
    uintptr_t base = app_base();
    if (!base || a < base) return 0;
    uintptr_t off = a - base;
    if (off_out) *off_out = off;
    return off >= 0x7c5400 && off < 0x7c5700;
}

__attribute__((unused)) static void neuter_ijm_telemetry(void) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return;
    Class *classes = (Class *)calloc((size_t)total, sizeof(Class));
    if (!classes) return;
    total = objc_getClassList(classes, total);
    char b[256];
    int hit = 0;
    for (int i = 0; i < total; i++) {
        Class c = classes[i];
        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass((id)c) : c;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(target, &n);
            if (!ms) continue;
            for (unsigned int k = 0; k < n; k++) {
                IMP imp = method_getImplementation(ms[k]);
                uintptr_t off = 0;
                if (!imp_is_ijm_stub(imp, &off)) continue;
                const char *name = sel_getName(method_getName(ms[k]));
                BOOL isBool = strstr(name, "is") == name || strstr(name, "has") == name;
                snprintf(b, sizeof(b), "  IJM %s%s%s stub=+0x%lx\n",
                         meta ? "+" : "-", class_getName(c), name, (unsigned long)off);
                log_raw(b);
                if (!meta) {
                    MSHookMessageEx(c, method_getName(ms[k]),
                                    isBool ? (IMP)aia_return_no : (IMP)aia_return_nil, NULL);
                    hit++;
                }
            }
            free(ms);
        }
    }
    snprintf(b, sizeof(b), "IJM total methods neutered=%d\n", hit);
    log_raw(b);
    free(classes);
}
#endif


// ============================================================
// ijm 导入绑定器：把非法桩值改写为合法值
// ============================================================
// KYHAppStore 里所有 ijm 保护的导入都走同一段绑定器：
//   adr x15, #0x7c54b0     ; 元数据表
//   ...
//   cbz x15, #0x7c55f8     ; 绑定失败 -> brk #0xdead
//   cbz x14, #0x7c55f8
// x15 来自绑定器回调的返回值，为 0 就断言。观测到的失败现场里 x15 一直是 0，
// 而 VM 继续拿着 0 当游标去解字节码，最终跳飞。
// 这里 hook 绑定器入口，把 0 换成元数据表里记录的合法桩地址。
#ifndef AIA_PATCH_BINDER_VALUE
#define AIA_PATCH_BINDER_VALUE 1
#endif
// 1 = 把 ijm 绑定器失败出口的 brk #0xdead 补成 NOP。
// 实测有害：brk 之后 0x7c55fc 的上下文恢复依赖一个并不存在的现场，
// 补掉后失败路径会继续跑到无效代码，App 启动即闪退。
// 正确做法是让异常端口接住这条 brk（AIA_EXC_SKIP_BRK）。
#ifndef AIA_NOP_IJM_BRK
#define AIA_NOP_IJM_BRK 0
#endif

#if AIA_PATCH_BINDER_VALUE
// 绑定器入口在 KYHAppStore+0x7c5508，调用者用 x13=元数据槽、x14=桩、x15=期望值。
// 直接在 0x7c5590 的 cbz x15 上做不了（静态代码不可改，__TEXT 只读），
// 所以改为 hook 绑定器回调 0x7c5588 里 blr 出去的那个函数——它是 ijm 运行时的
// 导入解析器。解析失败的判据是返回 0，我们改成返回元数据表里的 PTR。
__attribute__((unused)) static void patch_binder_zero_values(void) {
    uintptr_t base = app_base();
    if (!base) { log_raw("BINDER no app base\n"); return; }
    // 元数据表在 0x7c54b0：+0x0 BOFF +0x8 ?? +0x10 PTR +0x18 SUPERV +0x20 SLOT
    const uint64_t *meta = (const uint64_t *)(base + 0x7c54b0);
    char b[224];
    snprintf(b, sizeof(b), "BINDER meta boff=%#llx a=%#llx ptr=%#llx sup=%#llx slot=%#llx\n",
             (unsigned long long)meta[0], (unsigned long long)meta[1],
             (unsigned long long)meta[2], (unsigned long long)meta[3],
             (unsigned long long)meta[4]);
    log_raw(b);
    // 绑定器代码区在只读段，改不了；只把观察到的槽位值打出来供后续判断。
    uintptr_t slot = (uintptr_t)meta[3] ? (uintptr_t)meta[3] : (uintptr_t)meta[4];
    snprintf(b, sizeof(b), "BINDER slotptr=%#lx\n", (unsigned long)slot);
    log_raw(b);
}
#endif


// ============================================================
// 关掉 Dynatrace 的 swizzle 配置器
// ============================================================
// Dynatrace 通过 +[DTXSwizzleDetectionConfigurator addClass:selectors:detector:
// updateImplementation:] 这类方法批量往 App 的类上装 IMP。被装上的 App 方法如果由
// ijm VM 实现，Dynatrace 回调原实现时会走导入绑定器，而绑定器在本进程里解析失败，
// 主线程直接撞 brk #0xdead 或跳飞。
// 这里把这个配置器的 add* 类方法全部变成空操作，Dynatrace 就一个 hook 都装不上。
// 实测有害：把 add* 变空操作会破坏 Dynatrace 的自洽状态，App 能起但界面不再
// 响应触摸（视图树只剩三层系统容器）。默认关闭。
#ifndef AIA_KILL_DT_SWIZZLE
#define AIA_KILL_DT_SWIZZLE 0
#endif

#if AIA_KILL_DT_SWIZZLE
static int g_dt_swizzle_killed;

static void aia_noop_void(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    if (g_dt_swizzle_killed < 80) {
        char b[160];
        snprintf(b, sizeof(b), "  DT-KILL %s\n", sel_getName(_cmd));
        log_raw(b);
        g_dt_swizzle_killed++;
    }
}

__attribute__((unused)) static void kill_dt_swizzle(void) {
    // 1) 配置器上的所有 add* 类方法
    Class cfg = objc_getClass("DTXSwizzleDetectionConfigurator");
    int n_hooked = 0;
    if (cfg) {
        Class meta = object_getClass((id)cfg);
        unsigned int n = 0;
        Method *ms = class_copyMethodList(meta, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = sel_getName(method_getName(ms[i]));
            if (strncmp(nm, "add", 3) != 0) continue;
            MSHookMessageEx(cfg, method_getName(ms[i]), (IMP)aia_noop_void, NULL);
            n_hooked++;
        }
        if (ms) free(ms);
    }
    // 2) 首屏启动时批量 swizzle UIKit 的那一步
    Class sm = objc_getClass("DTXStartupMeasurements");
    if (sm) {
        SEL sel = sel_registerName("swizzleUIKitClasses");
        if (class_getClassMethod(sm, sel))
            MSHookMessageEx(sm, sel, (IMP)aia_noop_void, NULL);
    }
    char b[160];
    snprintf(b, sizeof(b), "DT-KILL installed cfg=%s hooked=%d\n",
             cfg ? "yes" : "no", n_hooked);
    log_raw(b);
}
#endif

__attribute__((unused)) static void install_exc_handler(void) {
    log_exception_port_owners("pre");
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
    log_exception_port_owners("post");
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
    {
        struct thread_identifier_info tii;
        mach_msg_type_number_t c = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(mach_thread_self(), THREAD_IDENTIFIER_INFO, (thread_info_t)&tii, &c) == KERN_SUCCESS)
            g_main_tid = tii.thread_id;
    }
    aialog("module snapshot: %d mainTid=%llu", g_mod_count, (unsigned long long)g_main_tid);
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
#if AIA_OBSERVE_ONLY
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
    MSHookFunction((void *)getsectiondata, (void *)my_getsectiondata, (void **)&orig_getsectiondata);
    MSHookFunction((void *)NSClassFromString, (void *)my_NSClassFromString, (void **)&orig_NSClassFromString);
    MSHookFunction((void *)objc_getClass, (void *)my_objc_getClass, (void **)&orig_objc_getClass);
    MSHookFunction((void *)dlsym, (void *)my_dlsym, (void **)&orig_dlsym);
    MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&orig_exit);
    MSHookFunction((void *)_exit, (void *)my_Exit, (void **)&orig_Exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&orig_abort);
    MSHookFunction((void *)kill, (void *)my_kill, (void **)&orig_kill);
    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
    aialog("observe-only mode: safe hook subset installed");
    return;
#endif
#if AIA_EMPTY
    // 观测模式：不装任何会改变行为的 hook，只额外记录 task_info 与资源统计。
    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
#if AIA_EVENT_PROBE
    install_event_probe();
    aialog("empty mode: no hooks (含事件观测)");
#else
    aialog("empty mode: no hooks (无事件观测)");
#endif
#if AIA_BLOCK_DYNATRACE
    install_dynatrace_block();
#endif
#if AIA_KILL_DT_SWIZZLE
    kill_dt_swizzle();
#endif
#if AIA_PATCH_BINDER_VALUE
    patch_binder_zero_values();
#endif
#if AIA_NOP_IJM_BRK
    // 绑定器失败出口 KYHAppStore+0x7c55f8 是 brk #0xdead，主线程撞上就会被 SIGTRAP 打死。
    // 补成 NOP 后继续走 0x7c55fc 的 nop 和 0x7c5600 的上下文恢复代码。
    patch_app_code(0x7c55f8, 0xd43bd5a0, 0xd503201f, "ijm-brk");
#endif
#if AIA_NEUTER_IJM
    // 稍等片刻：App 的类和分类要等首屏建起来才齐。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ neuter_ijm_telemetry(); });
#endif
    start_stats_thread();
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

    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
    aialog("hooks installed; image_count=%u", orig_dyld_image_count ? orig_dyld_image_count() : 0);
    start_stats_thread();
}
