// HSBCChinaBypass 1.0.0：让汇丰中国 3.75.0 在 rootless 越狱设备上可用。
//
// 目标：cn.com.hsbc.hsbcchina 3.75.0（build 129890），可执行文件 China.app/China。
// 环境：iPhone 13 Pro / iOS 15.4.1 / Dopamine + ElleKit（rootless）。
//
// 判定方是 ZDefend.framework（Zimperium）。它几乎不看越狱路径，判定只用了三样东西：
//
//   1. 自己导入了哪些 libc 函数、这些函数的实现有没有被换过（规则 apptampering_hooked）；
//   2. dlopen 的目标库有没有被换成 systemhook.dylib（规则 app_tampering_interposed）；
//   3. statfs("/usr/lib") 的挂载信息（规则 JB Dopamine-Roothide，读到 bindfs + .fakelib）。
//
// 判定完成后它起一条线程收拾后事并 exit(0)，PlatformRASP 再把 ZDefend 报的威胁
// 转成拦截页。本 tweak 做两件事：
//
//   a) 把 ZDefend 那条自杀线程的入口（+0x23a380）改成 ret，进程不再被打断；
//   b) 把 ObjC 层的威胁列表清空，PlatformRASP 拿不到威胁就不弹拦截页。
//
// 至于它读到的那些"证据"，本来就在这里——系统的 statfs 确实返回 bindfs，
// 我们自己装的 hook 也确实存在。第 1、2 项要彻底消除只能靠不注入任何 tweak，
// 而那与"用 tweak 干预"直接矛盾；这个矛盾记在 analysis.md 里，没有绕过。
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdio.h>
#import <stdarg.h>
#import <stdint.h>
#import <pthread.h>
#import <signal.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <libkern/OSCacheControl.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);
extern void MSHookMessageEx(Class cls, SEL sel, IMP imp, IMP *result);

// 日志开关跟着构建类型走：theos 的 debug 构建带 -DDEBUG（make package 默认走这条），
// release 构建（make package FINALPACKAGE=1）不带，所有日志调用被编译掉。
#ifndef HSBC_LOG_ENABLED
#ifdef DEBUG
#define HSBC_LOG_ENABLED 1
#else
#define HSBC_LOG_ENABLED 0
#endif
#endif

static int g_fd = -1;
static uint64_t g_t0;

static uint64_t now_ms(void) {
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    uint64_t d = mach_absolute_time() - g_t0;
    return d * tb.numer / tb.denom / 1000000ULL;
}

__attribute__((unused)) static void wf(const char *fmt, ...) {
    char b[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (g_fd >= 0) (void)!write(g_fd, b, strlen(b));
}

// ------------------------------------------------------------
// 镜像表
//
// dladdr 在这个进程里不可靠（systemhook 接管过 dlsym），自己维护一份。
// 共享缓存里的库是紧挨着排布的，用"最小始址～最大末址"这个边界框会把邻居也圈进来，
// 所以按段记录，落在哪一段就算谁的。
// ------------------------------------------------------------
#define IMG_MAX_SEGS 8
typedef struct {
    uintptr_t lo[IMG_MAX_SEGS];
    uintptr_t hi[IMG_MAX_SEGS];
    int nseg;
    uintptr_t base;
    const char *name;
} img_t;
static img_t g_img[2048];
static int g_imgn;

static void snap_images(void) {
    uint32_t n = _dyld_image_count();
    g_imgn = 0;
    for (uint32_t i = 0; i < n && g_imgn < 2048; i++) {
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *nm = _dyld_get_image_name(i);
        if (!h || !nm) continue;
        // 主程序的 vmaddr 是绝对地址（0x100000000 起），slide 为 0；
        // 其它库的 vmaddr 从 0 起，要加上 slide 才是运行时地址。
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        g_img[g_imgn].base = (uintptr_t)h;
        g_img[g_imgn].name = nm;
        g_img[g_imgn].nseg = 0;
        const uint8_t *p = (const uint8_t *)(h + 1);
        for (uint32_t k = 0; k < h->ncmds && g_img[g_imgn].nseg < IMG_MAX_SEGS; k++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                // __PAGEZERO 的 vmaddr=0、vmsize=4GB，算进去会把整个地址空间都圈进来。
                if (sg->vmsize && strcmp(sg->segname, "__PAGEZERO") != 0) {
                    g_img[g_imgn].lo[g_img[g_imgn].nseg] = (uintptr_t)(sg->vmaddr + slide);
                    g_img[g_imgn].hi[g_img[g_imgn].nseg] = (uintptr_t)(sg->vmaddr + sg->vmsize + slide);
                    g_img[g_imgn].nseg++;
                }
            }
            p += lc->cmdsize;
        }
        g_imgn++;
    }
}

__attribute__((unused)) static const char *mod_name(uintptr_t a, uintptr_t *off) {
    // arm64e 的返回地址带 PAC 签名，先削掉高位的签名位再比对。
    a &= 0x0000FFFFFFFFFFFFULL;
    for (int i = 0; i < g_imgn; i++) {
        for (int k = 0; k < g_img[i].nseg; k++) {
            if (a >= g_img[i].lo[k] && a < g_img[i].hi[k]) {
                if (off) *off = a - g_img[i].base;
                return g_img[i].name;
            }
        }
    }
    if (off) *off = 0;
    return NULL;
}

static uintptr_t find_image_base(const char *needle) {
    for (int i = 0; i < g_imgn; i++)
        if (strstr(g_img[i].name, needle)) return g_img[i].base;
    return 0;
}

__attribute__((unused)) static void log_images(const char *tag) {
    snap_images();
    wf("[%llums] ==== 镜像 %s 共 %d ====\n", (unsigned long long)now_ms(), tag, g_imgn);
    static const char *keys[] = { "ZDefend", "PlatformRASP", "systemhook", "ellekit",
                                  "TweakInject", "/China.app/China", NULL };
    for (int i = 0; i < g_imgn; i++) {
        for (int k = 0; keys[k]; k++) {
            if (strstr(g_img[i].name, keys[k])) {
                wf("  [%d] %s base=%#lx\n", i, g_img[i].name, (unsigned long)g_img[i].base);
                break;
            }
        }
    }
}

// ------------------------------------------------------------
// 手法一：改掉 ZDefend 的自杀线程入口
//
// 终止链是 ZDefend+0x23a3c8 → +0x23a380（在新线程里）→ +0x1e569c →
// mov w0,#0 / exit(0)。这个入口没有直接调用者，地址被写进结构体再起线程，
// 所以在入口改一条指令最省事：把第一条 stp 换成 ret，线程刚起来就结束。
//
// 试过但不行：改 +0x1e569c 内部那条"状态不对就 exit"的 b.eq。那样 App 能多活
// 十秒，随后变成 SIGILL —— 后续清理照常执行，破坏了别的状态。
// ------------------------------------------------------------
static int patch_word(uintptr_t addr, uint32_t val, const char *what) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = addr & ~(uintptr_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, ps, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        wf("[%llums] 补丁失败 %s：vm_protect=0x%x\n", (unsigned long long)now_ms(), what, kr);
        return -1;
    }
    uint32_t old = *(volatile uint32_t *)addr;
    *(volatile uint32_t *)addr = val;
    sys_icache_invalidate((void *)addr, 4);
    vm_protect(mach_task_self(), page, ps, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    wf("[%llums] 补丁 %s %#lx：%08x -> %08x\n", (unsigned long long)now_ms(),
       what, (unsigned long)addr, old, val);
    return 0;
}

static void patch_zd_killentry(void) {
    uintptr_t base = find_image_base("ZDefend.framework/ZDefend");
    if (!base) {
        wf("[%llums] 找不到 ZDefend 镜像\n", (unsigned long long)now_ms());
        return;
    }
    patch_word(base + 0x23a380, 0xD65F03C0, "ZDefend 自杀线程入口 ret");
}

// ------------------------------------------------------------
// 手法二：清空威胁列表
//
// 判定本身在 ZDefend 的 C++ 核心里，不走 ObjC；但平台层向外交付走的是这几个方法。
// 让它们返回空集合，PlatformRASP 与 App 就看不到任何威胁，也就不会弹拦截页。
//
// 这里只拦"读"，ZDefend 内部状态机不受影响，它照常跑自己的流程。
// ------------------------------------------------------------
static id (*o_get_all_threats)(id, SEL);
static id (*o_ds_all)(id, SEL);
static id (*o_ds_active)(id, SEL);
static id (*o_ds_active_new)(id, SEL);

static id my_get_all_threats(id self, SEL _cmd) {
    id v = o_get_all_threats ? o_get_all_threats(self, _cmd) : nil;
    wf("[%llums] 拦截 getAllThreats（原有 %lu 项），返回空\n",
       (unsigned long long)now_ms(), (unsigned long)(v ? [v count] : 0));
    return @[];
}
static id my_ds_all(id self, SEL _cmd) {
    id v = o_ds_all ? o_ds_all(self, _cmd) : nil;
    wf("[%llums] 拦截 allThreats（原有 %lu 项），返回空\n",
       (unsigned long long)now_ms(), (unsigned long)(v ? [v count] : 0));
    return @[];
}
static id my_ds_active(id self, SEL _cmd) {
    id v = o_ds_active ? o_ds_active(self, _cmd) : nil;
    wf("[%llums] 拦截 activeThreats（原有 %lu 项），返回空\n",
       (unsigned long long)now_ms(), (unsigned long)(v ? [v count] : 0));
    return @[];
}
static id my_ds_active_new(id self, SEL _cmd) {
    id v = o_ds_active_new ? o_ds_active_new(self, _cmd) : nil;
    wf("[%llums] 拦截 activeNewThreats（原有 %lu 项），返回空\n",
       (unsigned long long)now_ms(), (unsigned long)(v ? [v count] : 0));
    return @[];
}

static void clear_threats(void) {
    SEL all = sel_registerName("getAllThreats");
    Class zd = objc_getClass("ZDefend");
    Class impl = objc_getClass("ZDefendImpl");
    Class ds = objc_getClass("ZDeviceStatus");
    if (zd) MSHookMessageEx(object_getClass((id)zd), all, (IMP)my_get_all_threats,
                            (IMP *)&o_get_all_threats);
    if (impl) {
        // 两个类各有自己的方法，各挂一次；原实现都落到同一个指针上，
        // 因为两边最终都调 libobjc 保存下来的原实现。
        IMP prev = (IMP)o_get_all_threats;
        MSHookMessageEx(object_getClass((id)impl), all, (IMP)my_get_all_threats, &prev);
    }
    if (ds) {
        MSHookMessageEx(ds, sel_registerName("allThreats"), (IMP)my_ds_all, (IMP *)&o_ds_all);
        MSHookMessageEx(ds, sel_registerName("activeThreats"), (IMP)my_ds_active, (IMP *)&o_ds_active);
        MSHookMessageEx(ds, sel_registerName("activeNewThreats"), (IMP)my_ds_active_new,
                        (IMP *)&o_ds_active_new);
    }
    wf("[%llums] 威胁列表拦截已装（ZDefend=%p ZDefendImpl=%p ZDeviceStatus=%p）\n",
       (unsigned long long)now_ms(), zd, impl, ds);
}

// ------------------------------------------------------------
// 排查工具：把 ZDefend 的判定结果读出来
//
// 不进发布配置。需要重新排查时把 HSBC_DUMP_THREATS 改成 1。
// 3.75.0 上实测能读到 11 个威胁对象，每条都带 forensicJson，写明命中了哪条规则、
// 看到的是什么——analysis.md 第 78 轮的证据就是这份输出。
// ------------------------------------------------------------
#ifndef HSBC_DUMP_THREATS
#define HSBC_DUMP_THREATS 0
#endif

#if HSBC_DUMP_THREATS
static void dump_threats(id arr) {
    if (!arr) { wf("  (没有威胁对象)\n"); return; }
    NSUInteger n = [arr count];
    wf("  威胁对象 %lu 个\n", (unsigned long)n);
    for (NSUInteger i = 0; i < n; i++) {
        id t = [arr objectAtIndex:i];
        NSString *name = nil, *vec = nil;
        @try { name = [t valueForKey:@"humanThreatName"]; } @catch (id e) {}
        @try { vec  = [t valueForKey:@"threatVector"]; }   @catch (id e) {}
        wf("   [%lu] 名称=%s 向量=%s\n", (unsigned long)i,
           name ? [name UTF8String] : "-", vec ? [vec UTF8String] : "-");
        @try {
            id js = [t valueForKey:@"threatJson"];
            if (js) wf("        详情 = %s\n", [[js description] UTF8String]);
        } @catch (id e) {}
    }
}

// constructor 阶段 ZDefend 的 ObjC 类还没注册，必须等 App 起来之后再问。
static void ask_zdefend(void) {
    wf("[%llums] ======== 问 ZDefend ========\n", (unsigned long long)now_ms());
    Class impl = objc_getClass("ZDefendImpl");
    if (impl) {
        SEL s = sel_registerName("getLoginStatus");
        if ([impl respondsToSelector:s])
            wf("  getLoginStatus = %ld\n", ((long (*)(id, SEL))objc_msgSend)(impl, s));
        s = sel_registerName("getAllThreats");
        if ([impl respondsToSelector:s])
            dump_threats(((id (*)(id, SEL))objc_msgSend)(impl, s));
    }
    wf("[%llums] ======== 问完 ========\n", (unsigned long long)now_ms());
}

static void *late_thread(void *arg) {
    (void)arg;
    usleep(2500000); ask_zdefend();
    return NULL;
}
#endif

__attribute__((constructor)) static void probe_init(void) {
    g_t0 = mach_absolute_time();
#if HSBC_LOG_ENABLED
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (caches) {
        NSString *lp = [caches stringByAppendingPathComponent:@"hsbcchinabypass.log"];
        g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
#endif
    wf("===== HSBCChinaBypass 启动 pid=%d 日志=%s =====\n", getpid(), g_fd >= 0 ? "开" : "关");

    snap_images();
    patch_zd_killentry();
    clear_threats();

#if HSBC_DUMP_THREATS
    pthread_t t;
    if (pthread_create(&t, NULL, late_thread, NULL) == 0) pthread_detach(t);
#endif
}
