// HSBCBypass —— AppSecurityMonitor 检测观测版
//
// 目标:汇丰中国 (cn.com.hsbc.hsbcchina) / 汇丰香港 (hk.com.hsbc.hsbchkmobilebanking)
// 检测核心 = OneSpan RASP 的 Swift 类 `AppSecurityMonitor`
//   (ObjC 名 `_TtC15WithOneSpanRASP18AppSecurityMonitor`)。
// 该类暴露一组 ObjC 检测方法(jailbreakStatus:/libraryInjectionDetected/... 见 analysis.md)。
// 本版本 hook 这些方法做「观测」:记录调用顺序 + 参数 + 返回值,据此确定"安全"返回值,
// 再改为始终返回未检测到。纯观测,先不改行为。

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <pthread.h>
#import <dlfcn.h>
#import <execinfo.h>

// 日志写沙盒文件(设备无 syslog 工具,靠文件回捞)
static void hsbc_log(NSString *line) {
    static NSString *path = nil;
    if (!path) path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"hsbc_probe_%d.log", getpid()]];
    NSString *e = [line stringByAppendingString:@"\n"];
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (f) { fwrite(e.UTF8String, 1, strlen(e.UTF8String), f); fclose(f); }
    NSLog(@"[HSBCBypass] %@", line);
}
#define HSBCLOG(fmt, ...) hsbc_log([NSString stringWithFormat:(fmt), ##__VA_ARGS__])

static NSString *const kMonitorClass = @"_TtC15WithOneSpanRASP18AppSecurityMonitor";

// ---- 观测:带一个参数、返回标量(疑 Bool/枚举)的方法 jailbreakStatus: 等 ----
// 由 thunk 反汇编:方法接收 x2 参数,返回 x0(值)。用 IMP 直接替换记录。

// 保存各方法原 IMP
static IMP orig_imps[16];
static const char *sel_names[16];
static int n_hooked = 0;

// 通用观测:返回值当作 intptr_t 原始记录(不解引用,避免 Swift 标量当对象崩溃)
static intptr_t observe_arg_ret(id self, SEL _cmd, intptr_t arg) {
    int idx = -1;
    for (int i = 0; i < n_hooked; i++)
        if (sel_getName(_cmd) && strcmp(sel_names[i], sel_getName(_cmd)) == 0) { idx = i; break; }
    intptr_t r = ((intptr_t(*)(id,SEL,intptr_t))orig_imps[idx])(self, _cmd, arg);
    HSBCLOG(@"→ -[AppSecurityMonitor %s] arg=0x%lx ret=0x%lx", sel_getName(_cmd), arg, r);
    return r;
}
static intptr_t observe_noarg_ret(id self, SEL _cmd) {
    int idx = -1;
    for (int i = 0; i < n_hooked; i++)
        if (sel_getName(_cmd) && strcmp(sel_names[i], sel_getName(_cmd)) == 0) { idx = i; break; }
    intptr_t r = ((intptr_t(*)(id,SEL))orig_imps[idx])(self, _cmd);
    HSBCLOG(@"→ -[AppSecurityMonitor %s] ret=0x%lx", sel_getName(_cmd), r);
    return r;
}

static void hook_method(Class cls, const char *name, BOOL hasArg) {
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { HSBCLOG(@"⚠ 方法不存在: %s", name); return; }
    if (n_hooked >= 16) return;
    sel_names[n_hooked] = strdup(name);
    IMP newimp = hasArg ? (IMP)observe_arg_ret : (IMP)observe_noarg_ret;
    orig_imps[n_hooked] = method_setImplementation(m, newimp);
    HSBCLOG(@"已 hook -[AppSecurityMonitor %s] (hasArg=%d)", name, hasArg);
    n_hooked++;
}

static void hsbc_hook_monitor(void) {
    Class cls = NSClassFromString(kMonitorClass);
    if (!cls) { HSBCLOG(@"⚠ 未找到类 %@", kMonitorClass); return; }
    HSBCLOG(@"找到 AppSecurityMonitor 类 %p", (void *)cls);
    hook_method(cls, "jailbreakStatus:", YES);
    hook_method(cls, "repackagingStatus:", YES);
    hook_method(cls, "debuggerStatus:", YES);
    hook_method(cls, "developerModeStatus:", YES);
    hook_method(cls, "screenshotDetected", NO);
    hook_method(cls, "libraryInjectionDetected", NO);
    hook_method(cls, "hookingFrameworksDetected", NO);
    hook_method(cls, "emulatorDetected", NO);
}

#import <sys/mman.h>

// 回溯调用栈定位发起模块
static void hsbc_bt(const char *tag) {
    void *fr[16]; int n = backtrace(fr, 16);
    for (int i = 1; i < n && i < 8; i++) {
        Dl_info di;
        if (dladdr(fr[i], &di) && di.dli_fname) {
            const char *b = strrchr(di.dli_fname, '/'); b = b?b+1:di.dli_fname;
            HSBCLOG(@"    %s #%d %s +0x%lx", tag, i, b, (uintptr_t)fr[i]-(uintptr_t)di.dli_fbase);
        }
    }
}

// ---- hook mmap:抓 PROT_EXEC(生成可执行 stub 的必经路径)----
static void *(*orig_mmap)(void *, size_t, int, int, int, off_t);
static _Atomic int g_mmap_count = 0;
static void *my_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    void *r = orig_mmap(addr, len, prot, flags, fd, off);
    g_mmap_count++;
    if (prot & PROT_EXEC) {
        HSBCLOG(@"mmap RWX/RX len=0x%zx prot=%d → %p", len, prot, r);
        hsbc_bt("mmap");
    }
    return r;
}
// ---- hook mprotect:抓给内存加 EXEC 权限 ----
static int (*orig_mprotect)(void *, size_t, int);
static int my_mprotect(void *addr, size_t len, int prot) {
    if (prot & PROT_EXEC) {
        HSBCLOG(@"mprotect +EXEC addr=%p len=0x%zx prot=%d", addr, len, prot);
        hsbc_bt("mprotect");
    }
    return orig_mprotect(addr, len, prot);
}
// ---- hook mach 层 VM(比 libc 更底层,OneSpan 可能直接用);mach_vm.h 不可用,dlsym 取址 ----
#import <mach/mach.h>
#define VMP_EXEC 0x4  // VM_PROT_EXECUTE
static kern_return_t (*orig_mach_vm_protect)(mach_port_t, uint64_t, uint64_t, boolean_t, vm_prot_t);
static kern_return_t my_mach_vm_protect(mach_port_t t, uint64_t a, uint64_t s, boolean_t setmax, vm_prot_t prot) {
    if (prot & VMP_EXEC) { HSBCLOG(@"mach_vm_protect +EXEC addr=0x%llx len=0x%llx prot=%d", a, s, prot); hsbc_bt("mvp"); }
    return orig_mach_vm_protect(t, a, s, setmax, prot);
}
static kern_return_t (*orig_vm_protect)(mach_port_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static kern_return_t my_vm_protect(mach_port_t t, vm_address_t a, vm_size_t s, boolean_t setmax, vm_prot_t prot) {
    if (prot & VMP_EXEC) { HSBCLOG(@"vm_protect +EXEC addr=0x%lx len=0x%lx prot=%d", (unsigned long)a, (unsigned long)s, prot); hsbc_bt("vp"); }
    return orig_vm_protect(t, a, s, setmax, prot);
}

static void *hsbc_heartbeat(void *a) {
    for (int i = 0; ; i++) {
        if (i % 10 == 0) HSBCLOG(@"♥ #%d mmap计数=%d", i, g_mmap_count);
        usleep(10000);
    }
    return NULL;
}

// ---- hook pthread_create:记录新线程入口函数所属模块,定位检测线程 ----
static int (*orig_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int my_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*start)(void *), void *arg) {
    Dl_info di;
    if (dladdr((void *)start, &di) && di.dli_fname) {
        const char *b = strrchr(di.dli_fname, '/'); b = b?b+1:di.dli_fname;
        HSBCLOG(@"pthread_create → start=%p [%s +0x%lx] sym=%s",
                (void *)start, b, (uintptr_t)start - (uintptr_t)di.dli_fbase,
                di.dli_sname ? di.dli_sname : "?");
    } else {
        HSBCLOG(@"pthread_create → start=%p [未知模块]", (void *)start);
    }
    return orig_pthread_create(t, a, start, arg);
}

// 类可能晚加载:注册 dyld 回调,每次新 image 都尝试;并在 ctor 立即试一次
#import <mach-o/dyld.h>
static bool g_done = false;
static void try_hook(void) {
    if (g_done) return;
    Class cls = NSClassFromString(kMonitorClass);
    if (!cls) return;
    g_done = true;
    hsbc_hook_monitor();
}
static void on_image(const struct mach_header *mh, intptr_t slide) { try_hook(); }

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入: pid=%d bundle=%@", getpid(),
                [[NSBundle mainBundle] bundleIdentifier]);
        MSHookFunction((void *)pthread_create, (void *)my_pthread_create, (void **)&orig_pthread_create);
        MSHookFunction((void *)mmap, (void *)my_mmap, (void **)&orig_mmap);
        MSHookFunction((void *)mprotect, (void *)my_mprotect, (void **)&orig_mprotect);
        void *p_mvp = dlsym(RTLD_DEFAULT, "mach_vm_protect");
        if (p_mvp) MSHookFunction(p_mvp, (void *)my_mach_vm_protect, (void **)&orig_mach_vm_protect);
        void *p_vp = dlsym(RTLD_DEFAULT, "vm_protect");
        if (p_vp) MSHookFunction(p_vp, (void *)my_vm_protect, (void **)&orig_vm_protect);
        HSBCLOG(@"mach VM hook: mvp=%p vp=%p", p_mvp, p_vp);
        // 心跳:确认进程存活时长 + mmap hook 是否生效(计数)
        pthread_t hb;
        pthread_create(&hb, NULL, hsbc_heartbeat, NULL);
        pthread_detach(hb);
        try_hook();
        _dyld_register_func_for_add_image(&on_image);
        HSBCLOG(@"已注册 dyld 回调等待 AppSecurityMonitor + hook pthread_create");
    }
}
