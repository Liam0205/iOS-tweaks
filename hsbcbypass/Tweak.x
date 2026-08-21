// HSBCBypass —— 多 SDK 检测动态插桩版（路径1:定位真凶）
//
// 汇丰装了多个风控 SDK(ThreatMetrix/Transmit/Turing/BioCatch...),各自做越狱检测。
// 真凶(触发秒退的)未定位。本版 hook 各 SDK 的检测入口 + TMXProfiling 的 svc wrapper,
// 运行时记录:谁被调用、传入什么路径、时序,借此定位触发退出的检测。

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <execinfo.h>
#import <pthread.h>

static double g_t0 = 0;
static void hsbc_log(NSString *line) {
    static NSString *path = nil;
    if (!path) path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"hsbc_probe_%d.log", getpid()]];
    NSString *e = [line stringByAppendingString:@"\n"];
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (f) { fwrite(e.UTF8String, 1, strlen(e.UTF8String), f); fclose(f); }
}
#define HSBCLOG(fmt, ...) do { \
    if (g_t0==0) g_t0=CFAbsoluteTimeGetCurrent(); \
    double dt=(CFAbsoluteTimeGetCurrent()-g_t0)*1000.0; \
    hsbc_log([NSString stringWithFormat:(@"[+%.0fms] " fmt), dt, ##__VA_ARGS__]); \
} while(0)

// 找 image 基址
static uintptr_t image_base(const char *name) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, name)) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// ---- TMXProfiling svc wrapper hook ----
// access wrapper @0x4a38: access(path[x0], mode[x1]) via svc; stat wrapper @0x197c0
static int (*orig_tmx_access)(const char *, int);
static int my_tmx_access(const char *p, int m) {
    int r = orig_tmx_access(p, m);
    HSBCLOG(@"TMX.access(\"%s\") = %d", p?p:"(null)", r);
    return r;
}
static int (*orig_tmx_stat)(const char *, void *);
static int my_tmx_stat(const char *p, void *st) {
    int r = orig_tmx_stat(p, st);
    HSBCLOG(@"TMX.stat(\"%s\") = %d", p?p:"(null)", r);
    return r;
}

__attribute__((unused)) static void hook_tmx(void) {
    uintptr_t base = image_base("TMXProfiling");
    if (!base) { HSBCLOG(@"TMX 未加载"); return; }
    HSBCLOG(@"TMXProfiling base=0x%lx", base);
    MSHookFunction((void *)(base + 0x4a38), (void *)my_tmx_access, (void **)&orig_tmx_access);
    MSHookFunction((void *)(base + 0x197c0), (void *)my_tmx_stat, (void **)&orig_tmx_stat);
    HSBCLOG(@"已 hook TMX access@0x4a38 stat@0x197c0");
}

// ---- 各 SDK 越狱判定入口 hook（记录被调用+返回值,先不改）----
// TransmitSDK3: _isJailbroken(导出C符号) / amIJailbroken(0x12b16c)
static int (*orig_tx_amIJail)(void);
static int my_tx_amIJail(void) {
    int r = orig_tx_amIJail();
    HSBCLOG(@"Transmit.amIJailbroken = %d", r);
    return r;
}

static void hook_transmit(void) {
    uintptr_t base = image_base("TransmitSDK3");
    if (!base) { HSBCLOG(@"Transmit 未加载"); return; }
    HSBCLOG(@"TransmitSDK3 base=0x%lx", base);
    MSHookFunction((void *)(base + 0x12b16c), (void *)my_tx_amIJail, (void **)&orig_tx_amIJail);
    HSBCLOG(@"已 hook Transmit amIJailbroken@0x12b16c");
}

// ---- Turing: isJailbrokenEnvironment: (ObjC) ----
static void hook_turing(void) {
    // 遍历所有类找带 isJailbrokenEnvironment: 的
    unsigned int n = 0;
    Class *classes = objc_copyClassList(&n);
    int hooked = 0;
    for (unsigned int i = 0; i < n && hooked < 5; i++) {
        Class c = classes[i];
        const char *cn = class_getName(c);
        if (!cn) continue;
        if (strstr(cn, "Turing") || strstr(cn, "TSecure") || strstr(cn, "TDefender")) {
            SEL sel = sel_registerName("isJailbrokenEnvironment:");
            if (class_getInstanceMethod(c, sel) || class_getClassMethod(c, sel)) {
                HSBCLOG(@"Turing 类 %s 有 isJailbrokenEnvironment:", cn);
                hooked++;
            }
        }
    }
    free(classes);
}

// 心跳
static void *heartbeat(void *a) {
    for (int i = 0; ; i++) { if (i%10==0) HSBCLOG(@"♥ #%d", i); usleep(10000); }
    return NULL;
}

static bool g_done = false;
static void try_hooks(void) {
    if (g_done) return;
    if (!image_base("TMXProfiling")) return;  // 等 TMX 加载
    g_done = true;
    // 全部暂禁,先测基线存活(仅心跳)
    // hook_tmx(); hook_transmit(); hook_turing();
    (void)hook_tmx; (void)hook_transmit; (void)hook_turing;
}
static void on_image(const struct mach_header *mh, intptr_t slide) { try_hooks(); }

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入 pid=%d bundle=%@", getpid(), [[NSBundle mainBundle] bundleIdentifier]);
        try_hooks();
        _dyld_register_func_for_add_image(&on_image);
        pthread_t hb; pthread_create(&hb, NULL, heartbeat, NULL); pthread_detach(hb);
        HSBCLOG(@"已注册回调+心跳");
    }
}
