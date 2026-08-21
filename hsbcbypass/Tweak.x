// HSBCBypass —— fishhook 抓 RWX 生成者(定位退出/自毁模块)
//
// 反 inline-hook 自检会秒杀 MSHookFunction(改函数头)。改用 fishhook 改 GOT(不动函数头),
// hook mmap/mprotect 抓 PROT_EXEC 分配(生成 RWX stub 的必经),记录调用栈定位来源模块。
// 崩溃日志证明退出=跳 RWX stub 触发 SIGBUS,抓到 RWX 生成者即锁定真凶。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <execinfo.h>
#import <pthread.h>
#import <sys/mman.h>
#import "fishhook.h"

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

// 调用栈 → 模块+偏移(定位发起者)
static void bt(const char *tag) {
    void *fr[20]; int n = backtrace(fr, 20);
    for (int i = 1; i < n && i < 12; i++) {
        Dl_info di;
        if (dladdr(fr[i], &di) && di.dli_fname) {
            const char *b = strrchr(di.dli_fname, '/'); b = b?b+1:di.dli_fname;
            HSBCLOG(@"  %s#%d %s +0x%lx", tag, i, b, (uintptr_t)fr[i]-(uintptr_t)di.dli_fbase);
        }
    }
}

static void *(*orig_mmap)(void*,size_t,int,int,int,off_t);
static void *my_mmap(void *a, size_t l, int prot, int fl, int fd, off_t o) {
    void *r = orig_mmap(a,l,prot,fl,fd,o);
    if (prot & PROT_EXEC) { HSBCLOG(@"★mmap EXEC len=0x%zx prot=%d → %p", l, prot, r); bt("mmap"); }
    return r;
}
static int (*orig_mprotect)(void*,size_t,int);
static int my_mprotect(void *a, size_t l, int prot) {
    if (prot & PROT_EXEC) { HSBCLOG(@"★mprotect EXEC addr=%p len=0x%zx prot=%d", a, l, prot); bt("mprot"); }
    return orig_mprotect(a,l,prot);
}

static void *heartbeat(void *a) {
    for (int i=0;;i++){ if(i%10==0) HSBCLOG(@"♥ #%d", i); usleep(10000);} return NULL;
}

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入 pid=%d", getpid());
        struct rebinding r[] = {
            {"mmap", (void*)my_mmap, (void**)&orig_mmap},
            {"mprotect", (void*)my_mprotect, (void**)&orig_mprotect},
        };
        rebind_symbols(r, 2);
        HSBCLOG(@"fishhook mmap/mprotect 已布设");
        pthread_t hb; pthread_create(&hb,NULL,heartbeat,NULL); pthread_detach(hb);
    }
}
