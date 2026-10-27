// HSBCHKBypass 0.0.24：对齐 pid，并补一条不依赖挂钩的出口观测。
//
// 目前最反常的一点是：从进程外看，App 是干净的 exit(1) 退出（kqueue 报 0x100），
// 但进程内的 exit/_exit/abort 钩子一次都没命中，而这些钩子在自己调用时是有效的。
//
// 这一版只做三件事：
//   1. 记下 pid 与 ppid，方便和外面看到的 pid 对上；
//   2. 注册 atexit 处理器——它能区分"走 exit()"和"走 _exit()"两条路，
//      而且不依赖挂钩是否成功；
//   3. 保留心跳，看我们的线程何时停止。

#import <Foundation/Foundation.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <signal.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>

#import <substrate.h>

static int g_fd = -1;

static uint64_t now_ms(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ULL;
}

static void wf(const char *fmt, ...) {
    if (g_fd < 0) return;
    char buf[1024];
    int off = snprintf(buf, sizeof(buf), "[%5llums] ", (unsigned long long)now_ms());
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    write(g_fd, buf, (size_t)(off + n));
}

static const char *img_of(uintptr_t a) {
    Dl_info info;
    if (a && dladdr((void *)a, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        return base ? base + 1 : info.dli_fname;
    }
    return "?";
}

static uintptr_t off_of(uintptr_t a) {
    Dl_info info;
    if (a && dladdr((void *)a, &info) && info.dli_fbase) return a - (uintptr_t)info.dli_fbase;
    return 0;
}

static void *g_o_exit, *g_o__exit, *g_o_abort;

static void my_exit(int c) {
    wf("!! exit(%d) 来自 %s+0x%lx\n", c, img_of((uintptr_t)__builtin_return_address(0)),
       (unsigned long)off_of((uintptr_t)__builtin_return_address(0)));
    ((void(*)(int))g_o_exit)(c);
}
static void my__exit(int c) { wf("!! _exit(%d)\n", c); ((void(*)(int))g_o__exit)(c); }
static void my_abort(void) { wf("!! abort() 来自 %s\n", img_of((uintptr_t)__builtin_return_address(0))); ((void(*)(void))g_o_abort)(); }

// 这条通道不看挂钩：只要进程走 exit()，这里一定先被调用。
static void at_exit_handler(void) {
    wf("!! atexit 处理器被调用（说明走的是 exit() 而不是 _exit()）\n");
}

static void hook_one(const char *name, void *repl, void **orig) {
    void *p = dlsym(RTLD_DEFAULT, name);
    if (!p) { wf("  %-8s 没找到\n", name); return; }
    MSHookFunction(p, repl, orig);
    wf("  %-8s %p 字=%08x\n", name, p, *(const volatile uint32_t *)p);
}

static void *heartbeat(void *arg) {
    (void)arg;
    for (int i = 0; i < 1500; i++) {
        wf("心跳 %d pid=%d\n", i, getpid());
        usleep(20 * 1000);
    }
    return NULL;
}

__attribute__((constructor)) static void ctor(void) {
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!caches) return;
    NSString *lp = [caches stringByAppendingPathComponent:@"hsbchkbypass.log"];
    g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) return;

    wf("===== HSBCHKBypass 0.0.24 启动 pid=%d ppid=%d 启动时刻=%llums =====\n",
       getpid(), getppid(), (unsigned long long)now_ms());

    hook_one("exit", (void *)my_exit, &g_o_exit);
    hook_one("_exit", (void *)my__exit, &g_o__exit);
    hook_one("abort", (void *)my_abort, &g_o_abort);
    atexit(at_exit_handler);
    wf("挂钩与 atexit 注册完成\n");

    pthread_t th;
    pthread_create(&th, NULL, heartbeat, NULL);
    wf("构造函数结束\n");
}
