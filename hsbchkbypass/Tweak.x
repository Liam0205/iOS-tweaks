// HSBCHKBypass 0.0.40：退出到底是谁发起的——按线程做二分。
//
// 到这一版为止，退出在所有用户态入口上都拦不住（符号、GOT、syscall、内联 svc 桩、
// 异常端口都试过；atexit 也不触发）。那就换个问法：
//   在退出前把"非主线程"全部挂起，看进程是否还能退出。
//   - 若不再退出 → 退出是某个后台线程发起的，下一步只需缩小到那一个；
//   - 若照退   → 退出来自主线程或进程外，方向要另找。
//
// 挂起用 thread_suspend，只挂 system 之外的普通线程，主线程与自身保持运行。

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/thread_act.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <signal.h>

#import <substrate.h>

static int g_fd = -1;
static uint64_t g_start;
static mach_port_t g_self_thread;
static mach_port_t g_main_thread;

static uint64_t now_ms(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ULL;
}

static void wf(const char *fmt, ...) {
    if (g_fd < 0) return;
    char buf[512];
    int off = snprintf(buf, sizeof(buf), "[%5llums] ", now_ms() - g_start);
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    write(g_fd, buf, (size_t)(off + n));
}

static void *g_o_exit;

static void my_exit(int code) {
    wf("!! exit(%d) 被调用\n", code);
    ((void(*)(int))g_o_exit)(code);
}

static int g_suspended;

static void suspend_other_threads(void) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) return;
    wf("  枚举到 %u 个线程\n", n);
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        thread_t t = list[i];
        if (t != g_main_thread && t != g_self_thread) {
            kern_return_t kr = thread_suspend(t);
            if (kr == KERN_SUCCESS) g_suspended++;
            wf("  挂起线程 %u → kr=%d\n", t, kr);
        } else {
            wf("  保持线程 %u 运行\n", t);
        }
        mach_port_deallocate(mach_task_self(), t);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, n * sizeof(thread_t));
    wf("  共挂起 %d 个\n", g_suspended);
}

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 400; i++) {
        uint64_t el = now_ms() - g_start;
        if (!g_suspended && el > 330) {
            wf("=== 到达 %llums，开始挂起非主线程 ===\n", el);
            suspend_other_threads();
        }
        if (i % 5 == 0) wf("心跳 相对=%llums\n", el);
        usleep(20 * 1000);
    }
    return NULL;
}

__attribute__((constructor)) static void ctor(void) {
    g_start = now_ms();
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!caches) return;
    NSString *lp = [caches stringByAppendingPathComponent:@"hsbchkbypass.log"];
    g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) return;
    wf("===== 0.0.40 启动 pid=%d =====\n", getpid());

    void *p = dlsym(RTLD_DEFAULT, "exit");
    MSHookFunction(p, (void *)my_exit, &g_o_exit);
    wf("exit=%p 首字=%08x\n", p, *(const volatile uint32_t *)p);

    g_main_thread = pthread_mach_thread_np(pthread_self());
    pthread_t th;
    pthread_create(&th, NULL, worker, NULL);
    g_self_thread = pthread_mach_thread_np(th);
    wf("主线程 %u 自身线程 %u\n", g_main_thread, g_self_thread);
}
