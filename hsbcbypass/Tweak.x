// HSBCBypass —— 探针版 (Round 0 观测)
//
// 目标:汇丰中国 (cn.com.hsbc.hsbcchina) / 汇丰香港 (hk.com.hsbc.hsbchkmobilebanking)
// 在越狱设备上闪退且不产生标准 crash log,推测是检测到越狱后主动干净退出。
// 本版本只做「观测」:hook 常见退出路径(exit/_exit/abort/kill/pthread_kill),
// 命中时打印调用栈到 syslog,借此定位是谁、走哪条路径触发退出,再决定 hook 层。
// 不改变行为(打印后仍调用原实现),纯诊断,可逆。

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <execinfo.h>
#import <dlfcn.h>
#import <signal.h>

// 同时写 syslog 和沙盒内文件(syslog 在本设备读不到,靠文件回捞)
static void hsbc_file_log(NSString *line) {
    static NSString *path = nil;
    if (!path) {
        path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"hsbc_probe.log"];
    }
    NSString *entry = [line stringByAppendingString:@"\n"];
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (f) { fwrite(entry.UTF8String, 1, strlen(entry.UTF8String), f); fclose(f); }
}

#define HSBCLOG(fmt, ...) do { \
    NSString *_s = [NSString stringWithFormat:(fmt), ##__VA_ARGS__]; \
    NSLog(@"[HSBCBypass] %@", _s); \
    hsbc_file_log(_s); \
} while (0)

// 打印当前调用栈(跳过本函数自身若干帧)
static void hsbc_dump_backtrace(const char *tag) {
    void *frames[64];
    int n = backtrace(frames, 64);
    char **syms = backtrace_symbols(frames, n);
    HSBCLOG(@"==== 退出路径命中: %s (栈深 %d) ====", tag, n);
    if (syms) {
        for (int i = 0; i < n; i++) {
            HSBCLOG(@"  #%02d %s", i, syms[i]);
        }
        free(syms);
    }
    HSBCLOG(@"==== 栈结束: %s ====", tag);
}

// ---- exit ----
static void (*orig_exit)(int);
static void my_exit(int code) {
    hsbc_dump_backtrace("exit");
    HSBCLOG(@"exit(%d) 被调用", code);
    orig_exit(code);
    __builtin_unreachable();
}

// ---- _exit ----
static void (*orig__exit)(int);
static void my__exit(int code) {
    hsbc_dump_backtrace("_exit");
    HSBCLOG(@"_exit(%d) 被调用", code);
    orig__exit(code);
    __builtin_unreachable();
}

// ---- abort ----
static void (*orig_abort)(void);
static void my_abort(void) {
    hsbc_dump_backtrace("abort");
    HSBCLOG(@"abort() 被调用");
    orig_abort();
    __builtin_unreachable();
}

// ---- kill ----
static int (*orig_kill)(pid_t, int);
static int my_kill(pid_t pid, int sig) {
    HSBCLOG(@"kill(pid=%d, sig=%d) 被调用 (self=%d)", pid, sig, getpid());
    hsbc_dump_backtrace("kill");
    return orig_kill(pid, sig);
}

// ---- pthread_kill ----
static int (*orig_pthread_kill)(pthread_t, int);
static int my_pthread_kill(pthread_t t, int sig) {
    HSBCLOG(@"pthread_kill(sig=%d) 被调用", sig);
    hsbc_dump_backtrace("pthread_kill");
    return orig_pthread_kill(t, sig);
}

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入成功: pid=%d bundle=%@", getpid(),
                [[NSBundle mainBundle] bundleIdentifier]);

        MSHookFunction((void *)exit,          (void *)my_exit,          (void **)&orig_exit);
        MSHookFunction((void *)_exit,         (void *)my__exit,         (void **)&orig__exit);
        MSHookFunction((void *)abort,         (void *)my_abort,         (void **)&orig_abort);
        MSHookFunction((void *)kill,          (void *)my_kill,          (void **)&orig_kill);
        MSHookFunction((void *)pthread_kill,  (void *)my_pthread_kill,  (void **)&orig_pthread_kill);

        HSBCLOG(@"退出路径探针已布设 (exit/_exit/abort/kill/pthread_kill)");
    }
}
