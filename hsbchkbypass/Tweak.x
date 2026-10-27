// HSBCHKBypass 0.0.2 探针版：只观察，不改行为。
//
// 目标：hk.com.hsbc.hsbchkmobilebanking（汇丰香港 3.69.12），可执行文件 HongKong.app/HongKong。
//
// 静态分析已经查明的检测栈：
//   - TransmitSDK3.framework 里的 libDeviceSecurityAssessment 直接内嵌了开源的
//     IOSSecuritySuite（amIJailbroken / amIReverseEngineered / amIDebugged 等），
//     另外还有自己的 JailbreakCheck 枚举：urlSchemes、symbolicLinks、
//     existenceOfSuspiciousFiles、suspiciousFilesCanBeOpened、
//     restrictedDirectoriesWriteable、dyld、fork。
//   - TechnicalPlatform.framework 里有 WafMobileSdk.JailBrokenHelper（F5/Shape 的
//     WAF 移动端 SDK），会读 /Applications/Cydia.app 一类的路径。
//   - DataProvider.framework 把结果汇成 deviceJailbroken、applicationRepackaged、
//     debuggerAttached、hookingFrameworks 等一组布尔标记。
//   - RASPFramework 只负责渲染拦截页，带 acceptJailbroken 策略。
//
// 已排除：主二进制里没有任何内联 svc；所有候选框架也都不导入 _exit。
// libc 的 exit/_exit/abort/kill/pthread_kill/raise 探针一条都没命中。
// 所以进程究竟怎么没的还没定论，本探针先加一条"心跳"线程把死亡时刻钉下来。
//
// 本版要回答两件事：
//   1. 进程在启动后第几毫秒消失，心跳线程崩了还是整进程没了；
//   2. 把各家 SDK 的越狱判定强行改成 false，App 能不能活下来。
//
// 日志写在 App 自己的 Caches 目录，不写 /tmp 或 /var/jb/tmp。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <execinfo.h>

#import <substrate.h>

#ifndef HSBCHK_LOG_ENABLED
#ifdef DEBUG
#define HSBCHK_LOG_ENABLED 1
#else
#define HSBCHK_LOG_ENABLED 0
#endif
#endif

static int g_fd = -1;
static uint64_t g_t0;

// 相对启动的毫秒数。进程在不到两秒内就没了，判断"哪一步之后死"全靠这个时间轴。
static uint64_t now_ms(void) {
    uint64_t t = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    return (t - g_t0) / 1000000ULL;
}

static void wf(const char *fmt, ...) {
#if HSBCHK_LOG_ENABLED
    if (g_fd < 0) return;
    char buf[2048];
    int off = snprintf(buf, sizeof(buf), "[%5llums] ", (unsigned long long)now_ms());
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
    va_end(ap);
    if (n > 0) write(g_fd, buf, (size_t)(off + n));
#else
    (void)fmt;
#endif
}

// 把地址换算成"镜像名+偏移"，避免看到一串裸地址还要自己算。
//
// 注意不能按"第一个落在区间里的镜像"来判：共享缓存里各镜像的边界互相贴合，
// 稍有不慎就会把主二进制的地址算到隔壁的 libcorecrypto 上。这里取包含该地址、
// 且起始地址最大的那个镜像，也就是最贴近的一个。
static void addr2img(uintptr_t a, char *out, size_t outlen) {
    out[0] = '\0';
    uint32_t n = _dyld_image_count();
    intptr_t best_i = -1;
    uintptr_t best_lo = 0;
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        uintptr_t lo = 0, hi = 0;
        const uint8_t *p = (const uint8_t *)(h + 1);
        for (uint32_t c = 0; c < h->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                if (sg->filesize == 0 && sg->vmsize == 0) { p += lc->cmdsize; continue; }
                uintptr_t s = sg->vmaddr + (uintptr_t)slide;
                if (lo == 0 || s < lo) lo = s;
                if (s + sg->vmsize > hi) hi = s + sg->vmsize;
            }
            p += lc->cmdsize;
        }
        if (a >= lo && a < hi && (intptr_t)lo > (intptr_t)best_lo) {
            best_lo = lo;
            best_i = (intptr_t)i;
        }
    }
    if (best_i >= 0) {
        const char *name = _dyld_get_image_name((uint32_t)best_i);
        snprintf(out, outlen, "%s+0x%lx", name ? name : "?", (unsigned long)(a - best_lo));
    } else {
        snprintf(out, outlen, "?0x%lx", (unsigned long)a);
    }
}

static void dump_stack(const char *tag) {
    void *bt[32];
    int n = backtrace(bt, 32);
    wf("  [%s] 调用栈 %d 层:\n", tag, n);
    for (int i = 0; i < n; i++) {
        char loc[512];
        addr2img((uintptr_t)bt[i], loc, sizeof(loc));
        wf("    #%d %s\n", i, loc);
    }
}

// ---------------------------------------------------------------------------
// 退出路径
// ---------------------------------------------------------------------------

static void (*o_exit)(int);
static void (*o_Exit)(int);
static void (*o__exit)(int);
static void (*o_abort)(void);
static int (*o_kill)(pid_t, int);
static int (*o_pthread_kill)(pthread_t, int);
static int (*o_raise)(int);

static __attribute__((unused)) void my_exit(int code) {
    wf("!! exit(%d)\n", code);
    dump_stack("exit");
    o_exit(code);
}
static __attribute__((unused)) void my_Exit(int code) {
    wf("!! _Exit(%d)\n", code);
    dump_stack("_Exit");
    o_Exit(code);
}
static __attribute__((unused)) void my__exit(int code) {
    wf("!! _exit(%d)\n", code);
    dump_stack("_exit");
    o__exit(code);
}
static __attribute__((unused)) void my_abort(void) {
    wf("!! abort()\n");
    dump_stack("abort");
    o_abort();
}
static __attribute__((unused)) int my_kill(pid_t pid, int sig) {
    wf("!! kill(%d, %d)\n", pid, sig);
    dump_stack("kill");
    return o_kill(pid, sig);
}
static __attribute__((unused)) int my_pthread_kill(pthread_t t, int sig) {
    wf("!! pthread_kill(%p, %d)\n", (void *)t, sig);
    dump_stack("pthread_kill");
    return o_pthread_kill(t, sig);
}
static __attribute__((unused)) int my_raise(int sig) {
    wf("!! raise(%d)\n", sig);
    dump_stack("raise");
    return o_raise(sig);
}

static void hook_exits(void) {
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&o_exit);
    MSHookFunction((void *)_Exit, (void *)my_Exit, (void **)&o_Exit);
    MSHookFunction((void *)_exit, (void *)my__exit, (void **)&o__exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&o_abort);
    MSHookFunction((void *)kill, (void *)my_kill, (void **)&o_kill);
    MSHookFunction((void *)pthread_kill, (void *)my_pthread_kill, (void **)&o_pthread_kill);
    MSHookFunction((void *)raise, (void *)my_raise, (void **)&o_raise);
}

// ---------------------------------------------------------------------------
// 把各家的越狱判定改成 false
// ---------------------------------------------------------------------------
//
// 这些都是 Swift 的静态方法，参数为无、返回 Bool，所以统一用一个返回 0
// 的函数替换即可。先按名字 dlsym，解析不到就记一笔，不做任何假设。

typedef struct {
    const char *mangled;   // Swift 符号名（demangle 后的形式见右边注释）
    const char *note;
    void *orig;
} swift_hook_t;

static char __attribute__((unused)) ret_false(void) { return 0; }

#define SWIFT_ISJB "_$s27libDeviceSecurityAssessment12isJailbrokenSbyF"
#define SWIFT_ISS  "_$s27libDeviceSecurityAssessment16IOSSecuritySuiteC"
#define SWIFT_WAF  "$s12WafMobileSdk16JailBrokenHelper014_909F9A5C007D9G17CF25C91341F05AD38LLV"

static swift_hook_t g_hooks[] = {
    { SWIFT_ISJB, "libDeviceSecurityAssessment.isJailbroken", NULL },
    { SWIFT_ISS "13amIJailbrokenSbyFZ", "IOSSecuritySuite.amIJailbroken", NULL },
    { SWIFT_ISS "20amIReverseEngineeredSbyFZ", "IOSSecuritySuite.amIReverseEngineered", NULL },
    { SWIFT_ISS "11amIDebuggedSbyFZ", "IOSSecuritySuite.amIDebugged", NULL },
    { SWIFT_ISS "10amIProxiedSbyFZ", "IOSSecuritySuite.amIProxied", NULL },
    { SWIFT_ISS "16amIRunInEmulatorSbyFZ", "IOSSecuritySuite.amIRunInEmulator", NULL },
    { SWIFT_ISS "28amIJailbrokenWithFailMessageSb10jailbroken_SS04failK0tyFZ",
      "IOSSecuritySuite.amIJailbrokenWithFailMessage", NULL },
    { SWIFT_ISS "29amIJailbrokenWithFailedChecksSb10jailbroken_SayAA14JailbreakCheckO5check_SS11failMessagetG06failedK0tyFZ",
      "IOSSecuritySuite.amIJailbrokenWithFailedChecks", NULL },
};
static const size_t g_hookn = sizeof(g_hooks) / sizeof(g_hooks[0]);

static void hook_swift_bool(void) {
    for (size_t i = 0; i < g_hookn; i++) {
        void *p = dlsym(RTLD_DEFAULT, g_hooks[i].mangled);
        if (!p) {
            wf("  跳过 %s：dlsym 没找到\n", g_hooks[i].note);
            continue;
        }
        MSHookFunction(p, (void *)ret_false, &g_hooks[i].orig);
        char loc[512];
        addr2img((uintptr_t)p, loc, sizeof(loc));
        wf("  已 hook %s @ %s\n", g_hooks[i].note, loc);
    }
}

static void list_waf_symbols(void) {
    wf("  WafMobileSdk.JailBrokenHelper 的类型符号：%s\n",
       dlsym(RTLD_DEFAULT, SWIFT_WAF) ? "已导出" : "未导出");
}

// ---------------------------------------------------------------------------
// 内联 svc 扫描
// ---------------------------------------------------------------------------
//
// 主二进制在磁盘上是加密的（cryptid=1），对着文件扫 __TEXT 只能是噪声，必须在
// 进程里扫已经解密的内存。
//
// 进程只活几百毫秒，逐字比较 200MB 来不及。先用 memchr 找指令字里的 0xD4，
// 只在这些位置做完整判断：memchr 是按字节优化过的，两三百毫秒的数据量几十毫秒就过。
//
// EL0 的 svc 指令编码为 0xD4000001 | (imm16 << 5)。imm 为 0x80 时是 Darwin 的
// svc #0x80，为 0 时是通用 svc #0。系统调用号放在 x16 或 w16 里，通常由紧邻的
// movz 写入，退出是 1（exit）或 0（也见过用 0 的实现）。

static void scan_svc_app_images(void) {
    const uint32_t svc_mask = 0xFFE0001F;
    int hits = 0;
    int scanned = 0;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        // 只看 App 自己带的镜像，系统库和共享缓存不关心
        if (!strstr(path, "/HongKong.app/")) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *p = (const uint8_t *)(h + 1);
        for (uint32_t c = 0; c < h->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                if (!(sg->initprot & VM_PROT_EXECUTE) || sg->filesize == 0) {
                    p += lc->cmdsize;
                    continue;
                }
                const uint8_t *base = (const uint8_t *)(sg->vmaddr + (uintptr_t)slide);
                size_t len = (size_t)sg->filesize;
                scanned++;
                const uint8_t *cur = base;
                const uint8_t *end = base + len;
                while (cur < end) {
                    const uint8_t *hit = (const uint8_t *)memchr(cur, 0xD4, (size_t)(end - cur));
                    if (!hit) break;
                    uintptr_t off = (uintptr_t)(hit - base);
                    cur = hit + 1;
                    // svc 是 4 字节对齐的指令，0xD4 必须落在每个字的最高字节
                    if (off < 8 || (off & 3) != 3) continue;
                    uint32_t insn = *(const uint32_t *)(base + off - 3);
                    if ((insn & 0xFFE0001F) != 0xD4000001) continue;
                    uint32_t prev = *(const uint32_t *)(base + off - 7);
                    uint32_t num = 0xFFFFFFFF;
                    if ((prev & 0xFFE0001F) == 0x52800010) num = (prev >> 5) & 0xFFFF;      // movz w16
                    else if ((prev & 0xFFE0001F) == 0xD2800010) num = (prev >> 5) & 0xFFFF; // movz x16
                    if (num == 1 || num == 0) {
                        wf("  svc 命中 syscall=%u @ %s+0x%lx（svc 立即数 0x%x）\n",
                           num, path, (unsigned long)off, (insn >> 5) & 0xFFFF);
                        if (++hits >= 40) { wf("  命中过多，截断\n"); return; }
                    }
                }
                (void)svc_mask;
            }
            p += lc->cmdsize;
        }
    }
    wf("  svc 扫描完成：扫了 %d 个可执行段，命中 %d 处\n", scanned, hits);
}

// ---------------------------------------------------------------------------
// 自检
// ---------------------------------------------------------------------------
//
// 如果 MSHookFunction 在这个进程里根本没生效，那"退出函数一条都没命中"这个结论
// 就毫无意义。所以每轮先对一个无害函数做一次自检：hook getpid，然后自己调一次。

static pid_t (*o_getpid)(void);
static int g_selftest_hits;

static __attribute__((unused)) pid_t my_getpid(void) {
    g_selftest_hits++;
    return o_getpid();
}

static long (*o_syscall)(long, ...);

// syscall(2) 是变参函数，替换时把前四个参数透传，够观察 SYS_exit / SYS_kill 用。
static __attribute__((unused)) long my_syscall(long n, long a1, long a2, long a3, long a4,
                                              long a5, long a6) {
    if (n == 1 || n == 0 || n == 37) {  // SYS_exit / 旧编号 / SYS_kill
        wf("!! syscall(%ld, %ld, %ld)\n", n, a1, a2);
        dump_stack("syscall");
    }
    return o_syscall(n, a1, a2, a3, a4, a5, a6);
}

static void self_test_hooks(void) {
    MSHookFunction((void *)getpid, (void *)my_getpid, (void **)&o_getpid);
    g_selftest_hits = 0;
    getpid();
    wf("  自检：hook getpid 之后调用一次，命中 %d 次（%s）\n",
       g_selftest_hits, g_selftest_hits > 0 ? "hook 有效" : "hook 无效，后面的结论都不可信");
    // syscall(2) 在 SDK 里被标成废弃，直接引用会编译失败；用 dlsym 拿地址绕开。
    void *sc = dlsym(RTLD_DEFAULT, "syscall");
    if (sc) {
        MSHookFunction(sc, (void *)my_syscall, (void **)&o_syscall);
        wf("  syscall(2) 已 hook\n");
    } else {
        wf("  syscall(2) 没找到，跳过\n");
    }
}

// ---------------------------------------------------------------------------
// 心跳
// ---------------------------------------------------------------------------

static void *heartbeat(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++) {
        usleep(20 * 1000);
        wf("心跳 %d\n", i);
    }
    wf("心跳跑满，进程还活着\n");
    return NULL;
}

static void at_exit_log(void) {
    wf("!! atexit 触发\n");
}

static void sig_log(int sig) {
    wf("!! 收到信号 %d\n", sig);
    dump_stack("signal");
}

static void install_watchdogs(void) {
    atexit(at_exit_log);
    for (int s = 1; s < 32; s++) {
        if (s == SIGKILL || s == SIGSTOP) continue;
        signal(s, sig_log);
    }
}

static void *scan_thread(void *arg) {
    (void)arg;
    wf("---- svc 扫描开始 ----\n");
    scan_svc_app_images();
    wf("---- svc 扫描结束 ----\n");
    return NULL;
}

__attribute__((constructor)) static void probe_init(void) {
    g_t0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#if HSBCHK_LOG_ENABLED
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (caches) {
        NSString *lp = [caches stringByAppendingPathComponent:@"hsbchkbypass.log"];
        g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
#endif
    wf("===== HSBCHKBypass 0.0.5 探针启动 pid=%d bundle=%s 日志=%s =====\n",
       getpid(), [[[NSBundle mainBundle] bundleIdentifier] UTF8String], g_fd >= 0 ? "开" : "关");
    install_watchdogs();
    hook_exits();
    wf("退出路径探针已布设 exit/_Exit/_exit/abort/kill/pthread_kill/raise\n");
    self_test_hooks();
    // 扫描和心跳各占一条线程，互不拖累：进程只活几十毫秒，先把最要紧的扫描跑起来。
    pthread_t ts, th;
    if (pthread_create(&ts, NULL, scan_thread, NULL) == 0) pthread_detach(ts);
    if (pthread_create(&th, NULL, heartbeat, NULL) == 0) pthread_detach(th);
    hook_swift_bool();
    list_waf_symbols();
}
