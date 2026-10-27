// WHBypass —— 国家网络身份认证（cn.cyberIdentity.certification）越狱检测绕过
//
// 第一版只做观测，不做任何 hook：SecureUtilityPlus 里有 MSHookFunctionChecker、
// FishHookChecker、IntegrityChecker 三类专门查 hook 的组件，在没摸清它们之前
// 不要动任何函数序言字节。
//
// 观测目标：
//   1. 进程里实际存在哪些 SecureUtilityPlus 类，各自有哪些方法；
//   2. 这些类的检测方法在启动后是否被调用、返回什么；
//   3. 崩溃前最后发生了哪些事。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <ctype.h>
#import <mach/mach.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#include <execinfo.h>
#include <libkern/OSCacheControl.h>
#include <mach/vm_region.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
extern int ptrace(int, pid_t, caddr_t, int);
#import <substrate.h>

static int g_logfd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_t0;

static uint64_t wh_now_ms(void) {
    if (!g_t0) g_t0 = mach_absolute_time();
    // 只在日志里用，精度到毫秒即可，不做 timebase 换算的精确性追求。
    static mach_timebase_info_data_t tb;
    if (!tb.denom) mach_timebase_info(&tb);
    uint64_t d = mach_absolute_time() - g_t0;
    return d * tb.numer / tb.denom / 1000000ULL;
}

// 信号处理器里不能拿锁：可能死锁在别人持有的互斥量上，表现成整个进程卡住。
// 这里只做一次裸 write，调用方自己把整行拼好。
static void log_unsafe(const char *s) {
    if (g_logfd >= 0) (void)!write(g_logfd, s, strlen(s));
}

static void log_raw(const char *s) {
    if (g_logfd < 0) return;
    pthread_mutex_lock(&g_lock);
    (void)!write(g_logfd, s, strlen(s));
    pthread_mutex_unlock(&g_lock);
}

static void aialog(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    char line[1100];
    snprintf(line, sizeof(line), "[%llums] %s\n", (unsigned long long)wh_now_ms(), buf);
    log_raw(line);
}

static void open_log(void) {
    // 日志文件放在 App 容器里会被加固壳清掉（实测 Documents 里的日志整份消失），
    // 所以写到设备控制台。syslog 由 launchd 收，App 自己没有删除权限。
    // 实测加固壳会清掉 Documents 里的非常规文件，控制台又只可写不可读。
    // Library/Caches 与 Library/gtRoot 是它自己要用的目录，清理策略相对宽松。
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (caches) {
        NSString *lp = [caches stringByAppendingPathComponent:@"gtcfg.log"];
        g_logfd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    if (g_logfd < 0) {
        NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (dir) {
            NSString *lp = [dir stringByAppendingPathComponent:@"gtcfg.log"];
            g_logfd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
        }
    }
}

// 打印一个类的方法清单。SecureUtilityPlus 是 Swift 类，方法多半没导出名字，
// 但 ObjC 运行时里仍能看到 selector（Swift 类若有 @objc 成员）。
__attribute__((unused)) static void dump_class_methods(Class c, int max) {
    if (!c) return;
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    aialog("  %s: %u 个方法", class_getName(c), n);
    for (unsigned int i = 0; i < n && (int)i < max; i++) {
        aialog("    -[%s %s] imp=%p type=%s", class_getName(c),
               sel_getName(method_getName(ms[i])),
               (void *)method_getImplementation(ms[i]),
               method_getTypeEncoding(ms[i]) ?: "?");
    }
    free(ms);
    unsigned int nc = 0;
    Method *cm = class_copyMethodList(object_getClass(c), &nc);
    if (nc) aialog("  %s (类方法): %u 个", class_getName(c), nc);
    for (unsigned int i = 0; i < nc && (int)i < max; i++) {
        aialog("    +[%s %s] imp=%p type=%s", class_getName(c),
               sel_getName(method_getName(cm[i])),
               (void *)method_getImplementation(cm[i]),
               method_getTypeEncoding(cm[i]) ?: "?");
    }
    free(cm);
}

// everisk SDK 的 checker 都实现了同一套协议：+[X name]、-[X check]、-[X defaultPeriod]。
// 类名被混淆成随机串，但 +name 返回的是可读名字，运行时调一次就能对上号。
__attribute__((unused)) static void dump_checkers(void) {
    unsigned int count = 0;
    Class *all = objc_copyClassList(&count);
    int n = 0;
    for (unsigned int i = 0; i < count; i++) {
        Class c = all[i];
        if (!class_respondsToSelector(object_getClass(c), @selector(name))) continue;
        if (!class_respondsToSelector(c, @selector(check))) continue;
        n++;
        Method mn = class_getClassMethod(c, @selector(name));
        NSString *nm = nil;
        if (mn) {
            id (*fn)(id, SEL) = (id (*)(id, SEL))method_getImplementation(mn);
            nm = fn((id)object_getClass(c), @selector(name));
        }
        aialog("CHECKER %d 类=%s name=%s check=%p", n, class_getName(c),
               nm ? [nm UTF8String] : "(nil)",
               (void *)method_getImplementation(class_getInstanceMethod(c, @selector(check))));
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        for (unsigned int j = 0; j < mc; j++)
            aialog("    -%s", sel_getName(method_getName(ms[j])));
        free(ms);
        mc = 0;
        ms = class_copyMethodList(object_getClass(c), &mc);
        for (unsigned int j = 0; j < mc; j++)
            aialog("    +%s", sel_getName(method_getName(ms[j])));
        free(ms);
        if (n > 200) break;
    }
    free(all);
    aialog("checker 总数=%d", n);
}

// 记录镜像列表，看基座注入了哪些库。
__attribute__((unused)) static void dump_images(void) {
    uint32_t n = _dyld_image_count();
    aialog("镜像数=%u", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strstr(nm, "/var/jb") || strstr(nm, "systemhook") || strstr(nm, "ellekit") ||
            strstr(nm, "injector") || strstr(nm, "TweakInject") || strstr(nm, "preboot"))
            aialog("  JB镜像[%u] %s", i, nm);
    }
}

// 崩溃前的心跳：每 200ms 记一次，用来确定崩溃发生在哪个时刻。
__attribute__((unused)) __attribute__((unused)) __attribute__((unused)) __attribute__((unused)) static void *heartbeat(void *arg) {
    (void)arg;
    for (int i = 0; i < 60; i++) {
        aialog("BEAT %d", i);
        usleep(200 * 1000);
    }
    return NULL;
}

// ============================================================
// 对齐农行的思路：不去对抗 SecureUtilityPlus 内部的各个 Checker，
// 而是在它上层的聚合入口处短路。农行那次是 swizzle
// -[DTFrameworkInterface initRiskManage] 为空实现；这里对应的上游入口
// 是 -[SecureUtilityPlus.CheckAllCall start]。
//
// 只用 ObjC 方法替换，不改任何函数序言字节 —— SecureUtilityPlus 自带
// MSHookFunctionChecker / FishHookChecker / IntegrityChecker，
// 改函数序言一定会被它自己发现（农行 0xb5a06000 那次就是这个原因）。
//
// WH_MODE: 0 = 只观测（记录入口被调用，原样转发）
//          1 = 入口置空（不执行任何检测）
#ifndef WH_MODE
#define WH_MODE 0
#endif

static void (*g_orig_cac_start)(id, SEL);
static id (*g_orig_cac_init)(id, SEL);

static void wh_cac_start(id self, SEL _cmd) {
    aialog("CheckAllCall start 进入 self=%s", object_getClassName(self));
#if WH_MODE == 1
    aialog("CheckAllCall start 已置空，不执行检测");
    return;
#else
    if (g_orig_cac_start) g_orig_cac_start(self, _cmd);
    aialog("CheckAllCall start 返回");
#endif
}

static id wh_cac_init(id self, SEL _cmd) {
    aialog("CheckAllCall init 进入 self=%s", object_getClassName(self));
#if WH_MODE == 1
    return self;
#else
    return g_orig_cac_init ? g_orig_cac_init(self, _cmd) : self;
#endif
}

__attribute__((unused)) static void install_checkallcall_swizzle(void) {
    Class c = objc_getClass("SecureUtilityPlus.CheckAllCall");
    if (!c) c = NSClassFromString(@"SecureUtilityPlus.CheckAllCall");
    if (!c) {
        // 类名在 ObjC 运行时里可能以 Swift 形式注册，退一步按后缀找。
        unsigned int n = 0;
        Class *all = objc_copyClassList(&n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = class_getName(all[i]);
            if (nm && strstr(nm, "CheckAllCall")) { c = all[i]; break; }
        }
        free(all);
    }
    if (!c) { aialog("找不到 CheckAllCall 类"); return; }
    aialog("CheckAllCall 类 = %s", class_getName(c));

    Method m = class_getInstanceMethod(c, sel_registerName("start"));
    if (m) {
        g_orig_cac_start = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)wh_cac_start);
        aialog("已替换 -[%s start] 原=%p", class_getName(c), (void *)g_orig_cac_start);
    } else {
        aialog("没有 -start 方法");
    }

    Method mi = class_getInstanceMethod(c, sel_registerName("init"));
    if (mi) {
        g_orig_cac_init = (id (*)(id, SEL))method_getImplementation(mi);
        method_setImplementation(mi, (IMP)wh_cac_init);
        aialog("已替换 -[%s init]", class_getName(c));
    }
}

// ============================================================
// 故障现场抓取
//
// 崩溃是"跳到一个无效地址然后执行"（EXC_BAD_INSTRUCTION，0xb5a01000 固定不变），
// 发生在 GCD 的 root queue worker 上，帧 0 就是那个坏地址，帧 1 已经是
// _dispatch_call_block_and_release —— 中间的调用链被吃掉了。
//
// 这里不 hook 任何函数（SecureUtilityPlus 自带 MSHookFunctionChecker /
// FishHookChecker，改函数序言一定会被发现），只用信号处理器把
// 帧指针对链上的返回地址全部打出来，看是谁提交的那个 block。
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <ucontext.h>

#define MAX_MODULES 1024
static struct { const char *name; uintptr_t base; uintptr_t size; } g_mods[MAX_MODULES];
static int g_mod_count;

static void snapshot_modules(void) {
    uint32_t n = _dyld_image_count();
    if (n > MAX_MODULES) n = MAX_MODULES;
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        uintptr_t base = (uintptr_t)h;
        // 只取 __TEXT 的 vmsize 作为范围。返回地址本来就落在 __TEXT 里，
        // 按所有段求上界在共享缓存镜像上会把范围算宽，把不相干的地址吸进来。
        uintptr_t size = 0;
        if (h->magic == MH_MAGIC_64) {
            const struct mach_header_64 *h64 = (const struct mach_header_64 *)h;
            const uint8_t *p = (const uint8_t *)h + sizeof(struct mach_header_64);
            for (uint32_t c = 0; c < h64->ncmds; c++) {
                const struct load_command *lc = (const struct load_command *)p;
                if (lc->cmdsize == 0) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                    if (strcmp(sg->segname, "__TEXT") == 0) { size = (uintptr_t)sg->vmsize; break; }
                }
                p += lc->cmdsize;
            }
        }
        g_mods[g_mod_count].name = _dyld_get_image_name(i);
        g_mods[g_mod_count].base = base;
        g_mods[g_mod_count].size = size ? size : 0x1000;
        g_mod_count++;
    }
}

static const char *module_for(uintptr_t addr, uintptr_t *off) {
    for (int i = 0; i < g_mod_count; i++) {
        if (addr >= g_mods[i].base && addr < g_mods[i].base + g_mods[i].size) {
            *off = addr - g_mods[i].base;
            return g_mods[i].name;
        }
    }
    *off = 0;
    return NULL;
}

// arm64e 的返回地址带 PAC 签名，48 位掩码不够；不成就用低 32 位配高位段重建。
static uintptr_t strip_pac(uintptr_t v) {
    uintptr_t t = v & 0x0000FFFFFFFFFFFFULL;
    if (t & 0x0000800000000000ULL) t |= 0xFFFF000000000000ULL;
    return t;
}

static uintptr_t real_ptr(uintptr_t v) {
    uintptr_t o = 0;
    uintptr_t t = strip_pac(v);
    if (module_for(t, &o) && o) return t;
    uintptr_t lo = v & 0xFFFFFFFFULL;
    for (uintptr_t hi = 0x1; hi <= 0x3; hi++) {
        uintptr_t c = (hi << 32) | lo;
        if (module_for(c, &o) && o) return c;
    }
    return v;
}

static void describe(uintptr_t addr, char *out, size_t n) {
    if (!addr) { snprintf(out, n, "0"); return; }
    // 只能用自己维护的段表：dladdr 已被 systemhook 接管，对任意指针都返回假模块名。
    uintptr_t off = 0;
    const char *m = module_for(addr, &off);
    if (!m) {
        uintptr_t real = real_ptr(addr);
        m = module_for(real, &off);
        addr = real;
    }
    if (m) {
        const char *leaf = strrchr(m, '/');
        snprintf(out, n, "%s+0x%lx", leaf ? leaf + 1 : m, (unsigned long)off);
    } else {
        snprintf(out, n, "?%#lx", (unsigned long)addr);
    }
}

static volatile int g_sig_count;

static void logfmt_unsafe(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_unsafe(buf);
}

static void fault_handler(int sig, siginfo_t *si, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    uint64_t pc = uc->uc_mcontext->__ss.__pc;
    uint64_t lr = uc->uc_mcontext->__ss.__lr;
    uint64_t fp = uc->uc_mcontext->__ss.__fp;
    uint64_t sp = uc->uc_mcontext->__ss.__sp;

    // 每一路信号都要记：si_code 区分"自己执行坏指令"（ILL_*）与"别人 kill/raise 过来"
    // （SI_USER / SI_TKILL），si_pid 告诉我们是谁发的。这是判断处决方向的关键。
    int n = ++g_sig_count;
    logfmt_unsafe("[%llums] FAULT #%d sig=%d code=%d pid=%d uid=%d addr=%p "
                  "pc=%#llx lr=%#llx fp=%#llx sp=%#llx\n",
                  (unsigned long long)wh_now_ms(), n, sig,
                  si ? si->si_code : 0, si ? si->si_pid : 0, si ? si->si_uid : 0,
                  si ? si->si_addr : NULL,
                  (unsigned long long)pc, (unsigned long long)lr,
                  (unsigned long long)fp, (unsigned long long)sp);

    // 前三路才做详查，避免日志失控。
    if (n > 3) return;

    char d[256];
    describe(pc, d, sizeof(d)); logfmt_unsafe("  pc = %s\n", d);
    describe(lr, d, sizeof(d)); logfmt_unsafe("  lr = %s\n", d);

    for (int i = 0; i < 29; i++) {
        describe((uintptr_t)uc->uc_mcontext->__ss.__x[i], d, sizeof(d));
        logfmt_unsafe("  x%-2d = %#018llx %s\n", i,
                      (unsigned long long)uc->uc_mcontext->__ss.__x[i], d);
    }

    // 帧指针对链：每个帧是 [fp]=上一帧 fp，[fp+8]=返回地址。
    log_unsafe("  ---- 帧链 ----\n");
    uintptr_t cur = (uintptr_t)fp;
    for (int i = 0; i < 40; i++) {
        if (!cur || cur < 0x100000000ULL || (cur & 7)) break;
        uintptr_t next = 0, ret = 0;
        memcpy(&next, (void *)cur, 8);
        memcpy(&ret, (void *)(cur + 8), 8);
        if (!ret) break;
        describe(ret, d, sizeof(d));
        logfmt_unsafe("  #%-2d fp=%#llx ret=%s\n", i, (unsigned long long)cur, d);
        if (next <= cur) break;
        cur = next;
    }
    log_unsafe("  ---- 帧链结束 ----\n");

    // 栈里落在镜像内的地址也扫一遍，帧链断裂时靠它兜底。
    log_unsafe("  ---- 栈扫描 ----\n");
    uintptr_t p = (uintptr_t)sp & ~7ULL;
    for (int i = 0; i < 200; i++) {
        uintptr_t v = 0;
        memcpy(&v, (void *)(p + (uintptr_t)i * 8), 8);
        if (!v) continue;
        uintptr_t real = real_ptr(v);
        uintptr_t off = 0;
        if (!module_for(real, &off) || off == 0) continue;
        describe(v, d, sizeof(d));
        logfmt_unsafe("  sp[+0x%x] %s\n", i * 8, d);
    }
    log_unsafe("  ---- 栈扫描结束 ----\n");
}

// 加固壳会在启动后的某一刻把 SIGILL/SIGSEGV/SIGTRAP 的处理器换成指向
// __objc_methname 数据段的坏指针（实测 5.5 秒时三个都是 0x10199ed8c），
// 之后任何信号都会直接要命。这里做成可反复调用的，好让定时器不断装回自己。
static void arm_fault_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
}

static void install_fault_handler(void) {
    arm_fault_handlers();
    aialog("已安装故障信号处理器");
}


// ============================================================
// Mach 异常端口接管
//
// 信号处理器收不到：ellekit 的异常线程先把 Mach 异常截走，直接把进程干掉
// （崩溃报告里 byProc=exc handler）。要拿到故障现场的完整调用链，必须自己
// 把 EXC_BAD_ACCESS / EXC_BAD_INSTRUCTION 收到自己的端口上。
//
// 这里只观测，不改变行为：拿到现场后不回复，故障线程停在异常状态，
// 进程留在原地等我们看完日志。
#include <mach/mach.h>

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
} wh_exc_req_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[128];
} wh_exc_reply_t;

// 线上 port descriptor 是 12 字节而不是结构体的 16 字节，全部按显式偏移解析。
#define EXC_THREAD_OFF 28
#define EXC_TYPE_OFF 60
#define EXC_CODED_OFF 64
#define EXC_CODE_OFF 68
#define EXC_FLAVOR_OFF 84
#define EXC_STATE_OFF 88
#define EXC_STATE_BODY_OFF 92

// 接住处决之后怎么处理触发线程：1 = 掐掉并回复，0 = 留在异常状态。
#ifndef WH_KILL_FAULTING_THREAD
#define WH_KILL_FAULTING_THREAD 0
#endif

// 1 = 2 秒后把异常端口还原成加固壳自己的
#ifndef WH_RESTORE_EXC_PORT
#define WH_RESTORE_EXC_PORT 0
#endif

// 1 = 不动主线程的异常端口
#ifndef WH_EXC_SKIP_MAIN
#define WH_EXC_SKIP_MAIN 0
#endif

// 1 = 每 250ms 重新装一遍处理器和线程异常端口。
// 关掉它用来判断"6 秒一次的处决"是不是被我们自己的高频探测搅出来的。
#ifndef WH_ARM_EVERY_TICK
#define WH_ARM_EVERY_TICK 0
#endif

static mach_port_t g_exc_port = MACH_PORT_NULL;
static __attribute__((unused)) int g_exc_installed;
static volatile int g_exc_count;
static volatile int g_unwind_count;

// 1 = 把卡在哨兵地址上的线程沿帧链退回调用方
#ifndef WH_UNWIND_BAD_PC
#define WH_UNWIND_BAD_PC 0
#endif

static void dump_fault(const wh_exc_req_t *req) {
    const uint8_t *b = (const uint8_t *)req;
    uint32_t etype = *(const uint32_t *)(b + EXC_TYPE_OFF);
    uint32_t codeCnt = *(const uint32_t *)(b + EXC_CODED_OFF);
    int64_t c0 = 0, c1 = 0;
    memcpy(&c0, b + EXC_CODE_OFF, 8);
    memcpy(&c1, b + EXC_CODE_OFF + 8, 8);
    uint32_t flavor = *(const uint32_t *)(b + EXC_FLAVOR_OFF);
    uint32_t stateCnt = *(const uint32_t *)(b + EXC_STATE_OFF);

    char buf[512], d[256];
    snprintf(buf, sizeof(buf),
             "EXCFAULT type=%u codeCnt=%u code0=%lld code1=%lld flavor=%u stateCnt=%u\n",
             etype, codeCnt, (long long)c0, (long long)c1, flavor, stateCnt);
    log_raw(buf);
    if (flavor != 6 || stateCnt < 34) { log_raw("  (状态不可用)\n"); return; }

    arm_thread_state64_t st;
    memcpy(&st, b + EXC_STATE_BODY_OFF, sizeof(st));

    uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
    uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
    uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
    uintptr_t fp = (uintptr_t)__darwin_arm_thread_state64_get_fp(st);
    snprintf(buf, sizeof(buf), "  pc=%#lx lr=%#lx fp=%#lx sp=%#lx\n",
             (unsigned long)pc, (unsigned long)lr, (unsigned long)fp, (unsigned long)sp);
    log_raw(buf);
    describe(pc, d, sizeof(d)); snprintf(buf, sizeof(buf), "  pc -> %s\n", d); log_raw(buf);
    describe(lr, d, sizeof(d)); snprintf(buf, sizeof(buf), "  lr -> %s\n", d); log_raw(buf);

    for (int i = 0; i < 29; i++) {
        uintptr_t v = (uintptr_t)st.__x[i];
        describe(v, d, sizeof(d));
        snprintf(buf, sizeof(buf), "  x%-2d = %#018lx %s\n", i, (unsigned long)v, d);
        log_raw(buf);
    }

    log_raw("  ---- 帧链 ----\n");
    uintptr_t cur = fp;
    for (int i = 0; i < 40; i++) {
        if (!cur || cur < 0x100000000ULL || (cur & 7)) break;
        uintptr_t next = 0, ret = 0;
        memcpy(&next, (void *)cur, 8);
        memcpy(&ret, (void *)(cur + 8), 8);
        if (!ret) break;
        describe(ret, d, sizeof(d));
        snprintf(buf, sizeof(buf), "  #%-2d ret=%s\n", i, d);
        log_raw(buf);
        if (next <= cur) break;
        cur = next;
    }
    log_raw("  ---- 帧链结束 ----\n");

    // sp 在异常状态里是 0（拿不到），但 fp 有效。以 fp 为基准向下扫：
    // 跳转方没建栈帧，它的返回地址还留在栈上。
    log_raw("  ---- 栈扫描（以 fp 为基准） ----\n");
    uintptr_t base = fp ? fp : sp;
    if (base) {
        uintptr_t lo = base - 0x6000;
        int hits = 0;
        for (uintptr_t p = lo; p < base + 0x400; p += 8) {
            uintptr_t v = 0;
            memcpy(&v, (void *)p, 8);
            if (!v) continue;
            uintptr_t off = 0;
            if (!module_for(v, &off) || off == 0) continue;
            describe(v, d, sizeof(d));
            snprintf(buf, sizeof(buf), "  [fp%+ld] %s\n", (long)((intptr_t)p - (intptr_t)base), d);
            log_raw(buf);
            if (++hits > 120) break;
        }
    }
    log_raw("  ---- 栈扫描结束 ----\n");
}

// 把卡在哨兵地址上的线程沿帧链退回调用方。
//
// arm_thread_state64_t 里 __fp 的偏移是 232（前面 29 个通用寄存器）。读到的 fp
// 指向的栈帧布局是 [fp]=上一层 fp、[fp+8]=返回地址，这是编译器默认生成的。
// 退回后线程从调用方继续执行，等于这次调用正常返回，不会留下挂死的锁。
// 跳飞的线程 lr=0、sp=0，没有任何返回路径，说明它不是要返回，而是要终结。
// 与其把它永久挂在异常状态（它多半还持有 GCD 工作队列的锁，实测会把界面卡死），
// 不如给它一块自己的栈，让它在上面执行 pthread_exit，按"线程自杀"的方式退出。
static void wh_thread_exit_stub(void) {
    pthread_exit(NULL);
}

#ifndef WH_THREAD_EXIT
#define WH_THREAD_EXIT 0
#endif

__attribute__((unused)) static int exit_faulting_thread(wh_exc_req_t *req) {
    const uint8_t *b = (const uint8_t *)req;
    uint32_t flavor = *(const uint32_t *)(b + EXC_FLAVOR_OFF);
    uint32_t stateCnt = *(const uint32_t *)(b + EXC_STATE_OFF);
    if (flavor != 6 || stateCnt < 34) { aialog("自杀放弃：flavor=%u cnt=%u", flavor, stateCnt); return 0; }

    uint8_t st[34 * 8];
    memcpy(st, b + EXC_STATE_BODY_OFF, sizeof(st));

    uint64_t pc = 0;
    memcpy(&pc, st + 256, 8);
    if (module_for(pc, NULL)) { aialog("自杀放弃：pc=%#llx 在镜像内", (unsigned long long)pc); return 0; }   // 落在正常镜像里的故障不按这条处理

    // 每个线程一块 128KB 栈，够 pthread_exit 的清理流程用。
    vm_address_t stack = 0;
    kern_return_t vkr = vm_allocate(mach_task_self(), &stack, 128 * 1024, VM_FLAGS_ANYWHERE);
    if (vkr != KERN_SUCCESS) { aialog("自杀放弃：vm_allocate=%d", vkr); return 0; }
    uint64_t sp = (stack + 128 * 1024) & ~15ULL;

    uint64_t entry = (uint64_t)(uintptr_t)&wh_thread_exit_stub;
    uint64_t zero = 0;
    for (int i = 0; i < 29; i++) memcpy(st + i * 8, &zero, 8);
    memcpy(st + 232, &zero, 8);   // fp
    memcpy(st + 240, &zero, 8);   // lr
    memcpy(st + 248, &sp, 8);     // sp
    memcpy(st + 256, &entry, 8);  // pc

    // 回复消息单独开缓冲，避免与请求消息里的旧状态重叠。
    static __thread uint8_t replybuf[2048];
    memset(replybuf, 0, sizeof(replybuf));
    memcpy(replybuf, &req->Head, 24);
    wh_exc_reply_t *rep = (wh_exc_reply_t *)replybuf;
    rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
    rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
    rep->Head.msgh_local_port = MACH_PORT_NULL;
    rep->Head.msgh_id = req->Head.msgh_id + 100;
    rep->Head.msgh_size = 40 + 68 * 4;
    rep->NDR = NDR_record;
    rep->RetCode = KERN_SUCCESS;
    rep->new_stateCnt = 68;
    memcpy(replybuf + 40, st, sizeof(st));
    (void)mach_msg(&rep->Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
                   rep->Head.msgh_size, 0, MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return 1;
}

__attribute__((unused)) static int unwind_to_caller(wh_exc_req_t *req) {
    const uint8_t *b = (const uint8_t *)req;
    uint32_t flavor = *(const uint32_t *)(b + EXC_FLAVOR_OFF);
    uint32_t stateCnt = *(const uint32_t *)(b + EXC_STATE_OFF);
    if (flavor != 6 || stateCnt < 34) return 0;

    uint8_t *st = (uint8_t *)(b + EXC_STATE_BODY_OFF);
    uint64_t pc = 0, fp = 0;
    memcpy(&pc, st + 256, 8);
    memcpy(&fp, st + 232, 8);

    uintptr_t off = 0;
    if (module_for(pc, &off)) { aialog("退回放弃：pc 在镜像内 %#lx", (unsigned long)pc); return 0; }
    if (!fp || fp < 0x100000000ULL || (fp & 7)) { aialog("退回放弃：fp=%#lx 非法", (unsigned long)fp); return 0; }

    uint64_t next_fp = 0, ret = 0;
    memcpy(&next_fp, (void *)fp, 8);
    memcpy(&ret, (void *)(fp + 8), 8);
    uintptr_t roff = 0;
    if (!ret || !module_for(ret, &roff)) {
        aialog("退回放弃：ret=%#llx 不在镜像内", (unsigned long long)ret);
        return 0;
    }
    if (next_fp && (next_fp <= fp || (next_fp & 7))) { aialog("退回放弃：next_fp=%#llx", (unsigned long long)next_fp); return 0; }

    // 同一个线程反复退回说明它在循环里重新跳飞，不能无限退。
    if (g_unwind_count > 64) return 0;
    g_unwind_count++;

    memcpy(st + 256, &ret, 8);          // pc = 返回地址
    memcpy(st + 240, &ret, 8);          // lr 也指向它，保持帧链自洽
    uint64_t new_sp = fp + 16;
    memcpy(st + 248, &new_sp, 8);       // sp = 弹出本帧
    memcpy(st + 232, &next_fp, 8);      // fp = 上一层

    wh_exc_reply_t *rep = (wh_exc_reply_t *)req;
    natural_t *ns = (natural_t *)((uint8_t *)rep + 40);
    // 目标区间 (40..312) 与源区间 (92..364) 在同一个缓冲区里重叠，必须用 memmove。
    // 计数单位是 4 字节的 natural，ARM_THREAD_STATE64 是 68 个，不是 34 个。
    memmove(ns, st, 68 * 4);

    rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
    rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
    rep->Head.msgh_local_port = MACH_PORT_NULL;
    rep->Head.msgh_id = req->Head.msgh_id + 100;
    rep->Head.msgh_size = 40 + 68 * 4;
    rep->NDR = NDR_record;
    rep->RetCode = KERN_SUCCESS;
    rep->new_stateCnt = 68;
    (void)mach_msg(&rep->Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
                   rep->Head.msgh_size, 0, MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return 1;
}

// 回复"已处理"，让内核恢复该线程继续执行（状态原样送回）。
__attribute__((unused)) static void wh_reply_success(wh_exc_req_t *req) {
    uint8_t *b = (uint8_t *)req;
    wh_exc_reply_t *rep = (wh_exc_reply_t *)b;
    natural_t *ns = (natural_t *)(b + 40);
    memmove(ns, b + EXC_STATE_BODY_OFF, 68 * 4);
    rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
    rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
    rep->Head.msgh_local_port = MACH_PORT_NULL;
    rep->Head.msgh_id = req->Head.msgh_id + 100;
    rep->Head.msgh_size = 40 + 68 * 4;
    rep->NDR = NDR_record;
    rep->RetCode = KERN_SUCCESS;
    rep->new_stateCnt = 68;
    (void)mach_msg(&rep->Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
                   rep->Head.msgh_size, 0, MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void *wh_exc_server(void *arg) {
    (void)arg;
    mach_msg_size_t rcv = 1024;
    wh_exc_req_t *req = (wh_exc_req_t *)calloc(1, rcv + 2048);
    if (!req) return NULL;
    while (1) {
        kern_return_t kr = mach_msg(&req->Head, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
                                    rcv, g_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == MACH_RCV_TOO_LARGE) {
            rcv = 8192;
            req = (wh_exc_req_t *)realloc(req, rcv + 2048);
            continue;
        }
        if (kr != KERN_SUCCESS) { usleep(20000); continue; }
        g_exc_count++;
        dump_fault(req);

        // 这些异常都是同一个模式：线程被送到 0xb5a01000 这个没映射的哨兵地址，
        // lr 和 sp 都是 0，回不去。不回复的话线程永久挂在异常状态，而它多半正
        // 持有 GCD 工作队列的锁——实测挂住 4 个线程后界面就整个卡死了。
        //
        // 栈上还留着完整帧链（[fp]=上一层 fp，[fp+8]=返回地址），所以可以沿帧
        // 指针把线程"退回"发起跳转那一层的返回点，让它像正常返回一样结束。
        // 跳向毒地址的线程不回复：让它停在异常态。它的 lr=0、sp=0，本来也回不去。
        // 注意不要对这类异常回复：pc 仍是毒地址，内核恢复后必然再次异常，
        // 实测直接变成 100% 忙循环。
#if WH_THREAD_EXIT
        if (exit_faulting_thread(req)) {
            aialog("EXCFAULT 第 %d 次：已让该线程自杀", g_exc_count);
            continue;
        }
#endif
#if WH_UNWIND_BAD_PC
        if (unwind_to_caller(req)) {
            aialog("EXCFAULT 第 %d 次：已退回调用方", g_exc_count);
            continue;
        }
#endif
#if WH_KILL_FAULTING_THREAD
        mach_port_t th = (mach_port_t)(*(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF) & 0xffffffffu);
        kern_return_t tk = thread_terminate(th);
        aialog("EXCFAULT 第 %d 次：thread_terminate(%u) -> %d", g_exc_count, th, tk);
        wh_exc_reply_t *rep = (wh_exc_reply_t *)req;
        rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
        rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
        rep->Head.msgh_local_port = MACH_PORT_NULL;
        rep->Head.msgh_id = req->Head.msgh_id + 100;
        rep->Head.msgh_size = 40;
        rep->NDR = NDR_record;
        rep->RetCode = KERN_SUCCESS;
        rep->new_stateCnt = 0;
        (void)mach_msg(&rep->Head, MACH_SEND_MSG | MACH_SEND_INTERRUPT,
                       rep->Head.msgh_size, 0, MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
#else
        aialog("EXCFAULT 第 %d 次，不回复，线程停在异常状态", g_exc_count);
#endif
    }
    return NULL;
}

// 加固壳可能自己装了任务级异常端口。接管之前先把它记下来，稍后还原，
// 用来验证"6.5 秒那一刀是不是因为发现异常端口被换过"。
static exception_mask_t g_omask[EXC_TYPES_COUNT];
static exception_handler_t g_ohand[EXC_TYPES_COUNT];
static exception_behavior_t g_obeh[EXC_TYPES_COUNT];
static thread_state_flavor_t g_ofl[EXC_TYPES_COUNT];
static mach_msg_type_number_t g_ocnt;

static __attribute__((unused)) void save_orig_exc_ports(void) {
    g_ocnt = EXC_TYPES_COUNT;
    kern_return_t kr = task_get_exception_ports(mach_task_self(),
        EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
        g_omask, &g_ocnt, g_ohand, g_obeh, g_ofl);
    aialog("原始异常端口 kr=%d 条数=%u", kr, g_ocnt);
    for (mach_msg_type_number_t i = 0; i < g_ocnt; i++) {
        aialog("  原始[%u] mask=%#x port=%u beh=%d flavor=%d",
               i, g_omask[i], g_ohand[i], (int)g_obeh[i], (int)g_ofl[i]);
    }
}

static __attribute__((unused)) void restore_orig_exc_ports(void) {
    for (mach_msg_type_number_t i = 0; i < g_ocnt; i++) {
        kern_return_t kr = task_set_exception_ports(mach_task_self(), g_omask[i],
            g_ohand[i], g_obeh[i], g_ofl[i]);
        aialog("还原异常端口[%u] -> %d", i, kr);
    }
}

// ============================================================
// 冻结探测
//
// 启动约 5 秒后我们自己的心跳线程停止，进程却还在，ps 里也没有崩溃记录。
// 这与同族 SDK（SecureUtilityPlus）在工行 App 里的做法一致：判定风险后
// 反复 thread_suspend 把线程全部冻住。这里挂住 thread_suspend，
// 只记录调用方，并让它空转（返回成功但不真正挂起）——先确认假设。
// ============================================================
#ifndef WH_BLOCK_SUSPEND
#define WH_BLOCK_SUSPEND 1
#endif

// 构造函数在主线程跑，记录主线程的 mach port（冻结判断与异常端口都用它）。
static mach_port_t g_main_thread = MACH_PORT_NULL;

#if WH_BLOCK_SUSPEND
static kern_return_t (*g_orig_thread_suspend)(mach_port_t);


// 全拦会让 SDK 陷入"冻结没生效"的忙循环（实测 3 秒吃掉 3.15 秒 CPU，
// 随后被系统的 CPU 资源限制杀掉），所以只拦主线程：主线程停住正是用户
// 看到的"界面卡死"，其他线程交给原函数处理。
static kern_return_t wh_thread_suspend(mach_port_t th) {
    // g_main_thread 在构造函数里记录（构造函数跑在主线程）。
    BOOL isMain = (g_main_thread != MACH_PORT_NULL && th == g_main_thread);
    static int n;
    if (++n <= 8) {
        aialog("THREAD_SUSPEND 第 %d 次 port=%u 主线程=%d", n, th, (int)isMain);
    }
    (void)isMain;
    return KERN_SUCCESS;
}

// KSCrash（本 App 里是腾讯 WPK 移植版）才是 thread_suspend 的调用方：
// 它捕获到异常后会把其它线程全部挂起抓现场，然后结束进程。
// 现象就是"界面卡死 → 十几秒后进程消失"。
// 我们已经在异常端口上接住了跳飞，所以这里让 KSCrash 干脆别安装。
#ifndef WH_DISABLE_KSCRASH
#define WH_DISABLE_KSCRASH 1
#endif

static void wh_noop_void(id self, SEL _cmd) { (void)self; (void)_cmd; }

static __attribute__((unused)) void disable_kscrash(void) {
    static const char *classes[] = {
        "WPKKSCrashInstallation", "WPKCrashInstallation", "WPKKSCrash",
        NULL
    };
    static const char *sels[] = { "install", "setupCrashSettings", NULL };
    int hit = 0;
    for (int i = 0; classes[i]; i++) {
        Class c = objc_getClass(classes[i]);
        if (!c) { aialog("KSCrash 类未找到 %s", classes[i]); continue; }
        for (int j = 0; sels[j]; j++) {
            SEL sel = sel_registerName(sels[j]);
            Method m = class_getClassMethod(c, sel);
            if (m) { method_setImplementation(m, (IMP)wh_noop_void); hit++; continue; }
            m = class_getInstanceMethod(c, sel);
            if (m) { method_setImplementation(m, (IMP)wh_noop_void); hit++; }
        }
    }
    aialog("KSCrash 安装入口已关闭 %d 处", hit);
}

static __attribute__((unused)) void install_suspend_hook(void) {
    MSHookFunction((void *)thread_suspend, (void *)wh_thread_suspend, (void **)&g_orig_thread_suspend);
    aialog("thread_suspend 已挂：orig=%p", (void *)g_orig_thread_suspend);
}
#endif

// ============================================================
// 退出链路追踪
//
// 进程在 6~9 秒时"有序退出"：没有崩溃报告、没有异常记录、日志戛然而止。
// 这种形态最可能是走到了 exit()。先只记录调用栈，随后照常退出——
// 目的是找到那个"拿到结论就结束进程"的 App 层入口。
// ============================================================
#ifndef WH_EXIT_TRACE
#define WH_EXIT_TRACE 0
#endif

#if WH_EXIT_TRACE
static void (*g_orig_exit)(int);

static void wh_exit(int code) {
    aialog("EXIT 被调用 code=%d", code);
    void *bt[40];
    int n = backtrace(bt, 40);
    for (int i = 0; i < n; i++) {
        char d[160];
        describe((uintptr_t)bt[i], d, sizeof d);
        aialog("  XT[%d] %s", i, d);
    }
    if (g_orig_exit) g_orig_exit(code);
}

// 退出可能不走 exit：_exit / abort / kill / task_terminate 都试一遍，
// 谁先打出调用栈，谁就是那条结束进程的路。
static void (*g_orig__exit)(int);
static void (*g_orig_abort)(void);
static int  (*g_orig_kill)(pid_t, int);
static int  (*g_orig_raise)(int);
static int  (*g_orig_pthread_kill)(pthread_t, int);
static kern_return_t (*g_orig_task_terminate)(mach_port_t);

static void dump_caller(const char *tag) {
    void *bt[24];
    int n = backtrace(bt, 24);
    aialog("%s 调用栈", tag);
    for (int i = 0; i < n && i < 12; i++) {
        char d[160];
        describe((uintptr_t)bt[i], d, sizeof d);
        aialog("  %s[%d] %s", tag, i, d);
    }
}

static void wh__exit(int code) { dump_caller("_EXIT"); if (g_orig__exit) g_orig__exit(code); }
static void wh_abort(void) { dump_caller("ABORT"); if (g_orig_abort) g_orig_abort(); }
static int wh_kill(pid_t p, int sig) { aialog("KILL pid=%d sig=%d", p, sig); dump_caller("KILL"); return g_orig_kill ? g_orig_kill(p, sig) : -1; }
static int wh_raise(int sig) { aialog("RAISE sig=%d", sig); dump_caller("RAISE"); return g_orig_raise ? g_orig_raise(sig) : -1; }
static int wh_pthread_kill(pthread_t t, int sig) { aialog("PKILL sig=%d", sig); dump_caller("PKILL"); return g_orig_pthread_kill ? g_orig_pthread_kill(t, sig) : -1; }
static kern_return_t wh_task_terminate(mach_port_t t) { dump_caller("TTE"); return g_orig_task_terminate ? g_orig_task_terminate(t) : KERN_FAILURE; }

static __attribute__((unused)) void install_exit_trace(void) {
    MSHookFunction((void *)exit, (void *)wh_exit, (void **)&g_orig_exit);
    MSHookFunction((void *)_exit, (void *)wh__exit, (void **)&g_orig__exit);
    MSHookFunction((void *)abort, (void *)wh_abort, (void **)&g_orig_abort);
    MSHookFunction((void *)kill, (void *)wh_kill, (void **)&g_orig_kill);
    MSHookFunction((void *)raise, (void *)wh_raise, (void **)&g_orig_raise);
    MSHookFunction((void *)pthread_kill, (void *)wh_pthread_kill, (void **)&g_orig_pthread_kill);
    MSHookFunction((void *)task_terminate, (void *)wh_task_terminate, (void **)&g_orig_task_terminate);
    aialog("退出链已挂观察 exit=%p _exit=%p abort=%p kill=%p",
           (void *)g_orig_exit, (void *)g_orig__exit, (void *)g_orig_abort, (void *)g_orig_kill);
}
#endif

// ============================================================
// 关掉安全检查开关
//
// GTCGbdDyncInfo 是远程配置对象，里面的 checkSafe / t116* / t43* / zx* / t251*
// 这一组字段看着就是"要不要做安全检查"以及各项安全任务的参数。按农行的经验，
// 改 App 层的判定开关比改 SDK 内部安全，所以这里用纯 ObjC 交换实现，
// 让 checkSafe 恒为 NO、所有 *_Enable 恒为 NO。
// ============================================================
#ifndef WH_CHECKSAFE_OFF
#define WH_CHECKSAFE_OFF 0
#endif

static BOOL wh_no(void *self, SEL _cmd) { (void)self; (void)_cmd; return NO; }
static void wh_setno(void *self, SEL _cmd, BOOL v) { (void)self; (void)_cmd; (void)v; }

static void force_no_on_class(const char *clsname) {
    Class c = objc_getClass(clsname);
    if (!c) { aialog("开关类未找到 %s", clsname); return; }
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    int hit = 0;
    for (unsigned int i = 0; i < n; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        BOOL isBoolProp = strcmp(sn, "checkSafe") == 0;
        BOOL isEnableSetter = (strncmp(sn, "setT", 4) == 0 || strncmp(sn, "setZx", 5) == 0) &&
                              strstr(sn, "Enable:") != NULL;
        if (!isBoolProp && !isEnableSetter) continue;
        char rt[8] = {0};
        method_getReturnType(ms[i], rt, sizeof(rt));
        if (isBoolProp && rt[0] != 'B' && rt[0] != 'c') continue;
        method_setImplementation(ms[i], isBoolProp ? (IMP)wh_no : (IMP)wh_setno);
        hit++;
    }
    if (ms) free(ms);
    aialog("开关类 %s 已关 %d 项", clsname, hit);
}

__attribute__((unused)) static void install_safe_switch_off(void) {
    force_no_on_class("GTCGbdDyncInfo");
}

// ============================================================
// 运行时指令补丁：跳过反调试调用
//
// WHClient+0x1406b0 这个带重入计数的守卫，在计数 >= 2 时先 getpid()，再带着
// 操作码 0xb 调进混淆分派器（+0x134730）。四处跳向 0xb5a01000 的线程，栈上的
// 返回地址都是 +0x1406d8，也就是这条 bl 的下一条指令——跳飞发生在分派器内部。
// 所以最小改动就是替掉这一条 bl，让守卫的计数逻辑保持原样，只是不再进分派器。
// ============================================================
#ifndef WH_ANTIDEBUG_NOP
#define WH_ANTIDEBUG_NOP 0
#endif

// 主二进制里的偏移，与虚拟地址的关系是 vm - 0x100000000
static const uintptr_t kAntidebugCallOff = 0x1406d4;

// 镜像 0 不一定是主程序：这台设备上它排到的是 IQKeyboardManagerSwift。
// 必须按可执行路径逐个比对，否则会把补丁写到别的库里。
static int main_image_index(void) {
    NSString *exe = [[NSBundle mainBundle] executablePath];
    const char *want = exe ? [exe fileSystemRepresentation] : NULL;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (want && strcmp(nm, want) == 0) return (int)i;
    }
    return -1;
}

static void patch_nops(uintptr_t off, int count) {
    int idx = main_image_index();
    if (idx < 0) { aialog("补丁：找不到主程序镜像"); return; }
    const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    if (!h) { aialog("补丁：拿不到主镜像头"); return; }
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)idx);
    uintptr_t page = ((uintptr_t)h + off) & ~0xFFFULL;
    size_t span = (((uintptr_t)h + off + 4 * count) & ~0xFFFULL) + 0x1000 - page;

    kern_return_t kr = vm_protect(mach_task_self(), page, span, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { aialog("补丁：改权限失败 %d", kr); return; }
    uint32_t *dst = (uint32_t *)((uintptr_t)h + off);
    uint32_t old[8] = {0};
    for (int i = 0; i < count; i++) old[i] = dst[i];
    {
        uint32_t *t = (uint32_t *)((uintptr_t)h + 0x4000);
        char d[160]; describe((uintptr_t)h + off, d, sizeof d);
        aialog("补丁定位 h=%p 目标=%s __text 首字=%#x", (void *)h, d, t[0]);
    }
    for (int i = 0; i < count; i++) dst[i] = 0xD503201F;   // nop
    sys_icache_invalidate(dst, 4 * count);
    kr = vm_protect(mach_task_self(), page, span, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    aialog("补丁 off=%#lx %d 条：原 %#x %#x 恢复权限=%d slide=%ld",
           (unsigned long)off, count, old[0], old[1], kr, (long)slide);
}

__attribute__((unused)) static void install_antidebug_patch(void) {
    patch_nops(kAntidebugCallOff, 1);
}

// 分派器本体 0x134730 的入口改成 ret：无论谁调进来都立刻返回，
// 不再进入那套会 br 到 0xb5a01000 的虚拟机。
#ifndef WH_DISPATCH_RET
#define WH_DISPATCH_RET 0
#endif

// 分派器换成跳板：记录参数与调用方，然后按"成功"返回。
// 用它确认毒地址到底是不是在这套虚拟机里面产生的。
#ifndef WH_DISPATCH_PROBE
#define WH_DISPATCH_PROBE 0
#endif

static long wh_dispatch_probe(long a0, long a1) {
    aialog("DISPATCH 被调用 a0=%ld a1=%#lx", a0, (unsigned long)a1);
    void *bt[24];
    int n = backtrace(bt, 24);
    for (int i = 0; i < n && i < 10; i++) {
        char d[160];
        describe((uintptr_t)bt[i], d, sizeof d);
        aialog("  DB[%d] %s", i, d);
    }
    return 0;
}

// 守卫 +0x1406b0：dispatch block 每次判断前都会进来。入口改成 ret，
// 用它判断毒地址到底是在守卫里产生的，还是在调用它的 block 里。
#ifndef WH_GUARD_RET
#define WH_GUARD_RET 1
#endif

__attribute__((unused)) static void patch_word(uintptr_t off, uint32_t insn, const char *tag) {
    int idx = main_image_index();
    if (idx < 0) { aialog("%s：找不到主镜像", tag); return; }
    const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    uintptr_t page = ((uintptr_t)h + off) & ~0xFFFULL;
    if (vm_protect(mach_task_self(), page, 0x1000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        aialog("%s：改权限失败", tag); return;
    }
    uint32_t *dst = (uint32_t *)((uintptr_t)h + off);
    uint32_t old = dst[0];
    dst[0] = insn;
    sys_icache_invalidate(dst, 4);
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    aialog("%s off=%#lx 原=%#x 新=%#x", tag, (unsigned long)off, old, insn);
}

// 只把 0x1406c8 那条 `b.lt`（计数 < 2 时跳到结尾）改成无条件跳转。
// 这样 getpid + 分派器整段被跳过，而函数的序言、收尾、返回值 x0=0
// 以及计数自增都保持原样——整段换掉入口会破坏返回约定，调用方拿到垃圾 x0，
// 结果是界面能画出来但事件不再处理。
//   0x1406c8: 0x540000ab  b.lt 0x1001406dc
//   0x14000005             b    0x1001406dc
__attribute__((unused)) static void install_guard_ret(void) {
    // 只把 0x1406c8 那条 b.lt 改成无条件跳转会保留计数自增，实测 8 秒就死；
    // 整段换成 `ret` 又破坏返回约定（x0 是垃圾），界面画得出来但事件不处理。
    // 所以换成两条指令：x0 置 0（与原函数的返回值一致）后返回。
    patch_word(0x1406b0, 0xD2800000, "守卫 x0=0");
    patch_word(0x1406b4, 0xD65F03C0, "守卫 ret");
}

__attribute__((unused)) static void install_dispatch_probe(void) {
    int idx = main_image_index();
    if (idx < 0) { aialog("分派器跳板：找不到主镜像"); return; }
    const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    uintptr_t off = 0x134730;
    uintptr_t page = ((uintptr_t)h + off) & ~0xFFFULL;
    if (vm_protect(mach_task_self(), page, 0x1000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        aialog("分派器跳板：改权限失败"); return;
    }
    uint32_t *dst = (uint32_t *)((uintptr_t)h + off);
    uint64_t t = (uint64_t)(uintptr_t)&wh_dispatch_probe;
    dst[0] = 0xD2800000u | (uint32_t)((t & 0xFFFF) << 5) | 16u;
    dst[1] = 0xF2800000u | (uint32_t)((((t >> 16) & 0xFFFF) << 5)) | 16u | (1u << 21);
    dst[2] = 0xF2800000u | (uint32_t)((((t >> 32) & 0xFFFF) << 5)) | 16u | (2u << 21);
    dst[3] = 0xD61F0200u;
    sys_icache_invalidate(dst, 16);
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    aialog("分派器入口已换跳板 target=%#llx", (unsigned long long)t);
}

__attribute__((unused)) static void install_dispatch_ret(void) {
    const struct mach_header_64 *h = NULL;
    int idx = main_image_index();
    if (idx >= 0) h = (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    if (!h) { aialog("分派器补丁：找不到主镜像"); return; }
    uintptr_t off = 0x134730;
    uintptr_t page = ((uintptr_t)h + off) & ~0xFFFULL;
    if (vm_protect(mach_task_self(), page, 0x1000, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        aialog("分派器补丁：改权限失败");
        return;
    }
    uint32_t *dst = (uint32_t *)((uintptr_t)h + off);
    uint32_t old = dst[0];
    dst[0] = 0xD65F03C0;   // ret
    sys_icache_invalidate(dst, 4);
    vm_protect(mach_task_self(), page, 0x1000, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    aialog("分派器入口已改 ret 原指令=%#x", old);
}

// ============================================================
// 反调试
//
// WHClient+0x1406b0 是个带重入计数的守卫：计数 >= 2 时先 getpid()，再带着
// 操作码 0xb 进混淆分派器，这是典型的 ptrace(PT_DENY_ATTACH, getpid(), 0, 0)
// 写法。在越狱环境里这类调用会失败，App 据此判定被调试。
// 让 ptrace 恒返回 0，等于告诉它"附加被拒绝成功"。
// ============================================================
#ifndef WH_PTRACE_NEUTER
#define WH_PTRACE_NEUTER 0
#endif

static int (*g_orig_ptrace)(int, pid_t, caddr_t, int);

static int wh_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    (void)request; (void)pid; (void)addr; (void)data;
    return 0;
}

__attribute__((unused)) static void install_ptrace_hook(void) {
    MSHookFunction((void *)ptrace, (void *)wh_ptrace, (void **)&g_orig_ptrace);
    aialog("ptrace 已接管 orig=%p", (void *)g_orig_ptrace);
}

// ============================================================
// 哨兵地址停放页
//
// 被判定为风险的线程会被一条 `br` 送到 0xb5a01000 这个没有映射的地址，
// 现场 lr=0、sp=0，没有任何返回路径，唯一结果就是进程崩掉。
// 这个地址每次运行都一样，所以直接在它上面铺一页可执行内存，内容是一条
// 自旋等待指令：
//     wfe        0xD503205F
//     b   .      0x17FFFFFE
// 跳过去的线程就此低功耗空转，不再产生异常，也不会去碰任何锁。
// 比起接管异常端口再想办法恢复，这样做不会在图谋失败时把进程拖死。
// ============================================================
#define WH_PARK_ADDR 0xb5a01000UL
#define WH_PARK_SIZE 0x4000

// 异常端口接管延迟多少毫秒。用来判断"跳转是不是被我们改端口这个动作引出来的"：
// 设成 800 的话，如果 App 能活过 800ms，说明前 800ms 里并没有跳转。
#ifndef WH_EXC_DELAY_MS
#define WH_EXC_DELAY_MS 0
#endif

#ifndef WH_PARK_SENTINEL
#define WH_PARK_SENTINEL 0
#endif

__attribute__((unused)) static void install_park_page(void) {
    // 先看清目标地址当前归谁：如果是别人已保留但没有落实的区间，固定映射会失败。
    vm_address_t q = (vm_address_t)WH_PARK_ADDR;
    vm_size_t qsz = 0;
    vm_region_basic_info_data_64_t bi;
    mach_msg_type_number_t bc = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t qkr = vm_region_64(mach_task_self(), &q, &qsz, VM_REGION_BASIC_INFO_64,
                                     (vm_region_info_t)&bi, &bc, &obj);
    aialog("停放页目标 %#lx 查询 kr=%d 实际起始=%#llx 大小=%#llx prot=%d",
           (unsigned long)WH_PARK_ADDR, qkr, (unsigned long long)q,
           (unsigned long long)qsz, qkr == KERN_SUCCESS ? bi.protection : -1);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);

    vm_address_t addr = (vm_address_t)WH_PARK_ADDR;
    kern_return_t kr = vm_allocate(mach_task_self(), &addr, WH_PARK_SIZE,
                                   VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (kr != KERN_SUCCESS) {
        void *m = mmap((void *)WH_PARK_ADDR, WH_PARK_SIZE,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        aialog("停放页 vm_allocate 失败 %d，改用 mmap -> %p", kr, m);
        if (m == MAP_FAILED) { aialog("停放页分配彻底失败"); return; }
        addr = (vm_address_t)m;
    }
    uint32_t code[2] = {0xD503205F, 0x17FFFFFE};
    memcpy((void *)addr, code, sizeof(code));
    kr = vm_protect(mach_task_self(), addr, WH_PARK_SIZE, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, sizeof(code));
    aialog("停放页已就绪 addr=%#lx 权限=%d", (unsigned long)addr, kr);
}

static void install_exc_handler(void) {
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) { aialog("异常端口分配失败 %d", kr); return; }
    mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);
    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                                  g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                  ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { aialog("设置异常端口失败 %d", kr); return; }
    pthread_t t;
    if (pthread_create(&t, NULL, wh_exc_server, NULL) == 0) pthread_detach(t);
    aialog("异常端口已接管 port=%u", g_exc_port);
}

// ============================================================
// 线程级异常端口接管
// ============================================================
static void arm_thread_exc_ports(void) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    int taken = 0;
    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
        if (WH_EXC_SKIP_MAIN && g_main_thread != MACH_PORT_NULL && list[i] == g_main_thread) {
            mach_port_deallocate(mach_task_self(), list[i]);
            continue;
        }
        kern_return_t kr = thread_set_exception_ports(list[i],
            EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
            g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            ARM_THREAD_STATE64);
        if (kr == KERN_SUCCESS) taken++;
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    (void)taken;
}

__attribute__((unused)) static void *ticker(void *arg) {
    (void)arg;
    // 每 250ms 打一行，用来确定进程究竟死在第几毫秒——崩溃报告只给到秒。
    for (int i = 0; i < 60; i++) {
        struct timespec ts = {0, 250 * 1000 * 1000};
        nanosleep(&ts, NULL);
        aialog("tick %d", i);
#if WH_EXC_DELAY_MS > 0
        // 每 250ms 一拍，到点一次性接管任务级与全部线程级异常端口。
        if ((int)(i + 1) * 250 >= WH_EXC_DELAY_MS && !g_exc_installed) {
            g_exc_installed = 1;
            install_exc_handler();
            arm_thread_exc_ports();
            aialog("已在 %dms 接管异常端口", (i + 1) * 250);
        }
#endif
    }
    return NULL;
}

// ============================================================
// 判定链路追踪：谁弹的"设备存在风险"，谁结束的进程
//
// 短路 checker 对崩溃次数没有影响（对照实验：开/关都是 4 次），说明结论不是
// 从 -(check) 返回的。真正要定位的是 App 层那个"拿到结论就弹窗然后退出"的入口，
// 也就是农行例子里 -[DTFrameworkInterface initRiskManage] 的对应物。
// ============================================================
#ifndef WH_TRACE_VERDICT
#define WH_TRACE_VERDICT 0
#endif

// 独立心跳：每 5 秒打一行，用来判断 App 是否已经整体卡死。
// 只有一行日志，不影响任何 hook 面。
#ifndef WH_TICK
#define WH_TICK 0
#endif
// 1 = 心跳同时用需要加锁的 aialog 写日志。用来区分"线程停了"和"线程被日志锁挡住"。
#ifndef WH_TICK_LOCKED
#define WH_TICK_LOCKED 0
#endif

#if WH_TICK
static void *wh_tick(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++) {
        struct timespec ts = {5, 0};
        nanosleep(&ts, NULL);
        // 先做一次无锁写：如果这一行出现了但下一行没有，说明是被日志互斥量挡住了，
        // 而不是线程本身停住。两者含义完全不同。
        log_unsafe("[TICK-RAW] alive\n");
#if WH_TICK_LOCKED
        aialog("TICK %d", i);
#endif
    }
    return NULL;
}
#endif

#if WH_TRACE_VERDICT

static void dump_bt(const char *tag) {
    void *bt[48];
    int n = backtrace(bt, 48);
    log_raw(tag);
    for (int i = 0; i < n; i++) {
        char d[160];
        describe((uintptr_t)bt[i], d, sizeof d);
        aialog("  BT[%d] %s", i, d);
    }
}

static id (*g_orig_alert3)(id, SEL, NSString *, NSString *, NSInteger);

static id wh_alert3(id self, SEL _cmd, NSString *title, NSString *message, NSInteger style) {
    aialog("ALERT 创建 title=%s | msg=%s",
           title ? [title UTF8String] : "(nil)",
           message ? [message UTF8String] : "(nil)");
    dump_bt("ALERT 调用栈");
    return g_orig_alert3 ? g_orig_alert3(self, _cmd, title, message, style) : nil;
}

static id (*g_orig_alertinit)(id, SEL, NSString *, NSString *, id, NSString *);

static id wh_alertinit(id self, SEL _cmd, NSString *title, NSString *message, id del, NSString *cancel) {
    aialog("UIALERT 创建 title=%s | msg=%s",
           title ? [title UTF8String] : "(nil)",
           message ? [message UTF8String] : "(nil)");
    dump_bt("UIALERT 调用栈");
    return g_orig_alertinit ? g_orig_alertinit(self, _cmd, title, message, del, cancel) : nil;
}

static void (*g_orig_present)(id, SEL, id, BOOL, id);

static void wh_present(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    aialog("PRESENT %s（调用方 %s）",
           vc ? object_getClassName(vc) : "(nil)",
           self ? object_getClassName(self) : "(nil)");
    if (g_orig_present) g_orig_present(self, _cmd, vc, animated, completion);
}

// Bangcle Everisk 的主控类。类名被混淆成 NgabsWzdwtYWXpPV，但方法名是明文：
// initWithKey: / runEveriskWithKey: / onlineEntry / offlineEntry / dispatchCheckers。
// 这里只观测调用顺序和调用方，不改返回值——先弄清楚 App 层是从哪一步走进来的。
#ifndef WH_EVERISK_OFF
#define WH_EVERISK_OFF 1
#endif

static id   (*g_orig_ev_initWithKey)(id, SEL, id);
static void (*g_orig_ev_run)(id, SEL, id);
static void (*g_orig_ev_online)(id, SEL);
static void (*g_orig_ev_offline)(id, SEL);
static void (*g_orig_ev_dispatch)(id, SEL);

static id wh_ev_initWithKey(id self, SEL _cmd, id key) {
    aialog("EVERISK initWithKey: key=%s", key ? [[key description] UTF8String] : "(nil)");
    dump_bt("EVERISK initWithKey: 调用栈");
#if WH_EVERISK_OFF
    return nil;
#else
    return g_orig_ev_initWithKey ? g_orig_ev_initWithKey(self, _cmd, key) : nil;
#endif
}

static void wh_ev_run(id self, SEL _cmd, id key) {
    aialog("EVERISK runEveriskWithKey: key=%s", key ? [[key description] UTF8String] : "(nil)");
    dump_bt("EVERISK runEveriskWithKey: 调用栈");
#if WH_EVERISK_OFF
    aialog("EVERISK 入口已短路，不调用原实现");
#else
    if (g_orig_ev_run) g_orig_ev_run(self, _cmd, key);
#endif
}

static void wh_ev_online(id self, SEL _cmd) {
    aialog("EVERISK onlineEntry");
    dump_bt("EVERISK onlineEntry 调用栈");
#if !WH_EVERISK_OFF
    if (g_orig_ev_online) g_orig_ev_online(self, _cmd);
#endif
}

static void wh_ev_offline(id self, SEL _cmd) {
    aialog("EVERISK offlineEntry");
    dump_bt("EVERISK offlineEntry 调用栈");
#if !WH_EVERISK_OFF
    if (g_orig_ev_offline) g_orig_ev_offline(self, _cmd);
#endif
}

static void wh_ev_dispatch(id self, SEL _cmd) {
    aialog("EVERISK dispatchCheckers");
#if !WH_EVERISK_OFF
    if (g_orig_ev_dispatch) g_orig_ev_dispatch(self, _cmd);
#endif
}

static void swizzle_cls(Class cls, const char *selname, IMP newimp, IMP *save) {
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel_registerName(selname));
    if (!m) m = class_getInstanceMethod(cls, sel_registerName(selname));
    if (!m) return;
    if (save) *save = method_getImplementation(m);
    method_setImplementation(m, newimp);
}

// 6.4 秒那一刀没有进我们的信号处理器，怀疑信号处理器被加固壳换掉了。
// 这里定期回读当前登记的处理器，变了就说明被接管。
static void report_handlers(const char *tag) {
    const int sigs[3] = {SIGILL, SIGSEGV, SIGTRAP};
    const char *names[3] = {"SIGILL", "SIGSEGV", "SIGTRAP"};
    for (int i = 0; i < 3; i++) {
        struct sigaction cur;
        memset(&cur, 0, sizeof(cur));
        if (sigaction(sigs[i], NULL, &cur) != 0) { aialog("%s %s 查询失败", tag, names[i]); continue; }
        aialog("%s %s handler=%p flags=%#x 是否我们=%d", tag, names[i],
               (void *)cur.sa_sigaction, (unsigned)cur.sa_flags,
               (void *)cur.sa_sigaction == (void *)fault_handler);
    }
}

// 在死亡前把每个线程的停在哪儿打出来：谁在倒计时，谁就是那一刀的执行者。
static void dump_all_threads(const char *tag) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    aialog("%s 线程数=%u", tag, cnt);
    for (mach_msg_type_number_t i = 0; i < cnt && i < 96; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS) continue;
        uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
        uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
        uintptr_t fp = (uintptr_t)__darwin_arm_thread_state64_get_fp(st);
        char d1[160], d2[160];
        describe(pc, d1, sizeof(d1));
        describe(lr, d2, sizeof(d2));
        aialog("  T%u pc=%s lr=%s", i, d1, d2);
        // 沿帧链往上挪几层，看它是在谁的代码里等。
        uintptr_t cur = fp;
        for (int k = 0; k < 6 && cur; k++) {
            uintptr_t next = 0, ret = 0;
            memcpy(&next, (void *)cur, 8);
            memcpy(&ret, (void *)(cur + 8), 8);
            if (!ret) break;
            char d3[160];
            describe(ret, d3, sizeof(d3));
            aialog("     T%u #%d %s", i, k, d3);
            if (next <= cur) break;
            cur = next;
        }
    }
    for (mach_msg_type_number_t i = 0; i < cnt; i++) mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
}

static __attribute__((unused)) void install_verdict_trace(void) {
    Class ac = objc_getClass("UIAlertController");
    swizzle_cls(ac, "alertControllerWithTitle:message:preferredStyle:",
                (IMP)wh_alert3, (IMP *)&g_orig_alert3);
    Class av = objc_getClass("UIAlertView");
    swizzle_cls(av, "initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:",
                (IMP)wh_alertinit, (IMP *)&g_orig_alertinit);
    Class vc = objc_getClass("UIViewController");
    swizzle_cls(vc, "presentViewController:animated:completion:",
                (IMP)wh_present, (IMP *)&g_orig_present);
    aialog("判定链路追踪已安装 alert=%d alertview=%d present=%d", ac != nil, av != nil, vc != nil);

    Class ev = objc_getClass("NgabsWzdwtYWXpPV");
    if (ev) {
        swizzle_cls(ev, "initWithKey:", (IMP)wh_ev_initWithKey, (IMP *)&g_orig_ev_initWithKey);
        swizzle_cls(ev, "runEveriskWithKey:", (IMP)wh_ev_run, (IMP *)&g_orig_ev_run);
        swizzle_cls(ev, "onlineEntry", (IMP)wh_ev_online, (IMP *)&g_orig_ev_online);
        swizzle_cls(ev, "offlineEntry", (IMP)wh_ev_offline, (IMP *)&g_orig_ev_offline);
        swizzle_cls(ev, "dispatchCheckers", (IMP)wh_ev_dispatch, (IMP *)&g_orig_ev_dispatch);
        aialog("Everisk 主控类已挂观察：init=%d run=%d online=%d dispatch=%d",
               g_orig_ev_initWithKey != NULL, g_orig_ev_run != NULL,
               g_orig_ev_online != NULL, g_orig_ev_dispatch != NULL);
    } else {
        aialog("未找到 Everisk 主控类 NgabsWzdwtYWXpPV");
    }
}

#endif

// ============================================================
// 短路所有 checker
//
// everisk SDK 的每个检测项都是一个实现了 +(name) / -(check) 的 ObjC 类。
// 这里把 -(check) 换成空实现，检测照常被"跑过"，但不会产生任何结论。
//
// 只用 method_setImplementation 改 ObjC 方法表，不改函数序言字节 ——
// SecureUtilityPlus 自带 MSHookFunctionChecker / FishHookChecker /
// RuntimeHookChecker，改函数序言会被它自己发现。
// 这一点与农行 abcbypass 的最终方案一致。
#ifndef WH_NEUTER_CHECKERS
#define WH_NEUTER_CHECKERS 1
#endif
// 诊断默认关闭。这里是 4.4 万个类，遍历加写日志会把启动拖过 watchdog 的
// 20 秒预算，表现为白屏卡住然后被系统杀掉。
#ifndef WH_DIAG
#define WH_DIAG 0
#endif

static __attribute__((unused)) int g_neutered;

static void wh_noop_check(id self, SEL _cmd) {
    (void)self; (void)_cmd;
}

// objc_copyClassNamesForImage 是公开 API，返回 C 字符串数组，调用方负责 free。
extern const char **objc_copyClassNamesForImage(const char *image, unsigned int *outCount);

__attribute__((unused)) static int neuter_checkers(void) {
    uint64_t t0 = mach_absolute_time();

    // 不能对整个类表做 respondsToSelector：这台设备上有 44620 个类，
    // 逐个做继承查找会把启动拖过 watchdog 的 20 秒预算（实测白屏后被杀）。
    // everisk 的 checker 与主二进制静态链接在一起，只查主二进制里的类就够，
    // 数量从四万多个降到几百个。
    NSString *exe = [[NSBundle mainBundle] executablePath];
    const char *img = exe ? [exe fileSystemRepresentation] : _dyld_get_image_name(0);
    unsigned int count = 0;
    const char **names = objc_copyClassNamesForImage(img, &count);
    aialog("N1 image=%s 类数=%u 用时=%llums", img ? img : "?",
           count, (unsigned long long)((mach_absolute_time() - t0) / 1000000ULL));
    if (!names) { aialog("N1 类名表为空"); return 0; }

    int n = 0;
    for (unsigned int i = 0; i < count; i++) {
        Class c = objc_getClass(names[i]);
        if (!c) continue;
        if (!class_respondsToSelector(c, @selector(check))) continue;
        if (!class_respondsToSelector(object_getClass(c), @selector(name))) continue;
        Method m = class_getInstanceMethod(c, @selector(check));
        if (!m || method_getImplementation(m) == (IMP)wh_noop_check) continue;
        method_setImplementation(m, (IMP)wh_noop_check);
        n++;
    }
    free(names);
    aialog("N2 短路=%d 总用时=%llums", n,
           (unsigned long long)((mach_absolute_time() - t0) / 1000000ULL));
    g_neutered = n;
    return n;
}

__attribute__((constructor)) static void wh_init(void) {
    open_log();
    aialog("===== WHBypass ctor =====");

    // 短路必须最先做，而且必须快：只遍历一遍类表，命中就换实现，不写日志。
#if WH_NEUTER_CHECKERS
    neuter_checkers();
#endif

    g_main_thread = pthread_mach_thread_np(pthread_self());
    snapshot_modules();
#if WH_PARK_SENTINEL
    install_park_page();
#endif
    install_fault_handler();
#if WH_PTRACE_NEUTER
    install_ptrace_hook();
#endif
#if WH_ANTIDEBUG_NOP
    install_antidebug_patch();
#endif
#if WH_DISPATCH_RET
    install_dispatch_ret();
#endif
#if WH_DISPATCH_PROBE
    install_dispatch_probe();
#endif
#if WH_GUARD_RET
    install_guard_ret();
#endif
#if WH_CHECKSAFE_OFF
    install_safe_switch_off();
#endif
#if WH_EXIT_TRACE
    install_exit_trace();
#endif
#if WH_DISABLE_KSCRASH
    disable_kscrash();
#endif
#if WH_BLOCK_SUSPEND
    install_suspend_hook();
#endif
    save_orig_exc_ports();
#if WH_EXC_DELAY_MS > 0
    aialog("异常端口推迟到 %dms 接管", WH_EXC_DELAY_MS);
#else
    install_exc_handler();
    arm_thread_exc_ports();
#endif

#if WH_TICK
    {
        pthread_t tk;
        if (pthread_create(&tk, NULL, wh_tick, NULL) == 0) pthread_detach(tk);
    }
#endif
#if WH_TRACE_VERDICT
    install_verdict_trace();
    pthread_t tk;
    if (pthread_create(&tk, NULL, ticker, NULL) == 0) pthread_detach(tk);
#endif

#if WH_DIAG
    dump_images();
    dump_checkers();
    install_checkallcall_swizzle();
    pthread_t t;
    if (pthread_create(&t, NULL, heartbeat, NULL) == 0) pthread_detach(t);
#endif
}
