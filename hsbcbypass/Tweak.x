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
#import <pthread.h>

// 同时写 syslog 和沙盒内文件(syslog 在本设备读不到,靠文件回捞)
static void hsbc_file_log(NSString *line) {
    static NSString *path = nil;
    if (!path) {
        path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hsbc_probe_%d.log", getpid()]];
    }
    NSString *entry = [line stringByAppendingString:@"\n"];
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (f) { fwrite(entry.UTF8String, 1, strlen(entry.UTF8String), f); fclose(f); }
}

static double g_t0 = 0;
#define HSBCLOG(fmt, ...) do { \
    if (g_t0 == 0) g_t0 = CFAbsoluteTimeGetCurrent(); \
    double _dt = (CFAbsoluteTimeGetCurrent() - g_t0) * 1000.0; \
    NSString *_s = [NSString stringWithFormat:(@"[+%.0fms] " fmt), _dt, ##__VA_ARGS__]; \
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

// ---- 更多退出变体 ----
static void (*orig_Exit)(int);
static void my_Exit(int code) { HSBCLOG(@"_Exit(%d)", code); hsbc_dump_backtrace("_Exit"); orig_Exit(code); }

static void (*orig_terminate)(void);
static void my_terminate(void) { HSBCLOG(@"std::terminate/objc"); hsbc_dump_backtrace("terminate"); orig_terminate(); }

// ---- 信号捕获:若靠 raise/信号退出,handler 会先记录(SIGKILL/SIGSTOP 不可捕获)----
static void hsbc_sig_handler(int sig) {
    HSBCLOG(@"⚡ 收到信号 sig=%d", sig);
    hsbc_dump_backtrace("signal");
    // 记录后恢复默认并重抛,保持原行为
    signal(sig, SIG_DFL);
    raise(sig);
}
static void hsbc_install_sig_handlers(void) {
    int sigs[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGSYS, SIGFPE, SIGPIPE };
    for (unsigned i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) {
        signal(sigs[i], hsbc_sig_handler);
    }
    HSBCLOG(@"信号 handler 已安装 (ABRT/SEGV/BUS/ILL/TRAP/SYS/FPE/PIPE)");
}

// ======== RASPFramework Swift 决策点探针 ========
// 通过 image 加载基址 + nm 符号偏移定位并 hook,记录「进入/返回」。
// 若只见「进入」不见「返回」,证明退出(raw syscall)发生在该方法内部。
// 只透传不解引用 self(x20 swiftself 由 substrate trampoline 保留),安全。

#import <mach-o/dyld.h>

// nm 给出的 __TEXT 相对偏移(RASPFramework, base=0)
#define OFF_setupSecureModel        0x6a70  // RASPAppInteractor.setupSecureModel()
#define OFF_presentUntrusted_accept 0x79f8  // RASPAppRouter.presentUntrustedDeviceScreen(acceptJailbroken:track:)
#define OFF_RASPAppController_init   0x6508  // RASPAppController.init(bundle:...)
#define OFF_configViewController     0x5f20  // RASPAppConfigurator.configViewController(...)
#define OFF_RASPvcViewDidLoad        0x8080  // RASPAppViewController.viewDidLoad()

static void *raspfw_base(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "RASPFramework")) {
            return (void *)_dyld_get_image_header(i);
        }
    }
    return NULL;
}

static void (*orig_setupSecureModel)(void);
static void my_setupSecureModel(void) {
    HSBCLOG(@"→ 进入 RASPAppInteractor.setupSecureModel");
    orig_setupSecureModel();
    HSBCLOG(@"← 返回 RASPAppInteractor.setupSecureModel (未在此退出)");
}

// 心跳线程:每 10ms 记录一次存活,精确定位退出发生的时间窗口
__attribute__((unused)) static void hsbc_dump_images(const char *filter) {
    uint32_t n = _dyld_image_count();
    HSBCLOG(@"==== image 列表 (filter=%s, 共%u) ====", filter, n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (filter && !strcasestr(nm, filter)) continue;
        HSBCLOG(@"  [%u] %s", i, nm);
    }
}

static void *hsbc_heartbeat(void *arg) {
    for (int i = 0; ; i++) {
        if (i % 10 == 0) HSBCLOG(@"♥ 存活 #%d", i);  // 每 100ms 落一条
        usleep(10 * 1000);
    }
    return NULL;
}

// naked trampoline:记录进入 RASPAppController 构造器,参数寄存器原样透传后 tail-call 原实现
extern void hsbc_log_ctrl_init(void);
void hsbc_log_ctrl_init(void) { HSBCLOG(@"→ 进入 RASPAppController.__allocating_init"); }

static void *orig_ctrl_init = NULL;
__attribute__((naked)) static void my_ctrl_init(void) {
    __asm__ volatile(
        "sub sp, sp, #0xa0\n"
        "stp x0, x1, [sp, #0x00]\n"
        "stp x2, x3, [sp, #0x10]\n"
        "stp x4, x5, [sp, #0x20]\n"
        "stp x6, x7, [sp, #0x30]\n"
        "stp x8, x20, [sp, #0x40]\n"
        "stp d0, d1, [sp, #0x50]\n"
        "stp d2, d3, [sp, #0x60]\n"
        "stp d4, d5, [sp, #0x70]\n"
        "stp d6, d7, [sp, #0x80]\n"
        "stp x29, x30, [sp, #0x90]\n"
        "bl _hsbc_log_ctrl_init\n"
        "ldp x29, x30, [sp, #0x90]\n"
        "ldp d6, d7, [sp, #0x80]\n"
        "ldp d4, d5, [sp, #0x70]\n"
        "ldp d2, d3, [sp, #0x60]\n"
        "ldp d0, d1, [sp, #0x50]\n"
        "ldp x8, x20, [sp, #0x40]\n"
        "ldp x6, x7, [sp, #0x30]\n"
        "ldp x4, x5, [sp, #0x20]\n"
        "ldp x2, x3, [sp, #0x10]\n"
        "ldp x0, x1, [sp, #0x00]\n"
        "add sp, sp, #0xa0\n"
        "adrp x16, _orig_ctrl_init@PAGE\n"
        "ldr x16, [x16, _orig_ctrl_init@PAGEOFF]\n"
        "br x16\n"
    );
}

static bool g_rasp_hooked = false;

static void hsbc_try_hook_rasp(const char *whence) {
    if (g_rasp_hooked) return;
    void *base = raspfw_base();
    if (!base) return;
    g_rasp_hooked = true;
    HSBCLOG(@"[%s] RASPFramework base=%p", whence, base);
    void *addr = (void *)((uintptr_t)base + OFF_setupSecureModel);
    MSHookFunction(addr, (void *)my_setupSecureModel, (void **)&orig_setupSecureModel);
    HSBCLOG(@"已 hook setupSecureModel @ %p (off=0x%x)", addr, OFF_setupSecureModel);
    void *ci = (void *)((uintptr_t)base + OFF_RASPAppController_init);
    MSHookFunction(ci, (void *)my_ctrl_init, (void **)&orig_ctrl_init);
    HSBCLOG(@"已 hook RASPAppController.init @ %p (off=0x%x)", ci, OFF_RASPAppController_init);
}

static void hsbc_dyld_image_added(const struct mach_header *mh, intptr_t slide) {
    // 每次有新 image 加载都尝试(RASPFramework 可能晚加载)
    hsbc_try_hook_rasp("dyld-add-image");
}

// ======== 脱壳:dump 主二进制解密后的加密页 ========
// China 只有 1 页(cryptoff=0x8000, cryptsize=0x1000)加密。
// 内存里该页已解密,dump 出来即可离线拼回完整明文二进制。
#import <mach-o/loader.h>
#import <mach-o/getsect.h>

static void hsbc_dump_decrypted(void) {
    // 遍历找 MH_EXECUTE 主可执行(image[0] 在有注入时未必是主 App)
    const struct mach_header_64 *mh = NULL;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) {
            const char *nm = _dyld_get_image_name(i);
            if (nm && strstr(nm, "China.app/China")) { mh = h; break; }
            if (!mh) mh = h;  // 兜底:第一个 MH_EXECUTE
        }
    }
    if (!mh) { HSBCLOG(@"脱壳:未找到主可执行"); return; }
    HSBCLOG(@"脱壳:主二进制 header=%p", mh);

    // 遍历 load commands 找 LC_ENCRYPTION_INFO_64
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    uint64_t text_vmaddr = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            const struct encryption_info_command_64 *e =
                (const struct encryption_info_command_64 *)lc;
            cryptoff = e->cryptoff; cryptsize = e->cryptsize; cryptid = e->cryptid;
        } else if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *s = (const struct segment_command_64 *)lc;
            if (strcmp(s->segname, "__TEXT") == 0) text_vmaddr = s->vmaddr;
        }
        p += lc->cmdsize;
    }
    HSBCLOG(@"脱壳:cryptoff=0x%x cryptsize=0x%x cryptid=%u text_vmaddr=0x%llx",
            cryptoff, cryptsize, cryptid, text_vmaddr);
    if (cryptsize == 0) { HSBCLOG(@"脱壳:无加密段"); return; }

    // 加密页在内存的地址 = text_vmaddr(含 slide, header 即 text_vmaddr+slide) + cryptoff
    // header 地址就是 __TEXT 段的运行时基址
    const uint8_t *decptr = (const uint8_t *)mh + cryptoff;
    NSString *out = [NSTemporaryDirectory() stringByAppendingPathComponent:@"China_dec_page.bin"];
    FILE *f = fopen([out fileSystemRepresentation], "wb");
    if (f) {
        size_t w = fwrite(decptr, 1, cryptsize, f);
        fclose(f);
        HSBCLOG(@"脱壳:已 dump %zu 字节 → %@", w, out);
    } else {
        HSBCLOG(@"脱壳:无法写文件 %@", out);
    }
}

// ======== 检测「输入」观测(纯记录,原样放行)========
// 越狱检测必须先读环境。记录含越狱特征的查询,定位判定方式。
#import <sys/stat.h>
#import <sys/sysctl.h>

// 判断路径是否是越狱/敏感探测特征
static bool hsbc_is_jb_query(const char *p) {
    if (!p) return false;
    static const char *kw[] = {
        "MobileSubstrate", "TweakInject", "substrate", "Substitute",
        "Cydia", "Sileo", "Zebra", "/var/jb", "/private/preboot",
        "apt", "dpkg", "/bin/bash", "/bin/sh", "/usr/sbin/sshd", "ssh",
        "cydia", "frida", "cynject", "cycript", ".dylib", "jailbreak",
        "/Library/", "/Applications/", "procursus", "roothide", "Dopamine",
        "bootstrap", "/var/mobile/Library/Preferences/", NULL
    };
    for (int i = 0; kw[i]; i++) if (strcasestr(p, kw[i])) return true;
    return false;
}

#define DEF_PATH_HOOK(name, rettype, ...) \
    static rettype (*orig_##name)(__VA_ARGS__);

static void hsbc_bt_caller(const char *tag, const char *arg);

static int (*orig_stat)(const char *, struct stat *);
static int my_stat(const char *p, struct stat *b) {
    if (hsbc_is_jb_query(p)) HSBCLOG(@"stat(\"%s\")", p);
    return orig_stat(p, b);
}
static int (*orig_lstat)(const char *, struct stat *);
static int my_lstat(const char *p, struct stat *b) {
    if (hsbc_is_jb_query(p)) hsbc_bt_caller("lstat", p);
    return orig_lstat(p, b);
}
// 回溯调用栈,标出发起检测的模块+偏移(过滤系统/探针自身噪声)
static void hsbc_bt_caller(const char *tag, const char *arg) {
    void *frames[24];
    int n = backtrace(frames, 24);
    HSBCLOG(@"%s(\"%s\") ← 调用栈:", tag, arg);
    for (int i = 1; i < n && i < 10; i++) {
        Dl_info info;
        if (dladdr(frames[i], &info) && info.dli_fname) {
            const char *base = strrchr(info.dli_fname, '/');
            base = base ? base + 1 : info.dli_fname;
            uintptr_t off = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
            HSBCLOG(@"    #%d %s +0x%lx", i, base, off);
        }
    }
}

static int (*orig_access)(const char *, int);
static int my_access(const char *p, int m) {
    if (hsbc_is_jb_query(p)) hsbc_bt_caller("access", p);
    return orig_access(p, m);
}
static int (*orig_open)(const char *, int, ...);
static int my_open(const char *p, int fl, ...) {
    if (hsbc_is_jb_query(p)) hsbc_bt_caller("open", p);
    return orig_open(p, fl, 0);
}
static FILE *(*orig_fopen)(const char *, const char *);
static FILE *my_fopen(const char *p, const char *m) {
    if (hsbc_is_jb_query(p)) HSBCLOG(@"fopen(\"%s\")", p);
    return orig_fopen(p, m);
}
static void *(*orig_dlopen)(const char *, int);
static void *my_dlopen(const char *p, int m) {
    if (hsbc_is_jb_query(p)) hsbc_bt_caller("dlopen", p);
    return orig_dlopen(p, m);
}
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int nl, void *op, size_t *os, void *np, size_t ns) {
    if (nl >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID)
        HSBCLOG(@"sysctl(KERN_PROC PID=%d) ← 可能查被调试", name[3]);
    return orig_sysctl(name, nl, op, os, np, ns);
}
static pid_t (*orig_fork)(void);
static pid_t my_fork(void) {
    HSBCLOG(@"fork() 被调用 ← 可能 fork 检测");
    return orig_fork();
}

%ctor {
    @autoreleasepool {
        HSBCLOG(@"探针注入成功: pid=%d ppid=%d bundle=%@ argv0=%s", getpid(), getppid(),
                [[NSBundle mainBundle] bundleIdentifier],
                [[NSProcessInfo processInfo] arguments].count > 0 ?
                  [[[NSProcessInfo processInfo] arguments][0] UTF8String] : "?");

        MSHookFunction((void *)exit,          (void *)my_exit,          (void **)&orig_exit);
        MSHookFunction((void *)_exit,         (void *)my__exit,         (void **)&orig__exit);
        MSHookFunction((void *)abort,         (void *)my_abort,         (void **)&orig_abort);
        MSHookFunction((void *)kill,          (void *)my_kill,          (void **)&orig_kill);
        MSHookFunction((void *)pthread_kill,  (void *)my_pthread_kill,  (void **)&orig_pthread_kill);

        void *pExit = dlsym(RTLD_DEFAULT, "_Exit");
        if (pExit) MSHookFunction(pExit, (void *)my_Exit, (void **)&orig_Exit);
        void *pTerm = dlsym(RTLD_DEFAULT, "_ZSt9terminatev");
        if (pTerm) MSHookFunction(pTerm, (void *)my_terminate, (void **)&orig_terminate);

        hsbc_install_sig_handlers();

        HSBCLOG(@"退出路径探针已布设 (exit/_exit/abort/kill/pthread_kill/_Exit/terminate/signals)");

        hsbc_dump_decrypted();  // 尽早脱壳,趁进程存活

        // 检测「输入」观测
        MSHookFunction((void *)stat,   (void *)my_stat,   (void **)&orig_stat);
        MSHookFunction((void *)lstat,  (void *)my_lstat,  (void **)&orig_lstat);
        MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
        MSHookFunction((void *)open,   (void *)my_open,   (void **)&orig_open);
        MSHookFunction((void *)fopen,  (void *)my_fopen,  (void **)&orig_fopen);
        MSHookFunction((void *)dlopen, (void *)my_dlopen, (void **)&orig_dlopen);
        MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
        MSHookFunction((void *)fork,   (void *)my_fork,   (void **)&orig_fork);
        HSBCLOG(@"检测输入探针已布设 (stat/lstat/access/open/fopen/dlopen/sysctl/fork)");

        // App 退出极快(注入后 <0.5s),不能用 dispatch_after。
        // 立即尝试同步定位;若 RASPFramework 尚未加载,注册 dyld 回调在其加载瞬间 hook。
        hsbc_try_hook_rasp("ctor-immediate");
        _dyld_register_func_for_add_image(&hsbc_dyld_image_added);
        HSBCLOG(@"已注册 dyld image 回调,等待 RASPFramework 加载");

        pthread_t hb;
        pthread_create(&hb, NULL, hsbc_heartbeat, NULL);
        pthread_detach(hb);
        HSBCLOG(@"心跳线程已启动");
    }
}
