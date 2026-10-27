// HSBCHKBypass 0.0.45：接管网关，把盾要问内核的东西原样抄下来。
//
// 进展与结论：
//   0.0.41 证明网关接管可行（槽 0x8510c8，网关 0x78befc，83 个封装走它）。
//   0.0.42 拦下退出后进程从 ~100ms 活到 15 秒以上，但停在启动图。
//   0.0.43 崩溃报告的栈指向我们自己的 snprintf：盾会在 libc 尚未就绪的线程上调用网关，
//          处理函数里一进 libc 就踩空。这是我们自己打崩的，不是被检测到。
//   0.0.44 改成环形缓冲 + 手写格式化 + 裸 svc write，不再崩；但发现两个测量错误——
//          一是我把第 6 个参数从 x6 读（C 只放到 x5），调用点全是垃圾；
//          二是消息缓冲区在调用者的栈上，等排空线程晚 1ms 再去读，内容早被覆盖了。
//
// 这一版：
//   - 参数按 AAPCS64 从 x0..x5 取，调用点用 x5；
//   - 处理函数当场把 mach 消息头（6 个字）和路径前缀（64 字节）原样拷进环形缓冲，
//     只做整数读写和直接内存加载，不调 libc；
//   - 排空线程只负责格式化（含十六进制、十进制都由手写函数完成）和裸 write。

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <pthread.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>

#import <substrate.h>

// 这一版只保留"改数据"的干预。下面这些函数是把 libc hook、dyld 枚举 hook、代码 patch
// 等已经验证无效或会自曝的手段留下来备查的，暂时不调用，所以关掉未使用告警。
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

#define GW_CODE_OFF  0x78befcULL
#define GW_SLOT_OFF  0x8510c8ULL
#define GW_SVC_WORD  0xd4001001u

#define RING 4096

// 1 = 把盾对注入库的那几次内存读取改指到盾自己的镜像上，用来确认这是不是判定依据
#define PAY   24         // 消息头 6 个字，或者完整路径（192 字节）

// ---------------------------------------------------------------- 裸写

static long raw_write(int fd, const void *buf, size_t n) {
    register long x16 __asm__("x16") = 4;   // SYS_write
    register long x0  __asm__("x0")  = fd;
    register long x1  __asm__("x1")  = (long)buf;
    register long x2  __asm__("x2")  = (long)n;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

extern uint64_t clock_gettime_nsec_np(unsigned clk);

static uint64_t up_ms(void) {
    return clock_gettime_nsec_np(4 /* CLOCK_UPTIME_RAW */) / 1000000ULL;
}

// ---------------------------------------------------------------- 手写格式化

typedef struct { char *p; char *end; } out_t;

static void o_ch(out_t *o, char c) { if (o->p < o->end) *o->p++ = c; }
static void o_s(out_t *o, const char *s) { while (*s) o_ch(o, *s++); }
static void o_u(out_t *o, unsigned long long v) {
    char t[24]; int n = 0;
    if (v == 0) { o_ch(o, '0'); return; }
    while (v && n < 24) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) o_ch(o, t[--n]);
}
static void o_d(out_t *o, long long v) {
    if (v < 0) { o_ch(o, '-'); o_u(o, (unsigned long long)(-v)); }
    else o_u(o, (unsigned long long)v);
}
static void o_h(out_t *o, unsigned long long v) {
    char t[18]; int n = 0;
    o_s(o, "0x");
    if (v == 0) { o_ch(o, '0'); return; }
    while (v && n < 18) {
        int d = (int)(v & 0xf);
        t[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (n) o_ch(o, t[--n]);
}

// ---------------------------------------------------------------- 环形缓冲

typedef struct {
    uint64_t nr;
    uint64_t a0, a1, a2, a3;
    uint64_t caller;
    uint64_t pay[PAY];
    uint32_t tid;
    uint32_t pad;
} rec_t;

static rec_t g_ring[RING];
static volatile unsigned g_head;
static volatile unsigned g_tail;
static int g_fd = -1;
static uintptr_t g_base;
static volatile uint64_t *g_slot;
static volatile int g_taken;
static uint64_t g_t0;
static volatile int g_draining;
static volatile int g_total;

// 注入库的地址范围。构造函数里填好，网关处理函数只做整数比较。
#define MAX_INJ 8
static uint64_t g_inj_lo[MAX_INJ];
static uint64_t g_inj_hi[MAX_INJ];
static volatile int g_inj_n;
static volatile uint64_t g_decoys[MAX_INJ];  // 每个注入库对应的系统库替身
static volatile int g_decoys_n;
static volatile int g_redirects;

static unsigned raw_tid(void) {
    uint64_t t = 0;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(t));
    return (unsigned)(t & 0xffffffff);
}

static void ring_push(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller) {
    unsigned h = g_head;
    unsigned n = (h + 1) % RING;
    if (n == g_tail) return;
    rec_t *r = &g_ring[h];
    r->nr = nr; r->a0 = a0; r->a1 = a1; r->a2 = a2; r->a3 = a3;
    r->caller = caller; r->tid = raw_tid(); r->pad = 0;

    // 现场就地拷贝：消息头和路径都在调用者的栈上，晚一点就没了。
    // 只做直接内存加载，不调任何库函数。
    int64_t snr = (int64_t)nr;
    const volatile uint64_t *src = NULL;
    int words = 0;
    if (snr == -31 && a0 > 0x1000) { src = (const volatile uint64_t *)(uintptr_t)a0; words = PAY; }
    else if ((snr == 5 || snr == 33) && a0 > 0x1000) { src = (const volatile uint64_t *)(uintptr_t)a0; words = PAY; }
    for (int i = 0; i < PAY; i++) {
        r->pay[i] = (src && i < words) ? src[i] : 0;
    }

    __atomic_store_n(&g_head, n, __ATOMIC_RELEASE);
    g_total++;
}

// ---------------------------------------------------------------- 排空线程侧

static void emit(const char *s, size_t n) { if (g_fd >= 0) raw_write(g_fd, s, n); }

static void emit_rec(const rec_t *r, uint64_t now) {
    char buf[768];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    int64_t nr = (int64_t)r->nr;

    o_ch(&o, '[');
    o_u(&o, (unsigned long long)(now - g_t0));
    o_s(&o, "ms] ");

    if (nr == -31) {
        uint32_t bits = (uint32_t)r->pay[0];
        uint32_t size = (uint32_t)(r->pay[0] >> 32);
        uint32_t id   = (uint32_t)(r->pay[2] >> 32);
        (void)bits; (void)size;
        o_s(&o, "mach id="); o_u(&o, id);
        o_s(&o, " w0="); o_h(&o, r->pay[0]);
        o_s(&o, " w3="); o_h(&o, r->pay[3]);
        o_s(&o, " w4="); o_h(&o, r->pay[4]);
        o_s(&o, " w5="); o_h(&o, r->pay[5]);
    } else if (nr == 26) {
        o_s(&o, "!! ptrace 请求="); o_u(&o, r->a0);
    } else if (nr == 1) {
        o_s(&o, "!! exit code="); o_u(&o, r->a0);
    } else if (nr == 5 || nr == 33) {
        char p[PAY * 8 + 1];
        int n = 0;
        for (int i = 0; i < PAY * 8; i++) {
            char c = (char)((r->pay[i / 8] >> ((i % 8) * 8)) & 0xff);
            if (c == 0) break;
            p[n++] = c;
        }
        p[n] = 0;
        o_s(&o, nr == 5 ? "open " : "access ");
        o_ch(&o, '"'); o_s(&o, p); o_ch(&o, '"');
        o_s(&o, " a1="); o_h(&o, r->a1);
    } else {
        o_s(&o, "syscall "); o_d(&o, (long long)nr);
        o_s(&o, " a0="); o_h(&o, r->a0);
        o_s(&o, " a1="); o_h(&o, r->a1);
        o_s(&o, " a2="); o_h(&o, r->a2);
        o_s(&o, " a3="); o_h(&o, r->a3);
    }
    o_s(&o, " 调用点=+"); o_h(&o, r->caller - g_base);
    o_s(&o, " tid="); o_u(&o, r->tid);
    o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));
}

// ---------------------------------------------------------------- 网关入口

// 从网关处理函数里直接落地的一行：纯算术 + 裸 write。
static void emergency_line(const rec_t *r) {
    char buf[160];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, "!! exit code="); o_u(&o, r->a0);
    o_s(&o, " 调用点=+");     o_h(&o, r->caller - g_base);
    o_s(&o, " tid=");         o_u(&o, r->tid);
    o_s(&o, " 已重定向=");     o_u(&o, (unsigned long long)g_redirects);
    o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));
}

// 由 gw_entry 调用，6 个参数：x0..x5（x5 是返回地址）。
void gw_record(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller) {
    ring_push(nr, a0, a1, a2, a3, caller);

    // 盾把每个已加载镜像的头读出来看。落在注入库上的那些读，改指到一个真正的系统
    // dylib 上，相对偏移保持不变：它读到的就是一份结构完全正常的库头。
    //
    // 注意不能拿盾自己当替身——它是可执行文件，第一个 load command 是 LC_SEGMENT_64，
    // 而解析器期待 LC_ID_DYLIB，会顺着垃圾偏移读崩（0.0.48 就是这么死的）。
    if (nr == (uint64_t)-31 && a0 > 0x1000 && g_decoys_n > 0) {
        volatile uint32_t *msg = (volatile uint32_t *)(uintptr_t)a0;
        if (msg[5] == 4808) {                      // msgh_id 在消息头偏移 20
            volatile uint64_t *srcp = (volatile uint64_t *)(uintptr_t)(a0 + 32);
            volatile uint64_t *lenp = (volatile uint64_t *)(uintptr_t)(a0 + 40);
            uint64_t src = *srcp;
            uint64_t len = *lenp;
            int n = g_inj_n;
            for (int i = 0; i < n; i++) {
                if (src >= g_inj_lo[i] && src < g_inj_hi[i]) {
                    uint64_t rel = src - g_inj_lo[i];
                    if (rel + len <= 0x20000 && i < g_decoys_n) {
                        *srcp = g_decoys[i] + rel;
                        g_redirects++;
                    }
                    break;
                }
            }
        }
    }

    if (nr == 1) {
        unsigned h = (g_head + RING - 1) % RING;
        emergency_line(&g_ring[h]);
    }
}

__attribute__((naked)) static void gw_entry(void) {
    // 原网关只有 svc + ret，除了 x0/x1 什么都不改。所以这里必须把 x0..x15 全部原样
    // 保存再恢复——中间那次 bl 会按 AAPCS64 把 x0..x18 全当调用者保存寄存器用，
    // 只备份 x0..x7 会让盾里内联在循环中的计数器悄悄变值。
    __asm__ volatile(
        "sub sp, sp, #0xa0\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x2,  x3,  [sp, #0x20]\n"
        "stp x4,  x5,  [sp, #0x30]\n"
        "stp x6,  x7,  [sp, #0x40]\n"
        "stp x8,  x9,  [sp, #0x50]\n"
        "stp x10, x11, [sp, #0x60]\n"
        "stp x12, x13, [sp, #0x70]\n"
        "stp x14, x15, [sp, #0x80]\n"
        "str x16,      [sp, #0x90]\n"
        "mov x0, x16\n"          // nr
        "ldr x1, [sp, #0x10]\n"  // a0
        "ldr x2, [sp, #0x18]\n"  // a1
        "ldr x3, [sp, #0x20]\n"  // a2
        "ldr x4, [sp, #0x28]\n"  // a3
        "ldr x5, [sp, #0x08]\n"  // caller = 进入时的 x30（stp x29,x30 里的第二个字）
        "bl _gw_record\n"
        "ldr x16, [sp, #0x90]\n"
        "ldp x14, x15, [sp, #0x80]\n"
        "ldp x12, x13, [sp, #0x70]\n"
        "ldp x10, x11, [sp, #0x60]\n"
        "ldp x8,  x9,  [sp, #0x50]\n"
        "ldp x6,  x7,  [sp, #0x40]\n"
        "ldp x4,  x5,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp], #0xa0\n"
        "svc #0x80\n"
        "ret\n"
    );
}

// ---------------------------------------------------------------- 接管

static uintptr_t find_shield(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "hsbchkmobilebankingx")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static void say(const char *s) { emit(s, strlen(s)); }

static void say_hex(const char *label, unsigned long long v) {
    char buf[128];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, label); o_h(&o, v); o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));
}

static void try_takeover(void) {
    if (g_taken == -1) return;
    if (!g_base) {
        g_base = find_shield();
        if (!g_base) return;
        uint32_t w = *(const volatile uint32_t *)(g_base + GW_CODE_OFF);
        say_hex("盾基址=", g_base);
        say_hex("网关首字=", w);
        if (w != GW_SVC_WORD) { g_taken = -1; say("网关首字不符，放弃\n"); return; }
        g_slot = (volatile uint64_t *)(g_base + GW_SLOT_OFF);
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (!nm) continue;
            if (strstr(nm, "hsbc") || strstr(nm, "hield") || strstr(nm, "promon") || strstr(nm, "RASP")) {
                say_hex("镜像 ", (unsigned long long)(uintptr_t)_dyld_get_image_header(i));
                say("  "); say(nm); say("\n");
            }
        }
    }
    uint64_t cur = *g_slot;
    if (cur == 0) return;
    uint64_t want = (uint64_t)(uintptr_t)&gw_entry;
    if (cur == want) { g_taken = 1; return; }
    *g_slot = want;
    g_taken = 1;
    say_hex("接管网关槽 原值=", cur);
    say_hex("          新值=", want);
}

static void *poller(void *arg) {
    (void)arg;
    for (int i = 0; i < 30000; i++) {
        try_takeover();
        if (g_taken == 1) {
            uint64_t want = (uint64_t)(uintptr_t)&gw_entry;
            uint64_t cur = *g_slot;
            if (cur != want && cur != 0) {
                *g_slot = want;
                say_hex("网关槽被改回=", cur);
                say("已重新接管\n");
            }
        }
        usleep(1000);
    }
    return NULL;
}

// 把当前进程加载的全部镜像打一遍，用来把盾读的地址对上具体是哪个库。
static void dump_images(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        say_hex("IMG ", (unsigned long long)(uintptr_t)_dyld_get_image_header(i));
        say("  ");
        say(nm);
        say("\n");
    }
}


// ---------------------------------------------------------------- dyld 枚举对抗
//
// 盾判定的输入是"已加载镜像的头"。它要拿到这些地址只能靠 dyld 的枚举接口。
// 这里把这些接口换成"过滤版"：路径不在 App 包内、也不在系统目录下的镜像一律不出现。
//
// 两个约束（链家那套踩过）：
//   1. 必须按调用方限定作用域。全局重排会让按索引遍历镜像的框架退化成 O(n²) 并冻结，
//      所以只有调用方落在盾自己的镜像里时才过滤，其它调用原样透传。
//   2. 不能用镜像地址范围判断调用方（返回值与执行地址不在同一范围），用 dladdr。

typedef uint32_t (*cnt_fn)(void);
typedef const void *(*hdr_fn)(uint32_t);
typedef const char *(*name_fn)(uint32_t);
typedef int (*dladdr_fn)(const void *, Dl_info *);

static cnt_fn      g_o_count;
static hdr_fn      g_o_header;
static name_fn     g_o_name;
static dladdr_fn   g_o_dladdr;
static uintptr_t   g_shield_lo, g_shield_hi;
static volatile int g_hiding;

static int caller_is_shield(const void *ret_addr) {
    if (!g_o_dladdr || !ret_addr) return 0;
    Dl_info info;
    if (g_o_dladdr(ret_addr, &info) == 0 || !info.dli_fbase) return 0;
    uintptr_t b = (uintptr_t)info.dli_fbase;
    return b >= g_shield_lo && b < g_shield_hi;
}

static int path_is_injected(const char *p) {
    if (!p) return 0;
    if (strncmp(p, "/private/var/containers/Bundle/", 31) == 0) return 0;
    if (strncmp(p, "/usr/lib/", 9) == 0) return 0;
    if (strncmp(p, "/System/", 8) == 0) return 0;
    return 1;
}

static uint32_t my_image_count(void) {
    uint32_t n = g_o_count();
    if (!g_hiding || !caller_is_shield(__builtin_return_address(0))) return n;
    uint32_t vis = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!path_is_injected(g_o_name(i))) vis++;
    }
    return vis;
}

// 按索引取。过滤之后索引要重新映射，所以必须做一张表；
// 表在每次调用时按需重建，规模是镜像数（约 900），一次 O(n) 可以接受。
static const void *my_image_header(uint32_t idx) {
    uint32_t n = g_o_count();
    if (!g_hiding || !caller_is_shield(__builtin_return_address(0))) {
        return idx < n ? g_o_header(idx) : NULL;
    }
    uint32_t vis = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (path_is_injected(g_o_name(i))) continue;
        if (vis == idx) return g_o_header(i);
        vis++;
    }
    return NULL;
}

static const char *my_image_name(uint32_t idx) {
    uint32_t n = g_o_count();
    if (!g_hiding || !caller_is_shield(__builtin_return_address(0))) {
        return idx < n ? g_o_name(idx) : NULL;
    }
    uint32_t vis = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = g_o_name(i);
        if (path_is_injected(nm)) continue;
        if (vis == idx) return nm;
        vis++;
    }
    return NULL;
}

static void install_dyld_hooks(void) {
    g_o_dladdr = (dladdr_fn)dlsym(RTLD_DEFAULT, "dladdr");
    void *c  = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    void *h  = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    void *n  = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    say_hex("dyld 接口 count=", (unsigned long long)(uintptr_t)c);
    say_hex("             header=", (unsigned long long)(uintptr_t)h);
    say_hex("             name=", (unsigned long long)(uintptr_t)n);
    if (!c || !h || !n || !g_o_dladdr) { say("dyld 接口不全，跳过\n"); return; }
    MSHookFunction(c, (void *)my_image_count,  (void **)&g_o_count);
    MSHookFunction(h, (void *)my_image_header, (void **)&g_o_header);
    MSHookFunction(n, (void *)my_image_name,   (void **)&g_o_name);
    g_hiding = 1;
    say("已挂上 dyld 枚举接口（仅对盾的调用生效）\n");
}


// ---------------------------------------------------------------- 改写自身路径
//
// 盾把每个已加载镜像的头读出来看。汇丰中国那套同源构建的记录里，把注入库头部的路径
// 特征字符串换掉能把退出从 3 秒推后到 17 秒，说明路径确实是判定输入之一。
// 这里把注入库 LC_ID_DYLIB 里的路径就地改成系统库的名字。
// 只改字符串内容，长度不变，不动任何代码，所以不会破坏盾的状态机。

static int patch_id_dylib(const struct mach_header_64 *mh, uintptr_t slide,
                          const char *replacement) {
    const uint8_t *base = (const uint8_t *)mh;
    const struct load_command *lc = (const struct load_command *)(base + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_ID_DYLIB) {
            struct dylib_command *dc = (struct dylib_command *)lc;
            char *path = (char *)((uint8_t *)dc + dc->dylib.name.offset);
            size_t cap = dc->cmdsize - dc->dylib.name.offset;
            size_t len = strlen(replacement);
            if (len + 1 > cap) return 0;
            uintptr_t page = (uintptr_t)path & ~0x3fffULL;
            size_t psize = ((uintptr_t)path + len + 1 - page + 0x3fff) & ~0x3fffULL;
            vm_protect(mach_task_self(), (vm_address_t)page, psize, 0,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            memcpy(path, replacement, len + 1);
            // 必须恢复成可执行：这一页是代码页，留成可写会被代码签名校验判死（SIGBUS）。
            vm_protect(mach_task_self(), (vm_address_t)page, psize, 0,
                       VM_PROT_READ | VM_PROT_EXECUTE);
            say_hex("已改写 LC_ID_DYLIB → ", (unsigned long long)(uintptr_t)path);
            say("  "); say(replacement); say("\n");
            return 1;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }
    (void)slide;
    return 0;
}

static void disguise_injected(void) {
    uint32_t n = _dyld_image_count();
    int done = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strncmp(nm, "/private/var/containers/Bundle/", 31) == 0) continue;
        if (strncmp(nm, "/usr/lib/", 9) == 0) continue;
        if (strncmp(nm, "/System/", 8) == 0) continue;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        if (patch_id_dylib(mh, 0, "/usr/lib/libSystem.B.dylib")) done++;
    }
    say_hex("改写路径的注入库数=", (unsigned long long)done);
}


// ---------------------------------------------------------------- 改掉退出函数
//
// 盾判定失败时走的是一条"无条件死"的叶子函数：
//     +0x5d842c:  mov x16,#1 ; mov x0,#1 ; 从网关槽取地址 ; blr x17 ; ret
// 它被四个守卫函数调用。拦系统调用（拦的是内核层）会让盾停在这条调用里再也回不去，
// 界面就一直停在启动图；把这个函数的第一条指令改成 ret，调用方会当成"已经处理完了"
// 继续往下跑，状态机的栈和寄存器都是完整的。
//
// 只改一条指令，不动任何数据，也不碰网关那张表。

static uint32_t g_orig_exit_fn_word;
static int g_exit_fn_patched;

static void patch_exit_function(void) {
    if (g_exit_fn_patched || !g_base) return;
    uintptr_t fn = g_base + 0x5d842c;
    uintptr_t page = fn & ~0x3fffULL;
    const uint32_t RET = 0xd65f03c0;
    if (*(volatile uint32_t *)fn == RET) { g_exit_fn_patched = 1; return; }
    if (vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        say("改退出函数：拿不到写权限\n");
        return;
    }
    g_orig_exit_fn_word = *(volatile uint32_t *)fn;
    *(volatile uint32_t *)fn = RET;
    // 这一页是代码页，必须马上恢复成可执行，否则走到这块代码会 SIGBUS（代码签名）。
    vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, 0,
               VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)page, 0x4000);
    g_exit_fn_patched = 1;
    say_hex("已把退出函数 +0x5d842c 改成 ret，原指令=", g_orig_exit_fn_word);
}


// ---------------------------------------------------------------- 看盾查了什么符号
//
// 盾没有导入任何镜像枚举接口（_dyld_image_count / _dyld_get_image_header 一个都没有），
// 却能准确读到每个已加载镜像的头。它导入了 _dlsym，最可能是用 dlsym 取
// _dyld_all_image_infos 这个全局结构，再顺着 infoArray 拿到全部基址。
// 先把它查过的每个符号名记下来。
typedef void *(*dlsym_fn)(void *, const char *);
static dlsym_fn g_o_dlsym;

static void *my_dlsym(void *handle, const char *name) {
    void *r = g_o_dlsym(handle, name);
    if (name) {
        uintptr_t off = (uintptr_t)__builtin_return_address(0) - g_base;
        if (off < 0x8c0000) {                 // 调用方在盾里
            say_hex("盾 dlsym 调用点=+", off);
            say("  符号="); say(name); say("\n");
        }
    }
    return r;
}

static void install_dlsym_hook(void) {
    void *p = dlsym(RTLD_DEFAULT, "dlsym");
    if (!p) { say("取不到 dlsym\n"); return; }
    if (*(const volatile uint32_t *)p == 0xd4200020) { say("dlsym 是 brk 桩\n"); return; }
    g_o_dlsym = (dlsym_fn)dlsym(RTLD_DEFAULT, "dlsym");
    MSHookFunction(p, (void *)my_dlsym, (void **)&g_o_dlsym);
    say_hex("已挂 dlsym，首字=", *(const volatile uint32_t *)p);
}

static void *drainer(void *arg) {
    (void)arg;
    for (int i = 0; i < 60000; i++) {
        if (!__atomic_exchange_n(&g_draining, 1, __ATOMIC_ACQ_REL)) {
            unsigned t = g_tail;
            uint64_t now = up_ms();
            while (t != g_head) {
                emit_rec(&g_ring[t], now);
                t = (t + 1) % RING;
                __atomic_store_n(&g_tail, t, __ATOMIC_RELEASE);
            }
            __atomic_store_n(&g_draining, 0, __ATOMIC_RELEASE);
        }
        usleep(1000);
    }
    return NULL;
}

static void *heartbeat(void *arg) {
    (void)arg;
    for (int i = 0; i < 3000; i++) {
        char buf[128];
        out_t o = { buf, buf + sizeof(buf) - 1 };
        o_s(&o, "心跳 pid="); o_d(&o, getpid());
        o_s(&o, " 累计="); o_d(&o, g_total);
        o_s(&o, " 待排="); o_u(&o, (g_head + RING - g_tail) % RING);
        o_s(&o, " 已重定向="); o_u(&o, (unsigned long long)g_redirects);
        o_ch(&o, '\n');
        emit(buf, (size_t)(o.p - buf));
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
    g_t0 = up_ms();
    say("===== 0.0.59 启动（只改数据，不碰任何代码）=====\n");

    try_takeover();
    dump_images();
    if (g_base) {
        g_shield_lo = g_base;
        g_shield_hi = g_base + 0x8c0000;
    }

    // 记下注入库的地址范围：路径不在 App 包内、也不在系统目录下的镜像就是。
    {
        uint32_t n = _dyld_image_count();
        int k = 0;
        for (uint32_t i = 0; i < n && k < MAX_INJ; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (!nm) continue;
            if (strncmp(nm, "/private/var/containers/Bundle/", 31) == 0) continue;
            if (strncmp(nm, "/usr/lib/", 9) == 0) continue;
            if (strncmp(nm, "/System/", 8) == 0) continue;
            uint64_t b = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
            g_inj_lo[k] = b;
            g_inj_hi[k] = b + 0x200000;
            k++;
        }
        g_inj_n = k;
        say_hex("注入库个数=", (unsigned long long)k);
        for (int i = 0; i < k; i++) say_hex("  范围 起点=", g_inj_lo[i]);
    }

    {
        // 替身优先选 libobjc / libsystem，它们本身就是 dylib，load command 结构齐全。
        const char *want[] = { "/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib", NULL };
        uint64_t decoy = 0;
        for (int w = 0; want[w] && !decoy; w++) {
            uint32_t n = _dyld_image_count();
            for (uint32_t i = 0; i < n; i++) {
                const char *nm = _dyld_get_image_name(i);
                if (nm && strcmp(nm, want[w]) == 0) {
                    decoy = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
                    break;
                }
            }
        }
        for (int i = 0; i < g_inj_n; i++) g_decoys[i] = decoy;
        g_decoys_n = decoy ? g_inj_n : 0;
        say_hex("替身库基址=", decoy);
    }



    pthread_t a, b, c;
    pthread_create(&a, NULL, poller, NULL);
    pthread_create(&b, NULL, drainer, NULL);
    pthread_create(&c, NULL, heartbeat, NULL);
}
