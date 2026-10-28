// HSBCHKBypass 0.0.131：接管网关，把盾要问内核的东西原样抄下来。
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
#import <mach/vm_region.h>
#import <mach/thread_act.h>
#import <mach/arm/thread_status.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <pthread.h>
#import <signal.h>
#import <setjmp.h>
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

// 两个干预开关。0.0.130 之前把"让盾对注入库的读取失败"留在了代码里，
// 之后又叠了"改写检查项"，多个变量同时在场，退出链路对不上任何单一原因。
// 现在分开关，一次只上一个。
#define DO_TAKEOVER 1   // 接管网关（0 = 完全不干预，只留着当对照）
#define DO_LATEDL   0   // 枚举之后 dlopen 一个新库，看盾会不会读到它
#define DO_REDIRECT 0   // 0=不改 1=改指替身库 2=返回全零页
#define DO_FAKE     0   // 把检查项换成恒返回 0 的假对象
#define DO_ZEROFLAG 0   // 把 0x866fc8 处的标志清零（非零就走原因码 4）
#define DO_QUIET    1   // 安静模式：不做密集线程快照
#define DO_BLKIMMAP 1   // 让"映射整份共享缓存"这次调用失败
#define DO_HOOKCHK  0   // 检查 libc 函数序言有没有被注入器改成跳板
#define DO_DISGUISE 0   // 改写注入库在 dyld 里登记的名字
#define DO_SENTINEL 0   // 哨兵：会被 dyld 自己的校验搞崩，只留作记录
#define DO_DISKCHECK 0  // 逐镜像比对内存与磁盘（实验用，平时关掉）

#define ZERO_PAGE 0x4000
static char g_zero_page[ZERO_PAGE] __attribute__((aligned(ZERO_PAGE)));

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
    uint64_t ts;      // 拦截当时的 CNTPCT_EL0，排空线程换算成毫秒
    uint64_t fp;      // 拦截当时的 x29，用来回溯是谁发起的这次调用
} rec_t;

static rec_t g_ring[RING];
static volatile unsigned g_head;
static volatile unsigned g_tail;
static int g_fd = -1;
static uintptr_t g_base;
static volatile uint64_t *g_slot;
static volatile int g_taken;
static uint64_t g_t0;
static volatile uint64_t g_ts0;

extern kern_return_t mach_vm_protect(vm_map_t, uint64_t, uint64_t, boolean_t, vm_prot_t);
static void say(const char *s);
static void say_hex(const char *label, unsigned long long v);
static void emit_ts(const char *s, size_t n);

// 把一段代码改成"直接返回 0"。必须把页临时改成可写，写完立刻恢复可读可执行，
// 否则代码签名会以 SIGBUS 收场（0.0.51 踩过）。
static int patch_ret0(uintptr_t addr) {
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("改页权限失败 kr=", (unsigned long long)kr); return 0; }
    ((volatile uint32_t *)addr)[0] = 0x52800000;   // mov w0, #0
    ((volatile uint32_t *)addr)[1] = 0xd65f03c0;   // ret
    sys_icache_invalidate((void *)addr, 8);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    return 1;
}
static volatile int g_draining;
static volatile int g_total;

// 注入库的地址范围。构造函数里填好，网关处理函数只做整数比较。
#define MAX_INJ 8
static uint64_t g_inj_lo[MAX_INJ];
static uint64_t g_inj_hi[MAX_INJ];
static volatile int g_inj_n;
static volatile int g_sent_hit;      // 盾有没有来读我们插进去的哨兵镜像
static uint64_t g_sent_addr;         // 哨兵镜像头地址
static uint64_t g_sent_hdr[0x200] __attribute__((aligned(0x1000)));

// 构造函数里抄下来的镜像基址表（升序）。哈希阶段 x1 每跨进一张镜像就是一个基址，
// 用它来回答"盾到底哈希了哪几张"。
// 把注入库在 dyld 里登记的名字改掉。盾如果按"已加载库的路径"判断越狱
// （/private/preboot、TweakInject、ellekit、systemhook 这些字眼），
// 那么最简单有效的做法就是把名字换成普通系统库——只改数据，不碰任何代码页。
// 名字长度必须不超过原来那段缓冲区，短了就用 NUL 收尾。
static int g_disguised;
static void disguise_paths(void) {
    static const char *mask[4] = {
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/system/libcache.dylib",
        "/usr/lib/libc++.1.dylib",
    };
    uint32_t n = _dyld_image_count();
    int k = 0;
    for (uint32_t i = 0; i < n && k < 4; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        int bad = 0;
        if (strstr(nm, "/private/preboot/")) bad = 1;
        else if (strstr(nm, "systemhook")) bad = 1;
        else if (strstr(nm, "TweakInject")) bad = 1;
        else if (strstr(nm, "ellekit")) bad = 1;
        if (!bad) continue;

        size_t len = strlen(nm);
        size_t wl = strlen(mask[k]);
        if (wl > len) { say_hex("伪装：缓冲不够，跳过 长度=", len); continue; }

        uintptr_t page = (uintptr_t)nm & ~(uintptr_t)0xfff;
        kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) { say_hex("伪装：改页权限失败 kr=", (unsigned long long)kr); continue; }
        volatile char *dst = (volatile char *)(uintptr_t)nm;
        for (size_t j = 0; j < len; j++) dst[j] = 0;
        for (size_t j = 0; j < wl; j++) dst[j] = mask[k][j];
        dst[wl] = 0;
        k++;
        g_disguised++;
        char lb[160];
        out_t o = { lb, lb + sizeof(lb) - 1 };
        o_s(&o, "伪装："); o_h(&o, (unsigned long long)(uintptr_t)nm);
        o_s(&o, " → ");
        for (size_t j = 0; j < wl; j++) o_ch(&o, mask[k - 1][j]);
        o_ch(&o, '\n');
        emit_ts(lb, (size_t)(o.p - lb));
    }
    say_hex("伪装：改掉了几个=", g_disguised);
}

static uint64_t g_img_tab[1200];
static int g_img_tab_n;
static uint64_t g_last_hash_base;

static int img_index_of(uint64_t a) {
    int lo = 0, hi = g_img_tab_n - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (g_img_tab[mid] <= a) { best = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    return best;
}
static volatile uint64_t g_decoys[MAX_INJ];  // 每个注入库对应的系统库替身
static volatile int g_decoys_n;
static volatile int g_redirects;

static unsigned raw_tid(void) {
    uint64_t t = 0;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(t));
    return (unsigned)(t & 0xffffffff);
}

// 本轮探针：把盾第一次读的那个 0x140 字节结构体原样搬出来。
// 搬运必须发生在拦截现场（源在共享缓存里，稳定，但只搬一次最省事），
// 并且只能用逐字节循环，不能落到 memcpy——这个函数跑在盾的线程上。
#define PROBE_LEN 0x140
static unsigned char g_probe[PROBE_LEN];
static uint64_t      g_probe_addr;
static volatile int  g_probe_len;
static volatile int  g_probe_done;

static int safe_read(uint64_t addr, void *dst, size_t n);
static void *heartbeat(void *arg);
static int disguise_one(uintptr_t base, const char *newname);
static void *neutralizer(void *arg);
static void patch_verdict_slots(void);
static void probe_install_handlers(void);
static void scan_subobjects(uint64_t e1, int (*vf)(void *), int r0);
static void run_oracle_scan(void);

static volatile uint64_t g_last_fp;

static inline uint64_t read_pct(void) {
    uint64_t v = 0;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));
    return v;
}

static void ring_push(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller) {
    unsigned h = g_head;
    unsigned n = (h + 1) % RING;
    if (n == g_tail) return;
    rec_t *r = &g_ring[h];
    r->nr = nr; r->a0 = a0; r->a1 = a1; r->a2 = a2; r->a3 = a3;
    r->caller = caller; r->tid = raw_tid(); r->pad = 0; r->ts = read_pct();
    r->fp = g_last_fp;

    // 现场就地拷贝：消息头和路径都在调用者的栈上，晚一点就没了。
    // 只做直接内存加载，不调任何库函数。
    int64_t snr = (int64_t)nr;
    const volatile uint64_t *src = NULL;
    int words = 0;
    if (snr == -31 && a0 > 0x1000) { src = (const volatile uint64_t *)(uintptr_t)a0; words = PAY; }
    else if ((snr == 5 || snr == 33) && a0 > 0x1000) { src = (const volatile uint64_t *)(uintptr_t)a0; words = PAY; }
    else if (snr == 202 && a0 > 0x1000) { src = (const volatile uint64_t *)(uintptr_t)a0; words = PAY; }
    // 116 疑似 syslog：报告原因时盾会写字到系统日志，如果能抄下来就直接读到判定理由。
    else if (snr == 116) {
        if (a0 > 0x1000) src = (const volatile uint64_t *)(uintptr_t)a0;
        else if (a1 > 0x1000) src = (const volatile uint64_t *)(uintptr_t)a1;
        if (src) words = PAY;
    }
    for (int i = 0; i < PAY; i++) {
        r->pay[i] = (src && i < words) ? src[i] : 0;
    }
    if (snr == 202 && a2 > 0x1000) {   // oldp：sysctl 填出来的结果
        const volatile uint64_t *v = (const volatile uint64_t *)(uintptr_t)a2;
        r->pay[12] = v[0];
        r->pay[13] = v[1];
    }

    // 盾在 12ms 左右读的第一个 0x140 字节结构体就是它拿镜像列表的地方。
    if (snr == -31 && !g_probe_done && (uint32_t)(r->pay[2] >> 32) == 4808 && r->pay[5] == PROBE_LEN) {
        const volatile unsigned char *s2 = (const volatile unsigned char *)(uintptr_t)r->pay[4];
        for (int i = 0; i < PROBE_LEN; i++) g_probe[i] = s2[i];
        g_probe_addr = r->pay[4];
        g_probe_len = PROBE_LEN;
    }

    __atomic_store_n(&g_head, n, __ATOMIC_RELEASE);
    g_total++;
}

// ---------------------------------------------------------------- 排空线程侧

static void emit(const char *s, size_t n) { if (g_fd >= 0) raw_write(g_fd, s, n); }

static uint64_t g_pct_per_ms = 24000;

static void calibrate_pct(void) {
    uint64_t a = read_pct(), ma = up_ms();
    usleep(5 * 1000);
    uint64_t b = read_pct(), mb = up_ms();
    if (mb > ma && b > a) {
        uint64_t v = (b - a) / (mb - ma);
        if (v) g_pct_per_ms = v;
    }
}

// 相对构造函数开始时刻的毫秒数。0.0.130 之前这里是"以标定时刻为锚点"的算法，
// 而标定发生在 ctor 末尾、还带 50ms 睡眠，结果所有记录的时间戳都等于标定时刻
// （每段日志里所有记录都是同一个数字），时序信息全丢。现在直接用 g_ts0 作锚点。
static uint64_t rec_ms(uint64_t ts) {
    if (!g_ts0 || !ts || ts < g_ts0) return 0;
    return (ts - g_ts0) / (g_pct_per_ms ? g_pct_per_ms : 24000);
}

static volatile int64_t g_fake_rw;
static uint64_t g_flag_last;
static volatile uint64_t g_ret_override;   // 非零时用它替换系统调用的返回值
static volatile int g_blk_mmap;
// 枚举之后才加载的镜像。若盾的清单是靠 dyld 的 add-image 回调累积的，
// 它会在下一次处理时读到这个新库；若是一次性枚举，就什么都看不到。
static uint64_t g_late_base, g_late_hi;
static volatile int g_late_hit;
static int g_late_tried;       // 检查项一共被改写过几次

static void emit_rec(const rec_t *r, uint64_t now) {
    char buf[768];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    int64_t nr = (int64_t)r->nr;

    (void)now;
    o_ch(&o, '[');
    o_u(&o, (unsigned long long)rec_ms(r->ts));
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
    } else if (nr == 202) {
        // sysctl(mib, namelen, oldp, oldlenp, newp, newlen)
        o_s(&o, "sysctl mib=[");
        int nl = (int)r->a1;
        if (nl > 8) nl = 8;
        for (int i = 0; i < nl; i++) {
            if (i) o_ch(&o, ',');
            o_d(&o, (long long)(int32_t)((r->pay[i / 2] >> ((i % 2) * 32)) & 0xffffffff));
        }
        o_s(&o, "] 长度="); o_u(&o, r->a1);
        o_s(&o, " 值0="); o_h(&o, r->pay[12]);
        o_s(&o, " 值1="); o_h(&o, r->pay[13]);
    } else if ((r->nr >> 32) == 0x70000000ULL) {
        o_s(&o, "回复 id="); o_u(&o, r->nr & 0xffffffffULL);
        o_s(&o, " kr="); o_h(&o, r->a1);
        o_s(&o, " 字数="); o_h(&o, r->pay[1] & 0xffffffffULL);
        for (int i = 2; i < 10; i++) { o_s(&o, " ["); o_d(&o, i); o_s(&o, "]="); o_h(&o, r->pay[i]); }
    } else if (nr == 116) {
        o_s(&o, "syslog a0="); o_h(&o, r->a0);
        o_s(&o, " a1="); o_h(&o, r->a1);
        o_s(&o, " 文本=");
        const char *t = (const char *)r->pay;
        int cnt = 0;
        for (int i = 0; i < PAY * 8 && cnt < 150; i++) {
            char c = t[i];
            if (!c) break;
            o_ch(&o, (c >= 0x20 && c < 0x7f) ? c : '.');
            cnt++;
        }
    } else if (nr == -77) {
        o_s(&o, "假判定被调用 项="); o_h(&o, r->a0);
        o_s(&o, " 返回点=");
        if (r->caller >= g_base && r->caller < g_base + 0x8c0000) { o_s(&o, "+0x"); o_h(&o, r->caller - g_base); }
        else { o_h(&o, r->caller); }
    } else if (nr == 26) {
        o_s(&o, "!! ptrace 请求="); o_u(&o, r->a0);
    } else if (nr == 1) {
        o_s(&o, "!! exit code="); o_u(&o, r->a0);
        o_s(&o, " 改动="); o_d(&o, g_fake_rw);
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
    if (nr == -31) {
        uint64_t fp = r->fp;
        for (int k = 0; k < 4; k++) {
            if (fp < 0x100000000ULL || (fp & 7)) break;
            uint64_t fr[2] = {0};
            if (!safe_read(fp, fr, 16)) break;
            if (fr[1] > g_base && fr[1] < g_base + 0x8c0000) {
                o_s(&o, " <-"); o_h(&o, fr[1] - g_base);
            }
            fp = fr[0];
        }
    }
    o_s(&o, " tid="); o_u(&o, r->tid);
    o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));

    // 判定就在此刻：把盾的检查表就地读出来，看是哪一项在报警。
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    out_t p2 = { buf, buf + sizeof(buf) - 1 };
    o_s(&p2, "检查表 对象="); o_h(&p2, obj);
    o_s(&p2, " 起点="); o_h(&p2, begin);
    o_s(&p2, " 终点="); o_h(&p2, end); o_ch(&p2, '\n');
    emit(buf, (size_t)(p2.p - buf));
    if (begin < 0x100000000ULL || end <= begin || end - begin > 0x1000) return;

    uint32_t n = (uint32_t)((end - begin) / 8);
    // 把报警那一项自己 dump 出来，看它身上带了什么状态。
    if (n >= 2) {
        uint64_t e1 = ((const uint64_t *)(uintptr_t)begin)[1];
        if (e1 > 0x100000000ULL && e1 < 0x800000000ULL) {
            const unsigned char *b = (const unsigned char *)(uintptr_t)e1;
            const char *hx = "0123456789abcdef";
            for (int off = 0; off < 0x80; off += 16) {
                char lb[80];
                out_t o2 = { lb, lb + sizeof(lb) - 1 };
                o_s(&o2, "  项1+"); o_h(&o2, (unsigned long long)off); o_s(&o2, "  ");
                for (int k = 0; k < 16; k++) {
                    unsigned v = b[off + k];
                    o_ch(&o2, hx[(v >> 4) & 0xf]); o_ch(&o2, hx[v & 0xf]); o_ch(&o2, ' ');
                }
                o_ch(&o2, '\n');
                emit(lb, (size_t)(o2.p - lb));
            }
        }
    }
    out_t p3 = { buf, buf + sizeof(buf) - 1 };
    o_s(&p3, "检查项数="); o_u(&p3, n); o_ch(&p3, '\n');
    for (uint32_t i = 0; i < n && i < 16; i++) {
        uint64_t elem = ((const uint64_t *)(uintptr_t)begin)[i];
        if (elem < 0x100000000ULL || elem > 0x800000000ULL) continue;
        uint64_t vt = *(const uint64_t *)(uintptr_t)elem;
        o_s(&p3, "  项"); o_u(&p3, i);
        o_s(&p3, " vtable="); o_h(&p3, vt);
        if (vt > 0x100000000ULL && vt < 0x800000000ULL) {
            uint64_t s10 = *(const uint64_t *)(uintptr_t)(vt + 0x10);
            o_s(&p3, " 判定=");
            if (s10 > g_base && s10 < g_base + 0x8c0000) {
                o_ch(&p3, '+'); o_h(&p3, s10 - g_base);
                // 盾就是这么调它们的：x0 = 检查项自身，返回值非零就是命中。
                int (*verdict)(void *) = (int (*)(void *))(uintptr_t)s10;
                int r = verdict((void *)(uintptr_t)elem);
                o_s(&p3, " 结果="); o_d(&p3, r);
            } else o_h(&p3, s10);
        }
        o_ch(&p3, '\n');
    }
    emit(buf, (size_t)(p3.p - buf));
}

// ---------------------------------------------------------------- 网关入口

// 从网关处理函数里直接落地的一行：纯算术 + 裸 write。
static void flush_ring(void);

static void emergency_line(const rec_t *r) {
    char buf[640];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, "!! exit code="); o_u(&o, r->a0);
    o_s(&o, " 调用点=+");     o_h(&o, r->caller - g_base);
    o_s(&o, " tid=");         o_u(&o, r->tid);
    o_s(&o, " 时刻=");         o_u(&o, g_ts0 && r->ts > g_ts0 ? (r->ts - g_ts0) / 24000 : 0);
    o_s(&o, "ms 已重定向=");   o_u(&o, (unsigned long long)g_redirects);
    // 谁下的判定：沿着帧指针往上走。除了盾自己的地址，也认其它镜像里的地址——
    // "到底是谁调的"往往要到盾外面才看得清。走不深就说明这段代码不维护帧指针。
    uint64_t fp = r->fp;
    int depth = 0;
    for (int k = 0; k < 40; k++) {
        if (fp < 0x100000000ULL || (fp & 7) || fp > 0x800000000ULL) break;
        uint64_t fr[2];
        fr[0] = *(volatile uint64_t *)(uintptr_t)fp;
        fr[1] = *(volatile uint64_t *)(uintptr_t)(fp + 8);
        if (fr[1] > g_base && fr[1] < g_base + 0x8c0000) {
            o_s(&o, " <-"); o_h(&o, fr[1] - g_base);
            depth++;
        } else if (fr[1] > 0x100000000ULL) {
            int i = img_index_of(fr[1]);
            if (i >= 0) {
                o_s(&o, " <~img"); o_d(&o, i); o_s(&o, "+"); o_h(&o, fr[1] - g_img_tab[i]);
                depth++;
            }
        }
        fp = fr[0];
    }
    o_s(&o, " 深度="); o_d(&o, depth);
    o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));

    // 判定就在此刻：把盾的检查表就地读出来，看是哪一项在报警。
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    out_t p2 = { buf, buf + sizeof(buf) - 1 };
    o_s(&p2, "检查表 对象="); o_h(&p2, obj);
    o_s(&p2, " 起点="); o_h(&p2, begin);
    o_s(&p2, " 终点="); o_h(&p2, end); o_ch(&p2, '\n');
    emit(buf, (size_t)(p2.p - buf));
    if (begin < 0x100000000ULL || end <= begin || end - begin > 0x1000) return;

    uint32_t n = (uint32_t)((end - begin) / 8);
    // 把报警那一项自己 dump 出来，看它身上带了什么状态。
    if (n >= 2) {
        uint64_t e1 = ((const uint64_t *)(uintptr_t)begin)[1];
        if (e1 > 0x100000000ULL && e1 < 0x800000000ULL) {
            const unsigned char *b = (const unsigned char *)(uintptr_t)e1;
            const char *hx = "0123456789abcdef";
            for (int off = 0; off < 0x80; off += 16) {
                char lb[80];
                out_t o2 = { lb, lb + sizeof(lb) - 1 };
                o_s(&o2, "  项1+"); o_h(&o2, (unsigned long long)off); o_s(&o2, "  ");
                for (int k = 0; k < 16; k++) {
                    unsigned v = b[off + k];
                    o_ch(&o2, hx[(v >> 4) & 0xf]); o_ch(&o2, hx[v & 0xf]); o_ch(&o2, ' ');
                }
                o_ch(&o2, '\n');
                emit(lb, (size_t)(o2.p - lb));
            }
        }
    }
    out_t p3 = { buf, buf + sizeof(buf) - 1 };
    o_s(&p3, "检查项数="); o_u(&p3, n); o_ch(&p3, '\n');
    for (uint32_t i = 0; i < n && i < 16; i++) {
        uint64_t elem = ((const uint64_t *)(uintptr_t)begin)[i];
        if (elem < 0x100000000ULL || elem > 0x800000000ULL) continue;
        uint64_t vt = *(const uint64_t *)(uintptr_t)elem;
        o_s(&p3, "  项"); o_u(&p3, i);
        o_s(&p3, " vtable="); o_h(&p3, vt);
        if (vt > 0x100000000ULL && vt < 0x800000000ULL) {
            uint64_t s10 = *(const uint64_t *)(uintptr_t)(vt + 0x10);
            o_s(&p3, " 判定=");
            if (s10 > g_base && s10 < g_base + 0x8c0000) {
                o_ch(&p3, '+'); o_h(&p3, s10 - g_base);
                // 盾就是这么调它们的：x0 = 检查项自身，返回值非零就是命中。
                int (*verdict)(void *) = (int (*)(void *))(uintptr_t)s10;
                int r = verdict((void *)(uintptr_t)elem);
                o_s(&p3, " 结果="); o_d(&p3, r);
            } else o_h(&p3, s10);
        }
        o_ch(&p3, '\n');
    }
    emit(buf, (size_t)(p3.p - buf));
}

// ---------------------------------------------------------------- 网关入口

// 从网关处理函数里直接落地的一行：纯算术 + 裸 write。


// 由 gw_entry 调用，6 个参数：x0..x5（x5 是返回地址）。
// 调用返回之后再看一眼回复。0.0.160 之前只记录请求，回复里有什么从来没见过——
// 而 392 次 mach 4801 的回复正是"它枚举到了哪些内存区域"的唯一证据。
void gw_after(uint64_t nr, uint64_t a0, uint64_t ret);

void gw_record(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller) {
    ring_push(nr, a0, a1, a2, a3, caller);

    // 盾把整份共享缓存（约 1.42GB）只读映射进进程，很可能是拿磁盘原件和内存活副本比对。
    // 这次实验让它失败，看判定是否变化。只通过网关改返回值，不碰任何代码或数据。
    if (DO_BLKIMMAP && nr == 197 && a1 > 0x10000000ULL) g_blk_mmap = 1;

    // 盾把每个已加载镜像的头读出来看。落在注入库上的那些读，改指到一个真正的系统
    // dylib 上，相对偏移保持不变：它读到的就是一份结构完全正常的库头。
    //
    // 注意不能拿盾自己当替身——它是可执行文件，第一个 load command 是 LC_SEGMENT_64，
    // 而解析器期待 LC_ID_DYLIB，会顺着垃圾偏移读崩（0.0.48 就是这么死的）。
    if (nr == (uint64_t)-31 && a0 > 0x1000 && g_late_hi) {
        volatile uint32_t *m = (volatile uint32_t *)(uintptr_t)a0;
        if (m[5] == 4808) {
            uint64_t src = *(volatile uint64_t *)(uintptr_t)(a0 + 32);
            if (src >= g_late_base && src < g_late_hi) g_late_hit++;
        }
    }
    if (nr == (uint64_t)-31 && a0 > 0x1000 && g_sent_addr) {
        volatile uint32_t *m = (volatile uint32_t *)(uintptr_t)a0;
        if (m[5] == 4808) {
            uint64_t src = *(volatile uint64_t *)(uintptr_t)(a0 + 32);
            if (src >= (uint64_t)(uintptr_t)g_sent_hdr &&
                src < (uint64_t)(uintptr_t)g_sent_hdr + sizeof(g_sent_hdr)) {
                g_sent_hit++;
            }
        }
    }
#if DO_REDIRECT
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
                    if (DO_REDIRECT == 1) {
                        if (rel + len <= 0x400000 && g_decoys[i] > 0x100000000ULL) {
                            // 搬到替身库（App 自己的一个框架）上，相对偏移不变：
                            // 盾读到的是一份结构完整、签名有效的 dylib 头。
                            *srcp = g_decoys[i] + rel;
                            g_redirects++;
                        }
                    } else if (DO_REDIRECT == 2) {
                        // 让它读到一整页零：没有 Mach-O magic，就不像镜像。
                        if (len <= ZERO_PAGE) {
                            *srcp = (uint64_t)(uintptr_t)g_zero_page;
                            g_redirects++;
                        }
                    }
                    break;
                }
            }
        }
    }

#endif
    if (nr == 1) {
        unsigned h = (g_head + RING - 1) % RING;
        emergency_line(&g_ring[h]);
        // 排空线程在判定前那几十毫秒里落后几百条，而进程马上就要退出，
        // 那些还没来得及写出去的记录正是最要紧的一段。这里同步冲一遍。
        flush_ring();
    }
}

void gw_after(uint64_t nr, uint64_t a0, uint64_t ret) {
    if (g_blk_mmap) {
        g_blk_mmap = 0;
        g_ret_override = (uint64_t)-1;         // EPERM
        return;
    }
    if (nr != (uint64_t)-31 || a0 < 0x1000) return;
    volatile uint32_t *m = (volatile uint32_t *)(uintptr_t)a0;
    uint32_t id = m[5];
    // MIG 约定：回复的 msgh_id = 请求号 + 100，所以这里按区间收，不按具体号。
    if (!((id >= 4800 && id < 5000) || (id >= 3400 && id < 3600))) return;

    unsigned h = g_head;
    unsigned n = (h + 1) % RING;
    if (n == g_tail) return;
    rec_t *r = &g_ring[h];
    r->nr = (0x70000000ULL << 32) | id;              // 用这个前缀区分"回复"和"请求"
    r->a0 = a0; r->a1 = ret; r->a2 = 0; r->a3 = 0;
    r->caller = 0; r->tid = raw_tid(); r->pad = 0;
    r->ts = read_pct(); r->fp = 0;
    const volatile uint64_t *src = (const volatile uint64_t *)(uintptr_t)a0;
    for (int i = 0; i < PAY; i++) r->pay[i] = src[i];
    __atomic_store_n(&g_head, n, __ATOMIC_RELEASE);
    g_total++;
}

__attribute__((naked)) static void gw_entry(void) {
    // 原网关只有 svc + ret，除了 x0/x1 什么都不改。所以这里必须把 x0..x15 全部原样
    // 保存再恢复——中间那次 bl 会按 AAPCS64 把 x0..x18 全当调用者保存寄存器用，
    // 只备份 x0..x7 会让盾里内联在循环中的计数器悄悄变值。
    //
    // 0.0.161 起还要在调用**之后**看回复，所以帧从 0xa0 扩到 0x100，
    // 并且 svc 放在帧还活着的时候执行，返回的 x0..x8 先存回帧里再调 gw_after。
    __asm__ volatile(
        "sub sp, sp, #0x100\n"
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
        "ldr x9, [sp, #0x00]\n"        // 进入时的 x29
        "adrp x10, _g_last_fp@PAGE\n"
        "str x9, [x10, _g_last_fp@PAGEOFF]\n"
        "mov x0, x16\n"                // nr
        "ldr x1, [sp, #0x10]\n"        // a0
        "ldr x2, [sp, #0x18]\n"
        "ldr x3, [sp, #0x20]\n"
        "ldr x4, [sp, #0x28]\n"
        "ldr x5, [sp, #0x08]\n"        // caller
        "bl _gw_record\n"
        // 恢复全部入口寄存器，然后真正发系统调用
        "ldr x16, [sp, #0x90]\n"
        "ldp x14, x15, [sp, #0x80]\n"
        "ldp x12, x13, [sp, #0x70]\n"
        "ldp x10, x11, [sp, #0x60]\n"
        "ldp x8,  x9,  [sp, #0x50]\n"
        "ldp x6,  x7,  [sp, #0x40]\n"
        "ldp x4,  x5,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "svc #0x80\n"
        // 返回值先落回帧里，别被下面那次 bl 冲掉
        "stp x0, x1, [sp, #0x98]\n"
        "stp x2, x3, [sp, #0xa8]\n"
        "stp x4, x5, [sp, #0xb8]\n"
        "stp x6, x7, [sp, #0xc8]\n"
        "str x8,     [sp, #0xd8]\n"
        "ldr x0, [sp, #0x90]\n"        // nr
        "ldr x1, [sp, #0x10]\n"        // msgbuf
        "ldr x2, [sp, #0x98]\n"        // 返回值
        "bl _gw_after\n"
        "adrp x9, _g_ret_override@PAGE\n"
        "ldr x9, [x9, _g_ret_override@PAGEOFF]\n"
        "cbz x9, 1f\n"
        "str x9, [sp, #0x98]\n"        // 用覆盖值替换 x0
        "mov x10, #0\n"
        "adrp x11, _g_ret_override@PAGE\n"
        "str x10, [x11, _g_ret_override@PAGEOFF]\n"
        "1:\n"
        "ldr x8,     [sp, #0xd8]\n"
        "ldp x6, x7, [sp, #0xc8]\n"
        "ldp x4, x5, [sp, #0xb8]\n"
        "ldp x2, x3, [sp, #0xa8]\n"
        "ldp x0, x1, [sp, #0x98]\n"
        "ldp x29, x30, [sp], #0x100\n"
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

// 直接写的日志也带上真实时刻。否则它和环形缓冲排出来的记录混在一个文件里，
// 文件顺序并不等于时间顺序（排空会落后上千条），事后没法把两边的线索对上。
// 整行一次 write() 写完：多个线程写同一个文件时，分成两次写会把行切碎
// （0.0.131 之前的日志里出现过 "[1003ms] [1003ms] 线程快照" 这种断行）。
static void emit_ts(const char *s, size_t n) {
    char buf[1024];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_ch(&o, '[');
    o_u(&o, rec_ms(read_pct()));
    o_s(&o, "ms] ");
    if (n > 900) n = 900;
    memcpy(o.p, s, n);
    o.p += n;
    emit(buf, (size_t)(o.p - buf));
}

static void say(const char *s) { emit_ts(s, strlen(s)); }

static void say_hex(const char *label, unsigned long long v) {
    char buf[160];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, label); o_h(&o, v); o_ch(&o, '\n');
    emit_ts(buf, (size_t)(o.p - buf));
}

static void try_takeover(void) {
#if !DO_TAKEOVER
    return;
#endif
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

// 把环形缓冲里剩下的记录全部写出去。只在即将退出时调用。
static void flush_ring(void) {
    for (int guard = 0; guard < RING; guard++) {
        unsigned t = g_tail;
        if (t == g_head) break;
        emit_rec(&g_ring[t], 0);
        g_tail = (t + 1) % RING;
    }
}

static void *poller(void *arg) {
    (void)arg;
    for (int i = 0; i < 30000; i++) {
        try_takeover();
    probe_install_handlers();
    // 心跳线程只在构造函数开头创建一次。0.0.131 之前这里是每轮循环各建一个，
    // 一次启动里会有成百上千个线程同时改写检查项、同时写日志，结果既没法归因，
    // 日志行也被切碎。这个循环只负责重新接管网关槽。
    // 就地改 LC_ID_DYLIB 会 SIGBUS（写的是代码页），已关闭。
    if (0 && g_inj_n > 0) {
        char want[256];
        want[0] = 0;
        const char *mainp = NULL;
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (nm && strstr(nm, "/HongKong.app/HongKong")) { mainp = nm; break; }
        }
        if (mainp) {
            const char *cut = strstr(mainp, "/HongKong.app/");
            if (cut) {
                size_t pre = (size_t)(cut - mainp) + 14;   // 含 "/HongKong.app/"
                if (pre < sizeof(want) - 64) {
                    memcpy(want, mainp, pre);
                    strcpy(want + pre, "Frameworks/RASPFramework.framework/RASPFramework");
                    for (int i = 0; i < g_inj_n; i++) {
                        int ok = disguise_one((uintptr_t)g_inj_lo[i], want);
                        say_hex("伪装 ok=", ok);
                        if (ok) say(want), say("\n");
                    }
                }
            }
        }
    }

    // 所有威胁上报最后都汇到 +0x40e7e4（w0=原因码，x1=描述）。它是个正常函数，
    // 由 callers 用 bl 调用、返回后 callers 各自继续走自己的清理流程。
    // 把它换成直接返回，等于"上报了但什么都不做"——比改更深处的 exit 安全得多，
    // 因为不动调用方的栈假设。
    if (g_base) {
        // 已证实改代码会被盾的自检抓到（SIGBUS），关闭。
    }
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
static void fill_img_tab(void) {
    uint32_t n = _dyld_image_count();
    g_img_tab_n = 0;
    for (uint32_t i = 0; i < n && g_img_tab_n < 1200; i++) {
        uint64_t b = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
        if (b) g_img_tab[g_img_tab_n++] = b;
    }
    for (int i = 1; i < g_img_tab_n; i++) {          // 插入排序，n 不到 1000
        uint64_t v = g_img_tab[i];
        int j = i - 1;
        while (j >= 0 && g_img_tab[j] > v) { g_img_tab[j + 1] = g_img_tab[j]; j--; }
        g_img_tab[j + 1] = v;
    }
    say_hex("镜像表条数=", g_img_tab_n);
}

// 把盾镜像的 __TEXT 与磁盘文件逐页比对。
// 盾在 44-60ms 间对自己的代码页做 xxHash 并比对期望值，那说明它有一份自检；
// 只要有一段字节和文件对不上，就是它眼里的"被改过"。
static void compare_self_with_disk(void) {
    if (!g_base) return;
    uint32_t n = _dyld_image_count();
    const char *path = NULL;
    for (uint32_t i = 0; i < n; i++) {
        if ((uint64_t)(uintptr_t)_dyld_get_image_header(i) == (uint64_t)g_base) {
            path = _dyld_get_image_name(i);
            break;
        }
    }
    if (!path) { say("找不到盾的路径\n"); return; }
    say("自查文件="); say(path); say("\n");

    const uint8_t *hdr = (const uint8_t *)(uintptr_t)g_base;
    uint32_t ncmds = *(const uint32_t *)(hdr + 16);
    uint64_t vmaddr = 0, vmsize = 0, fileoff = 0;
    const uint8_t *c = hdr + 32;
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(const uint32_t *)c;
        uint32_t sz  = *(const uint32_t *)(c + 4);
        if (cmd == 0x19) {                       // LC_SEGMENT_64
            if (!strncmp((const char *)(c + 8), "__TEXT", 16)) {
                vmaddr  = *(const uint64_t *)(c + 24);
                vmsize  = *(const uint64_t *)(c + 32);
                fileoff = *(const uint64_t *)(c + 40);
                break;
            }
        }
        if (!sz) break;
        c += sz;
    }
    if (!vmsize) { say("没找到 __TEXT\n"); return; }
    say_hex("__TEXT vmaddr=", vmaddr);
    say_hex("__TEXT vmsize=", vmsize);
    say_hex("__TEXT fileoff=", fileoff);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { say("打不开盾文件\n"); return; }
    static uint8_t fb[0x4000];
    int diffs = 0;
    uint64_t pages = (vmsize + 0x3fff) / 0x4000;
    for (uint64_t k = 0; k < pages; k++) {
        uint64_t off = k * 0x4000;
        size_t want = (size_t)((vmsize - off) < 0x4000 ? (vmsize - off) : 0x4000);
        ssize_t got = pread(fd, fb, want, (off_t)(fileoff + off));
        if (got <= 0) { say_hex("pread 失败 off=", off); break; }
        const uint8_t *mem = (const uint8_t *)(uintptr_t)(g_base + off);
        if (!memcmp(mem, fb, (size_t)got)) continue;
        diffs++;
        if (diffs <= 24) {
            uint64_t first = 0;
            while (first < (uint64_t)got && mem[first] == fb[first]) first++;
            say_hex("页不同 相对盾=+0x", off);
            say_hex("  首个差异字节=+0x", first + off);
            char buf[96];
            out_t o = { buf, buf + sizeof(buf) - 1 };
            o_s(&o, "  内存=");
            for (int j = 0; j < 8; j++) { o_h(&o, mem[first + j]); o_ch(&o, ' '); }
            o_s(&o, " 文件=");
            for (int j = 0; j < 8; j++) { o_h(&o, fb[first + j]); o_ch(&o, ' '); }
            o_ch(&o, '\n');
            emit_ts(buf, (size_t)(o.p - buf));
        }
    }
    close(fd);
    say_hex("自查：不同的页数=", diffs);
}

// 逐镜像把 __TEXT 与磁盘文件比对，只比能打开的（缓存内的镜像没有独立文件，跳过）。
// 跑在独立线程上：判定发生在 52ms 左右，进程可能中途就没了，已经写出去的行还在。
static void *disk_check(void *arg) {
    (void)arg;
    static uint8_t fb[0x4000];
    uint32_t n = _dyld_image_count();
    int done = 0, skipped = 0, opened = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        uint64_t base = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
        if (!path || !base) continue;
        int fd = open(path, O_RDONLY);
        if (fd < 0) { skipped++; continue; }
        opened++;
        const uint8_t *hdr = (const uint8_t *)(uintptr_t)base;
        if (*(const uint32_t *)hdr != 0xfeedfacf) { close(fd); continue; }
        uint32_t ncmds = *(const uint32_t *)(hdr + 16);
        uint64_t vmsize = 0, fileoff = 0;
        const uint8_t *c = hdr + 32;
        for (uint32_t k = 0; k < ncmds; k++) {
            uint32_t cmd = *(const uint32_t *)c;
            uint32_t sz  = *(const uint32_t *)(c + 4);
            if (cmd == 0x19 && !strncmp((const char *)(c + 8), "__TEXT", 16)) {
                vmsize  = *(const uint64_t *)(c + 32);
                fileoff = *(const uint64_t *)(c + 40);
                break;
            }
            if (!sz) break;
            c += sz;
        }
        if (!vmsize) { close(fd); continue; }
        uint64_t pages = (vmsize + 0x3fff) / 0x4000;
        int bad = 0;
        for (uint64_t k = 0; k < pages; k++) {
            uint64_t off = k * 0x4000;
            size_t want = (size_t)((vmsize - off) < 0x4000 ? (vmsize - off) : 0x4000);
            ssize_t got = pread(fd, fb, want, (off_t)(fileoff + off));
            if (got <= 0) break;
            const uint8_t *mem = (const uint8_t *)(uintptr_t)(base + off);
            if (memcmp(mem, fb, (size_t)got)) {
                bad++;
                if (bad <= 3) {
                    uint64_t first = 0;
                    while (first < (uint64_t)got && mem[first] == fb[first]) first++;
                    {
                        char lb[600];
                        out_t lo = { lb, lb + sizeof(lb) - 1 };
                        o_s(&lo, "!! 内存与磁盘不同 ");
                        const char *pp = path;
                        for (int q = 0; pp[q] && q < 300; q++) o_ch(&lo, pp[q]);
                        o_s(&lo, " 差异字节=+0x"); o_h(&lo, off + first);
                        o_ch(&lo, '\n');
                        emit_ts(lb, (size_t)(lo.p - lb));
                    }
                }
            }
        }
        if (bad) { done++; say_hex("   该镜像不同页数=", bad); }
        if (opened % 50 == 0) say_hex("已比对镜像数=", opened);
        close(fd);
    }
    say_hex("全镜像自查完成：能打开=", opened);
    say_hex("  不同镜像数=", done);
    say_hex("  无文件跳过=", skipped);
    return NULL;
}

// 往 dyld 的 AllImages 数组末尾插一个"不存在的镜像"，指向我们自己的一个假头。
// 盾如果去读这个地址，就说明它的镜像清单确实来自这份数组；不读就说明另有来源。
static uint64_t g_fake_loader[0x10];

static void plant_sentinel(uintptr_t cache_base) {
    if (!cache_base) { say("哨兵：没有缓存基址\n"); return; }
    uintptr_t g = cache_base + (0x202acdcd0ULL - 0x1a8ef4000ULL);
    uint64_t obj = 0;
    if (!safe_read(g, &obj, 8) || obj < 0x100000000ULL || obj > 0x800000000ULL) {
        say("哨兵：读不到 AllImages 对象\n");
        return;
    }
    uint64_t arr = 0, cnt = 0, cap = 0;
    safe_read(obj + 0x28, &arr, 8);
    safe_read(obj + 0x30, &cnt, 8);
    safe_read(obj + 0x38, &cap, 8);
    if (arr < 0x100000000ULL || cnt < 4) { say("哨兵：数组不可用\n"); return; }

    // 0.0.147 试过"追加一条并把计数加一"，进程立刻 SIGABRT——dyld 自己在校验，
    // 说明条目数不能动。改成**原地覆盖最后一条**，计数保持不变：
    // 目标页先拷一份被覆盖镜像的真实头部，结构完全合法，唯一变化是地址。
    uint64_t slot = arr + (cnt - 1) * 8;
    uint64_t orig = 0;
    if (!safe_read(slot, &orig, 8)) { say("哨兵：读不到末条\n"); return; }
    uint64_t hdr = 0;
    if (!safe_read(orig + 0x8, &hdr, 8) || hdr < 0x100000000ULL) {
        say_hex("哨兵：末条没有镜像头=", orig);
        return;
    }
    uint8_t *h = (uint8_t *)g_sent_hdr;
    for (int i = 0; i < 0x4000; i++) h[i] = *(const volatile uint8_t *)(uintptr_t)(hdr + i);
    g_sent_addr = (uint64_t)(uintptr_t)g_sent_hdr;

    // 原 Loader 的前 0x40 字节整块抄过来（虚表和几个字段），只改 +0x8 的镜像头。
    // 只抄虚表是不够的：dyld 的方法会读别的字段，读到 0 就崩。
    for (int i = 0; i < 8; i++)
        g_fake_loader[i] = *(const volatile uint64_t *)(uintptr_t)(orig + (uint64_t)i * 8);
    g_fake_loader[1] = g_sent_addr;
    *(volatile uint64_t *)(uintptr_t)slot = (uint64_t)(uintptr_t)g_fake_loader;

    uint64_t back = 0;
    safe_read(slot, &back, 8);
    say_hex("哨兵：覆盖末条 原 Loader=", orig);
    say_hex("  原镜像头=", hdr);
    say_hex("  哨兵页=", g_sent_addr);
    say_hex("  回读=", back);
}


// 系统注入器 systemhook.dylib 会 hook 文件类 libc 函数。盾如果检查函数序言
// 有没有被改成跳板，那"只要有注入就退出"就解释得通了。
// 这里把常见符号的首字读出来：0x58000050 = ldr x16,#8; br x16（ElleKit 的跳板）。
static void check_hooks(void) {
    static const char *syms[] = {
        "open", "openat", "stat", "lstat", "fstat", "access", "getattrlist",
        "readlink", "realpath", "opendir", "getenv", "sysctl", "syscall",
        "kill", "ptrace", "fork", "posix_spawn", "dlopen", "dlsym",
        "objc_getClass", "class_getMethodImplementation", "method_getImplementation",
        "task_get_special_port", "mach_msg", "exit", "_exit", "abort",
        "getpid", "getppid", "uname", "sysctlby name", NULL
    };
    int hooked = 0, missing = 0, total = 0;
    for (int i = 0; syms[i]; i++) {
        void *p = dlsym(RTLD_DEFAULT, syms[i]);
        if (!p) { missing++; continue; }
        total++;
        uint32_t w0 = *(const volatile uint32_t *)p;
        if (w0 == 0x58000050u || w0 == 0x58000051u || w0 == 0x58000090u) {
            hooked++;
            say("!! 被改成跳板: "); say(syms[i]);
            say_hex("  首字=", w0);
        }
    }
    say_hex("钩子自检：查到符号=", total);
    say_hex("  跳板形态=", hooked);
    say_hex("  找不到=", missing);
}

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


// ---------------------------------------------------------------- 镜像列表的真实来源
//
// 盾不导入任何 _dyld_* 枚举接口，却拿得到完整镜像列表。原因是它绕开了符号：
// 先用 294 号系统调用（shared_region_check_np）问出共享缓存的实际映射基址，
// 再从"基址 + 固定偏移"处用普通加载读 dyld_all_image_infos。普通加载不经过网关，
// 所以在本探针里完全看不见——这就是前几轮一直找不到入口的原因。
//
// 下面两个函数只读：把共享缓存基址和 dyld_all_image_infos 的实际位置量出来。

// 读之前先确认可读：走 vm_read_overwrite，读不到就返回失败，不会把进程打死。
// iOS SDK 里的 <mach/mach_vm.h> 是内核对外的头，用户态没有，所以自己声明。
extern kern_return_t vm_read_overwrite(vm_map_t target_task, vm_address_t address,
                                       vm_size_t size, vm_address_t data, vm_size_t *outsize);
extern kern_return_t mach_vm_region(vm_map_t target_task, uint64_t *address, uint64_t *size,
                                    vm_region_flavor_t flavor, vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt, mach_port_t *object_name);

static int safe_read(uint64_t addr, void *dst, size_t n) {
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         (vm_size_t)n, (vm_address_t)(uintptr_t)dst, &got);
    return (kr == KERN_SUCCESS && got == n) ? 1 : 0;
}

static uintptr_t image_base_of(const char *want);

// 共享缓存头的 magic "dyld_v1 "。从 libdyld 的基址沿页向下找，找到就是缓存映射起点。
static uintptr_t find_cache_base(void) {
    uintptr_t libdyld = image_base_of("/usr/lib/system/libdyld.dylib");
    if (!libdyld) return 0;
    uintptr_t a = libdyld & ~(uintptr_t)0xfff;
    for (int k = 0; k < 0x800 && a > 0x100000000ULL; k++, a -= 0x1000) {
        uint64_t magic = 0;
        if (!safe_read(a, &magic, 8)) return 0;
        if (magic == 0x2031765f646c7964ULL) return a;
    }
    return 0;
}

static const char *dylib_path(const char *want) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strcmp(nm, want) == 0) return nm;
    }
    return NULL;
}

static uintptr_t image_base_of(const char *want) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strcmp(nm, want) == 0) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// _dyld_get_image_header 的实现必然从 dyld_all_image_infos 取 infoArray，
// 把它的开头几十字节原样抄出来，离线用 adrp/ldr 的立即数反推结构体地址。
static void dump_fn(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    say_hex(sym, (unsigned long long)(uintptr_t)p);
    if (!p) return;
    unsigned char b[96];
    if (!safe_read((uint64_t)(uintptr_t)p, b, sizeof(b))) { say("  读不到\n"); return; }
    const char *hx = "0123456789abcdef";
    for (int off = 0; off < (int)sizeof(b); off += 16) {
        char line[160];
        out_t o = { line, line + sizeof(line) - 1 };
        o_s(&o, "  +"); o_h(&o, (unsigned long long)off); o_s(&o, "  ");
        for (int i = 0; i < 16; i++) {
            unsigned v = b[off + i];
            o_ch(&o, hx[(v >> 4) & 0xf]); o_ch(&o, hx[v & 0xf]); o_ch(&o, ' ');
        }
        o_ch(&o, '\n');
        emit(line, (size_t)(o.p - line));
    }
}

// 镜像列表本身是一串 24 字节记录：{Mach-O 头地址, 路径指针, 修改时间}。
// 与其猜结构体，不如直接找这串记录：里面必然出现我们自己的头地址。
static unsigned long long g_scan_bytes;
static int g_arr_hits;
static uint64_t g_known[1024];
static uint32_t g_known_n;

// 每个字都要比对一次，线性扫 932 项会把整个扫描拖到几分钟，所以用哈希表。
#define HBITS 12
#define HSIZE (1u << HBITS)
static uint64_t g_ht[HSIZE];

static void ht_build(void) {
    for (uint32_t i = 0; i < HSIZE; i++) g_ht[i] = 0;
    for (uint32_t i = 0; i < g_known_n; i++) {
        uint64_t v = g_known[i];
        uint32_t h = (uint32_t)((v >> 12) * 2654435761u) & (HSIZE - 1);
        for (uint32_t k = 0; k < HSIZE; k++) {
            uint32_t j = (h + k) & (HSIZE - 1);
            if (g_ht[j] == 0 || g_ht[j] == v) { g_ht[j] = v; break; }
        }
    }
}

static inline int is_known_header(uint64_t v) {
    uint32_t h = (uint32_t)((v >> 12) * 2654435761u) & (HSIZE - 1);
    for (uint32_t k = 0; k < 64; k++) {
        uint64_t e = g_ht[(h + k) & (HSIZE - 1)];
        if (e == v) return 1;
        if (e == 0) return 0;
    }
    return 0;
}

// 镜像列表是内存里一串 24 字节记录：{Mach-O 头, 路径指针, 修改时间}。
// 这一轮直接改数据：把注入库那几条记录整条换成一份正常的 App 框架记录，
// 谁去读这份列表，看到的都只有 App 自己的框架。
static const char *BAD[] = { "ellekit", "TweakInject", "systemhook", "libinjector", NULL };
static uint64_t g_decoy_rec[3];
static int      g_decoy_ok;
static int      g_patched;

static int is_bad_path(const char *p) {
    for (int i = 0; BAD[i]; i++) if (strstr(p, BAD[i])) return 1;
    return 0;
}

// 在一串镜像记录里改掉注入库的那几条。返回改到的条数。
static int patch_chunk(uint64_t *buf, vm_size_t words) {
    int n = 0;
    char path[256];
    for (vm_size_t i = 0; i + 3 <= words; i++) {
        if (!is_known_header(buf[i])) continue;
        uint64_t pp = buf[i + 1];
        if (pp < 0x100000000ULL) continue;
        if (!safe_read(pp, path, sizeof(path) - 1)) continue;
        path[sizeof(path) - 1] = 0;
        if (!is_bad_path(path)) continue;
        if (!g_decoy_ok) continue;
        buf[i]     = g_decoy_rec[0];
        buf[i + 1] = g_decoy_rec[1];
        buf[i + 2] = g_decoy_rec[2];
        n++;
        say("  已替换："); say(path);
        say_hex("    → 新头=", g_decoy_rec[0]);
    }
    return n;
}

// 找一条 App 包内的正常记录当替身。
static int find_decoy(uint64_t *buf, vm_size_t words) {
    char path[256];
    for (vm_size_t i = 0; i + 3 <= words; i++) {
        if (!is_known_header(buf[i])) continue;
        uint64_t pp = buf[i + 1];
        if (pp < 0x100000000ULL) continue;
        if (!safe_read(pp, path, sizeof(path) - 1)) continue;
        path[sizeof(path) - 1] = 0;
        if (strncmp(path, "/private/var/containers/Bundle/Application/", 43) != 0) continue;
        if (!strstr(path, ".framework/")) continue;
        g_decoy_rec[0] = buf[i];
        g_decoy_rec[1] = buf[i + 1];
        g_decoy_rec[2] = buf[i + 2];
        g_decoy_ok = 1;
        say("替身记录："); say(path); say("\n");
        return 1;
    }
    return 0;
}

// dyld4 内部维护的是一串 Loader*（8 字节指针），每个 Loader 对象里某个固定偏移处
// 放着这个镜像的 Mach-O 头。上一轮改的是 24 字节的 {头,路径,时间} 记录，盾读的显然
// 不是那一份。这里顺着"自身头地址"反过来找这串 Loader*：
//   1. 全内存找出所有存放自身头地址的位置 A；
//   2. 每个 A 附近，找出指向 A 附近地址的指针 (S, w)，k = A - w 就是 Loader 里头的偏移；
//   3. 如果 S±8 也是堆指针，且 *(*(S+8)+k) 是一个已知镜像头，那么 S 就落在那串里。
static uintptr_t g_arr_at;
static uint64_t g_k_off;

static void probe_loader_array(uint64_t self) {
    const vm_size_t CH = 0x40000;
    uint64_t *buf = (uint64_t *)malloc(CH);
    if (!buf) return;

    // 第一遍：找所有存放自身头地址的位置。
    uintptr_t *hits = (uintptr_t *)malloc(sizeof(uintptr_t) * 64);
    int nhit = 0;
    uint64_t addr = 0x100000000ULL;
    while (addr < 0x800000000ULL) {
        uint64_t sz = 0;
        vm_region_basic_info_data_64_t bi;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = 0;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt, &obj);
        if (obj) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS || sz == 0) break;
        if ((bi.protection & VM_PROT_WRITE) && !(bi.protection & VM_PROT_EXECUTE) && sz >= 0x1000) {
            for (uint64_t a = addr; a < addr + sz; a += CH) {
                vm_size_t want = (vm_size_t)((addr + sz - a) < CH ? (addr + sz - a) : CH);
                vm_size_t got = 0;
                if (vm_read_overwrite(mach_task_self(), (vm_address_t)a, want,
                                      (vm_address_t)(uintptr_t)buf, &got) != KERN_SUCCESS) continue;
                for (vm_size_t i = 0; i + 1 <= got / 8; i++) {
                    if (buf[i] != self) continue;
                    if (nhit < 64) hits[nhit++] = (uintptr_t)(a + i * 8);
                }
            }
        }
        addr += sz;
    }
    say_hex("自身头地址出现次数=", nhit);
    for (int i = 0; i < nhit && i < 8; i++) say_hex("  出现在=", hits[i]);

    // 第二遍：找指向 A 附近地址的指针，再验证它是否落在一串 Loader* 里。
    for (int h = 0; h < nhit && !g_arr_at; h++) {
        uint64_t A = hits[h];
        uint64_t lo = A > 0x800 ? A - 0x800 : 0;
        uint64_t addr2 = 0x100000000ULL;
        while (addr2 < 0x800000000ULL && !g_arr_at) {
            uint64_t sz = 0;
            vm_region_basic_info_data_64_t bi;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = 0;
            kern_return_t kr = mach_vm_region(mach_task_self(), &addr2, &sz, VM_REGION_BASIC_INFO_64,
                                              (vm_region_info_t)&bi, &cnt, &obj);
            if (obj) mach_port_deallocate(mach_task_self(), obj);
            if (kr != KERN_SUCCESS || sz == 0) break;
            if ((bi.protection & VM_PROT_WRITE) && !(bi.protection & VM_PROT_EXECUTE) && sz >= 0x1000) {
                for (uint64_t a = addr2; a < addr2 + sz && !g_arr_at; a += CH) {
                    vm_size_t want = (vm_size_t)((addr2 + sz - a) < CH ? (addr2 + sz - a) : CH);
                    vm_size_t got = 0;
                    if (vm_read_overwrite(mach_task_self(), (vm_address_t)a, want,
                                          (vm_address_t)(uintptr_t)buf, &got) != KERN_SUCCESS) continue;
                    for (vm_size_t i = 0; i + 1 <= got / 8; i++) {
                        uint64_t w = buf[i];
                        if (w < lo || w > A) continue;
                        uintptr_t S = (uintptr_t)(a + i * 8);
                        uint64_t k = A - w;
                        // 必须连续 8 项都指向"同一偏移处放着已知镜像头"的对象，
                        // 才算一串 Loader*。只验一项会命中 24 字节记录数组里的假位置。
                        int run = 0;
                        for (int j = 0; j < 8; j++) {
                            uint64_t p2 = 0, hdr = 0;
                            if (!safe_read(S + (uint64_t)j * 8, &p2, 8)) break;
                            if (p2 <= 0x100000000ULL || p2 >= 0x800000000ULL) break;
                            if (!safe_read(p2 + k, &hdr, 8) || !is_known_header(hdr)) break;
                            run++;
                        }
                        if (run >= 8) {
                            g_arr_at = S;
                            g_k_off = k;
                            break;
                        }
                    }
                }
            }
            addr2 += sz;
        }
    }

    free(buf);
    free(hits);
    if (!g_arr_at) { say("没找到 Loader 指针数组\n"); return; }
    say_hex("Loader 数组 命中=", g_arr_at);
    say_hex("  头偏移 k=", g_k_off);

    // 向前退到数组起点，向后数到末尾。
    uintptr_t start = g_arr_at;
    uint64_t v = 0;
    while (start >= 0x100000000ULL + 8 &&
           safe_read(start - 8, &v, 8) && v > 0x100000000ULL && v < 0x800000000ULL) {
        uint64_t hdr = 0;
        if (!safe_read(v + g_k_off, &hdr, 8) || !is_known_header(hdr)) break;
        start -= 8;
    }
    uint32_t cnt2 = 0;
    while (cnt2 < 8000) {
        uint64_t p = 0, hdr = 0;
        if (!safe_read(start + (uint64_t)cnt2 * 8, &p, 8)) break;
        if (!safe_read(p + g_k_off, &hdr, 8) || !is_known_header(hdr)) break;
        cnt2++;
    }
    say_hex("  起点=", start);
    say_hex("  条目数=", cnt2);
    say_hex("  我的下标=", (g_arr_at - start) / 8);
}

// 盾的判定是这么做的：把一串"检查项"放在容器里，逐个调 vtable+0x10，任一非零就退出。
// 这里把容器拿出来，把每项的函数地址列出来——离线一看就知道是哪一项在报警。
static volatile int g_checks_dumped;

// 主动把报警那一项调一次，前后打时刻标记。它在这段时间里发的系统调用
// 就是它的全部输入——比静态读虚拟机快得多。
// 把注入库的 LC_ID_DYLIB 路径就地改成 App 包内的路径。
// 关键点：这条字符串就是库镜像自己的 load command 里的那份，改它等于同时改了
// "dyld 列表里的路径"和"LC_ID_DYLIB"，两边始终一致，不会出现对不上的破绽。
static int disguise_one(uintptr_t base, const char *newname) {
    const uint32_t *h = (const uint32_t *)base;
    if (h[0] != 0xfeedfacf) return 0;
    uint32_t ncmds = h[4];
    uintptr_t lc = base + 32;
    for (uint32_t i = 0; i < ncmds && i < 400; i++) {
        uint32_t cmd  = *(const uint32_t *)lc;
        uint32_t size = *(const uint32_t *)(lc + 4);
        if (size < 8 || size > 0x10000) return 0;
        if (cmd == 0x0d) {                       // LC_ID_DYLIB
            uint32_t stroff = *(const uint32_t *)(lc + 8);
            char *str = (char *)(lc + stroff);
            size_t oldlen = strlen(str);
            size_t newlen = strlen(newname);
            if (newlen > oldlen) return 0;       // 不能写长，会踩到后面的数据
            uintptr_t page = (uintptr_t)str & ~(uintptr_t)0xfff;
            size_t span = (((uintptr_t)str + newlen + 1) - page + 0xfff) & ~(size_t)0xfff;
            if (mach_vm_protect(mach_task_self(), page, span, 0,
                                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) return 0;
            for (size_t k = 0; k < newlen; k++) str[k] = newname[k];
            for (size_t k = newlen; k < oldlen; k++) str[k] = 0;
            sys_icache_invalidate((void *)page, span);
            mach_vm_protect(mach_task_self(), page, span, 0, VM_PROT_READ | VM_PROT_EXECUTE);
            return 1;
        }
        lc += size;
    }
    return 0;
}

// 判定函数是纯内存的、可重复调用的。把它当预言机做大规模实验时，
// 必然会有一些改动让它解引用坏指针而崩溃。这里用信号恢复把崩溃接住：
// 崩溃就当"这个字段不能碰"，恢复原值继续下一个。
static sigjmp_buf g_jmp;
static volatile int g_in_probe;
static volatile int g_crashed;

static void probe_handler(int sig) {
    if (g_in_probe) {
        g_crashed = 1;
        siglongjmp(g_jmp, 1);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static char g_sigstack[64 * 1024];

static void probe_install_handlers(void) {
    stack_t ss;
    ss.ss_sp = g_sigstack;
    ss.ss_size = sizeof(g_sigstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = probe_handler;
    sa.sa_flags = SA_NODEFER | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}

// 受保护的实验体：写内存和调用判定都放在 setjmp 范围内，
// 这样"写只读页"和"判定解引用坏指针"两种崩溃都能接住。
typedef void (*probe_fn)(void);
static probe_fn g_probe_fn;
static int       g_probe_ret;
static volatile uint64_t *g_probe_slot;
static uint64_t  g_probe_val;
static int       g_probe_skip_write;
static int     (*g_probe_vf)(void *);
static void     *g_probe_arg;

static void probe_body(void) {
    if (!g_probe_skip_write) *g_probe_slot = g_probe_val;
    g_probe_ret = g_probe_vf(g_probe_arg);
}

// 返回判定结果；-1 表示这次崩了。
static int run_probe(void) {
    if (sigsetjmp(g_jmp, 1) == 0) {
        g_crashed = 0;
        g_in_probe = 1;
        g_probe_fn();
        g_in_probe = 0;
        return g_probe_ret;
    }
    g_in_probe = 0;
    return -1;
}

// 递归式找判据：把检查对象指向的每个子对象里的每个字段清零，
// 看哪一个能把判定从 1 翻成 0。崩了就恢复原值、跳过。
static void scan_subobjects(uint64_t e1, int (*vf)(void *), int r0) {
    g_probe_fn = probe_body;
    g_probe_vf = vf;
    g_probe_arg = (void *)(uintptr_t)e1;
    g_probe_skip_write = 1;

    char buf[320];
    int hits = 0, tried = 0, crashes = 0;

    // 窗口只有几毫秒，所以只扫最可能是"检测结果容器"的几个指针，
    // 每个只看前 8 个字段。vtable（+0x0）跳过——动它必然崩，还占时间。
    static const int offs[] = { 0x10, 0x18, 0x20, 0x30, 0x40, 0x50, 0x70, -1 };
    for (int oi = 0; offs[oi] >= 0; oi++) {
        int off = offs[oi];
        uint64_t p = *(volatile uint64_t *)(uintptr_t)(e1 + (uint64_t)off);
        if (p < 0x100000000ULL || p > 0x800000000ULL) continue;
        for (int k = 0; k < 0x40; k += 8) {
            uint64_t saved = 0;
            if (!safe_read(p + (uint64_t)k, &saved, 8)) break;
            if (!saved) continue;
            g_probe_slot = (volatile uint64_t *)(uintptr_t)(p + (uint64_t)k);
            g_probe_val = 0;
            g_probe_skip_write = 0;
            int r = run_probe();
            *g_probe_slot = saved;          // 崩没崩都要恢复
            g_probe_skip_write = 1;
            tried++;
            if (r == -1) { crashes++; continue; }
            if (r != r0) {
                out_t o = { buf, buf + sizeof(buf) - 1 };
                o_s(&o, "命中 子对象+"); o_h(&o, (unsigned long long)off);
                o_s(&o, " 字段+"); o_h(&o, (unsigned long long)k);
                o_s(&o, " 原值="); o_h(&o, saved);
                o_s(&o, " 变成="); o_d(&o, r); o_ch(&o, '\n');
                emit(buf, (size_t)(o.p - buf));
                hits++;
                if (hits >= 6) return;
            }
        }
    }
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, "扫描结束 试了="); o_d(&o, tried);
    o_s(&o, " 崩溃="); o_d(&o, crashes);
    o_s(&o, " 命中="); o_d(&o, hits);
    o_s(&o, " 结束 ms="); o_u(&o, up_ms() - g_t0); o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));
}

// 在心跳线程里做预言机扫描：线程上下文完整，信号恢复可靠。
static volatile int g_scan_done;

static void run_oracle_scan(void) {
    if (g_scan_done || !g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t bg = *(volatile uint64_t *)(obj + 0x10);
    uint64_t en = *(volatile uint64_t *)(obj + 0x18);
    if (bg < 0x100000000ULL || en <= bg || (en - bg) / 8 > 64) return;
    uint64_t e1 = ((const uint64_t *)(uintptr_t)bg)[1];
    if (e1 < 0x100000000ULL) return;
    uint64_t vt = *(const uint64_t *)(uintptr_t)e1;
    uint64_t vf = *(const uint64_t *)(uintptr_t)(vt + 0x10);
    if (vf < g_base || vf > g_base + 0x8c0000) return;

    g_scan_done = 1;
    say_hex("预言机 起始 ms=", up_ms() - g_t0);
    int r0 = ((int (*)(void *))(uintptr_t)vf)((void *)(uintptr_t)e1);
    say_hex("预言机 基线=", (unsigned long long)(int64_t)r0);
    if (r0 != 0) scan_subobjects(e1, (int (*)(void *))(uintptr_t)vf, r0);
}

static int my_verdict(void *self) { (void)self; return 0; }

// 检查表里的每一项都是"对象 + 虚表"。与其改虚表（会被自检记账），
// 不如把向量里的项整体换成一个自己构造的假对象：
// 它的虚表 +0x10 指向盾自己代码段里的 "mov w0,#0; ret"，地址完全合法。
// 向量里的元素指针是被复制进副本的，所以必须在复制之前换。
static void ring_push(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller);

// 假对象的判定函数。用环形缓冲记一笔只是为了回答一个问题：
// 迭代器到底有没有调用到我们换进去的对象。它返回 0，语义上与盾自己的
// "mov w0,#0; ret" 相同，但能让我们看见调用。
static uint64_t fake_verdict(uint64_t self) __attribute__((noinline));
static uint64_t fake_verdict(uint64_t self) {
    ring_push((uint64_t)-77, self,
              (uint64_t)(uintptr_t)__builtin_return_address(0), 0, 0, 0);
    return 0;
}

static uint64_t g_fake_vt[4];
static uint64_t g_fake_obj[2];
static uint64_t g_fake_bg, g_fake_en;   // 上一次改写时的向量范围
static uint64_t g_seen_obj;              // 上一次看到的单例地址

// 0.0.130 只在第一次成功时改写一次，之后同一次启动里再也不动。可这条向量是
// 边构造边增长的标准容器：追加第三项时可能整块重分配，新缓冲区里是货真价实的
// 对象，先前写进去的假对象根本不在那儿了。所以现在每次轮询都回读第一格，
// 只要发现被换掉（或范围变了）就整条重写，并把每次变化连同时刻一起记下来。
static void install_fake_checks(void) {
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    if (obj != g_seen_obj) {
        g_seen_obj = obj;
        say_hex("检查表单例出现=", obj);
    }
    uint64_t bg = *(volatile uint64_t *)(obj + 0x10);
    uint64_t en = *(volatile uint64_t *)(obj + 0x18);
    if (bg < 0x100000000ULL || en <= bg) return;
    uint32_t n = (uint32_t)((en - bg) / 8);
    if (n < 1 || n > 64) return;

    g_fake_vt[2] = g_base + 0x15984;          // vtable+0x10 → mov w0,#0; ret
    g_fake_obj[0] = (uint64_t)(uintptr_t)g_fake_vt;
    g_fake_obj[1] = 0;

    int moved = (bg != g_fake_bg || en != g_fake_en);
    if (moved) {
        // 改写前先把原来的三项是谁记下来，事后再判断是不是我们以为的那三个。
        for (uint32_t i = 0; i < n && i < 6; i++) {
            uint64_t it = *(volatile uint64_t *)(uintptr_t)(bg + (uint64_t)i * 8);
            uint64_t vt = 0;
            if (it > 0x100000000ULL && it < 0x800000000ULL) safe_read(it, &vt, 8);
            say_hex("  原项对象=", it);
            say_hex("  原项虚表=", vt);
            if (vt >= g_base && vt < g_base + 0x8c0000) say_hex("    虚表相对盾=+0x", vt - g_base);
        }
    }
    // 范围没变时再确认第一格还是我们的假对象，不是就说明被重新填充过。
    if (!moved && *(volatile uint64_t *)(uintptr_t)bg == (uint64_t)(uintptr_t)g_fake_obj) return;
    for (uint32_t i = 0; i < n; i++)
        *(volatile uint64_t *)(uintptr_t)(bg + (uint64_t)i * 8) = (uint64_t)(uintptr_t)g_fake_obj;
    g_fake_bg = bg; g_fake_en = en;
    g_fake_rw++;
    say_hex(moved ? "检查项换假对象，项数=" : "检查项被重新填充，项数=", n);
    say_hex("  向量起点=", bg);
    say_hex("  回读第一格=", *(volatile uint64_t *)(uintptr_t)bg);
}

// 三个检查项的虚表都在可写的 __DATA 里（镜像内固定偏移），判定函数在 vtable+0x10。
// 把这三个槽改指到自己的恒返回 0 函数——只写数据，不碰任何代码页，
// 因此不会触发代码签名；改完之后立刻回读确认。
static void patch_verdict_slots(void) {
    static const uint64_t vt_off[3] = { 0x820d50, 0x832a60, 0x819cf8 };
    if (!g_base) return;
    for (int i = 0; i < 3; i++) {
        volatile uint64_t *slot = (volatile uint64_t *)(g_base + vt_off[i] + 0x10);
        uint64_t old = *slot;
        // 不能指向自己 dylib 里的函数：地址不在盾的镜像范围内，盾会据此判"被改过"
        // （原因码 4）。改成指向盾自己 __TEXT 里现成的 "mov w0,#0; ret" 片段，
        // 地址完全合法，行为和我们要的一样。
        *slot = (uint64_t)(g_base + 0x15984);
        uint64_t now = *slot;
        say_hex("判定槽 项=", i);
        say_hex("  原值=", old);
        say_hex("  现值=", now);
    }
}

static volatile int g_called;

static volatile int g_diag;

static void call_verdict(void) {
    if (g_called || !g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    if (!g_diag) { g_diag = 1; say_hex("诊断 obj=", obj); say_hex("  begin=", begin); say_hex("  end=", end); }
    if (begin < 0x100000000ULL || end <= begin || (end - begin) / 8 > 64) return;
    uint64_t elem = ((const uint64_t *)(uintptr_t)begin)[1];
    if (elem < 0x100000000ULL) return;
    uint64_t vt = *(const uint64_t *)(uintptr_t)elem;
    if (vt < 0x100000000ULL) return;
    uint64_t verdict = *(const uint64_t *)(uintptr_t)(vt + 0x10);
    if (verdict < g_base || verdict > g_base + 0x8c0000) return;

    g_called = 1;
    say_hex("VERDICT 开始 ms=", up_ms() - g_t0);
    int r = ((int (*)(void *))(uintptr_t)verdict)((void *)(uintptr_t)elem);
    say_hex("VERDICT 结果=", (unsigned long long)(int64_t)r);
    say_hex("VERDICT 结束 ms=", up_ms() - g_t0);
}

// 检查项放在单例的向量里（对象 +0x10 起点 / +0x18 终点）。盾的循环按这对指针遍历，
// 把终点写成起点，遍历就一项都不跑，判定自然落到"无威胁"。
// 只改这一个数据字，不碰任何代码。
static volatile int g_neutralized;
static volatile unsigned long long g_clear_count;
static volatile unsigned g_neutralized_mark;
static void *neutralizer(void *arg);
static void neutralize_checks(void);

// 盾在 50ms 左右就把检查表建好并立刻遍历，晚一步就来不及。所以单开一个线程，
// 从构造函数一开始就高频盯着，一旦表被填出来立刻清空。
static void *neutralizer(void *arg) {
    (void)arg;
    // 不预建单例：盾的初始化完成之前调 getter 会崩。只能等它自己出现。
    // 填充到复制之间的空档只有微秒级，休眠轮询会漏掉。这里忙等，一直盯到判定窗口过去。
    uint64_t t0 = up_ms();
    while (up_ms() - t0 < 400) {
        neutralize_checks();
    }
    return NULL;
}

static void neutralize_checks(void) {
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    if (begin < 0x100000000ULL || end <= begin) return;
    uint32_t n = (uint32_t)((end - begin) / 8);
    if (n > 64) return;
    // 检查对象身上 +0x08 是一个全 1 的位掩码，看着像"检测项覆盖面"。
    // 把它清零，对象本身不变，但判定可能就没有可报的项了。
    for (uint32_t i = 0; i < n; i++) {
        uint64_t e = *(volatile uint64_t *)(uintptr_t)(begin + (uint64_t)i * 8);
        if (e < 0x100000000ULL || e > 0x800000000ULL) continue;
        volatile uint64_t *mask = (volatile uint64_t *)(uintptr_t)(e + 8);
        if (*mask == 0xffffffffffff0701ULL) *mask = 0;
    }

    g_clear_count++;
    if (!g_neutralized) {
        g_neutralized = 1;
        say_hex("检查表已改指：项数=", n);
        say_hex("  改指时刻 ms=", up_ms() - g_t0);
    } else {
        g_redirects++;   // 复用这个计数，表示"又清空了一次"
    }
}

// 主动把第二项检查调用一次，前后打上时刻标记；它在这段时间里做的系统调用
// 就是它的全部输入。
static void call_check1(void) {
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL) {
        void *(*get_obj)(void) = (void *(*)(void))(g_base + 0x5d8490);
        obj = (uint64_t)(uintptr_t)get_obj();
        say_hex("  自建单例=", obj);
    }
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    if (begin < 0x100000000ULL || end <= begin || (end - begin) / 8 > 64) {
        say_hex("  容器还没填=", end - begin);
        return;
    }
    uint64_t elem = ((const uint64_t *)(uintptr_t)begin)[1];
    if (elem < 0x100000000ULL) return;
    uint64_t vt = *(const uint64_t *)(uintptr_t)elem;
    uint64_t verdict = *(const uint64_t *)(uintptr_t)(vt + 0x10);
    if (verdict < g_base || verdict > g_base + 0x8c0000) return;

    say_hex("CHECK1 开始 ms=", up_ms() - g_t0);
    int r = ((int (*)(void *))(uintptr_t)verdict)((void *)(uintptr_t)elem);
    say_hex("CHECK1 结果=", (unsigned long long)(int64_t)r);
    say_hex("CHECK1 结束 ms=", up_ms() - g_t0);
}

static void dump_threat_checks(void) {
    if (!g_base) return;
    // 盾的单例对象指针就存在固定全局里（+0x8509d0），纯读，不调用任何东西。
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) { say_hex("检查表 尚未创建=", obj); return; }
    uint64_t begin = *(volatile uint64_t *)(obj + 0x10);
    uint64_t end   = *(volatile uint64_t *)(obj + 0x18);
    if (g_checks_dumped) return;
    say_hex("检查表 对象=", obj);
    say_hex("  起点=", begin);
    say_hex("  终点=", end);
    if (begin < 0x100000000ULL || end <= begin || end - begin > 0x1000) return;
    g_checks_dumped = 1;

    uint32_t n = (uint32_t)((end - begin) / 8);
    say_hex("  检查项数=", n);
    for (uint32_t i = 0; i < n && i < 40; i++) {
        uint64_t elem = ((const uint64_t *)(uintptr_t)begin)[i];
        say_hex("   项=", elem);
        if (elem < 0x100000000ULL || elem > 0x800000000ULL) continue;
        uint64_t vt = *(const uint64_t *)(uintptr_t)elem;
        say_hex("      vtable=", vt);
        if (vt > 0x100000000ULL && vt < 0x800000000ULL) {
            uint64_t s10 = *(const uint64_t *)(uintptr_t)(vt + 0x10);
            uint64_t s18 = *(const uint64_t *)(uintptr_t)(vt + 0x18);
            if (s10 > g_base && s10 < g_base + 0x8c0000) say_hex("      判定 +", s10 - g_base);
            else say_hex("      判定 =", s10);
            if (s18 > g_base && s18 < g_base + 0x8c0000) say_hex("      命中 +", s18 - g_base);
        }
    }
}

// 把主二进制内存里的头部（load command 区）原样 dump 出来，跟磁盘原文逐字节比对。
static void dump_main_header(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, "/HongKong.app/HongKong")) continue;
        const unsigned char *p = (const unsigned char *)_dyld_get_image_header(i);
        say_hex("主二进制 基址=", (uint64_t)(uintptr_t)p);
        say("HDRDUMP 开始\n");
        const char *hx = "0123456789abcdef";
        for (uint32_t off = 0; off < 0x6000; off += 16) {
            char line[64];
            out_t o = { line, line + sizeof(line) - 1 };
            for (int k = 0; k < 16; k++) {
                unsigned v = p[off + k];
                o_ch(&o, hx[(v >> 4) & 0xf]); o_ch(&o, hx[v & 0xf]);
            }
            o_ch(&o, '\n');
            emit(line, (size_t)(o.p - line));
        }
        say("HDRDUMP 结束\n");
        return;
    }
}

// 把注入库从 dyld 的镜像数组里摘掉。
// 数组在 AllImages 对象的 +0x28，条目数是 +0x30，每项是 Loader*（其 +0x8 是 Mach-O 头）。
// 做法是把要摘的项和末尾一项对调，再把条目数减一——只动两个数字和一个指针，
// 不碰任何代码页，也不留下"被改过"的痕迹。
static int hide_injected_images(uintptr_t cache_base) {
    if (!cache_base || g_inj_n <= 0) return 0;
    uint64_t g = 0;
    if (!safe_read(cache_base + (0x202acdcd0ULL - 0x1a8ef4000ULL), &g, 8)) return 0;
    if (g < 0x100000000ULL || g > 0x800000000ULL) return 0;

    uint64_t arr = 0, cnt = 0, cap = 0;
    if (!safe_read(g + 0x28, &arr, 8)) return 0;
    if (!safe_read(g + 0x30, &cnt, 8)) return 0;
    if (!safe_read(g + 0x38, &cap, 8)) return 0;
    if (arr < 0x100000000ULL || cnt < 10 || cnt > cap || cap > 100000) return 0;
    say_hex("dyld 镜像数组=", arr);
    say_hex("  条目数=", cnt);
    say_hex("  容量=", cap);

    int removed = 0;
    for (uint64_t i = 0; i < cnt; i++) {
        uint64_t p = 0, hdr = 0;
        if (!safe_read(arr + i * 8, &p, 8)) break;
        if (p < 0x100000000ULL || p > 0x800000000ULL) continue;
        if (!safe_read(p + 8, &hdr, 8)) continue;
        int bad = 0;
        for (int k = 0; k < g_inj_n; k++)
            if (hdr >= g_inj_lo[k] && hdr < g_inj_hi[k]) { bad = 1; break; }
        if (!bad) {
            // 兜底：Loader 里可能还有别处记着头，按路径再认一次。
            uint64_t pp = 0;
            if (safe_read(p + 0x10, &pp, 8) && pp > 0x100000000ULL && pp < 0x800000000ULL) {
                char nm[160];
                if (safe_read(pp, nm, sizeof(nm) - 1)) {
                    nm[sizeof(nm) - 1] = 0;
                    if (strstr(nm, "preboot") || strstr(nm, "systemhook") ||
                        strstr(nm, "TweakInject") || strstr(nm, "ellekit")) bad = 1;
                }
            }
        }
        if (!bad) continue;
        uint64_t last = 0;
        if (!safe_read(arr + (cnt - 1) * 8, &last, 8)) break;
        *(volatile uint64_t *)(uintptr_t)(arr + i * 8) = last;
        cnt--;
        *(volatile uint64_t *)(uintptr_t)(g + 0x30) = cnt;
        removed++;
        say_hex("  摘掉一个注入镜像，头=", hdr);
        say_hex("    剩=", cnt);
        if (i > 0) i--;
    }
    say_hex("共摘掉=", removed);
    return removed;
}

// _dyld_get_image_header 的桩里有这么两条：
//     adrp x8, #0x202acd000 ; ldr x0, [x8, #0xcd0]
// 取到的就是 dyld 的 AllImages 对象，镜像数组就在它身上。
// 那个全局在共享缓存里的偏移是固定的，换算成 cache_base + 固定偏移即可。
static void probe_all_images_object(uintptr_t cache_base) {
    if (!cache_base) { say("没有缓存基址\n"); return; }
    uintptr_t g = cache_base + (0x202acdcd0ULL - 0x1a8ef4000ULL);
    uint64_t obj = 0;
    if (!safe_read(g, &obj, 8)) { say("读不到全局\n"); return; }
    say_hex("AllImages 全局=", g);
    say_hex("  → 对象=", obj);
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;

    const char *hx = "0123456789abcdef";
    for (int off = 0; off < 0x60; off += 16) {
        char lb[96];
        out_t o = { lb, lb + sizeof(lb) - 1 };
        o_s(&o, "  +"); o_h(&o, (unsigned long long)off); o_s(&o, "  ");
        for (int k = 0; k < 16; k++) {
            unsigned v = *(const volatile unsigned char *)(obj + off + k);
            o_ch(&o, hx[(v >> 4) & 0xf]); o_ch(&o, hx[v & 0xf]); o_ch(&o, ' ');
        }
        o_ch(&o, '\n');
        emit(lb, (size_t)(o.p - lb));
    }

    // 逐个字段当成"可能是数组指针"来试：指向的内存里连续几项都指向已知镜像头，就是它。
    say_hex("  已知镜像头个数=", g_known_n);
    for (int off = 0; off < 0x60; off += 8) {
        uint64_t p = 0;
        if (!safe_read(obj + off, &p, 8)) continue;
        if (p < 0x100000000ULL || p > 0x800000000ULL) continue;
        for (int k = 0; k < 0x100; k += 8) {
            int run = 0;
            for (int j = 0; j < 6; j++) {
                uint64_t q = 0, h = 0;
                if (!safe_read(p + j * 8, &q, 8)) break;
                if (q < 0x100000000ULL || q > 0x800000000ULL) break;
                if (!safe_read(q + k, &h, 8) || !is_known_header(h)) break;
                run++;
            }
            if (run >= 6) {
                say_hex("  数组字段 +", (unsigned long long)off);
                say_hex("    数组=", p);
                say_hex("    头偏移=", (unsigned long long)k);
                goto found;
            }
        }
    }
found:
    ;
}

static void probe_all_image_infos(uintptr_t cache_base) {
    uint32_t n = _dyld_image_count();
    say_hex("镜像总数=", n);
    say_hex("缓存基址=", cache_base);

    uint64_t nk = n < 1024 ? n : 1024;
    for (uint32_t i = 0; i < nk; i++) g_known[i] = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
    g_known_n = (uint32_t)nk;
    ht_build();

    Dl_info di;
    uint64_t self = 0;
    if (dladdr((void *)&probe_loader_array, &di) && di.dli_fbase)
        self = (uint64_t)(uintptr_t)di.dli_fbase;
    say_hex("自身头=", self);
    say_hex("扫描开始 ms=", up_ms() - g_t0);
    if (getenv("HSB_SCAN")) probe_loader_array(self);
    say_hex("扫描结束 ms=", up_ms() - g_t0);
    return;

    uintptr_t hit = 0;

    uint32_t ver = 0, cnt = 0;
    uint64_t arr = 0;
    if (!safe_read(hit, &ver, 4) || !safe_read(hit + 4, &cnt, 4) || !safe_read(hit + 8, &arr, 8)) return;
    say_hex("dyld_all_image_infos=", hit);
    say_hex("  相对缓存基址 +", cache_base ? (hit - cache_base) : 0);
    say_hex("  版本=", ver);
    say_hex("  条目数=", cnt);
    say_hex("  数组=", arr);

    uint32_t outside = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint64_t e = 0;
        if (!safe_read(arr + (uint64_t)i * 24, &e, 8)) break;
        if (cache_base == 0 || e < cache_base) outside++;
    }
    say_hex("  缓存之外的条目数=", outside);

    for (int i = 0; i < 5 && i < (int)cnt; i++) {
        uint64_t e[2] = {0};
        if (!safe_read(arr + (uint64_t)i * 24, e, 16)) break;
        say_hex("    [", i);
        say_hex("] 头=", e[0]);
        if (e[1] > 0x100000000ULL) {
            char path[160];
            if (safe_read(e[1], path, sizeof(path) - 1)) {
                path[sizeof(path) - 1] = 0;
                say("  "); say(path);
            }
        }
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

static volatile int g_drain_loops;

static void *drainer(void *arg) {
    (void)arg;
    emit("排空线程启动\n", strlen("排空线程启动\n"));
    for (int i = 0; i < 60000; i++) {
        g_drain_loops = i;
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

static void dump_probe(void) {
    char buf[160];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, "探针 地址="); o_h(&o, g_probe_addr);
    o_s(&o, " 长度="); o_u(&o, PROBE_LEN); o_ch(&o, '\n');
    emit(buf, (size_t)(o.p - buf));

    for (int off = 0; off < PROBE_LEN; off += 32) {
        char lb[160];
        out_t l = { lb, lb + sizeof(lb) - 1 };
        o_s(&l, "  +"); o_h(&l, (unsigned long long)off); o_s(&l, "  ");
        for (int i = 0; i < 32 && off + i < PROBE_LEN; i++) {
            unsigned b = g_probe[off + i];
            const char *hx = "0123456789abcdef";
            o_ch(&l, hx[(b >> 4) & 0xf]);
            o_ch(&l, hx[b & 0xf]);
            o_ch(&l, ' ');
        }
        o_s(&l, " |");
        for (int i = 0; i < 32 && off + i < PROBE_LEN; i++) {
            unsigned b = g_probe[off + i];
            o_ch(&l, (b >= 0x20 && b < 0x7f) ? (char)b : '.');
        }
        o_s(&l, "|");
        o_ch(&l, '\n');
        emit(lb, (size_t)(l.p - lb));
    }
}

// 在指定时刻把所有线程的 PC/LR 拍下来。3098ms 那次运行里 App 活了三秒才死，
// 但不知道主线程那三秒在等什么。这里直接看它卡在哪个地址。
static int is_image_base(uint64_t a) {
    int lo = 0, hi = g_img_tab_n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (g_img_tab[mid] == a) return 1;
        if (g_img_tab[mid] < a) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

static void dump_threads(int tag_ms) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    kern_return_t kr = task_threads(mach_task_self(), &list, &cnt);
    if (kr != KERN_SUCCESS) { say_hex("线程快照失败 kr=", (unsigned long long)kr); return; }
    say_hex("线程快照 时刻=", (unsigned long long)tag_ms);
    say_hex("  线程数=", cnt);
    for (mach_msg_type_number_t i = 0; i < cnt && i < 40; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64,
                             (thread_state_t)&st, &sc) == KERN_SUCCESS) {
            uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(st);
            uint64_t lr = (uint64_t)__darwin_arm_thread_state64_get_lr(st);
            char buf[96];
            out_t o = { buf, buf + sizeof(buf) - 1 };
            int in_shield = (pc >= g_base && pc < g_base + 0x8a0000);
            o_s(&o, "  t"); o_u(&o, i);
            o_s(&o, " pc=");
            if (in_shield) { o_s(&o, "+0x"); o_h(&o, pc - g_base); }
            else { o_h(&o, pc); }
            o_s(&o, " lr=");
            if (lr >= g_base && lr < g_base + 0x8a0000) { o_s(&o, "+0x"); o_h(&o, lr - g_base); }
            else { o_h(&o, lr); }
            if (in_shield) {
                // 落在盾里时把参数寄存器也带上：判定函数正在处理哪段内存，只能这样看。
                static const char *nm[9] = {" x0="," x1="," x2="," x3="," x4="," x5="," x6="," x7="," x8="};
                const uint64_t *rv = (const uint64_t *)&st;
                for (int k = 0; k < 9; k++) {
                    o_s(&o, nm[k]);
                    o_h(&o, rv[k]);
                }
                if (is_image_base(rv[1]) && rv[1] != g_last_hash_base) {
                    g_last_hash_base = rv[1];
                    int inj = 0;
                    for (int j = 0; j < g_inj_n; j++)
                        if (rv[1] >= g_inj_lo[j] && rv[1] < g_inj_hi[j]) inj = 1;
                    o_s(&o, inj ? " 哈希注入库=" : " 哈希镜像="); o_h(&o, rv[1]);
                }
                for (int k = 0; k < 9; k++) {
                    for (int j = 0; j < g_inj_n; j++) {
                        if (rv[k] >= g_inj_lo[j] && rv[k] < g_inj_hi[j]) {
                            o_s(&o, " 落在注入库"); o_d(&o, j); o_s(&o, "的x"); o_d(&o, k);
                        }
                    }
                }
            }
            o_ch(&o, '\n');
            emit_ts(buf, (size_t)(o.p - buf));
        }
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list,
                  (vm_size_t)(cnt * sizeof(thread_t)));
}

static void *heartbeat(void *arg) {
    (void)arg;
    // 36-62ms 每 0.2ms 采样：哈希阶段每张镜像只花 1-3ms，粗采样会整张漏掉。
    static int g_snap_at[200];
    static int g_snap_n;
    if (!g_snap_n) {
        if (DO_QUIET) {
            g_snap_at[g_snap_n++] = 10000;
        } else {
            for (int t = 360; t <= 620; t += 2) g_snap_at[g_snap_n++] = t;
            g_snap_at[g_snap_n++] = 10000;
        }
    }
    int g_snap_i = 0;
    uint64_t last_hb = 0;
    for (;;) {
        if (g_probe_len && !g_probe_done) { g_probe_done = 1; dump_probe(); }
        uint64_t el = rec_ms(read_pct());
#if DO_LATEDL
        if (!g_late_tried && el >= 45) {
            g_late_base = 1;   // 只试一次
            static const char *cand[] = {
                "/System/Library/Frameworks/GLKit.framework/GLKit",
                "/System/Library/Frameworks/Speech.framework/Speech",
                "/System/Library/PrivateFrameworks/GameCenterFoundation.framework/GameCenterFoundation",
                "/System/Library/PrivateFrameworks/OnBoardingKit.framework/OnBoardingKit",
                "/System/Library/Frameworks/CoreAudio.framework/CoreAudio",
                "/System/Library/PrivateFrameworks/MediaRemote.framework/MediaRemote",
            };
            g_late_tried = 1;
            for (unsigned ci = 0; ci < sizeof(cand)/sizeof(cand[0]); ci++) {
                uint32_t n0 = _dyld_image_count();
                void *h = dlopen(cand[ci], RTLD_LAZY | RTLD_LOCAL);
                uint32_t n1 = _dyld_image_count();
                if (h && n1 > n0) {
                    g_late_base = (uint64_t)(uintptr_t)_dyld_get_image_header(n1 - 1);
                    g_late_hi = g_late_base + 0x400000;
                    say("迟到的镜像："); say(cand[ci]); say("\n");
                    say_hex("  基址=", g_late_base);
                    say_hex("  镜像数 ", n0); say_hex("  → ", n1);
                    break;
                }
            }
            if (!g_late_base) say("迟到：一个都没加载成功\n");
        }
#endif
#if DO_FAKE
#if DO_FAKE
        install_fake_checks();
#endif
        // 0x43ce74 之后紧接着读全局 +0x866fc8，非零就报告原因码 4 并退出。
        // 先看清它到底是什么值：像小整数的当标志处理，像指针的只记录不动。
        if (g_base) {
            volatile uint64_t *fl = (volatile uint64_t *)(g_base + 0x866fc8);
            uint64_t v = *fl;
            if (v != g_flag_last) {
                g_flag_last = v;
                say_hex("标志 +0x866fc8=", v);
                if (DO_ZEROFLAG && v && v < 0x1000) {
                    *fl = 0;
                    say("  已清零\n");
                }
            }
        }
#endif
        if (el > 12000) break;
        if (g_snap_i < g_snap_n && (int)(el * 10) >= g_snap_at[g_snap_i]) {
            dump_threads(g_snap_at[g_snap_i]);
            g_snap_i++;
        }
        if (el - last_hb >= 50) {
            last_hb = el;
            char buf[192];
            out_t o = { buf, buf + sizeof(buf) - 1 };
            o_s(&o, "心跳 pid="); o_d(&o, getpid());
            o_s(&o, " 累计="); o_d(&o, g_total);
            o_s(&o, " 待排="); o_u(&o, (g_head + RING - g_tail) % RING);
            o_s(&o, " 已重定向="); o_u(&o, (unsigned long long)g_redirects);
            o_s(&o, " 排空轮次="); o_d(&o, g_drain_loops);
            o_s(&o, " 改动次数="); o_d(&o, g_fake_rw);
            o_s(&o, " 哨兵被读="); o_d(&o, g_sent_hit);
            o_ch(&o, '\n');
            emit_ts(buf, (size_t)(o.p - buf));
        }
        // 检查表是"刚重建、马上复制"，中间没有可睡的缝。判定发生在 40-60ms，
        // 这一段只能不留空隙地盯着；过了 300ms 再恢复到普通节奏。
        if (el < 300) {
            __asm__ volatile("yield");
        } else {
            usleep(el < 1000 ? 200 : 5000);
        }
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
    g_ts0 = read_pct();
    say("===== 0.0.165 启动（让共享缓存的整体映射失败）=====\n");

    try_takeover();
    {
        // 观测线程必须最早起来：下面枚举镜像要几十毫秒，而盾的判定就发生在那段时间里。
        static int started;
        if (!started) {
            started = 1;
            pthread_t hb;
            pthread_create(&hb, NULL, heartbeat, NULL);
        }
    }
    fill_img_tab();
    if (DO_HOOKCHK) check_hooks();
    compare_self_with_disk();
    if (DO_DISKCHECK) { pthread_t dt; pthread_create(&dt, NULL, disk_check, NULL); }
    dump_images();
    if (0) {
        uintptr_t cb = find_cache_base();
        probe_all_image_infos(cb);
        probe_all_images_object(cb);
        dump_main_header();
    }
    if (g_base) {
        g_shield_lo = g_base;
        g_shield_hi = g_base + 0x8c0000;
    }

    // 记下注入库的地址范围。上一版把 /usr/lib/ 整个当成系统目录跳过了，
    // 结果漏掉了最关键的 /usr/lib/systemhook.dylib——它是越狱的注入器本体。
    {
        uint32_t n = _dyld_image_count();
        int k = 0;
        for (uint32_t i = 0; i < n && k < MAX_INJ; i++) {
            const char *nm = _dyld_get_image_name(i);
            if (!nm) continue;
            int bad = 0;
            if (strstr(nm, "/private/preboot/")) bad = 1;
            else if (strstr(nm, "systemhook")) bad = 1;
            else if (strstr(nm, "TweakInject")) bad = 1;
            else if (strstr(nm, "ellekit")) bad = 1;
            if (!bad) continue;
            uint64_t b = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
            g_inj_lo[k] = b;
            g_inj_hi[k] = b + 0x400000;   // 够覆盖这些小库的全部映射
            k++;
            say("注入库 "); say(nm); say("\n");
            say_hex("  范围 起点=", b);
        }
            g_inj_n = k;
        say_hex("注入库个数=", k);
        if (DO_DISGUISE) disguise_paths();
    }

    // 摘除 dyld 镜像数组里的注入条目：实测无效（盾不用这份数组），
    // 而且范围匹配会误伤邻近镜像，已关闭。
    if (0) hide_injected_images(find_cache_base());

    {
        // 替身优先选 libobjc / libsystem，它们本身就是 dylib，load command 结构齐全。
        const char *want[] = { NULL };
        uint64_t decoy = 0;
        {
            // 替身取 App 包内的一个框架：它既在 App 签名覆盖范围内，
            // 又是一个结构完整的 dylib 头部。
            uint32_t n = _dyld_image_count();
            for (uint32_t i = 0; i < n && !decoy; i++) {
                const char *nm = _dyld_get_image_name(i);
                if (!nm) continue;
                if (!strstr(nm, "/HongKong.app/Frameworks/")) continue;
                if (!strstr(nm, "RASPFramework")) continue;
                decoy = (uint64_t)(uintptr_t)_dyld_get_image_header(i);
            }
        }
        // 本轮只观察，不参与：重定向整轮关闭，保证只有一个变量。
        for (int i = 0; i < g_inj_n; i++) g_decoys[i] = decoy;
        g_decoys_n = decoy ? g_inj_n : 0;
        say_hex("替身库基址=", decoy);
    }



    // 哨兵必须放在我们自己的 _dyld_* 枚举之后：覆盖条目之后 dyld 再走那条数组
    // 就会崩在自己的字段上，那种崩溃是我们的探针造成的，会把结论带偏。
    if (DO_SENTINEL) plant_sentinel(find_cache_base());

    pthread_t a, b, c;
    pthread_create(&a, NULL, poller, NULL);
    calibrate_pct();
    say_hex("每分钟计数=", g_pct_per_ms);
    int rc1 = pthread_create(&b, NULL, drainer, NULL);
    int rc2 = 0;
    say_hex("排空线程 rc=", (unsigned long long)(int64_t)rc1);
    say_hex("心跳线程 rc=", (unsigned long long)(int64_t)rc2);
}
