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
#import <objc/runtime.h>
#import <objc/message.h>
#import <pthread.h>
#import <signal.h>
#import <sys/time.h>
#define _XOPEN_SOURCE 700
#import <ucontext.h>
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
// 0.0.240：要弄清最后那次 SIGILL 是谁发的，得先知道盾对信号做了什么。
// 它装 sigaction / 改信号掩码走的是自己的裸系统调用，libc 层钩子看不到。
// 这里打开网关接管，只记录信号相关和进程控制相关的编号。
#define DO_TAKEOVER 0   // 0.0.186：不接管网关。0.0.183 之后每次都在 20ms 停写日志、
                        // 约 600ms SIGSEGV；0.0.182 却能活 5.9s。先确认接管本身是不是元凶。
#define DO_LATEDL   0   // 枚举之后 dlopen 一个新库，看盾会不会读到它
#define DO_REDIRECT 0   // 0=不改 1=改指替身库 2=返回全零页
#define DO_FAKE     0   // 把检查项换成恒返回 0 的假对象
#define DO_REPATCH_AT 9999
#define DO_VTPATCH  0   // 换检查项虚表（实测会让盾在 458ms 直接 raise(SIGSEGV)）   // 保留真实检查项，只换它们的判定函数
#define DO_ZEROFLAG 0   // 把 0x866fc8 处的标志清零（非零就走原因码 4）
#define DO_SETFLAG  0   // 反过来：在判定之前把它设成非零（该位置只读，写入即 SIGBUS）
#define DO_SETFLAG_AT 20  // 在第几毫秒写
#define DO_QUIET    1   // 安静模式：不做密集线程快照
#define DO_BLKEXIT  0   // 不拦 exit：只让代码补丁干活，排除"跳过 exit 导致调用方拿着垃圾状态继续"
#define DO_CTRLEXIT 0   // 自己发一次裸 exit(7)，用来验证这条系统调用是否真的有效
#define DO_NORECORD 0   // 1 = 完全不记录系统调用，用来判断探针开销是否拖垮启动
#define DO_FILELOG  0   // 记 open/access 的返回值
#define DO_ENVHOOK  0   // 挂 libc 的 getenv/uname（实测会让盾提前动手）
#define DO_EXITFN   0   // 1=改成替身 2=原值写回（隔离"写入方式"和"写入值"）   // 把 0x40e7e4 的退出目标换成替身（要按混淆基准编码）
#define DO_DN_PARK  0   // 1=让那条线程原地停住 2=正常返回给调用方
#define DO_DIENEXT  0   // 把退出函数末尾的"下一站"换成按栈帧正常收尾的替身
#define DO_BLKIMMAP 0   // 让"映射整份共享缓存"这次调用失败
#define DO_HOOKCHK  0   // 检查 libc 函数序言有没有被注入器改成跳板
#define DO_DISGUISE 0   // 改写注入库在 dyld 里登记的名字
#define DO_SENTINEL 0   // 哨兵：会被 dyld 自己的校验搞崩，只留作记录
#define DO_DISKCHECK 0  // 逐镜像比对内存与磁盘（实验用，平时关掉）
// 0.0.182：盾自检的第 3 条是对共享缓存里 0x1e0dac000 那一页算 SHA-256，
// 而 kill 就住在同一页的 0x1e0dae27c。MSHookFunction 改了这一页，
// 摘要自然对不上——这很可能就是原因码 5 的真正来源。先不挂，验一次。
#define DO_KILLHOOK 0
// 0.0.238：0.0.235-237 三次实验都以"正常退出，退出码 1"结束——不是崩溃，也不是
// SIGKILL。也就是说最后拍板的是 exit(1) 的调用方。这里只记这个调用方是谁，
// 不改任何行为：返回地址落在 App 里，说明是 App 自己决定退出；落在盾里，
// 说明还是盾。
#define DO_EXITHOOK 1
// 0.0.184：自检结构的扫描要读 9MB 再用 115 万次 vm_read 试探，
// 在盾已经动手的时刻跑它，会把自己的观测结果搅乱（0.0.183 两次都 SIGSEGV）。
// 这个问题已经有结论了，先关掉。
#define DO_SELFSCAN 0
// 0.0.185：检查表/完整性表的读表探针会周期性读几百 KB 并算 SHA-256，
// 在盾动手的那几十毫秒里它是额外负载。要回答"exit 到底生不生效"时先关掉。
#define DO_TABLEPROBE 0
#define DO_SYMCHK 0
// 0.0.194：心跳在 130-160ms 停住，而 0.0.187 起每次都在 catch_selfcheck 在场时发生。
// 关掉它，看心跳能不能一路走到进程结束——这是观察 150-700ms 那一段的前提。
#define DO_CATCH 0     // 打印关键 libc 符号的头 4 条指令，看注入器有没有打补丁
// 0.0.195：清点盾对 App 暴露的 ObjC 接口。只读，不 hook、不改任何代码字节。
#define DO_OBJC 0

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

// 纯系统调用的 open，不经过 libc。故障处理函数里必须用它：如果盾把 libc 内部的
// 锁弄成了死锁，处理函数里任何一次 libc 调用都会永远等下去，现场就永远写不出来。
static long raw_open(const char *path, int flags, int mode) {
    register long x16 __asm__("x16") = 5;   // SYS_open
    register long x0  __asm__("x0")  = (long)path;
    register long x1  __asm__("x1")  = flags;
    register long x2  __asm__("x2")  = mode;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}
static long raw_close(int fd) {
    register long x16 __asm__("x16") = 6;   // SYS_close
    register long x0  __asm__("x0")  = fd;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    return x0;
}

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
// 0.0.204：把自检的比较点本身改成"永远相等"。
//
// 自检的形状是 0x43ccdc 处的 cmp x21, x20，随后由虚拟机在后面按条件码分支。
// 把这条 cmp 换成 subs xzr, x21, x21（自己减自己），条件码就永远是"相等"，
// 而它不修改任何寄存器的值，后面的虚拟机逻辑照常读到它期望的条件码。
// 这一条改完之后，改动盾的其它代码不会再被自检抓到——前十九轮卡住的那道墙就打开了。
//
// 注意：这条补丁本身也落在被哈希的 __text 里，所以必须在第一次自检之前写好；
// 构造函数在 3ms 左右运行，自检在 44ms 之后才开始。
#define DO_HASHBYPASS 1
// 0.0.205：改成只改退出闸门本身。
// 0x40e804 处是 `cbz x19, 0x40e810`——说明文字为空才走退出。把它换成一条
// 无条件跳往"只上报"分支（0x40e848）的 b，两条退出链就都变成"记一笔然后正常返回"。
// 这样调用方拿到的是正常的返回路径，而不是被我们硬拦下来之后的垃圾状态。
#define DO_FAIL_EXIT_NOP 0
// 0.0.237：0x7133e4 是虚拟机里那次"原因码 5 + 说明"的上报。失败状态是在这里
// 记下的；只要这次上报不发生，0x712668 也许就会返回成功。Round 18 试过这条，
// 当时没有自检旁路所以被 SIGBUS 打掉；现在可以安全地再试一次。
#define DO_GATE_RET 0
// 0.0.207：闸门改成 ret 之后进程照样以退出码 1 结束，说明 exit 不是从闸门发的。
// 盾自己的退出函数是 0x5d842c（除了闸门里那处间接调用，还有四个直接调用点）。
// 把它整个换成 ret，如果进程仍然退出，那 exit 就不是盾发的。
// 0.0.239：0.0.238 证明了进程不是走 libc 的 exit/_exit 结束的——钩子装上了却
// 一条记录都没有。真正发出 SYS_exit 的是盾自己的 0x5d842c 末尾那次间接调用。
// 既然自检旁路已经能让代码补丁不被 SIGBUS 打掉，这里直接把这函数改成 ret，
// 让它"退不掉"，看进程能不能越过 ~550ms 那道坎。
// 0.0.243：0.0.241（跳过检查）已经把存活拉到 910ms，但那里仍然以退出码 1 收场。
// 这一版把退出函数一并改成 ret，看 910ms 那道坎是它自己设的时限，还是又一条击杀路径。
#define DO_EXITFN_RET 0
#define DO_EXITPROBE 0
#define OFF_GATE_NULL 0x40e804ULL
#define WORD_B_REPORT_FROM_NULL 0x14000011U   // → 0x40e848
#define OFF_GATE_EMPTY 0x40e80cULL
#define WORD_B_REPORT_FROM_EMPTY 0x1400000fU  // → 0x40e848
// 0.0.250：把"每一次上报"都记下来：原因码、说明指针、说明前 8 字节、调用者，
// 以及当时 SIGILL 的处置函数是不是还是我们的。探针每次都会把我们的处理器重装一遍，
// 所以它同时也是"盾换完处理器之后我们补装回去"的唯一时机。
#define DO_REPORT_PROBE 1
// 0.0.214：5d8758 这个函数的形状是
//   5d87a0  bl  0x712668        ; 判定，结果在 w0
//   5d87a4  tbnz w0, #0, 5d87e0 ; bit0 置位就正常返回
//   5d87d4  blr x8              ; 否则调退出
// 把 tbnz 换成无条件跳往"正常返回"，这一次判定就等于永远通过。
// 0.0.262：0.0.261 让理由码 5 消失了，但判定本身仍返回失败（退出调用者变成
// +0x5d87d8）。这一步直接把 0x5d87a4 的 tbnz 换成无条件跳往成功出口。
// Round 21 单独做过这一步会挨 SIGILL，但现在退出守护、虚拟机成功出口都在，
// 死法可能已经不同。
#define DO_VERDICT_OK 0
// 0.0.224：Round 4 当场读出过检查表：3 项里第 1 项报警，判定函数是 0x6f3d54，返回 1。
// 现在能改代码了，直接把这一项改成恒返回 0——这是让判定真正通过，不是拦退出。
#define DO_CHECKITEM_OK 0
// 0.0.236：区分"盾抽查了这个地址"和"走成功路径必然出事"。
// 把 0x5d87a4 的 tbnz 换成等价的 nop：未打补丁时位 0 为 0、本来就不跳，
// 所以行为完全不变。如果这样仍以退出码 1 结束，说明盾并不抽查这里。
#define DO_VERDICT_NOP 0
#define OFF_VERDICT_TBNZ2 0x5d87a4ULL
// 0.0.226：除了那条被旁路的 xxHash，盾还有一张 SHA-256 完整性表，
// 校验函数是 0x5e7aa4（返回值位 0 被调用方直接当布尔用）。
// 先假设"返回 0 = 通过"，把它固定成 0，看 590ms 那次击杀是否消失。
#define DO_INTEGRITY_OK 0
// 0.0.227：先验证故障处理函数本身可用——构造函数里主动发一次 SIGILL。
// 如果这一条记录都没出现，说明问题在处理函数或写文件，而不是信号被盾挡掉。
#define DO_FAULTTEST 0
#define DO_SIGHOOK 1
#define DO_CHECKTAB_LOG 0
#define OFF_INTEGRITY 0x5e7aa4ULL
#define OFF_CHECK_ITEM1 0x6f3d54ULL
#define WORDS_ITEM_OK_0  0x52800000U   // mov w0, #0
#define WORDS_ITEM_OK_1  0xd65f03c0U   // ret
#define DO_FAULTPROBE 1
// 0.0.222：先回答一个基础问题——如果盾根本没初始化起来，App 能不能用？
// 第五节记录过"置空 71 个 __mod_init_func 无效，盾走 ObjC +load"。
// 现在改了代码不会被自检发现，可以第一次直接把 +load 改成 ret。
//   0x228f74 = PRMShieldEventManager 的 +load
// 0.0.241：换思路。前面 21 轮都在"盾判定失败之后去挡它的各种击杀路径"，
// 挡一条就换一条，是打地鼠。这次改成不让它去做判定：
// 两个事件管理器的 performSecurityChecks 都是 mov w0,#1 之后 b 0x38d974，
// 把那个 b 换成 ret，就变成"直接回答 1，完全不进检查"。
// +load 保持原样，引擎照常初始化，避免半初始化状态引来别的崩溃。
// 0.0.268：0.0.241 起把两个 performSecurityChecks 改成直接返回 1，
// 等于检查根本没跑、判定拿不到结果——这本身就可能制造出"无说明的失败"。
// 这一版把它关掉，看检查链（0x5d883c / 0x5d8ed0）会不会真的跑起来。
#define DO_SHIELD_NOLOAD 0
// 0.0.223：盾会通过自己的网关装信号处理器（sigaction = 46），把我们的换掉。
// 在网关里把 46 号整体挡掉之后，它永远装不上，我们的故障处理函数就一直有效。
// libc 的 sigaction 走 libSystem，不经这个网关，所以不会误伤我们自己。
#define DO_BLOCK_SIGACTION 0
#define OFF_MGR_LOAD 0x228f74ULL
#define OFF_MGR_CHECK 0x229110ULL   // PRMShieldEventManager：b 0x38d974
#define OFF_CB_CHECK  0x693f8cULL   // ShieldCallbackManager：b 0x38d974
#define WORD_RET 0xd65f03c0U
#define OFF_VERDICT_TBNZ 0x5d87a4ULL
#define WORD_B_RETURN    0x1400000fU   // b 0x5d87e0
// 闸门里那条"无说明就走退出"的分支，单独开关，避免多变量同时在场。
#define DO_GATE_PATCH 0
// 0.0.210：退出是从 0x43e0f8 那条 `blr x8` 发起的（探针实测），而它后面
// 紧跟的就是这个函数正常的收尾（add sp / ret）。把这条换成 nop，等于让这一步
// "当作已经做完、正常返回"——比让退出函数返回干净得多。
#define DO_SKIP_EXIT_CALL 0
#define OFF_EXIT_CALL 0x43e0f8ULL
#define OFF_EXITFN 0x5d842cULL
#define WORD_NOP_RET 0xd65f03c0U   // ret
#define OFF_GATE_EXIT      0x40e804ULL
#define WORD_B_TO_REPORT   0x14000011U   // b 0x40e848
#define OFF_SELFCHECK_CMP  0x43ccdcULL   // cmp x21, x20
#define WORD_SUBS_SELF     0xeb1502bfU   // subs xzr, x21, x21  → 永远相等
#define OFF_FAIL_EXIT_BL   0x7133e4ULL   // 失败块里那次 bl 0x40e7e4
#define WORD_NOP           0xd503201fU

// 盾是不是会把自己被改过的代码页改回去？在几个时刻重读一次就知道。
static void verify_patches(void) {
    if (!g_base) return;
    uint32_t a = *(volatile uint32_t *)(g_base + OFF_SELFCHECK_CMP);
    uint32_t b = *(volatile uint32_t *)(g_base + OFF_GATE_EXIT);
    uint32_t c = *(volatile uint32_t *)(g_base + OFF_EXITFN);
    char lb[192];
    out_t o = { lb, lb + sizeof(lb) - 1 };
    o_s(&o, "核对补丁 t="); o_u(&o, up_ms() - g_t0);
    o_s(&o, " 比较点="); o_h(&o, a);
    o_s(&o, " 闸门分支="); o_h(&o, b);
    o_s(&o, " 退出函数="); o_h(&o, c);
    o_ch(&o, '\n');
    emit_ts(lb, (size_t)(o.p - lb));
}

static void *ver(void *arg);
static void *busy_probe(void *arg);

static int install_exit_probe(void);
static void arm_fault_probe(void);
static int install_report_probe(void);
static void arm_fault_probe(void);
static void install_sighooks(void);
static int install_checktab_log(void);


static int patch_word(uintptr_t addr, uint32_t word) {
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("补丁：改页权限失败 kr=", (unsigned long long)kr); return 0; }
    uint32_t before = *(volatile uint32_t *)addr;
    ((volatile uint32_t *)addr)[0] = word;
    sys_icache_invalidate((void *)addr, 4);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("补丁：地址=", addr);
    say_hex("  原=", before);
    say_hex("  新=", word);
    return 1;
}


static void install_hash_bypass(void) {
    if (!g_base) { say("补丁：没有盾基址，放弃\n"); return; }
    patch_word(g_base + OFF_SELFCHECK_CMP, WORD_SUBS_SELF);
#if DO_FAIL_EXIT_NOP
    patch_word(g_base + OFF_FAIL_EXIT_BL, WORD_NOP);
#endif
#if DO_GATE_PATCH
    patch_word(g_base + OFF_GATE_NULL, WORD_B_REPORT_FROM_NULL);
    patch_word(g_base + OFF_GATE_EMPTY, WORD_B_REPORT_FROM_EMPTY);
#endif
#if DO_VERDICT_OK
    patch_word(g_base + OFF_VERDICT_TBNZ, WORD_B_RETURN);
#endif
#if DO_VERDICT_NOP
    patch_word(g_base + OFF_VERDICT_TBNZ2, WORD_NOP);
#endif
#if DO_SHIELD_NOLOAD
    patch_word(g_base + OFF_MGR_CHECK, WORD_RET);
    patch_word(g_base + OFF_CB_CHECK, WORD_RET);
#if DO_SHIELD_NOLOAD >= 2
    patch_word(g_base + OFF_MGR_LOAD, WORD_RET);
#endif
#endif
#if DO_CHECKITEM_OK
    patch_word(g_base + OFF_CHECK_ITEM1, WORDS_ITEM_OK_0);
    patch_word(g_base + OFF_CHECK_ITEM1 + 4, WORDS_ITEM_OK_1);
#endif
#if DO_INTEGRITY_OK
    patch_word(g_base + OFF_INTEGRITY, WORDS_ITEM_OK_0);
    patch_word(g_base + OFF_INTEGRITY + 4, WORDS_ITEM_OK_1);
#endif
#if DO_EXITFN_RET
    patch_word(g_base + OFF_EXITFN, WORD_NOP_RET);
#endif
#if DO_EXITPROBE
    install_exit_probe();
#endif
#if DO_REPORT_PROBE
    install_report_probe();
#endif
#if DO_SKIP_EXIT_CALL
    patch_word(g_base + OFF_EXIT_CALL, WORD_NOP);
#endif
#if DO_GATE_RET
    // 更彻底的一步：把闸门函数本身改成一条 ret。这样它既不上报也不退出。
    // 如果进程仍然以退出码 1 结束，就说明 exit 根本不是从这道闸门发出的。
    patch_word(g_base + 0x40e7e4ULL, WORD_NOP_RET);
#endif
}

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
static const char *g_img_names[1200];   // 与 g_img_tab 一一对应（排序时一起搬）
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

__attribute__((used)) static volatile uint64_t g_last_fp;

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

static volatile int g_write_err;
static char g_logpath[512];
// 0.0.192：日志在 110-150ms 之后突然什么都没有，而进程还活到 600-700ms。
// 怀疑盾在判定后把进程里不属于它的文件描述符关掉了。这里记下写失败，
// 由心跳线程（跑在 libc 就绪的线程上）重新打开，顺便把这件事本身写进日志。
static void emit(const char *s, size_t n) {
    if (g_fd < 0) { g_write_err = 1; return; }
    if (raw_write(g_fd, s, n) < 0) g_write_err = 1;
}

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
static int g_setflag_done;
static int g_ctrl_done;
static volatile uint64_t g_ret_override;   // 非零时用它替换系统调用的返回值
volatile uint64_t g_skip_ret;      // 跳过系统调用之后返回到了哪个地址
static volatile int g_blk_mmap;
static volatile int64_t g_mmap_blocked;   // 拦截生效了 N 次
static uint64_t g_mmap_len;
// 网关的汇编用 64 位 LDR/STR 访问它，所以这里必须是 8 字节且对齐的。
// 0.0.170 调整代码布局后它落到 0x1100c，链接期才发现这个隐患。
static __attribute__((used)) volatile uint64_t g_sigact_blocked;
static __attribute__((used)) volatile uint64_t g_block_nr;   // 非零时，编号等于它的系统调用不发出去、直接返回 0
__attribute__((used)) volatile uint64_t g_block_nr2;  // 同上，第二个要拦的编号（kill=37）
volatile uint64_t g_kill_seen;  // 网关看到 kill 的次数
volatile uint64_t g_kill_blocked;
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
static void dump_mem(const char *label, uint64_t addr, int n);
static void dump_mem_safe(const char *label, uint64_t addr, int n);

// 退出那一刻，把失败函数（0x712668）的局部变量原样读出来。
// 它的帧是 sp+0x1a0（x29 = sp+0x1a0），所以 [sp+X] 就是 [x29 - 0x1a0 + X]。
// 关键几格：+0x48 是被调用去取"说明文字"的对象（它返回了空，才走到退出），
// +0x58 是 x24（检查对象），+0x90 是取到的虚函数指针。
static void dump_exit_frames(uint64_t fp0) {
    uint64_t fp = fp0;
    for (int k = 0; k < 16; k++) {
        if (fp < 0x100000000ULL || (fp & 7) || fp > 0x800000000ULL) break;
        uint64_t nx = *(volatile uint64_t *)(uintptr_t)fp;
        uint64_t lr = *(volatile uint64_t *)(uintptr_t)(fp + 8);
        if (lr > g_base && lr < g_base + 0x8c0000 && (lr - g_base) == 0x5d87a4) {
            uint64_t sp = fp - 0x1a0;
            dump_mem("  失败帧 sp..sp+0xf0 @", sp, 0xf0);
            uint64_t msg = *(volatile uint64_t *)(uintptr_t)(sp + 0x48);
            uint64_t obj = *(volatile uint64_t *)(uintptr_t)(sp + 0x58);
            uint64_t fld = *(volatile uint64_t *)(uintptr_t)(sp + 0x90);
            say_hex("  [sp+0x48] 消息对象=", msg);
            say_hex("  [sp+0x58] 检查对象=", obj);
            say_hex("  [sp+0x90] 取值函数=", fld);
            if (obj > 0x100000000ULL && obj < 0x800000000ULL)
                dump_mem("    检查对象 0x60 @", obj, 0x60);
            if (msg > 0x100000000ULL && msg < 0x800000000ULL) {
                dump_mem("    消息对象 0x40 @", msg, 0x40);
                uint64_t vt = *(volatile uint64_t *)(uintptr_t)msg;
                if (vt > 0x100000000ULL && vt < 0x800000000ULL)
                    dump_mem("    消息虚表 0x40 @", vt, 0x40);
            }
            if (fld > g_base && fld < g_base + 0x8c0000)
                dump_mem("    取值函数前 0x30 字节 @", fld, 0x30);
            // 0x713160 调 0x5e7aa4([0x850e48])：那个函数只有两种返回 1 的路径——
            // 对象首字节是 0，或者它列出的某一条自检没过。调用方把 bit0 当"中止"。
            uint64_t st = *(volatile uint64_t *)(uintptr_t)(g_base + 0x850e48);
            say_hex("  [0x850e48] 对象=", st);
            if (st > 0x100000000ULL && st < 0x800000000ULL) {
                dump_mem("    对象 0x40 @", st, 0x40);
                uint64_t s28 = *(volatile uint64_t *)(uintptr_t)(st + 0x28);
                uint64_t s30 = *(volatile uint64_t *)(uintptr_t)(st + 0x30);
                if (s30 >= s28 && s28 > 0x100000000ULL && s30 < 0x800000000ULL) {
                    say_hex("    条目数=", (s30 - s28) / 0x28);
                    for (int m = 0; m < 2; m++) {
                        if (s28 + (uint64_t)(m + 1) * 0x28 > s30) break;
                        dump_mem("    条目 0x28 @", s28 + (uint64_t)m * 0x28, 0x28);
                    }
                }
            }
            return;
        }
        fp = nx;
    }
}

static void emergency_line(const rec_t *r) {
    char buf[640];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, "!! exit code="); o_u(&o, r->a0);
    o_s(&o, " 调用点=+");     o_h(&o, r->caller - g_base);
    o_s(&o, " pid=");         o_d(&o, getpid());
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


// ---------------------------------------------------------------- 信号采样
//
// 30ms 之后文本日志、网关直写、心跳线程同时静默，但进程还要再跑 600ms。
// 定时器信号是投递给"进程"的，会被任意一个正在跑的线程接收，不依赖我们自己
// 创建的任何线程。处理函数只做裸 write，不碰 libc，可以在任何上下文里跑。
// 每条记录里带上被打断处的 pc/sp/lr，事后按镜像表换算就知道它在执行哪个库。
#define DO_SIGSAMPLE 1
static int g_sigfd = -1;
static volatile uint64_t g_sigseq;

static void sig_handler(int sig, siginfo_t *si, void *ucv) {
    (void)sig; (void)si;
    if (g_sigfd < 0) return;
    uint64_t r[6];
    r[0] = 0x5349475000000001ULL;
    r[1] = ++g_sigseq;
    r[2] = 0; r[3] = 0; r[4] = 0;
    ucontext_t *uc = (ucontext_t *)ucv;
    if (uc && uc->uc_mcontext) {
        r[2] = (uint64_t)uc->uc_mcontext->__ss.__pc;
        r[3] = (uint64_t)uc->uc_mcontext->__ss.__sp;
        r[4] = (uint64_t)uc->uc_mcontext->__ss.__lr;
    }
    r[5] = (uint64_t)g_base;
    raw_write(g_sigfd, r, sizeof(r));
}

static void arm_sig_sample(void) {
    if (g_sigfd < 0) { say("信号采样：没有文件描述符\n"); return; }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    int r1 = sigaction(SIGALRM, &sa, NULL);
    // 每条记录都从一次"从头"开始，附上本次构造的序号和盾基址，便于切段。
    {
        static uint32_t ctor_n;
        uint64_t h[6];
        h[0] = 0x5349474800000000ULL;   // 魔数 "SIGH"
        h[1] = ++ctor_n;
        h[2] = (uint64_t)g_base;
        h[3] = up_ms() - g_t0;
        h[4] = 0; h[5] = 0;
        raw_write(g_sigfd, h, sizeof(h));
    }
    struct itimerval it;
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 2000;
    it.it_value = it.it_interval;
    int r2 = setitimer(ITIMER_REAL, &it, NULL);
    say_hex("信号采样：sigaction=", (unsigned long long)(int64_t)r1);
    say_hex("信号采样：setitimer=", (unsigned long long)(int64_t)r2);
    // 立刻验证一次处理函数确实能写：如果下面这条记录没出现，问题在处理函数本身。
    raise(SIGALRM);
}

// 由 gw_entry 调用，6 个参数：x0..x5（x5 是返回地址）。
// 调用返回之后再看一眼回复。0.0.160 之前只记录请求，回复里有什么从来没见过——
// 而 392 次 mach 4801 的回复正是"它枚举到了哪些内存区域"的唯一证据。
void gw_after(uint64_t nr, uint64_t a0, uint64_t ret);

// 把内存里的一段字节按十六进制打出来。只读，不改任何东西。
static void dump_mem(const char *label, uint64_t addr, int n) {
    static const char hx[] = "0123456789abcdef";
    char buf[768];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, label); o_h(&o, addr); o_s(&o, ": ");
    const volatile unsigned char *m = (const volatile unsigned char *)(uintptr_t)addr;
    for (int i = 0; i < n; i++) {
        unsigned char b = m[i];
        o_ch(&o, hx[b >> 4]); o_ch(&o, hx[b & 15]); o_ch(&o, ' ');
    }
    o_ch(&o, '\n');
    emit_ts(buf, (size_t)(o.p - buf));
}

// 0.0.199：日志在 30-40ms 之后就没有任何新行，而进程活到 600-700ms。
// 排空线程、心跳线程、ObjC 线程同时静默，但网关处理函数是跑在盾自己的线程上的，
// 不受这件事影响。所以这里加一条"绕过环形缓冲、当场裸写"的通路，
// 记录写进单独的二进制文件 gw.bin，和文本日志互不干扰。
#define DO_GWDIRECT 1
static int g_gwfd = -1;

// 0.0.212：上一版的忙等探针在 t≈39ms 写完全部记录后停住（1245 轮 / 计划 4000 轮）。
// 我们每个线程的循环里都调 up_ms()，也就是 clock_gettime_nsec_np。为了分清
// "线程停了"和"取时间这一步卡住了"，这一版主循环完全不做时间调用，
// 只写轮次；每 100 轮单独取一次时间。若轮次能跑满，问题就在取时间；
// 若仍在 1200 轮上下停住，就是线程本身在 ~40ms 被停掉或挂起。
#define DO_BUSYPROBE 0
static void *busy_probe(void *arg) {
    (void)arg;
    if (g_gwfd < 0) return NULL;
    for (uint64_t round = 1; round <= 6000; round++) {
        for (volatile int i = 0; i < 20000; i++) { }
        uint64_t r[6];
        r[0] = 0x4255535900000002ULL;   // 魔数 "BUSY" v2
        r[1] = round;
        r[2] = (round % 100 == 0) ? (up_ms() - g_t0) : 0;
        r[3] = 0; r[4] = 0; r[5] = (uint64_t)g_base;
        raw_write(g_gwfd, r, sizeof(r));
    }
    return NULL;
}


static volatile uint64_t g_gwseq;

static void gw_direct(uint64_t kind, uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) {
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x4757524543000000ULL | (kind & 0xff);   // 魔数 "GWREC"
    r[1] = ++g_gwseq;
    r[2] = nr;
    r[3] = a0;
    r[4] = a1;
    r[5] = a2;
    raw_write(g_gwfd, r, sizeof(r));
}

void gw_record(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t caller) {
#if DO_GWDIRECT
    {
        static uint32_t dn;
        uint32_t c = ++dn;
        // 关心的编号照常记；其余按计数抽样，用来证明"这段时间里网关一直在被人们调用"。
        // 0.0.240：只关心"盾怎么处置信号"和"谁在结束进程"。
        // 1=exit 37=kill 46=sigaction 48=sigprocmask 53=sigaltstack
        // 95=sigsuspend 116=sigwait 169=csops 202=sysctl 336=proc_info
        int want = (nr == 1) || (nr == 37) || (nr == 46) || (nr == 48) ||
                   (nr == 53) || (nr == 95) || (nr == 116) || (nr == 169) ||
                   (nr == 202) || (nr == 336);
        if (want) gw_direct(1, nr, a0, a1, a2);
        else if ((c % 500) == 0) gw_direct(9, nr, c, 0, 0);
    }
#endif
    // 盾每秒要过 6-7 万次系统调用。全部都记的话，日志几秒就涨到 25MB，
    // 探针自己成了负载：写日志抢 CPU、抢 IO，App 的启动被拖慢，存活时间也跟着飘。
    // 所以按 1/200 采样，但 exit（1）、以及负数编号（mach trap）里的关键项照常记。
    // 只干预不记录：网关每次调用都要多一次 bl + 环形缓冲写入，盾每秒过 6-7 万次，
    // 这份开销可能正好把 App 的启动拖过系统的启动时限。要判断"界面起不来"
    // 是不是我们自己造成的，就把记录整体关掉再跑一次。
#if !DO_NORECORD
    static uint32_t g_n;
    // 文件类调用照常记：盾启动时只 open 了包内那几份资源，数量很少，
    // 但"缺了哪一份、返回什么"正是要看的。
    int keep = (nr == 1) || (nr == 5) || (nr == 33) || (((++g_n) % 200) == 0);
    if (keep) ring_push(nr, a0, a1, a2, a3, caller);
#endif

    // 盾把整份共享缓存（约 1.42GB）只读映射进进程，很可能是拿磁盘原件和内存活副本比对。
    // 这次实验让它失败，看判定是否变化。只通过网关改返回值，不碰任何代码或数据。
    if (DO_BLKIMMAP && nr == 197 && a1 > 0x10000000ULL) { g_blk_mmap = 1; g_mmap_len = a1; }

    // 第 1 号是 exit。拦截系统调用 ≠ 拦截函数：这里只是不把它发出去、让调用返回 0，
    // 调用方会以为处理完了继续跑。Round 4 做过这件事，但当时的存活测量被
    // "系统重新拉起"污染过，所以现在用绑定 pid 的测量重做一次。
    //
    // 注意：这个开关在 0.0.169 之前只是声明、代码里压根没引用，等于一直都在拦。
    // 那几轮所谓的"零干预基线"其实带着这个干预，结论要按"拦了 exit"重读。
#if DO_DIENEXT
    if (nr == 1 && g_base) {
        // 就在此刻看：退出函数末尾那几个字节，内存里和磁盘上是不是同一份。
        static int said_exit_mem;
        if (!said_exit_mem) {
            said_exit_mem = 1;
            dump_mem("退出时 函数尾", g_base + 0x5d8470, 48);
            dump_mem("退出时 下一站槽", g_base + 0x84c098, 8);
            dump_mem("退出时 跳板", g_base + 0x774770, 12);
        }
    }
#endif
#if DO_BLKEXIT
    if (nr == 1) g_block_nr = 1;
#if DO_BLOCK_SIGACTION
    // a0 = 信号编号。一律挡掉：盾装不上任何处理器，也就收不到任何信号。
    if (nr == 46) { g_block_nr = 46; g_sigact_blocked++; }
#endif
    // 进程最后是被 SIGKILL 收走的，而且没有崩溃报告。Promon 这类盾常用
    // kill(getpid(), SIGKILL) 直接抹掉进程，SIGKILL 又抓不到，所以从网关这里看。
    if (nr == 37) { g_block_nr2 = 37; g_kill_seen++; }
#endif

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
        if (g_base) dump_exit_frames(g_last_fp);
        // 排空线程在判定前那几十毫秒里落后几百条，而进程马上就要退出，
        // 那些还没来得及写出去的记录正是最要紧的一段。这里同步冲一遍。
        flush_ring();
    }
}

void gw_after(uint64_t nr, uint64_t a0, uint64_t ret) {
#if DO_GWDIRECT
    {
        int want = (nr == 1) || (nr == 5) || (nr == 33) || (nr == 197) ||
                   (nr == 202) || (nr == 294) || (nr > 1000);
        if (want) gw_direct(2, nr, a0, ret, 0);
    }
#endif
    // 文件类系统调用把结果当场记下来。盾在 50ms 内判定为"篡改"，
    // 而它启动时只 open 了 App 包内那几份文件——包里少一份（jigsaw.txt）
    // 是不是它眼里的"被拆过包"，只有看返回值才知道。
    // 文件类系统调用只记返回值，不在这里读路径。
    // 之前那版把 a0 当字符串读，遇到一个无效指针就把自己崩了（23-50ms 之间，
    // 退出记录一条都没有）。路径由环形缓冲那边照抄——那条路径在参数还在调用者
    // 栈上的时候就地拷贝，已经稳定跑了很多轮。
#if DO_FILELOG
    if (nr == 5 || nr == 33) {
        static int g_open_seen;
        if (g_open_seen < 40) {
            g_open_seen++;
            char buf[96];
            out_t o = { buf, buf + sizeof(buf) - 1 };
            o_s(&o, nr == 5 ? "打开结果 " : "检查结果 ");
            if ((long long)ret < 0) { o_s(&o, "失败 errno="); o_d(&o, -(long long)ret); }
            else { o_s(&o, "成功="); o_d(&o, (long long)ret); }
            o_ch(&o, '\n');
            emit_ts(buf, (size_t)(o.p - buf));
        }
        return;
    }
#endif
    if (nr == 1) {
        // 0.0.183：exit 系统调用如果真的生效，这里永远不会执行。
        // 之前几轮都默认"盾调 exit → 进程死"，但 0.0.182 里盾在 56ms 调过一次 exit，
        // 进程却活到 5.9 秒，之后同一个线程还在发系统调用。先把这件事钉死。
        char buf[96];
        out_t o = { buf, buf + sizeof(buf) - 1 };
        o_s(&o, "退出系统调用返回了 x0=");
        o_h(&o, ret);
        o_ch(&o, '\n');
        emit_ts(buf, (size_t)(o.p - buf));
    }
    if (g_blk_mmap) {
        g_blk_mmap = 0;
        g_ret_override = (uint64_t)-1;         // EPERM
        g_mmap_blocked++;
        say_hex("已拦下整份缓存映射 长度=", g_mmap_len);
        say_hex("  累计拦下=", (uint64_t)g_mmap_blocked);
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
    // 只拷消息头 6 个字。0.0.183/0.0.184 有四次在 26ms 前后直接 SIGSEGV，
    // 时间点正好压在这条记录之后——mach 回复缓冲区可能只有 64 字节，
    // 照 24 个字（192 字节）读会跨进未映射页。消息头已经够判读这次系统调用了。
    for (int i = 0; i < 6; i++) r->pay[i] = src[i];
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
        "ldr x9, [sp, #0x00]\n"
        "adrp x10, _g_last_fp@PAGE\n"
        "str x9, [x10, _g_last_fp@PAGEOFF]\n"
        "mov x0, x16\n"                // nr
        "ldr x1, [sp, #0x10]\n"        // a0
        "ldr x2, [sp, #0x18]\n"
        "ldr x3, [sp, #0x20]\n"
        "ldr x4, [sp, #0x28]\n"
        "ldr x5, [sp, #0x08]\n"        // caller
        "bl _gw_record\n"
        // 还原进入时的全部寄存器，然后决定这次调用要不要发出去。
        //
        // 0.0.170 之前这里是一个"一次性消耗"的标志：gw_record 把它置 1，
        // 这里读一次就清零。可盾会从两条线程几乎同时调用 exit，于是 A 线程置位、
        // B 线程（恰好是一个无关的 open）把名额领走——那个 open 返回了 0（stdin），
        // 而 A 线程的 exit 反而真发了出去。现在改成只比系统调用编号，不消耗任何状态。
        "ldr x16, [sp, #0x90]\n"
        "ldp x14, x15, [sp, #0x80]\n"
        "ldp x12, x13, [sp, #0x70]\n"
        "ldp x10, x11, [sp, #0x60]\n"
        "ldp x8,  x9,  [sp, #0x50]\n"
        "ldp x6,  x7,  [sp, #0x40]\n"
        "ldp x4,  x5,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "adrp x17, _g_block_nr@PAGE\n"
        "ldr x17, [x17, _g_block_nr@PAGEOFF]\n"
        "cbz x17, 3f\n"
        "cmp x17, x16\n"
        "b.eq 4f\n"
        "3:\n"
        "adrp x17, _g_block_nr2@PAGE\n"
        "ldr x17, [x17, _g_block_nr2@PAGEOFF]\n"
        "cbz x17, 2f\n"
        "cmp x17, x16\n"
        "b.ne 2f\n"
        "4:\n"
        "adrp x17, _g_skip_ret@PAGE\n"
        "str x30, [x17, _g_skip_ret@PAGEOFF]\n"
        "ldp x29, x30, [sp], #0x100\n"
        "mov x0, #0\n"
        "ret\n"
        "2:\n"
        "svc #0x80\n"
        // 达尔文系统调用只改 x0/x1，其余寄存器按约定不变。所以这里只把 x0/x1 落回帧里，
        // 剩下的 x2..x15 全部按进入时的原值还原——0.0.170 之前 x9..x15 是被
        // 后面那几次 adrp 覆盖掉之后再没还原的，等于每次系统调用都在破坏盾的寄存器。
        "stp x0, x1, [sp, #0x98]\n"
        "ldr x0, [sp, #0x90]\n"        // nr
        "ldr x1, [sp, #0x10]\n"        // a0
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
        "ldp x0, x1, [sp, #0x98]\n"
        "ldp x14, x15, [sp, #0x80]\n"
        "ldp x12, x13, [sp, #0x70]\n"
        "ldp x10, x11, [sp, #0x60]\n"
        "ldp x8,  x9,  [sp, #0x50]\n"
        "ldp x6,  x7,  [sp, #0x40]\n"
        "ldp x4,  x5,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
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
    // 这里必须逐字节拷，不能用 memcpy：emit_ts 会被网关里的处理函数调用，
    // 而那跑在盾的线程上，libc 可能还没就绪。0.0.170 用 memcpy 的版本
    // 在 23ms 就崩了，正是这个原因。
    for (size_t i = 0; i < n; i++) *o.p++ = s[i];
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
#if !DO_TAKEOVER
    // 0.0.185：只求盾基址，不动网关槽。槽在盾的 __DATA 里，如果盾的自检
    // 也覆盖自己这块数据，"原因码 4"就可能是我们自己改槽改出来的。
    static int said_once;
    if (!said_once) { said_once = 1; say("本版不接管网关（只取基址）\n"); }
    g_taken = 1;
    return;
#endif
    uint64_t cur = *g_slot;
    if (cur == 0) return;
    uint64_t want = (uint64_t)(uintptr_t)&gw_entry;
    if (cur == want) { g_taken = 1; return; }
    *g_slot = want;
    g_taken = 1;
    say_hex("接管网关槽 原值=", cur);
    say_hex("          新值=", want);
}

#if DO_DIENEXT
// 盾的退出函数（+0x5d842c）并不以退出系统调用收尾：它发完 exit 之后还有一步
//   +0x5d8488  mov w0, #1
//   +0x5d848c  bl  0x774770      → adrp x16,0x84c000; ldr x16,[x16,#0x98]; br x16
// 编译器把整个函数按"不返回"来排布，所以 0x5d8490 紧接着就是下一个函数的序言，
// 这里一旦真返回，执行流会直接冲进隔壁函数的函数体，栈还在本函数那一层上。
// 也就是说：在系统调用处拦下只会让调用方带着错误状态继续，最后崩在后面。
//
// 换个位置——不拦系统调用，而是把"下一站"换成一段按栈帧正常收尾的替身。
// 退出函数入口是 sub sp,sp,#0x20 与 stp x29,x30,[sp,#0x10]，
// 所以此刻 [sp,#0x10] 里就是调用者的 x29 和 x30；把它们取回来、把 sp 抬回去再 ret，
// 就等于这个退出函数正常返回给了调用者。
#define DIENEXT_SLOT_OFF 0x84c098ULL

static int g_dn_done;
volatile uint64_t g_dn_hits;      // 替身走"原样转发"的次数
volatile uint64_t g_dn_fixed;     // 替身走"正常返回"的次数（也就是真正改到退出流程的次数）

// 单独一个函数，用一条 BL 从替身调进来。BL 是页内相对跳转，
// 不依赖 adrp/add 那套重定位——0.0.170 最初那版用 adrp 读写计数器，
// 结果"命中=0"分不清是"替身没被调用"还是"计数器地址算错了"。
__attribute__((noinline, no_stack_protector)) void dn_hit(void) {
    g_dn_hits = g_dn_hits + 1;
}

// 临时探针：只要有人跳到这个槽上，就记一次数然后原地停住。
// 停住是为了让"命中了没有"这件事在心跳里一眼可读——如果它真的被调到，
// 这条线程会卡在这里，而心跳线程照常写日志，计数会一直涨到 1 以上。
__attribute__((noinline, no_stack_protector)) void dn_probe(void) {
    g_dn_hits = g_dn_hits + 1;
    for (;;) __asm__ volatile("yield");
}

static int g_dn_reassert;
static uint64_t g_dn_want;
static int g_dn_ro_said;
uint64_t g_dn_orig_val;   // 被我们顶掉的那个值：盾原本要跳去的目标
uint64_t g_dn_fix_ret;    // 退出函数里那条 bl 之后的下一条指令地址

// 这个槽有 30 处代码在用（退出函数只是其中一处），所以替身必须按调用者分流：
// 只有从退出函数那条 bl 过来的，才按它的栈帧正常收尾；其余的必须原样跳回盾自己的目标，
// 否则会按错误的栈帧弹栈，直接崩掉——这正是之前"活几秒就 SIGSEGV"的原因。
__attribute__((naked, noinline)) static void dienext_shim(void) {
    // 两条分支必须分开计数，否则分不清"替身把退出流程改成了正常返回"和
    // "替身只是原样转发、什么也没改变"。第一版用 cmp x30 直接比，
    // 而 arm64e 的返回地址带 PAC 签名，比较永远不成立——那一版其实一直在走转发。
    __asm__ volatile(
        "sub  sp, sp, #0x40\n"
        "stp  x0, x1, [sp, #0x00]\n"
        "stp  x2, x3, [sp, #0x10]\n"
        "stp  x9, x10, [sp, #0x20]\n"
        "str  x11, [sp, #0x30]\n"
        "adrp x9,  _g_dn_fix_ret@PAGE\n"
        "ldr  x9,  [x9, _g_dn_fix_ret@PAGEOFF]\n"
        "and  x10, x30, #0x0000ffffffffffff\n"
        "and  x11, x9,  #0x0000ffffffffffff\n"
        "eor  x11, x10, x11\n"
        "ldp  x9, x10, [sp, #0x20]\n"
        "cbnz x11, 9f\n"
        // —— 退出函数那条路径：正常返回给调用者 ——
        "ldr  x11, [sp, #0x30]\n"
        "ldp  x2, x3, [sp, #0x10]\n"
        "ldp  x0, x1, [sp, #0x00]\n"
        "add  sp, sp, #0x40\n"
        "adrp x9,  _g_dn_fixed@PAGE\n"
        "add  x9,  x9, _g_dn_fixed@PAGEOFF\n"
        "ldr  x10, [x9]\n"
        "add  x10, x10, #1\n"
        "str  x10, [x9]\n"
#if DO_DN_PARK == 1
        // 让这条线程原地停住。盾的本意是"这条检查路径必须终止"，但它用的是
        // 整个进程的 exit。停住单条线程是最接近它本意的做法：既不让调用方
        // 带着"本该永远不返回"的状态继续往下跑，也不牵连整个进程。
        "5:\n"
        "wfe\n"
        "b    5b\n"
#else
        "ldp  x29, x30, [sp, #0x10]\n"
        "add  sp, sp, #0x20\n"
        "ret\n"
#endif
        // —— 其余调用者：原样交给盾自己原本要去的目标 ——
        "9:\n"
        "ldr  x11, [sp, #0x30]\n"
        "ldp  x2, x3, [sp, #0x10]\n"
        "ldp  x0, x1, [sp, #0x00]\n"
        "add  sp, sp, #0x40\n"
        "adrp x9,  _g_dn_hits@PAGE\n"
        "add  x9,  x9, _g_dn_hits@PAGEOFF\n"
        "ldr  x10, [x9]\n"
        "add  x10, x10, #1\n"
        "str  x10, [x9]\n"
        "adrp x9,  _g_dn_orig_val@PAGE\n"
        "ldr  x9,  [x9, _g_dn_orig_val@PAGEOFF]\n"
        "br   x9\n"
    );
}

static void install_dienext(void) {
    if (!g_base) return;
    volatile uint64_t *slot = (volatile uint64_t *)(g_base + DIENEXT_SLOT_OFF);
    uint64_t cur = *slot;
    if (!cur) {
        // dyld 还没把这里填上。只记一次，之后每轮继续看。
        static int said_zero;
        if (!said_zero) { said_zero = 1; say("下一站槽此刻还是 0，继续等\n"); }
        return;
    }
    if (g_dn_done) {
        // 槽被盾改回去就再写一次。改回去的次数本身也是信息：说明盾在盯这个位置。
        if (cur != g_dn_want) {
            if (g_dn_reassert < 20) {
                // 记下每一次变化和时间：如果盾在每次使用前都自己重写这个槽，
                // 那我们的写入就总是被夹在两次使用之间，替身自然不会被执行。
                char lb[96];
                out_t o = { lb, lb + sizeof(lb) - 1 };
                o_s(&o, "下一站被盾改写，第"); o_u(&o, (unsigned long long)(g_dn_reassert + 1));
                o_s(&o, "次，新值="); o_h(&o, cur);
                o_s(&o, " 时刻="); o_d(&o, (long long)rec_ms(read_pct()));
                o_s(&o, "ms\n");
                emit_ts(lb, (size_t)(o.p - lb));
            }
            if (g_dn_reassert == 0) {
                // 首次看到盾自己把这里改掉：把它改成的值记下来，这才知道退出函数
                // 末尾真正要跳去的函数是谁。磁盘上那 8 个字节是没被 dyld 处理过的
                // 编码值（0x738e…），直接读它看不出任何东西。
                say_hex("盾自己把下一站改成了=", cur);
                Dl_info d2 = {0};
                if (dladdr((void *)(uintptr_t)cur, &d2) && d2.dli_fname) {
                    say("  "); say(d2.dli_fname);
                    say_hex(" +", (unsigned long long)(cur - (uint64_t)(uintptr_t)d2.dli_fbase));
                    if (d2.dli_sname) { say("  "); say(d2.dli_sname); }
                    say("\n");
                }
            }
            g_dn_reassert++;
            g_dn_orig_val = cur;      // 盾当前放的值，别的调用者要原样跳回去
            *slot = g_dn_want;
            uint64_t back = *slot;
            if (back != g_dn_want && !g_dn_ro_said) {
                g_dn_ro_said = 1;
                say_hex("写不进去：读回=", back);
                say_hex("            想写=", g_dn_want);
            }
            if (g_dn_reassert <= 3)
                say_hex("下一站被改回去了，重写次数=", (unsigned long long)g_dn_reassert);
        }
        return;
    }
    g_dn_done = 1;
    g_dn_orig_val = cur;
    g_dn_fix_ret = (uint64_t)g_base + 0x5d8490;   // bl 0x774770 之后的下一条
    say_hex("退出函数的下一站 原值=", cur);
    Dl_info di = {0};
    if (dladdr((void *)(uintptr_t)cur, &di) && di.dli_fname) {
        say("  "); say(di.dli_fname);
        say_hex(" +", (unsigned long long)(cur - (uint64_t)(uintptr_t)di.dli_fbase));
        if (di.dli_sname) { say("  "); say(di.dli_sname); }
        say("\n");
    }
    uint64_t want = (uint64_t)(uintptr_t)&dienext_shim;
    g_dn_want = want;
    *slot = want;
    say_hex("             换成=", want);
    say_hex("             计数器地址=", (unsigned long long)(uintptr_t)&g_dn_hits);
    say("  （取回调用者的 x29/x30、抬回 sp 再 ret，等于正常返回）\n");
}
#endif

// 把环形缓冲里剩下的记录全部写出去。只在即将退出时调用。
static void flush_ring(void) {
    for (int guard = 0; guard < RING; guard++) {
        unsigned t = g_tail;
        if (t == g_head) break;
        emit_rec(&g_ring[t], 0);
        g_tail = (t + 1) % RING;
    }
}

// ---------------------------------------------------------------- 退出函数本身
//
// 0x40e7e4(原因码, 细节) 是盾上报并退出进程的那个函数。它最后一步是
//   40e810: adrp x8, 0x848000 ; ldr x21, [x8, #0xd70]
//   40e838: sub  x8, x21, x8   ; x8 是另一处恒为 0 的槽，所以目标就是 [0x848d70]
//   40e83c: blr  x8
// 全二进制里只有 5 处读这个槽，全在退出/上报这一簇里。
//
// 所以它是一个纯粹的"函数指针 + 数据"，改法和网关槽一样，不碰任何代码。
// 而且它比在系统调用处拦截好在：这是一次正常的函数调用，替身正常返回之后，
// 调用方会接着走 0x40e848 那条上报路径，而不是带着半截状态往下跑。
#define EXITFN_SLOT_OFF 0x848d70ULL

static volatile uint64_t g_exitfn_hits;
static uint64_t g_exitfn_obf;
static int g_exitfn_hits_written;

__attribute__((noinline, no_stack_protector)) void exitfn_stub(void) {
    g_exitfn_hits = g_exitfn_hits + 1;
    static const char msg[] = "退出被替身接住\n";
    emit_ts(msg, sizeof(msg) - 1);
}


// 往盾的数据页里写一个 64 位值。
// [0x848d70] 所在的页是只读映射的，直接写会 SIGBUS（Round 13/15 两次都是这么崩的）。
// 先解保护、写完再恢复成只读。VM_PROT_COPY 让内核给我们一份私有副本，
// 不会改到磁盘上的文件。
static int poke64(uint64_t addr, uint64_t val) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, (vm_size_t)ps, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("解保护失败 kr=", kr); return -1; }
    *(volatile uint64_t *)(uintptr_t)addr = val;
    // 不要在这里把页恢复成只读：盾自己也要写这片数据，
    // 一旦被我们设成只读，它下一次写就是 SIGBUS（Round 15 两次都死在这里）。
    return 0;
}

static void install_exitfn(void) {
    if (!g_base) return;
    volatile uint64_t *slot = (volatile uint64_t *)(g_base + EXITFN_SLOT_OFF);
    uint64_t want = (uint64_t)(uintptr_t)&exitfn_stub;

    // 每轮都重新读一次混淆基准，不能只在开头算一次。
    // 实测 35ms 时 [0x838138] 还是 0，真正的调用发生在 80ms 左右，
    // 那时基准已经被初始化——按早先的 0 算出来的编码值到那时就是垃圾地址。
    uint64_t obf = *(volatile uint64_t *)(g_base + 0x838138) & ~0xffULL;
    if (obf != g_exitfn_obf) {
        g_exitfn_obf = obf;
        say_hex("混淆基准变为=", obf);
    }
    uint64_t cur = *slot;
#if DO_EXITFN == 2
    // 对照：把读到的值原样写回去。内容和盾自己放的一样，
    // 所以如果这一步也崩，问题就在"写这个页"本身，而不是我们写进去的值。
    static uint64_t g_probe_orig;
    if (!g_probe_orig) g_probe_orig = cur;
    uint64_t enc = g_probe_orig;
    if (cur == enc) return;
    poke64(g_base + EXITFN_SLOT_OFF, enc);
    return;
#else
    uint64_t enc = want + obf;
    if (cur == enc) return;
    if (cur == want && obf == 0) {
        // 磁盘上是未重定位的编码值，dyld 还没填。等它填。
        return;
    }
    if (poke64(g_base + EXITFN_SLOT_OFF, enc) == 0) {
        if (g_exitfn_hits_written < 3) {
            g_exitfn_hits_written++;
            say_hex("已改退出目标 编码=", enc);
            say_hex("             基准=", obf);
            say_hex("             原值=", cur);
        }
    }
#endif
}

static void *poller(void *arg) {
    (void)arg;
    // 前 500 轮热跑（构造函数阶段必须尽快接管网关，盾 40 多毫秒就开始判定），
    // 之后每轮睡 1ms。0.0.169 之前这里是有次数没有时长的死循环，几毫秒就跑完了，
    // 结果"槽还没被 dyld 填好"这类情况根本等不到，后面的复查也全都不会发生。
    for (int i = 0; i < 30000; i++) {
        if (i > 500) usleep(1000);
        try_takeover();
#if DO_DIENEXT
        install_dienext();
#endif
#if DO_EXITFN
        install_exitfn();
#endif
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
#if DO_TAKEOVER
        // 0.0.187：这段复查以前不受 DO_TAKEOVER 约束。0.0.186 明明写着"不接管"，
        // 日志里却仍然有网关记录，就是它把槽又写回去了。开关必须覆盖所有写槽的地方。
        if (g_taken == 1) {
            uint64_t want = (uint64_t)(uintptr_t)&gw_entry;
            uint64_t cur = *g_slot;
            if (cur != want && cur != 0) {
                *g_slot = want;
                say_hex("网关槽被改回=", cur);
                say("已重新接管\n");
            }
        }
#endif
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
        if (b) { g_img_names[g_img_tab_n] = _dyld_get_image_name(i); g_img_tab[g_img_tab_n++] = b; }
    }
    for (int i = 1; i < g_img_tab_n; i++) {          // 插入排序，n 不到 1000
        uint64_t v = g_img_tab[i];
        const char *nv = g_img_names[i];
        int j = i - 1;
        while (j >= 0 && g_img_tab[j] > v) {
            g_img_tab[j + 1] = g_img_tab[j];
            g_img_names[j + 1] = g_img_names[j];
            j--;
        }
        g_img_tab[j + 1] = v;
        g_img_names[j + 1] = nv;
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

// 越狱的 systemhook 会给每个进程的 libSystem 函数打内联补丁。盾有没有可能正是
// 通过"自己导入的函数序言被改过"来判断环境？这里把关键符号的头 4 条指令原样打出来，
// 人眼一看就知道是不是跳板（ElleKit 的形态是 ldr x16,#8; br x16 或 b <trampoline>）。
static void dump_sym_heads(void) {
    static const char *syms[] = {
        "open", "openat", "stat", "lstat", "fstat", "access", "readlink",
        "sysctl", "getpid", "dlsym", "dlopen", "class_copyMethodList",
        "method_getImplementation", "timingsafe_bcmp", "memcpy", "exit", NULL
    };
    for (int i = 0; syms[i]; i++) {
        void *p = dlsym(RTLD_DEFAULT, syms[i]);
        if (!p) { say("符号缺失 "); say(syms[i]); say("\n"); continue; }
        char line[160];
        out_t o = { line, line + sizeof(line) - 1 };
        o_s(&o, "符号 "); o_s(&o, syms[i]); o_s(&o, " @"); o_h(&o, (uint64_t)(uintptr_t)p);
        o_s(&o, " :");
        for (int k = 0; k < 4; k++) {
            uint32_t w = 0;
            if (safe_read((uint64_t)(uintptr_t)p + (uint64_t)k * 4, &w, 4)) {
                o_s(&o, " "); o_h(&o, w);
            }
        }
        o_ch(&o, '\n');
        emit_ts(line, (size_t)(o.p - line));
    }
}

// ---------------------------------------------------------------- 盾的 ObjC 接口
//
// 这是唯一一块还没被碰过的东西。盾对 App 暴露的类、方法列表、协议全在可写数据段，
// swizzle 改的是方法列表里的 IMP，不改变 __text 的任何一个字节，所以 19.3 那个
// __text 哈希不受影响——这正是"不改盾的 dylib 也能干预"所需要的性质。
// 这一版只做只读清点：协议叫什么、有哪些方法、谁实现了它、管理器的观察者是谁。

static void dump_name(const char *tag, const char *s) {
    say(tag); say(s ? s : "(空)"); say("\n");
}

static void dump_class_methods(const char *clsname) {
    Class c = objc_getClass(clsname);
    say("── 类 "); say(clsname); say(" : ");
    if (!c) { say("未注册\n"); return; }
    say("已注册\n");
    unsigned int mc = 0;
    Method *ms = class_copyMethodList(c, &mc);
    for (unsigned int j = 0; ms && j < mc; j++) {
        char line[224];
        out_t o = { line, line + sizeof(line) - 1 };
        o_s(&o, "    -"); o_s(&o, sel_getName(method_getName(ms[j])));
        o_s(&o, "  @"); o_h(&o, (uint64_t)(uintptr_t)method_getImplementation(ms[j]));
        o_ch(&o, '\n');
        emit_ts(line, (size_t)(o.p - line));
    }
    if (ms) free(ms);
    Class meta = object_getClass((id)c);
    mc = 0;
    ms = class_copyMethodList(meta, &mc);
    for (unsigned int j = 0; ms && j < mc; j++) {
        char line[224];
        out_t o = { line, line + sizeof(line) - 1 };
        o_s(&o, "    +"); o_s(&o, sel_getName(method_getName(ms[j])));
        o_s(&o, "  @"); o_h(&o, (uint64_t)(uintptr_t)method_getImplementation(ms[j]));
        o_ch(&o, '\n');
        emit_ts(line, (size_t)(o.p - line));
    }
    if (ms) free(ms);
}

static void dump_shield_objc(void) {
    dump_class_methods("PRMShieldEventManager");
    dump_class_methods("ShieldCallbackManager");
    dump_class_methods("PRMShieldConfig");
    dump_class_methods("ShieldConfig");

    Protocol *p = objc_getProtocol("PRMShieldEventDelegate");
    say("── 协议 PRMShieldEventDelegate : ");
    if (!p) { say("未找到\n"); return; }
    say("已找到\n");
    for (int k = 0; k < 2; k++) {
        unsigned int cnt = 0;
        struct objc_method_description *d =
            protocol_copyMethodDescriptionList(p, k == 0 ? YES : NO, YES, &cnt);
        say_hex(k == 0 ? "  必需实例方法 数=" : "  可选实例方法 数=", cnt);
        for (unsigned int i = 0; d && i < cnt; i++) {
            char line[224];
            out_t o = { line, line + sizeof(line) - 1 };
            o_s(&o, "    "); o_s(&o, sel_getName(d[i].name));
            o_s(&o, "  types="); o_s(&o, d[i].types ? d[i].types : "?");
            o_ch(&o, '\n');
            emit_ts(line, (size_t)(o.p - line));
        }
        if (d) free(d);
    }
}

// 盾会在某个事件发生时回调观察者。App 那种实现我们自己挂一个进去：
// 只要盾回调了，就等于它亲口说出"我判定的是什么"，比猜寄存器可靠得多。
// 注册观察者走的是 ObjC 消息，不碰任何代码页。
static void obs_log(SEL cmd, int v) {
    char line[192];
    out_t o = { line, line + sizeof(line) - 1 };
    o_s(&o, "[事件] 盾回调 -"); o_s(&o, sel_getName(cmd));
    if (v >= 0) { o_s(&o, "="); o_u(&o, (unsigned long long)v); }
    o_s(&o, "  t="); o_u(&o, up_ms() - g_t0);
    o_ch(&o, '\n');
    emit_ts(line, (size_t)(o.p - line));
}
static void obs_plain(id self, SEL cmd) { (void)self; obs_log(cmd, -1); }
static void obs_bool(id self, SEL cmd, BOOL v) { (void)self; obs_log(cmd, v ? 1 : 0); }

static Class make_observer_class(void) {
    static Class c;
    if (c) return c;
    c = objc_allocateClassPair(objc_getClass("NSObject"), "HSBCKObserver", 0);
    if (!c) return NULL;
    static const char *bools[] = {
        "jailbreakStatus:", "systemIntegrityProtectionStatus:", "repackagingStatus:",
        "debuggerStatus:", "screenRecordingStatus:", "developerModeStatus:", NULL
    };
    static const char *plains[] = {
        "emulatorDetected", "screenshotDetected", "libraryInjectionPrevented",
        "libraryInjectionDetected", "hookingFrameworksDetected", NULL
    };
    for (int i = 0; bools[i]; i++)
        class_addMethod(c, sel_registerName(bools[i]), (IMP)obs_bool, "v20@0:8B16");
    for (int i = 0; plains[i]; i++)
        class_addMethod(c, sel_registerName(plains[i]), (IMP)obs_plain, "v16@0:8");
    objc_registerClassPair(c);
    return c;
}

static void register_observer(const char *clsname) {
    Class c = objc_getClass(clsname);
    if (!c) return;
    id shared = ((id (*)(id, SEL))objc_msgSend)((id)c, sel_registerName("shared"));
    if (!shared) { say("    注册观察者失败：shared 为空\n"); return; }
    Class oc = make_observer_class();
    if (!oc) { say("    注册观察者失败：造类失败\n"); return; }
    id obj = ((id (*)(id, SEL))objc_msgSend)((id)oc, sel_registerName("new"));
    ((void (*)(id, SEL, id))objc_msgSend)(shared, sel_registerName("addObserver:"), obj);
    say("    已注册观察者 → "); say(clsname); say("\n");
}

// 逐轮读管理器当前登记了哪些观察者。观察者就是实现了上面那个协议的 App 对象，
// 拿到它的类名，就能去找 App 那边收到 jailbreakStatus:YES 之后到底做了什么。
static void dump_observers(const char *clsname, uint64_t tag) {
    Class c = objc_getClass(clsname);
    char line[256];
    out_t o = { line, line + sizeof(line) - 1 };
    o_s(&o, "  "); o_s(&o, clsname); o_s(&o, " 观察者 t="); o_u(&o, tag); o_ch(&o, '\n');
    emit_ts(line, (size_t)(o.p - line));
    if (!c) { say("    类未注册\n"); return; }
    id shared = ((id (*)(id, SEL))objc_msgSend)((id)c, sel_registerName("shared"));
    if (!shared) { say("    shared 为空\n"); return; }
    id obs = ((id (*)(id, SEL))objc_msgSend)(shared, sel_registerName("observers"));
    if (!obs) { say("    observers 为空\n"); return; }
    unsigned long n = (unsigned long)((unsigned long (*)(id, SEL))objc_msgSend)
                        (obs, sel_registerName("count"));
    say_hex("    观察者个数=", n);
    for (unsigned long i = 0; i < n && i < 8; i++) {
        id it = ((id (*)(id, SEL, unsigned long))objc_msgSend)
                    (obs, sel_registerName("objectAtIndex:"), i);
        if (!it) continue;
        const char *nm = class_getName(object_getClass(it));
        say("    ["); say(nm ? nm : "?"); say("] 实现了:\n");
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(object_getClass(it), &mc);
        for (unsigned int j = 0; ms && j < mc; j++) {
            const char *sn = sel_getName(method_getName(ms[j]));
            if (!sn) continue;
            if (!strstr(sn, "Status:") && !strstr(sn, "Detected") &&
                !strstr(sn, "Prevented") && !strstr(sn, "hookingFrameworks")) continue;
            char l2[224];
            out_t o2 = { l2, l2 + sizeof(l2) - 1 };
            o_s(&o2, "      -"); o_s(&o2, sn);
            o_s(&o2, "  @"); o_h(&o2, (uint64_t)(uintptr_t)method_getImplementation(ms[j]));
            o_ch(&o2, '\n');
            emit_ts(l2, (size_t)(o2.p - l2));
        }
        if (ms) free(ms);
    }
}

// ObjC 运行时必须已经初始化，所以在独立线程里等一小会儿再动手。
static void *objc_dump_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++) {
        if (objc_getClass("NSObject")) break;
        usleep(500);
    }
    usleep(4000);
    say_hex("[ObjC] 清点开始 t=", up_ms() - g_t0);
    dump_shield_objc();
    say_hex("[ObjC] 清点结束 t=", up_ms() - g_t0);
    // 观察者是在 App 启动过程中才登记进来的，所以在判定之前多读几次。
    static const uint64_t probes[] = { 18, 26, 34, 42, 50, 58, 66 };
    for (unsigned i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint64_t now = up_ms() - g_t0;
        if (probes[i] > now) usleep((useconds_t)((probes[i] - now) * 1000));
        uint64_t t = up_ms() - g_t0;
        if (i == 2) {
            register_observer("PRMShieldEventManager");
            register_observer("ShieldCallbackManager");
        }
        dump_observers("PRMShieldEventManager", t);
        dump_observers("ShieldCallbackManager", t);
    }
    say_hex("[ObjC] 观察者清点结束 t=", up_ms() - g_t0);
    return NULL;
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
    // 0.0.233：盾的收尾动作是"自己发一个信号，伪装成崩溃"。
    // 既然处理函数这次留住了，就干脆不重新抛：记一笔然后正常返回，
    // 让它那一步变成空动作。只吞前若干次，避免真的出错时无限循环。
    static volatile int swallowed;
    if (swallowed < 200) { swallowed++; return; }
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

// ---------------------------------------------------------------- 只换判定函数
//
// Round 6 试过把整张检查表换成假对象，结果换来"篡改"判定（原因码 4）。
// 那种做法改的是向量本身。这里只动每个**检查项对象自己**的虚表指针：
// 对象是运行时在堆上 new 出来的，盾的自检哈希覆盖不到；向量、对象内容、
// 项数全都保持原样。虚表在盾的 __DATA 里，我们只在旁边做一份拷贝再指过去。
#define VT_SLOTS 8
static uint64_t g_vtcopy[6][VT_SLOTS];
static uint64_t g_vt_orig[6];
static int g_vt_n;
static int g_vt_patched;

static void patch_verdict_vtables(void) {
    static int diag;
    if (!g_base) return;
    uint64_t obj = *(volatile uint64_t *)(g_base + 0x8509d0);
    if (!diag && obj > 0x100000000ULL && obj < 0x800000000ULL) {
        diag = 1;
        say_hex("换虚表 诊断 obj=", obj);
        {
            say_hex("   bg=", *(volatile uint64_t *)(obj + 0x10));
            say_hex("   en=", *(volatile uint64_t *)(obj + 0x18));
        }
    }
    if (obj < 0x100000000ULL || obj > 0x800000000ULL) return;
    uint64_t bg = *(volatile uint64_t *)(obj + 0x10);
    uint64_t en = *(volatile uint64_t *)(obj + 0x18);
    if (bg < 0x100000000ULL || en <= bg) return;
    uint32_t n = (uint32_t)((en - bg) / 8);
    if (n < 1 || n > 6) return;

    int changed = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t it = *(volatile uint64_t *)(uintptr_t)(bg + (uint64_t)i * 8);
        if (it < 0x100000000ULL || it > 0x800000000ULL) continue;
        uint64_t vt = *(volatile uint64_t *)(uintptr_t)it;
        // 这些虚表并不在盾自己的镜像里（实测比盾基址高出几十 MB），
        // 所以不能按"必须落在盾里"来筛。改成尝试着安全读：读得到就认。
        uint64_t probe[VT_SLOTS];
        int ok = 1;
        for (int k = 0; k < VT_SLOTS && ok; k++)
            ok = safe_read(vt + (uint64_t)k * 8, &probe[k], 8);
        if (!ok || vt < 0x100000000ULL) continue;

        int slot = -1;
        for (int k = 0; k < g_vt_n; k++) if (g_vt_orig[k] == vt) { slot = k; break; }
        if (slot < 0) {
            if (g_vt_n >= 6) continue;
            slot = g_vt_n++;
            g_vt_orig[slot] = vt;
            for (int k = 0; k < VT_SLOTS; k++) g_vtcopy[slot][k] = probe[k];
            // 偏移 0x10 那一格就是盾遍历时调用的判定函数，换成一个恒返回 0 的桩。
            g_vtcopy[slot][2] = g_base + 0x15984;
            say_hex("复制虚表 原=", vt);
            say_hex("        判定原函数=", probe[2]);
            say_hex("        改成=", g_vtcopy[slot][2]);
        }
        uint64_t want = (uint64_t)(uintptr_t)&g_vtcopy[slot][0];
        if (*(volatile uint64_t *)(uintptr_t)it != want) {
            *(volatile uint64_t *)(uintptr_t)it = want;
            changed = 1;
        }
    }
    if (changed) {
        g_vt_patched++;
        if (g_vt_patched <= 3) say_hex("已换判定函数，第几次=", (unsigned long long)g_vt_patched);
    }
}

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

// ---------------------------------------------------------------- 它问了什么
//
// 从导入符号清单看，盾确实导入了 getenv 和 _uname（早前的笔记写成"没有"，是错的）。
// 这两个都是经典的越狱检测入口：DYLD_INSERT_LIBRARIES 之类的环境变量、
// 以及 uname 里的版本/机型。先看它到底问了什么，再决定怎么答。
static volatile int g_in_hook;
static char *(*o_getenv)(const char *);
static int (*o_uname)(void *);

static char *my_getenv(const char *name) {
    if (name && !g_in_hook) {
        g_in_hook = 1;
        char lb[160];
        out_t o = { lb, lb + sizeof(lb) - 1 };
        o_s(&o, "getenv(\"");
        for (int i = 0; name[i] && i < 80; i++) o_ch(&o, name[i]);
        o_s(&o, "\") = ");
        char *v = o_getenv ? o_getenv(name) : NULL;
        if (v) { for (int i = 0; v[i] && i < 60; i++) o_ch(&o, v[i]); }
        else o_s(&o, "(空)");
        o_ch(&o, '\n');
        emit_ts(lb, (size_t)(o.p - lb));
        g_in_hook = 0;
        return v;
    }
    return o_getenv ? o_getenv(name) : NULL;
}

static int my_uname(void *u) {
    int r = o_uname ? o_uname(u) : -1;
    if (!g_in_hook && u && r == 0) {
        g_in_hook = 1;
        const char *p = (const char *)u;
        char lb[220];
        out_t o = { lb, lb + sizeof(lb) - 1 };
        o_s(&o, "uname: 系统=");   for (int i = 0;   i < 32 && p[i];  i++) o_ch(&o, p[i]);
        o_s(&o, " 主机=");         for (int i = 256; i < 288 && p[i];  i++) o_ch(&o, p[i]);
        o_s(&o, " 版本=");         for (int i = 512; i < 560 && p[i];  i++) o_ch(&o, p[i]);
        o_ch(&o, '\n');
        emit_ts(lb, (size_t)(o.p - lb));
        g_in_hook = 0;
    }
    return r;
}

static void install_env_hooks(void) {
    void *g = dlsym(RTLD_DEFAULT, "getenv");
    void *u = dlsym(RTLD_DEFAULT, "uname");
    if (g) MSHookFunction(g, (void *)my_getenv, (void **)&o_getenv);
    if (u) MSHookFunction(u, (void *)my_uname, (void **)&o_uname);
    say_hex("已挂 getenv/uname，地址=", (unsigned long long)(uintptr_t)g);
}

// ---------------------------------------------------------------- 谁在杀进程
//
// 进程最后被 SIGKILL 收走，没有崩溃报告，内存只有 62MB（排除 jetsam），
// 而盾自己网关里的 kill（37 号）一次都没出现。剩下的解释是：盾走的是 libc 的
// kill()/raise()/abort()，那条路直接进 libsystem 的系统调用桩，不经过它的私有网关。
// 所以这里在 libc 层面挂一层，把调用记下来。拦不拦先不管，先确认是谁。
static int (*o_kill)(int, int);
static int (*o_raise)(int);
static void (*o_abort)(void);

static int my_kill(int pid, int sig) {
    char lb[96];
    out_t o = { lb, lb + sizeof(lb) - 1 };
    o_s(&o, "libc kill: 目标="); o_d(&o, pid);
    o_s(&o, " 信号="); o_d(&o, sig);
    o_s(&o, " 自己="); o_d(&o, getpid());
    o_ch(&o, '\n');
    emit_ts(lb, (size_t)(o.p - lb));
    return o_kill ? o_kill(pid, sig) : -1;
}
static int my_raise(int sig) {
    say_hex("libc raise: 信号=", (unsigned long long)sig);
    return o_raise ? o_raise(sig) : -1;
}
static void my_abort(void) {
    say("libc abort 被调用\n");
    if (o_abort) o_abort();
}

static void install_kill_hooks(void) {
    void *k = dlsym(RTLD_DEFAULT, "kill");
    void *r = dlsym(RTLD_DEFAULT, "raise");
    void *a = dlsym(RTLD_DEFAULT, "abort");
    if (k) MSHookFunction(k, (void *)my_kill,  (void **)&o_kill);
    if (r) MSHookFunction(r, (void *)my_raise, (void **)&o_raise);
    if (a) MSHookFunction(a, (void *)my_abort, (void **)&o_abort);
    say_hex("已挂 kill hook，地址=", (unsigned long long)(uintptr_t)k);
}

// 0.0.238：exit/_exit 只记录不干预。
static void (*o_exit)(int);
static void (*o__exit)(int);

static void exit_record(uint64_t kind, int code, void *ra) {
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x4558495400000000ULL | (kind & 0xff);
    r[1] = (uint64_t)(int64_t)code;
    r[2] = (uint64_t)(uintptr_t)ra;
    r[3] = (uint64_t)g_base;
    r[4] = up_ms() - g_t0;
    r[5] = 0;
    raw_write(g_gwfd, r, sizeof(r));
}

static void my_exit(int code) {
    exit_record(0x21, code, __builtin_return_address(0));
    if (o_exit) o_exit(code);
    _exit(code);
}
static void my__exit(int code) {
    exit_record(0x22, code, __builtin_return_address(0));
    if (o__exit) o__exit(code);
    __builtin_trap();
}

static void install_exit_hooks(void) {
    void *e = dlsym(RTLD_DEFAULT, "exit");
    void *x = dlsym(RTLD_DEFAULT, "_exit");
    if (e) MSHookFunction(e, (void *)my_exit,  (void **)&o_exit);
    if (x) MSHookFunction(x, (void *)my__exit, (void **)&o__exit);
    say_hex("已挂 exit hook，exit 地址=", (unsigned long long)(uintptr_t)e);
    say_hex("              _exit 地址=", (unsigned long long)(uintptr_t)x);
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
            if (!in_shield) {
                // 不在盾里时最有用的是"这是哪个库里的哪一段"。dladdr 在这个进程里
                // 不可靠（注入器接管过 dlsym），所以改用自己维护的镜像表。
                int ii = img_index_of(pc);
                if (ii >= 0) {
                    o_s(&o, " img"); o_d(&o, ii);
                    o_s(&o, "+"); o_h(&o, pc - g_img_tab[ii]);
                    const char *nm = (ii < g_img_tab_n) ? g_img_names[ii] : NULL;
                    if (nm) { const char *bn = strrchr(nm, '/'); o_s(&o, "  "); o_s(&o, bn ? bn + 1 : nm); }
                }
            }
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

            // 光有 pc 只能知道"卡在哪个系统调用"，不知道是谁在调它。
            // 非盾的线程按 x29 链往上走几层，把调用路径打出来——
            // 界面起不来，缺的正是这一串。
            if (!in_shield) {
                const uint64_t *rv = (const uint64_t *)&st;
                uint64_t fp = rv[29];
                for (int d = 0; d < 6; d++) {
                    if (fp < 0x100000000ULL || fp > 0x800000000000ULL || (fp & 7)) break;
                    uint64_t nfp = *(const uint64_t *)(uintptr_t)fp;
                    uint64_t ra  = *(const uint64_t *)(uintptr_t)(fp + 8);
                    if (ra < 0x100000000ULL || ra > 0x800000000000ULL) break;
                    uint64_t m = ra & 0x0000FFFFFFFFFFFFULL;
                    char fb[192];
                    out_t o2 = { fb, fb + sizeof(fb) - 1 };
                    o_s(&o2, "     ^"); o_d(&o2, d + 1); o_s(&o2, " ");
                    int jj = img_index_of(m);
                    if (jj >= 0) {
                        o_s(&o2, "img"); o_d(&o2, jj); o_s(&o2, "+"); o_h(&o2, m - g_img_tab[jj]);
                        const char *nm = (jj < g_img_tab_n) ? g_img_names[jj] : NULL;
                        if (nm) { const char *bn = strrchr(nm, '/'); o_s(&o2, "  "); o_s(&o2, bn ? bn + 1 : nm); }
                    } else {
                        o_h(&o2, m);
                    }
                    o_ch(&o2, '\n');
                    emit_ts(fb, (size_t)(o2.p - fb));
                    if (nfp <= fp) break;
                    fp = nfp;
                }
            }
        }
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list,
                  (vm_size_t)(cnt * sizeof(thread_t)));
}


// ---------------------------------------------------------------- 抓自检现场
//
// 0x43cc08 那一段做的是：S = [0x848fb8] - k，从 S 的 7 个 64 位字段算出
// 期望哈希（x21 = a4 - a3*a6）与哈希函数地址（x9 = S + a6*a0 - a1 + a5 - a4*a6），
// 输入指针 x1 = a3 - a2*a6，输出 x0 = S + a6*a0 - a1 + a2 - a6*a1，然后
//   0x43cccc  blr x9
//   0x43ccdc  cmp x21, x20        ← 期望 vs 实算
// 两者不等的后果是原因码 4。
//
// 这段代码不调任何系统调用，网关看不见，只能靠外部线程快照。
// 哈希主循环在 +0x65bfa8，处理 3MB 左右的数据要几毫秒，足够抓到。
static int g_sc_caught;
static int g_rep_caught;
static int g_cmp_caught;

// 0.0.189：0.0.188 的反推证明自检是过的——磁盘文件 __text 段的 xxHash64
// （seed=0x9fca7ba5c41b2cec）正好等于盾的期望值 0x8d2fe35465f18925。
// 那么"原因码 4"就不是这段自检报的。接下来要看两件事：
//   1. 0x43ccdc 之后实算和期望到底相不相等（内存与磁盘可能不同）；
//   2. 报告函数拿到的原因码与说明字符串是什么。
// 这三段窗口都很短，只能靠提高采样次数去撞。
static void catch_selfcheck(void) {
    if (!g_base || (g_sc_caught >= 3 && g_cmp_caught >= 4 && g_rep_caught >= 6)) return;
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    for (mach_msg_type_number_t i = 0; i < cnt && i < 48; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64,
                             (thread_state_t)&st, &sc) == KERN_SUCCESS) {
            uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(st);
            if (pc >= g_base) {
                uint64_t off = pc - g_base;
                const uint64_t *rv = (const uint64_t *)&st;
                if (off >= 0x65bfa8ULL && off < 0x65c600ULL && g_sc_caught < 3) {
                    g_sc_caught++;
                    say_hex("自检现场 pc=+", off);
                    say_hex("  x21 期望=", rv[21]);
                    say_hex("  x20 全局0x848fb8=", rv[20]);
                    say_hex("  x1 当前指针=", rv[1]);
                    say_hex("  x8 长度=", rv[8]);
                    say_hex("  x11 终点前缀=", rv[11]);
                } else if (off >= 0x43ccc4ULL && off < 0x43cd10ULL && g_cmp_caught < 4) {
                    g_cmp_caught++;
                    say_hex("比较现场 pc=+", off);
                    say_hex("  x21 期望=", rv[21]);
                    say_hex("  x20 实算=", rv[20]);
                    say_hex("  相等=", (uint64_t)(rv[21] == rv[20]));
                } else if (off >= 0x37ca78ULL && off < 0x37cae8ULL && g_rep_caught < 6) {
                    // 报告函数的入口。它的参数是 x0,x1,x10,x11,x12,x13，
                    // 进来后分别落到 x21,x25,x27,x20,x28,x22。
                    g_rep_caught++;
                    say_hex("报告入口 pc=+", off);
                    say_hex("  x21 参数0=", rv[21]);
                    say_hex("  x25 参数1=", rv[25]);
                    say_hex("  x27 参数2=", rv[27]);
                    say_hex("  x20 参数3=", rv[20]);
                    say_hex("  x28 参数4=", rv[28]);
                    say_hex("  x22 参数5=", rv[22]);
                } else if (off >= 0x37d480ULL && off < 0x37d500ULL && g_rep_caught < 6) {
                    g_rep_caught++;
                    say_hex("报告构造 pc=+", off);
                    dump_mem_safe("  x0 @", rv[0], 0x20);
                    say_hex("  x1=", rv[1]);
                    say_hex("  x2=", rv[2]);
                    say_hex("  x19=", rv[19]);
                    say_hex("  x20=", rv[20]);
                } else if (off >= 0x40e7e4ULL && off < 0x40f000ULL && g_rep_caught < 6) {
                    g_rep_caught++;
                    // 0x40e7e4 一进来就把参数存进 x20(reason)/x19(desc)，
                    // 它们在整个函数体内都是 callee-saved，采样在任意位置都能读到。
                    say_hex("上报现场 pc=+", off);
                    say_hex("  原因码 x20=", rv[20]);
                    say_hex("  说明 x19=", rv[19]);
                    uint64_t descp = rv[19];
                    if (descp > 0x100000000ULL) {
                        char tmp[160];
                        int n2 = 0;
                        if (safe_read(descp, tmp, 128)) {
                            tmp[127] = 0;
                            say("  说明文本="); say(tmp); say("\n");
                            n2 = 1;
                        }
                        (void)n2;
                    }
                }
            }
        }
    }
    // 0.0.195：以前只释放了循环里查过的那几十个端口，cnt 更大的时候每一轮都在泄漏
    // send right，端口表迟早耗尽，task_threads 就会一直失败或卡住。
    // 现在不管查了几个，全部还回去。
    for (mach_msg_type_number_t i = 0; i < cnt; i++)
        mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (mach_vm_address_t)list,
                  (mach_vm_size_t)(cnt * sizeof(thread_t)));
}


// 进程实际占用的物理内存。盾把整份共享缓存（约 1.42GB）映射进了进程，
// 而"启动几秒后被 SIGKILL、没有任何崩溃报告"正是被系统按内存压力收走的典型样子。
// 把这条曲线打出来，就不用再猜。
static uint64_t footprint_kb(void) {
    task_vm_info_data_t vi;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vi, &cnt) != KERN_SUCCESS) return 0;
    return (uint64_t)(vi.phys_footprint / 1024);
}


// ---------------------------------------------------------------- 看 RASP 这一层
//
// 盾是 C++ 核心，但把结论交给 App 走的是 RASPFramework 的 ObjC 接口。
// 汇丰中国那套（ZDefend）就是靠 hook ObjC 层把威胁详情读出来的。
// 香港这套先看清楚有哪些类、哪些方法，再决定读哪个。
static int name_hits(const char *n) {
    static const char *kw[] = {"RASP","Security","Blocker","Strategy","Promon","Threat","Jailbreak",NULL};
    for (int i = 0; kw[i]; i++) if (strstr(n, kw[i])) return 1;
    return 0;
}

static void dump_objc_classes(void) {
    int cnt = objc_getClassList(NULL, 0);
    if (cnt <= 0) { say("取不到类列表\n"); return; }
    Class *cls = (Class *)malloc(sizeof(Class) * (size_t)cnt);
    if (!cls) return;
    cnt = objc_getClassList(cls, cnt);
    int shown = 0;
    for (int i = 0; i < cnt && shown < 60; i++) {
        const char *n = class_getName(cls[i]);
        if (!n || !name_hits(n)) continue;
        shown++;
        char lb[192];
        out_t o = { lb, lb + sizeof(lb) - 1 };
        o_s(&o, "类 "); o_s(&o, n); o_ch(&o, '\n');
        emit_ts(lb, (size_t)(o.p - lb));
        if (1) continue;   // 先只要类名：方法表太慢，会把心跳线程占住几百毫秒
        unsigned mc = 0;
        Method *ms = class_copyMethodList(cls[i], &mc);
        if (ms) {
            for (unsigned k = 0; k < mc && k < 40; k++) {
                const char *sn = sel_getName(method_getName(ms[k]));
                char b2[160];
                out_t o2 = { b2, b2 + sizeof(b2) - 1 };
                o_s(&o2, "    -"); o_s(&o2, sn); o_ch(&o2, '\n');
                emit_ts(b2, (size_t)(o2.p - b2));
            }
            free(ms);
        }
        // 类方法（很多单例是 +shared 形式）
        Class meta = object_getClass((id)cls[i]);
        unsigned mm = 0;
        Method *mm2 = class_copyMethodList(meta, &mm);
        if (mm2) {
            for (unsigned k = 0; k < mm && k < 20; k++) {
                const char *sn = sel_getName(method_getName(mm2[k]));
                char b3[160];
                out_t o3 = { b3, b3 + sizeof(b3) - 1 };
                o_s(&o3, "    +"); o_s(&o3, sn); o_ch(&o3, '\n');
                emit_ts(b3, (size_t)(o3.p - b3));
            }
            free(mm2);
        }
    }
    free(cls);
}


// ---------------------------------------------------------------- 自检之后再改代码
//
// 前面所有"只改数据"的路都封死了：退出的那个槽有 5 处读取、各自混淆基准不同，
// 改一处会把另一处带崩（Round 15 实测：原值写回能活 10 秒，写成别的值 80ms 就 SIGBUS）。
//
// 剩下能改的就只有代码本身。盾会对自己 __TEXT 做哈希自检，但自检发生得很早
// （44-60ms，实测自检结果是"0 处不同"）。所以只要等它算完再改，
// 那一次自检就看不见我们的改动。这一版就是验证这个时序能不能成立：
// 先在 100ms 之后把 0x40e7e4（上报并退出）的第一条指令改成 ret。
static int g_repatch_done;

volatile uint64_t g_verdict_calls;

// 盾的判定函数替身：恒返回 1（让 0x5d87a4 的 tbnz 直接跳过退出流程），
// 同时记一次数——用它来判断补丁到底有没有被用到。
__attribute__((noinline, no_stack_protector)) long verdict_pass(void) {
    g_verdict_calls = g_verdict_calls + 1;
    return 1;
}

static void patch_words(uint64_t addr, const uint32_t *ws, int n, const char *what) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, (vm_size_t)ps, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("解保护失败 kr=", kr); return; }
    for (int i = 0; i < n; i++)
        *(volatile uint32_t *)(uintptr_t)(addr + (uint64_t)i * 4) = ws[i];
    sys_icache_invalidate((void *)(uintptr_t)addr, (size_t)(n * 4));
    say_hex(what, addr);
    for (int i = 0; i < n; i++)
        say_hex("  现=", *(volatile uint32_t *)(uintptr_t)(addr + (uint64_t)i * 4));
}

static void patch_ret(uint64_t addr, const char *what) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, (vm_size_t)ps, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("解保护失败 kr=", kr); return; }
    uint32_t old = *(volatile uint32_t *)(uintptr_t)addr;
    *(volatile uint32_t *)(uintptr_t)addr = 0xD65F03C0u;   // ret
    sys_icache_invalidate((void *)(uintptr_t)addr, 4);
    say_hex(what, addr);
    say_hex("  原指令=", old);
    say_hex("  现指令=", *(volatile uint32_t *)(uintptr_t)addr);
}

static void patch_exit_after_selfcheck(uint64_t el) {
    if (g_repatch_done || !g_base || el < DO_REPATCH_AT) return;
    g_repatch_done = 1;

    // 只做一件事：把失败块里那次退出（0x7133e4 bl 0x40e7e4）改成 nop。
    // 不碰函数入口——实测改入口拦不住已经在函数里的线程。
    static const uint32_t nop1[] = { 0xD503201Fu };
    patch_words(g_base + 0x7133e4, nop1, 1, "已把失败块里那次退出改成 nop，地址=");

    // 只改判定函数，不再去挡 0x40e7e4。上一版两者都改，进程能活 14 秒但停在启动图——
    // 那是 App 在等一个被我们永久挡住的结果。让判定返回 1 才是"检查通过"，
    // 挡住退出只是"检查永远不结束"。
#ifndef DO_ALSO_RET
#define DO_ALSO_RET 0
#endif
#if DO_ALSO_RET
    patch_ret(g_base + 0x40e7e4, "已在自检之后把退出函数改成 ret，地址=");
#endif
}


// ---------------------------------------------------------------- 自检的期望值
//
// 0x43cc0c 读 [0x848fb8]，那是一个指向 0x30 字节结构的指针；0x43cc38 起把这 30 字节
// 按 msub/add 的线性运算解混淆出期望哈希，最后 0x43ccdc 与算出来的值比较。
// 只要能把结构里的期望值改成"补丁后的实际哈希"，自检就会通过。
// 这一步先把结构原样 dump 出来，配合离线复刻哈希来验证。
static void dump_expect_struct(uint64_t el) {
    static int done;
    if (done || !g_base || el < 30) return;
    done = 1;
    uint64_t p = *(volatile uint64_t *)(g_base + 0x848fb8);
    say_hex("期望值结构指针=", p);
    if (p < 0x100000000ULL || p > 0x800000000ULL) return;
    dump_mem("期望结构 0x30 字节 @", p, 0x30);
    // 自检比的是哪一页：把盾 __TEXT 的头 64 字节也 dump 出来做对照
    dump_mem("盾 __TEXT 头 64 字节 @", g_base, 64);
}

// ---------------------------------------------------------------- 检查表本体
//
// 0x6f3d54 是检查表的汇总函数：它拿 param_1 = 检查表对象，依次遍历四组向量，
// 对每一项调对应类的"判定"函数，任一项非零就返回 1（报警）。四组向量在对象里的
// 位置和元素大小可以直接从它的反汇编读出来：
//
//   +0x10 元素 0x30  → 0x6f2454（比较某个指针指向的 int 与期望 int）
//                     元素 +0x18 = 启用字节，+0x20 = 指针，+0x28 = 期望 int
//   +0x28 元素 0x58  → 0x6f32d4
//   +0x40 元素 0x18  → 0x6f2118（dlsym 一个名字，命中的地址必须落已加载镜像里）
//   +0x58 元素 0x20  → 0x6f3180（某个指针必须落在已加载镜像里）
//
// 单例指针存在 +0x8509d0（惰性创建）。这里只读不写，先看清表里到底有什么、
// 哪一项在报警——这是"从数据侧让判定通过"唯一能下手的地方。
static void dump_mem_safe(const char *label, uint64_t addr, int n) {
    static const char hx[] = "0123456789abcdef";
    unsigned char m[192];
    if (n > (int)sizeof(m)) n = (int)sizeof(m);
    char buf[640];
    out_t o = { buf, buf + sizeof(buf) - 1 };
    o_s(&o, label); o_h(&o, addr); o_s(&o, ": ");
    if (!safe_read(addr, m, (size_t)n)) {
        o_s(&o, "<不可读>\n");
        emit_ts(buf, (size_t)(o.p - buf));
        return;
    }
    for (int i = 0; i < n; i++) {
        o_ch(&o, hx[m[i] >> 4]); o_ch(&o, hx[m[i] & 15]); o_ch(&o, ' ');
    }
    o_ch(&o, '\n');
    emit_ts(buf, (size_t)(o.p - buf));
}

static void probe_checks(uint64_t el) {
    static int done;
    if (done || !g_base || el < 20) return;
    uint64_t p = 0;
    if (!safe_read(g_base + 0x8509d0, &p, 8)) { say_hex("读不到检查表槽=", g_base + 0x8509d0); done = 1; return; }
    if (p < 0x100000000ULL || p > 0x800000000ULL) return;   // 还没建出来，下一拍再看
    done = 1;
    say_hex("检查表单例=", p);
    dump_mem_safe("  单例头 0x80 @", p, 0x80);

    static const uint64_t voff[4] = { 0x10, 0x28, 0x40, 0x58 };
    static const uint64_t vsz[4]  = { 0x30, 0x58, 0x18, 0x20 };
    for (int k = 0; k < 4; k++) {
        uint64_t b = 0, e = 0;
        if (!safe_read(p + voff[k], &b, 8)) continue;
        if (!safe_read(p + voff[k] + 8, &e, 8)) continue;
        if (e < b || b < 0x100000000ULL || e > 0x800000000ULL) continue;
        uint64_t n = (e - b) / vsz[k];
        char lab[48];
        out_t o = { lab, lab + sizeof(lab) - 1 };
        o_s(&o, "向量"); o_d(&o, k); o_s(&o, " 条数=");
        o_ch(&o, '\0');
        say_hex(lab, n);
        say_hex("  起=", b);
        for (uint64_t i = 0; i < n && i < 3; i++) {
            uint64_t it = b + i * vsz[k];
            dump_mem_safe("  项 @", it, (int)vsz[k]);
            if (vsz[k] == 0x30) {
                uint64_t vt = 0, f = 0;
                uint64_t a = 0, ex = 0;
                if (safe_read(it, &vt, 8) && vt > 0x100000000ULL && safe_read(vt + 0x10, &f, 8))
                    say_hex("    vtable+0x10=", f);
                // 判定函数 0x6f2454 的语义：*ptr == 期望值 才算通过
                if (safe_read(it + 0x20, &a, 8) && a > 0x100000000ULL) {
                    uint32_t cur = 0;
                    if (safe_read(it + 0x28, &ex, 8) && safe_read(a, &cur, 4)) {
                        say_hex("    当前 int=", cur);
                        say_hex("    期望 int=", ex);
                    }
                }
            }
        }
    }
}

// 0x43cc38 起把这 0x38 字节按线性关系解混淆：
//
//   期望哈希 = a4 - a3*a6
//   哈希函数 = S + a6*a0 - a1 + a5 - a4*a6
//   参数 x0  = S + a6*a0 - a1 + a2 - a6*a1
//   参数 x1  = a3 - a2*a6
//
// 真实地址是 S = [0x848fb8] - K，K 是盾的每进程基准，事先不知道。
// 但结构本身就在盾的镜像里，而上面四条给了一组很强的自洽条件：算出来的
// 哈希函数必须落在盾的 __TEXT 里，x0/x1 必须可读。所以不用求 K，
// 直接在镜像里找满足条件的 0x38 字节块即可。只读不写。
static void probe_selfcheck(uint64_t el) {
    static int done;
    if (done || !g_base || el < 28) return;
    done = 1;

    uint64_t E = 0;
    if (!safe_read(g_base + 0x848fb8, &E, 8) || !E) { say("读不到 0x848fb8\n"); return; }
    say_hex("E=", E);

    const uint64_t IMG = 0x8c0000;
    uint8_t *buf = (uint8_t *)malloc(IMG + 0x40);
    if (!buf) { say("内存不足\n"); return; }
    for (uint64_t off = 0; off < IMG; off += 0x4000) {
        uint64_t want = (IMG - off) < 0x4000 ? (IMG - off) : 0x4000;
        safe_read(g_base + off, buf + off, (size_t)want);
    }

    int found = 0;
    for (uint64_t off = 0; off + 0x38 <= IMG; off += 8) {
        const uint64_t *a = (const uint64_t *)(buf + off);
        uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4], a5 = a[5], a6 = a[6];
        if (!a0 && !a1 && !a2 && !a3 && !a4 && !a6) continue;
        uint64_t S = g_base + off;
        uint64_t fn = S + a6 * a0 - a1 + a5 - a4 * a6;
        if (fn < g_base + 0x8000 || fn >= g_base + 0x80c000) continue;
        uint64_t x0 = S + a6 * a0 - a1 + a2 - a6 * a1;
        uint64_t x1 = a3 - a2 * a6;
        uint8_t t = 0;
        if (!safe_read(x1, &t, 1)) continue;
        if (!safe_read(x0, &t, 1)) continue;
        found++;
        say_hex("候选 off=", off);
        say_hex("  fn=", fn - g_base);
        say_hex("  期望=", a4 - a3 * a6);
        if (fn - g_base == 0x65bfa8) {
            say_hex("  ★ 命中的就是自检用的那个 xxHash，x0=", x0 - g_base);
            say_hex("     x1=", x1);
            if (E > S) say_hex("     K=", E - S);
            dump_mem_safe("     结构 0x38 @", S, 0x38);
            dump_mem_safe("     x1 起 32 字节 @", x1, 32);
        }
        if (found >= 400) break;
    }
    say_hex("候选总数=", (uint64_t)found);
    if (!found) say("没找到自洽的自检结构\n");
    free(buf);
}

// ---------------------------------------------------------------- 完整性表
//
// 0x713160 调 0x5e7aa4([0x850e48])，那个函数只有两种返回 1（=中止）的路径：
// 对象首字节是 0，或者它那 16 条自检里有一条对不上。实测首字节是 1，
// 所以中止来自某一条比对失败。
//
// 每条 0x28 字节：{目标地址, 期望块指针, 长度, 比对长度, 标志}。
// 第一条是共享缓存里的 0x1e0da0000、长度 0x4000、比对长度 0x20 —— 也就是
// 对 16KB 内存算 32 字节摘要（SHA-256）再和一块堆上的期望值比。
// 这里用 CommonCrypto 自己算一遍，把"哪一条对不上"直接指出来。
static int (*g_sha256)(const void *, unsigned int, unsigned char *);

static void probe_integrity(uint64_t el) {
    static int done;
    if (done || !g_base || el < 45) return;
    uint64_t st = 0;
    if (!safe_read(g_base + 0x850e48, &st, 8)) return;
    if (st < 0x100000000ULL || st > 0x800000000ULL) return;   // 还没建出来
    done = 1;

    if (!g_sha256) g_sha256 = (int (*)(const void *, unsigned int, unsigned char *))
        dlsym(RTLD_DEFAULT, "CC_SHA256");

    uint64_t b = 0, e = 0;
    if (!safe_read(st + 0x28, &b, 8) || !safe_read(st + 0x30, &e, 8)) return;
    if (e < b || b < 0x100000000ULL) return;
    uint64_t n = (e - b) / 0x28;
    say_hex("完整性表 条目数=", n);
    say_hex("  CC_SHA256=", (uint64_t)(uintptr_t)g_sha256);

    for (uint64_t i = 0; i < n && i < 20; i++) {
        uint64_t ent = b + i * 0x28;
        uint64_t addr = 0, obj = 0, len = 0, l2 = 0;
        if (!safe_read(ent, &addr, 8) || !safe_read(ent + 8, &obj, 8)) continue;
        safe_read(ent + 0x10, &len, 8);
        safe_read(ent + 0x18, &l2, 8);
        say_hex(" 条目 目标=", addr);
        say_hex("   期望块=", obj);
        say_hex("   长度=", len);
        say_hex("   比对长度=", l2);
        int ii = img_index_of(addr);
        if (ii >= 0 && ii < g_img_tab_n && g_img_names[ii]) {
            say("   所在镜像=");
            say(g_img_names[ii]);
            say("\n");
        } else {
            say_hex("   不在已加载镜像里，相对盾=", addr - g_base);
        }
        if (l2 == 32 && obj && len && len <= 0x100000 && g_sha256) {
            unsigned char *buf = (unsigned char *)malloc((size_t)len);
            unsigned char exp[32], dig[32];
            if (buf && safe_read(addr, buf, (size_t)len) && safe_read(obj, exp, 32)) {
                g_sha256(buf, (unsigned int)len, dig);
                int same = memcmp(dig, exp, 32) == 0;
                say_hex("   摘要一致=", (uint64_t)same);
                dump_mem("   实算=", (uint64_t)(uintptr_t)dig, 32);
                dump_mem("   期望=", obj, 32);
            }
            if (buf) free(buf);
        }
    }
}

// 16 条里只有一条对不上：共享缓存 0x1e0dac000 那一页（libsystem_kernel 里）。
// 也就是说盾中止的原因不是"发现越狱痕迹"，而是"系统库里有一页的摘要变了"。
// 期望摘要是堆上的一块 32 字节拷贝，属于可写数据——把实算值写进去，
// 这条自检就过了。整个过程不碰任何代码页，也不碰盾的文件。
static int g_fixint_done;
static void report_fix_count(void) { if (g_fixint_done) say_hex("完整性表 已改条数=", (uint64_t)g_fixint_done); }

static void fix_integrity(uint64_t el) {
    static uint64_t next_at, last_st;
    if (!g_base || el < next_at) return;
    next_at = el + 30;                       // 每 3ms 最多算一遍
    uint64_t st = 0;
    if (!safe_read(g_base + 0x850e48, &st, 8)) return;
    if (st < 0x100000000ULL || st > 0x800000000ULL) return;
    if (st != last_st) {
        last_st = st;
        say_hex("完整性表 对象首次/变化=", st);
        uint64_t t0 = 0, b0 = 0;
        if (safe_read(st + 0x28, &b0, 8) && b0 > 0x100000000ULL && safe_read(b0, &t0, 8))
            say_hex("  首条目标=", t0);
    }
    if (!g_sha256) g_sha256 = (int (*)(const void *, unsigned int, unsigned char *))
        dlsym(RTLD_DEFAULT, "CC_SHA256");
    if (!g_sha256) return;
    uint64_t b = 0, e = 0;
    if (!safe_read(st + 0x28, &b, 8) || !safe_read(st + 0x30, &e, 8)) return;
    if (e < b || b < 0x100000000ULL) return;

    for (uint64_t i = 0; i < (e - b) / 0x28 && i < 32; i++) {
        uint64_t ent = b + i * 0x28;
        uint64_t addr = 0, obj = 0, len = 0, l2 = 0;
        if (!safe_read(ent, &addr, 8) || !safe_read(ent + 8, &obj, 8)) continue;
        safe_read(ent + 0x10, &len, 8);
        safe_read(ent + 0x18, &l2, 8);
        if (l2 != 32 || !obj || !len || len > 0x100000) continue;
        unsigned char *buf = (unsigned char *)malloc((size_t)len);
        unsigned char exp[32], dig[32];
        if (!buf) return;
        if (safe_read(addr, buf, (size_t)len) && safe_read(obj, exp, 32)) {
            g_sha256(buf, (unsigned int)len, dig);
            if (memcmp(dig, exp, 32) != 0) {
                // 期望块在堆上，直接写；写完回读确认，写不进去就如实报出来
                memcpy((void *)(uintptr_t)obj, dig, 32);
                unsigned char back[32];
                int ok = safe_read(obj, back, 32) && memcmp(back, dig, 32) == 0;
                say_hex("完整性表 第", i);
                say_hex("  目标=", addr);
                say_hex("  已把期望摘要改成实算值，写回成功=", (uint64_t)ok);
                g_fixint_done++;
            }
        }
        free(buf);
    }
}


// ---------------------------------------------------------------- 抓上报参数
//
// 0x40e7e4(reason, desc) 是盾所有"上报问题"的唯一出口：desc 为空时它直接走退出，
// desc 非空时只上报、继续跑。所以"哪一项检查失败、失败理由是什么"全在这里。
// 它不经过网关（普通 bl 调用），采样窗口又只有几条指令，只能挂钩子。
//
// 注意：改 0x40e7e4 会改到盾的 __text，而 __text 的 xxHash64 自检在 75-130ms 之间跑，
// 所以挂上之后自检必然失败。这次实验只为了拿到上报参数，接受这个副作用。
static void (*o_report)(uint64_t, const char *);
static int g_rp_n;

static void my_report(uint64_t reason, const char *desc) {
    if (g_rp_n < 24) {
        g_rp_n++;
        char buf[256];
        out_t o = { buf, buf + sizeof(buf) - 1 };
        o_s(&o, "上报 原因码="); o_h(&o, reason);
        o_s(&o, " 说明="); o_h(&o, (uint64_t)(uintptr_t)desc);
        o_ch(&o, '\n');
        emit_ts(buf, (size_t)(o.p - buf));
        if (desc) {
            char txt[129];
            if (safe_read((uint64_t)(uintptr_t)desc, txt, 128)) {
                txt[128] = 0;
                char line[200];
                out_t o2 = { line, line + sizeof(line) - 1 };
                o_s(&o2, "  文字=");
                for (int i = 0; i < 128 && txt[i]; i++) o_ch(&o2, txt[i]);
                o_ch(&o2, '\n');
                emit_ts(line, (size_t)(o2.p - line));
            }
        }
    }
    if (o_report) o_report(reason, desc);
}

static void install_report_hook(void) {
    if (!g_base || o_report) return;
    MSHookFunction((void *)(g_base + 0x40e7e4), (void *)my_report, (void **)&o_report);
    say_hex("已挂上报钩子 原函数=", (uint64_t)(uintptr_t)o_report);
}

static void *heartbeat(void *arg) {
    (void)arg;
    // 0.0.218：心跳在 40-70ms 之后不再输出。这里在最前面加一条完全独立的通路：
    // 不调任何取时间的函数，每一轮重新 open 一次文件再写。只要它还在增长，
    // 就说明线程本身没停，之前看到的"静默"是取时间或旧文件描述符的问题。
    {
        static char hbloop_path[256];
        static int hb_path_ready;
        static uint64_t hb_round;
        if (!hb_path_ready) {
            hb_path_ready = 1;
            const char *lb = g_logpath;
            size_t k = 0;
            while (lb[k] && k < sizeof(hbloop_path) - 12) { hbloop_path[k] = lb[k]; k++; }
            const char *suf = "-hb.bin";
            for (size_t j = 0; suf[j]; j++) hbloop_path[k++] = suf[j];
            hbloop_path[k] = 0;
        }
        if (hbloop_path[0]) {
            for (;;) {
                hb_round++;
                int fd = open(hbloop_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd >= 0) {
                    uint64_t r[2];
                    r[0] = 0x48422d4c4f4f5000ULL;   // 魔数 "HB-LOOP"
                    r[1] = hb_round;
                    raw_write((int)fd, r, sizeof(r));
                    close(fd);
                }
                __asm__ volatile("" ::: "memory");
                if (hb_round >= 200000) break;
            }
        }
    }
    // 36-62ms 每 0.2ms 采样：哈希阶段每张镜像只花 1-3ms，粗采样会整张漏掉。
    static int g_snap_at[200];
    static int g_snap_n;
    if (!g_snap_n) {
        // 现在要回答的问题变了：不再是"判定前后盾在干什么"，而是"界面为什么起不来"。
        // 所以快照点挪到几秒后，并且中间留出时间让主线程真正卡住。
        // 注意单位是 0.1 毫秒：下面比较时用的是 el*10。
        g_snap_at[g_snap_n++] = 30000;   // 3 秒
        g_snap_at[g_snap_n++] = 50000;   // 5 秒
    }
    int g_snap_i = 0;
    uint64_t last_hb = 0;
    for (;;) {
        if (g_probe_len && !g_probe_done) { g_probe_done = 1; dump_probe(); }
        // 0.0.193：0.0.192 的证据说明 cntpct_el0 在 ~110ms 之后不再前进——
        // 日志里最后几条的时间戳全停在同一个数，而线程明明还在跑（自检现场还在写）。
        // 于是 `el - last_hb >= 50` 永远不成立，心跳整体静默。
        // 心跳线程上 libc 已就绪，改用 clock_gettime 做时间基准。
        // 无条件用 clock_gettime：cntpct 一旦停滞，这个循环就会永久静默，
        // 而"看起来像进程已经死了"。心跳线程上 libc 早就就绪，这个调用是安全的。
        uint64_t el = g_t0 ? (up_ms() - g_t0) : 0;
        {
            static int said_cls;
            {
            // objc_getClassList 一次遍历会让盾在 456ms 直接 raise(SIGSEGV)，
            // 所以改成逐个按名字查——开销只有几次哈希，不碰全局类表。
            static int said_cls;
            if (!said_cls && el >= 400) {
                said_cls = 1;
                static const char *cand[] = {
                    "AppSecurityEvent","AppSecurityState","AppSecurityEventProvider",
                    "UntrustedBlockerConfiguration","JailbrokenStrategy","RASPManager",
                    "RASP","PromonShield","ShieldManager", NULL };
                for (int i = 0; cand[i]; i++) {
                    Class c = objc_getClass(cand[i]);
                    char lb[96];
                    out_t o = { lb, lb + sizeof(lb) - 1 };
                    o_s(&o, "类 "); o_s(&o, cand[i]); o_s(&o, c ? " 有" : " 无");
                    o_ch(&o, '\n');
                    emit_ts(lb, (size_t)(o.p - lb));
                }
            }
        }
        }
#if DO_DIENEXT
        // 盾在运行期会改写自己的代码（App 里带着 __ostekake 段）。所以"磁盘上
        // 0x5d848c 是 bl 0x774770"不能直接当成运行期事实：先把那一刻的字节打出来比。
        {
            static int said_mem;
            if (!said_mem && g_base && el >= 60) {
                said_mem = 1;
                dump_mem("内存 退出函数尾", g_base + 0x5d8470, 48);
                dump_mem("内存 下一站槽", g_base + 0x84c098, 8);
            }
        }
#endif
#if DO_CTRLEXIT
        if (!g_ctrl_done && el >= 700) {
            g_ctrl_done = 1;
            say_hex("对照：自己发裸 exit(7)，此刻时刻=", el);
            register long x16 __asm__("x16") = 1;
            register long x0  __asm__("x0")  = 7;
            __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
            say_hex("对照：exit 之后居然还能写日志，返回值=", (uint64_t)x0);
        }
#endif
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
        install_fake_checks();
#endif
#if DO_VTPATCH
        patch_verdict_vtables();
#endif
#if DO_SETFLAG
        // 这个位置整轮恒为 0，而紧接着就是"为 0 就往下走"的分支，最后落到原因码 4。
        // 之前只试过清零（方向反了）；如果它其实是"初始化完成"的标志，
        // 在判定之前写成非零就应该换一条路走。
        if (g_base && !g_setflag_done && el >= DO_SETFLAG_AT) {
            g_setflag_done = 1;
            volatile uint64_t *fl = (volatile uint64_t *)(g_base + 0x866fc8);
            uint64_t old = *fl;
            *fl = 1;
            say_hex("已把标志 +0x866fc8 由=", old);
            say_hex("                改为=", *fl);
        }
#endif
#if DO_FAKE
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
#if DO_SELFSCAN
        probe_selfcheck(el);
#endif
#if DO_TABLEPROBE
        probe_checks(el);
        probe_integrity(el);
        fix_integrity(el);
#endif
        patch_exit_after_selfcheck(el);
        // 0.0.193：0.0.189/0.191 在 20-130ms 窗口里一次都没撞到 0x40e7e4，
        // 说明真正的上报发生在 150ms 之后。窗口延长到 1 秒，150ms 以后降频。
#if DO_CATCH
        if (el >= 20 && el <= 1200) {
            static uint32_t g_cc_n;
            if (++g_cc_n < 400 || (g_cc_n % 8) == 0) catch_selfcheck();
        }
#endif
        if (g_write_err && g_logpath[0]) {
            int f = open(g_logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (f >= 0) { g_fd = f; g_write_err = 0; say("[日志描述符已重开]\n"); }
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
            o_s(&o, " 拦下映射="); o_d(&o, g_mmap_blocked);
#if DO_DIENEXT
            o_s(&o, " 转发="); o_d(&o, (long long)g_dn_hits);
            o_s(&o, " 改成返回="); o_d(&o, (long long)g_dn_fixed);
#endif
            o_s(&o, " 跳过返回="); o_h(&o, g_skip_ret);
            o_s(&o, " 见过kill="); o_d(&o, (long long)g_kill_seen);
            o_s(&o, " 退出函数="); o_d(&o, (long long)g_exitfn_hits);
            o_s(&o, " 判定调用="); o_d(&o, (long long)g_verdict_calls);
            o_s(&o, " fd="); o_d(&o, g_fd);
            o_s(&o, " 写错="); o_d(&o, g_write_err);
            o_s(&o, " 内存MB="); o_d(&o, (long long)(footprint_kb() / 1024));
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

// 0.0.208：退出探针。
//
// 之前所有观测都死在 40ms 左右：心跳线程、排空线程、定时器信号同时静默，
// 而进程要到 500 多毫秒才结束。唯一能在盾自己的线程上跑起来的代码，
// 是打进去的补丁本身。所以把退出函数 0x5d842c 的入口改成一条跳转，
// 跳到下面这个探针：它先把调用者的返回地址、原因码、说明指针和帧指针
// 原样写进 gw.bin，再执行真正的 exit(1)。这样 40–500ms 那段就有了唯一的观测点。
__attribute__((noinline, used)) void exit_probe_log(uint64_t *f) {
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x4558495400000001ULL;   // 魔数 "EXIT"
    r[1] = f[11];                   // 调用者返回地址（x30 存在 #0x58）
    r[2] = f[0];                    // x0（原因码）
    r[3] = f[1];                    // x1（说明文字指针）
    r[4] = f[9];                    // x29（帧指针）
    r[5] = (uint64_t)g_base;
    raw_write(g_gwfd, r, sizeof(r));
    // 顺着帧链再往上走几层，每层记返回地址，够看清是谁发起的退出。
    uint64_t fp = f[9];
    for (int i = 0; i < 6 && fp; i++) {
        uint64_t *p = (uint64_t *)(uintptr_t)fp;
        uint64_t nfp = 0, lr = 0;
        if (!safe_read((uint64_t)(uintptr_t)p, &nfp, 8)) break;
        if (!safe_read((uint64_t)(uintptr_t)p + 8, &lr, 8)) break;
        uint64_t q[6];
        q[0] = 0x4558495400000002ULL;
        q[1] = (uint64_t)(i + 1);
        q[2] = lr;
        q[3] = nfp;
        q[4] = 0; q[5] = (uint64_t)g_base;
        raw_write(g_gwfd, q, sizeof(q));
        if (nfp <= fp) break;
        fp = nfp;
    }
}

__attribute__((naked)) static void exit_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x80\n"
        "stp x0, x1, [sp, #0x00]\n"
        "stp x2, x3, [sp, #0x10]\n"
        "stp x4, x5, [sp, #0x20]\n"
        "stp x6, x7, [sp, #0x30]\n"
        "stp x8, x9, [sp, #0x40]\n"
        "str x10,     [sp, #0x50]\n"
        "str x29,     [sp, #0x48]\n"
        "str x30,     [sp, #0x58]\n"
        "mov x0, sp\n"
        "bl _exit_probe_log\n"
        // 0.0.225：诊断用——记录之后原地停住，而不是真的退出。
        // 这样"谁想杀进程"会被钉在这里，我们能把这次的完整调用链拿到手。
        "1:\n"
        "wfe\n"
        "b 1b\n"
    );
}

// 把 0x5d842c 的头 12 字节改写成 ldr x16,#8; br x16; .quad 探针地址。
static int install_exit_probe(void) {
    if (!g_base) return 0;
    uintptr_t addr = g_base + 0x5d842cULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x8000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("退出探针：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;                        // ldr x16, #8
    w[1] = 0xd61f0200;                        // br  x16
    *lit = (uint64_t)(uintptr_t)&exit_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x8000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("退出探针：已装到 ", addr);
    say_hex("  探针地址=", (uint64_t)(uintptr_t)&exit_stub);
    return 1;
}

// 0.0.213：上报函数探针。
//
// 之前只知道"某次上报没带说明文字就退出"，看不到到底上报了几次、每次的原因码
// 和说明是什么。0x40e7e4 是唯一的上报出口，在它入口插一个记录桩：
// 把原因码、说明文字前 96 字节、以及调用者返回地址写进 gw.bin，然后原样继续执行。
//
// 桩必须把被替换掉的四条序言指令重放一遍（sub sp / 三次 stp），再跳到原函数
// 第 5 条指令，所以函数行为完全不变，只是多了一条记录。
static uint64_t g_report_resume;

__attribute__((used)) static void report_probe_log(uint64_t reason, const char *desc, uint64_t caller) {
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x5245505200000001ULL;   // 魔数 "REPR"
    r[1] = reason & 0xffffffffULL;
    r[2] = caller;
    r[3] = (uint64_t)(uintptr_t)desc;
    // 说明文字前 8 个字节原样带走，够看出是不是空串、以及前缀是什么。
    uint64_t head = 0;
    if (desc && safe_read((uint64_t)(uintptr_t)desc, &head, 8)) { }
    r[4] = head;
    // 顺便看一眼 SIGILL 的处置函数还是不是我们自己装的那个。
    // 盾是防调试库，重新装信号处理器是它的常规操作；若是被换掉，
    // 那故障信号就永远到不了我们的处理函数。
    // 0.0.220：既然盾会换掉处理函数，那就在它换完之后再装回来。
    // 这个函数跑在盾自己的线程上，不受我们线程被停住的影响，时机正好。
    struct sigaction cur;
    memset(&cur, 0, sizeof(cur));
    if (sigaction(SIGILL, NULL, &cur) == 0)
        r[5] = (uint64_t)(uintptr_t)cur.__sigaction_u.__sa_sigaction;
    else
        r[5] = 0;
    raw_write(g_gwfd, r, sizeof(r));
    extern void arm_fault_probe(void);
    arm_fault_probe();
}

__attribute__((naked)) static void report_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x100\n"
        "stp x0, x1, [sp, #0x00]\n"
        "stp x2, x3, [sp, #0x10]\n"
        "stp x4, x5, [sp, #0x20]\n"
        "stp x6, x7, [sp, #0x30]\n"
        "stp x8, x9, [sp, #0x40]\n"
        "stp x10, x11, [sp, #0x50]\n"
        "stp x12, x13, [sp, #0x60]\n"
        "stp x14, x15, [sp, #0x70]\n"
        "stp x16, x17, [sp, #0x80]\n"
        "stp x18, x19, [sp, #0x90]\n"
        "stp x20, x21, [sp, #0xa0]\n"
        "stp x22, x23, [sp, #0xb0]\n"
        "stp x24, x25, [sp, #0xc0]\n"
        "stp x26, x27, [sp, #0xd0]\n"
        "stp x28, x29, [sp, #0xe0]\n"
        "str x30,      [sp, #0xf0]\n"
        "ldr x0, [sp, #0x00]\n"
        "ldr x1, [sp, #0x08]\n"
        "ldr x2, [sp, #0xf0]\n"
        "bl _report_probe_log\n"
        "ldr x30,      [sp, #0xf0]\n"
        "ldp x28, x29, [sp, #0xe0]\n"
        "ldp x26, x27, [sp, #0xd0]\n"
        "ldp x24, x25, [sp, #0xc0]\n"
        "ldp x22, x23, [sp, #0xb0]\n"
        "ldp x20, x21, [sp, #0xa0]\n"
        "ldp x18, x19, [sp, #0x90]\n"
        "ldp x16, x17, [sp, #0x80]\n"
        "ldp x14, x15, [sp, #0x70]\n"
        "ldp x12, x13, [sp, #0x60]\n"
        "ldp x10, x11, [sp, #0x50]\n"
        "ldp x8,  x9,  [sp, #0x40]\n"
        "ldp x6,  x7,  [sp, #0x30]\n"
        "ldp x4,  x5,  [sp, #0x20]\n"
        "ldp x2,  x3,  [sp, #0x10]\n"
        "ldp x0,  x1,  [sp, #0x00]\n"
        "add sp, sp, #0x100\n"
        // 被替换掉的原序言，原样重放
        "sub sp, sp, #0x80\n"
        "stp x22, x21, [sp, #0x50]\n"
        "stp x20, x19, [sp, #0x60]\n"
        "stp x29, x30, [sp, #0x70]\n"
        "adrp x16, _g_report_resume@PAGE\n"
        "ldr x16, [x16, _g_report_resume@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_report_probe(void) {
    if (!g_base) return 0;
    g_report_resume = g_base + 0x40e7f4ULL;   // 原函数第 5 条指令 add x29, sp, #0x70
    uintptr_t addr = g_base + 0x40e7e4ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x8000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("上报探针：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;                        // ldr x16, #8
    w[1] = 0xd61f0200;                        // br  x16
    *lit = (uint64_t)(uintptr_t)&report_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x8000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("上报探针：已装到 ", addr);
    say_hex("  续行地址=", g_report_resume);
    return 1;
}

// 0.0.215：把退出跳过去之后，进程改在 ~613ms 死于 SIGILL。非法指令在用户态
// 只有几种来源：故意写进去的 brk/未定义指令、被关掉使能位的 mrs cntpct_el0、
// 或者我们自己的补丁写坏了。装一个故障处理函数，把出事那一刻的 pc/lr/sp
// 和故障地址原样记下来，一次性看清是哪一种。
// 0.0.244：退出函数 0x5d842c 换成"守护桩"。
// 它做两件事再原样返回：把调用者记下来；把我们的故障处理器重新装一遍。
// 后者是关键——盾可能在 40ms 之后用自己的裸系统调用把处理器换掉，
// 而我们的线程那时已经停了，没有别的机会再装一次。
#define DO_EXITFN_GUARD 1
static volatile uint64_t g_guard_hits;

// 0.0.251：0.0.250 证明上报那一刻 SIGILL 的处置函数还是我们的，可致命的那次
// 依然没进来。先弄清楚一件事：这个时刻新建的线程还跑不跑。如果跑，我们就有了
// 一个能在最后 200ms 里持续重装处理器的位置；如果不跑，问题就不在处理器上，
// 而在信号的投递层（线程掩码或异常端口）。
static void *late_guard_thread(void *arg) {
    (void)arg;
    if (g_gwfd >= 0) {
        uint64_t r[6] = { 0x4C41544500000009ULL, 0xFFFFFFFFULL, 0, 0, 0,
                          (uint64_t)g_base };
        raw_write(g_gwfd, r, sizeof(r));
    }
    // 0.0.254：带上时刻，并把循环拉长。要看的是"它到底在哪一刻停住"，
    // 以及停住之后还会不会恢复。
    for (int i = 0; i < 4000; i++) {
        arm_fault_probe();
        if (g_gwfd >= 0) {
            uint64_t r[6] = { 0x4C41544500000001ULL, (uint64_t)i, up_ms() - g_t0,
                              (uint64_t)(uintptr_t)pthread_self(), 0,
                              (uint64_t)g_base };
            raw_write(g_gwfd, r, sizeof(r));
        }
        usleep(2000);
    }
    return NULL;
}

static void usr1_probe(int sig, siginfo_t *si, void *ucv) {
    (void)si; (void)ucv;
    if (g_gwfd >= 0) {
        uint64_t r[6] = { 0x5553315000000001ULL, (uint64_t)sig, 0, 0,
                          g_guard_hits, (uint64_t)g_base };
        raw_write(g_gwfd, r, sizeof(r));
    }
}

__attribute__((noinline, used)) void exitfn_guard(uint64_t reason, uint64_t desc, uint64_t caller) {
    g_guard_hits = g_guard_hits + 1;
    if (g_gwfd >= 0) {
        uint64_t r[6] = { 0x4558495400000011ULL, caller, reason, desc,
                          (uint64_t)g_guard_hits, (uint64_t)g_base };
        raw_write(g_gwfd, r, sizeof(r));
    }
    arm_fault_probe();
    {
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
    }
    // 0.0.245：自检。此刻发一个 SIGUSR1 给自己，看装上去的处理器到底还在不在。
    // 在的话会写一条 USR1 记录；不在的话进程应该当场被 SIGUSR1 结束——而我们现在
    // 看到的是活到了 SIGILL，说明这里的处理器是被盾用它自己的裸系统调用换掉的。
    if (0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = usr1_probe;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
        raise(SIGUSR1);
        if (g_gwfd >= 0) {
            uint64_t r[6] = { 0x5553315000000002ULL, 0, 0, 0, 0, (uint64_t)g_base };
            raw_write(g_gwfd, r, sizeof(r));
        }
        // SIGUSR1 能送到，只证明普通信号这条路通。SIGILL 是硬件异常，
        // 内核走的是另一条路，这里单独试一次：执行一条 udf，看处理器会不会
        // 把 pc 往后挪一格让我们继续。
        __asm__ volatile("udf #0" ::: "memory");
        if (g_gwfd >= 0) {
            uint64_t r[6] = { 0x5544463000000001ULL, 0, 0, 0, 0, (uint64_t)g_base };
            raw_write(g_gwfd, r, sizeof(r));
        }
    }
    // 0.0.253：0.0.251 那次替换没匹配上，线程根本没创建，"晚建线程不跑"作废。
    // 这里真正起一个：记录创建返回码，然后立刻写一条心跳，再每 2ms 写一条。
    if (0) {
        static int started_lt;
        if (!started_lt) {
            started_lt = 1;
            pthread_t t;
            int rc = pthread_create(&t, NULL, late_guard_thread, NULL);
            if (g_gwfd >= 0) {
                uint64_t r[6] = { 0x4C43524500000001ULL, (uint64_t)(int64_t)rc,
                                  (uint64_t)(uintptr_t)t, up_ms() - g_t0, 0,
                                  (uint64_t)g_base };
                raw_write(g_gwfd, r, sizeof(r));
            }
        }
    }
    // 0.0.247：第二次退出调用处停 300ms，每 10ms 写一条心跳。
    // 如果进程在这 300ms 里就没了，说明凶手是另一条线程，与"退出调用返回之后
    // 继续往下走"无关；如果心跳写满 300ms、进程在返回之后才死，那问题就在续行路径上。
    // 0.0.248：0.0.247 证明致命 SIGILL 发生在退出调用返回之后，也就是续行路径上。
    // 那就把调用栈抓出来，好顺着去找那一层的 udf。
    if (0) {
        uint64_t fp = (uint64_t)(uintptr_t)__builtin_frame_address(0);
        for (int i = 0; i < 14 && fp; i++) {
            uint64_t nfp = 0, lr = 0;
            if (!safe_read(fp, &nfp, 8)) break;
            if (!safe_read(fp + 8, &lr, 8)) break;
            if (g_gwfd >= 0) {
                uint64_t r[6] = { 0x4652414d00000001ULL, (uint64_t)g_guard_hits,
                                  (uint64_t)(i + 1), lr, fp, (uint64_t)g_base };
                raw_write(g_gwfd, r, sizeof(r));
            }
            if (nfp <= fp) break;
            fp = nfp;
        }
    }
}

__attribute__((naked)) static void exitfn_guard_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x20\n"
        "stp x29, x30, [sp, #0x10]\n"
        "stp x0,  x1,  [sp, #0x00]\n"
        "mov x2, x30\n"
        "bl _exitfn_guard\n"
        "ldp x0,  x1,  [sp, #0x00]\n"
        "ldp x29, x30, [sp, #0x10]\n"
        "add sp, sp, #0x20\n"
        "ret\n"
    );
}

static int install_exitfn_guard(void) {
    if (!g_base) return 0;
    uintptr_t addr = g_base + 0x5d842cULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("退出守护：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&exitfn_guard_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("退出守护：已装到 ", addr);
    return 1;
}

// 0.0.249：看清"原因码 5 是哪个检查对象报的"。
//
// 离线把 0x712668 的比较树摊平之后，只有一条路通向 0x7133d0：
//   状态 == 0x1c4ee66b  →  0x7133d0
// 而进入这个状态的是 0x713348，它前面（0x71332c）刚从对象 [sp+0x48] 的虚表里
// 取出一项存进 [sp+0x90]。也就是说，这里做的是"调一个检查对象的方法，拿到说明，
// 然后上报原因码 5"。说明文字为空就是致命，非空只上报。
//
// 在 0x7133d0 开头插桩，把这四件事记下来：对象指针、虚表项、说明指针、
// 以及两者开头几十个字节。这四行指令正好 16 字节，续行点 0x7133e0
// （mov w0,#5）完好，桩里原样重放即可。
#define DO_VM_DESC_LOG 1
static uint64_t g_vm_join;
static volatile uint64_t g_vm_hits;

static void vm_rec(uint64_t kind, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x564D524500000000ULL | (kind & 0xff);   // 魔数 "VMRE"
    r[1] = a; r[2] = b; r[3] = c; r[4] = d; r[5] = (uint64_t)g_base;
    raw_write(g_gwfd, r, sizeof(r));
}

static void dump_got(void);
void vm_state_log(uint32_t st);

__attribute__((noinline, used)) void vm_report_log(uint64_t obj, uint64_t fn) {
    // 0.0.258：构造函数里读这些槽太早，那时还是密文。探针在 71ms 才跑，
    // 那时 GOT 已经被填好，重新读一次才能反解出真实符号。
    { static int once; if (!once) { once = 1; dump_got(); } }
    g_vm_hits = g_vm_hits + 1;
    uint64_t vt = 0;
    safe_read(obj, &vt, 8);
    vm_rec(1, obj, fn, vt, g_vm_hits);
    // 0.0.252：多打一些。上一版只看到前 8 个字（大多是 0），
    // 而 +0x18=0x19a40a000、+0x20=0x69ecee1e 这两个不像 0 的值没对上用途。
    for (int i = 0; i < 40; i++) {
        uint64_t w = 0;
        if (!safe_read(obj + (uint64_t)i * 8, &w, 8)) break;
        vm_rec(0x11, (uint64_t)i, w, obj, 0);
    }
}

__attribute__((noinline, used)) void vm_desc_log(uint64_t desc) {
    vm_rec(2, desc, 0, 0, 0);
    if (!desc) return;
    for (int i = 0; i < 6; i++) {
        uint64_t w = 0;
        if (!safe_read(desc + (uint64_t)i * 8, &w, 8)) break;
        vm_rec(0x12, (uint64_t)i, w, desc, 0);
    }
}

__attribute__((naked)) static void vm_desc_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x60\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x2,  x3,  [sp, #0x20]\n"
        "stp x8,  x9,  [sp, #0x30]\n"
        "str x10,      [sp, #0x40]\n"
        "add x10, sp, #0x60\n"          // 原始的 sp
        "ldr x0, [x10, #0x48]\n"        // 检查对象
        "ldr x1, [x10, #0x90]\n"        // 虚表项
        "bl _vm_report_log\n"
        "ldr x10,      [sp, #0x40]\n"
        "ldp x8,  x9,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x60\n"
        // 重放被覆盖的四条
        "ldr x0, [sp, #0x48]\n"
        "ldr x8, [sp, #0x90]\n"
        "blr x8\n"                      // → x0 = 说明文字
        "sub sp, sp, #0x20\n"
        "stp x0, x1, [sp, #0x00]\n"
        "bl _vm_desc_log\n"
        "ldp x0, x1, [sp, #0x00]\n"
        "add sp, sp, #0x20\n"
        "mov x1, x0\n"
        "adrp x16, _g_vm_join@PAGE\n"
        "ldr x16, [x16, _g_vm_join@PAGEOFF]\n"
        "br x16\n"
    );
}

// 0.0.255：把虚拟机的分派器插上桩。
//
// 141ms 上报原因码 5、两次退出调用被挡下，然后进程又活了 1.1 秒才死于 SIGILL。
// 那一秒里盾在干什么，只有它自己的线程知道——而分派器 0x7126e4 正是所有状态
// 的必经之路。把每次跳转的状态值记下来，事后用离线摊平的分派器还原成代码块序列，
// 就能看到最后一刀是从哪个状态发出的。
//
// 0x7126e4 起被覆盖的四条是：
//   7126e4  mov x9, x8
//   7126e8  cmp w8, w25
//   7126ec  b.gt 0x712788
//   7126f0  mov w8, #0x12ec
// 桩里按分支结果分别重放到 0x7126f4 或 0x712788。
#define DO_VM_STATE_LOG 1
uint64_t g_vm_gt, g_vm_fall;   // 只在桩的内联汇编里引用，必须非 static
static volatile uint64_t g_vm_states;
#define VM_STATE_CAP 60000

__attribute__((noinline, used)) void vm_state_log2(uint32_t st, uint64_t ra) {
    uint64_t n = g_vm_states;
    if (n == 0 && g_gwfd >= 0) {
        uint64_t r[6] = { 0x564D434100000001ULL, ra, 0, up_ms() - g_t0, 0,
                          (uint64_t)g_base };
        raw_write(g_gwfd, r, sizeof(r));
    }
    vm_state_log(st);
}

__attribute__((noinline, used)) void vm_state_log(uint32_t st) {
    uint64_t n = g_vm_states;
    if (n >= VM_STATE_CAP) return;
    g_vm_states = n + 1;
    if (g_gwfd < 0) return;
    uint64_t r[6];
    r[0] = 0x564D535400000001ULL;    // 魔数 "VMST"
    r[1] = n;
    r[2] = (uint64_t)st;
    r[3] = up_ms() - g_t0;
    r[4] = 0;
    r[5] = (uint64_t)g_base;
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((naked)) static void vm_state_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x8,  x9,  [sp, #0x20]\n"
        "mov w0, w8\n"
        "mov x1, x30\n"
        "bl _vm_state_log2\n"
        "ldp x8,  x9,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "mov x9, x8\n"
        "cmp w8, w25\n"
        "b.le 1f\n"
        "adrp x16, _g_vm_gt@PAGE\n"
        "ldr x16, [x16, _g_vm_gt@PAGEOFF]\n"
        "br x16\n"
        "1:\n"
        "mov w8, #0x12ec\n"
        "adrp x16, _g_vm_fall@PAGE\n"
        "ldr x16, [x16, _g_vm_fall@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_vm_state_probe(void) {
    if (!g_base) return 0;
    g_vm_gt   = g_base + 0x712788ULL;
    g_vm_fall = g_base + 0x7126f4ULL;
    uintptr_t addr = g_base + 0x7126e4ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("分派桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&vm_state_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("分派桩：已装到 ", addr);
    return 1;
}

// 0.0.256：0x774xxx 这一片是盾的导入桩，静态反汇编里没有。
// 虚拟机在几处检查里正是通过它们调外部函数（0x774f68 / 0x774ec0 / 0x774f74），
// 而它们的真实去向只有运行期才看得到。把桩的头几条指令打出来，
// 就能读出它用的是 0x84c000 那张表里的哪一格。
static void dump_thunks(void) {
    static const uint32_t offs[] = {
        0x774770, 0x774638, 0x774644, 0x774650, 0x774dd0, 0x774d58,
        0x774db8, 0x774ec0, 0x774f60, 0x774f68, 0x774f74, 0x774f88,
    };
    if (!g_base || g_gwfd < 0) return;
    for (unsigned i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
        const volatile uint32_t *p = (const volatile uint32_t *)(g_base + offs[i]);
        uint64_t r[6];
        r[0] = 0x54484E4B00000001ULL;    // 魔数 "THNK"
        r[1] = offs[i];
        r[2] = p[0]; r[3] = p[1]; r[4] = p[2]; r[5] = p[3];
        raw_write(g_gwfd, r, sizeof(r));
    }
}

// 0.0.257：把上面这些桩在运行期用的 GOT 槽读出来，再用 dladdr 反解符号名。
// 静态文件里这些槽还是待绑定的占位值，只有进程起来之后才看得出真实去向。
static const uint32_t g_got_slots[] = {
    0x84c098, 0x80c2f8, 0x80c300, 0x80c308, 0x84c948,
    0x84c8a8, 0x84c700, 0x84c768, 0x84c580, 0x84c8f0,
    // 0.0.264：0x713720 内部调的三个桩，静态绑定表里查不到，只能运行期解。
    0x84c000, 0x84bf88, 0x84c020,
};

static void dump_got(void) {
    if (!g_base || g_gwfd < 0) return;
    for (unsigned i = 0; i < sizeof(g_got_slots) / sizeof(g_got_slots[0]); i++) {
        uint64_t p = 0;
        if (!safe_read(g_base + g_got_slots[i], &p, 8)) continue;
        uint64_t n0 = 0, n1 = 0;
        Dl_info di;
        for (unsigned k = 0; k < sizeof(di); k++) ((char *)&di)[k] = 0;
        if (p && dladdr((void *)(uintptr_t)p, &di) && di.dli_sname) {
            const char *nm = di.dli_sname;
            for (int k = 0; k < 8 && nm[k]; k++) n0 |= ((uint64_t)(unsigned char)nm[k]) << (8 * k);
            for (int k = 0; k < 8 && nm[8 + k]; k++) n1 |= ((uint64_t)(unsigned char)nm[8 + k]) << (8 * k);
        }
        uint64_t r[6];
        r[0] = 0x474F545300000001ULL;    // 魔数 "GOTS"
        r[1] = g_got_slots[i];
        r[2] = p;
        r[3] = n0; r[4] = n1; r[5] = (uint64_t)g_base;
        raw_write(g_gwfd, r, sizeof(r));
    }
}

// 0.0.259：顺着"上报链"往上追。
//
// 0x712668 是事件的上报通道（互斥量、条件变量、属性读写），不是检测。
// 真正干活的是 0x5d8758 传进去的回调 0x5d883c：
//   5d888c  bl 0x5d8ed0    ← 检查表执行器
//   5d8894  bl 0x6adf2c    ← 取一个对象
//   5d88d0  blr x8         ← 虚表调用，疑似真正的检查
// 这一版在三个点插桩，一次看清谁被调用、调到了哪里。
#define DO_CHAIN_LOG 1
// 0.0.261：离线摊平之后发现，"0x713720 返回 0"会让虚拟机当场结束，
// 返回非零才一路走到原因码 5。把那次 csel 抹掉，等于固定走成功出口。
#define DO_VM_FORCE_OK 0
// 0.0.263：上一版只是把分派结果改成"w0 为零"那条，w0 本身仍是非零。
// 这一版直接让 0x713720 返回 0，配合它真实被调用时的上下文再看一次。
#define DO_GATE_RET_ZERO 0
// 0.0.264：不改行为，只记录 0x713720 的返回值，并解出它内部调的三个桩。
#define DO_GATE713720_PROBE 1
// 0.0.266：记录 0x713720 里那次 open 的路径与标志。
#define DO_OPEN_PATH_LOG 1
// 0.0.267：记录 0x713720 里那次 open 的返回值。
#define DO_FD_LOG 1
// 0.0.269：记录 0x713720 里那次 4 字节 read 的参数与结果。
#define DO_READ_LOG 1
// 0.0.270：记录 0x713720 自己的状态跳转。
#define DO_VM2_LOG 1
#define OFF_GATE713720 0x713720ULL
#define OFF_VM_CSEL 0x712e10ULL
uint64_t g_ch_cb, g_ch_ct, g_ch_vt;
static volatile uint64_t g_cb_n, g_ct_n, g_chvt_n;

static void chain_rec(uint64_t tag, uint64_t a, uint64_t b) {
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x4348414900000000ULL | (tag & 0xff), a, b,
                      up_ms() - g_t0, 0, (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((noinline, used)) void ch_cb_log(uint64_t x19) { g_cb_n++; chain_rec(1, x19, g_cb_n); }
__attribute__((noinline, used)) void ch_ct_log(uint64_t x0)  { g_ct_n++; chain_rec(2, x0, g_ct_n); }
__attribute__((noinline, used)) void ch_vt_log(uint64_t target, uint64_t self, uint64_t idx) {
    g_chvt_n++; chain_rec(3, target, self); chain_rec(4, idx, g_chvt_n);
}

__attribute__((naked)) static void ch_cb_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "mov x0, x8\n"
        "bl _ch_cb_log\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "sub sp, sp, #0x80\n"
        "stp x26, x25, [sp, #0x30]\n"
        "stp x24, x23, [sp, #0x40]\n"
        "stp x22, x21, [sp, #0x50]\n"
        "adrp x16, _g_ch_cb@PAGE\n"
        "ldr x16, [x16, _g_ch_cb@PAGEOFF]\n"
        "br x16\n"
    );
}

__attribute__((naked)) static void ch_ct_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "bl _ch_ct_log\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "sub sp, sp, #0x40\n"
        "stp x20, x19, [sp, #0x20]\n"
        "stp x29, x30, [sp, #0x30]\n"
        "adrp x16, _g_ch_ct@PAGE\n"
        "ldr x16, [x16, _g_ch_ct@PAGEOFF]\n"
        "br x16\n"
    );
}

__attribute__((naked)) static void ch_vt_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x60\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x8,  x9,  [sp, #0x20]\n"
        "str x22,      [sp, #0x30]\n"
        "mov x0, x8\n"                 // 目标
        "mov x1, x22\n"                // 对象
        "ldr x2, [sp, #0x30]\n"
        "bl _ch_vt_log\n"
        "ldp x8,  x9,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x60\n"
        "blr x8\n"
        "adrp x16, _g_ch_vt@PAGE\n"
        "ldr x16, [x16, _g_ch_vt@PAGEOFF]\n"
        "br x16\n"
    );
}

static void patch_entry_stub(uintptr_t addr, void *stub) {
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("链接探针：改页失败 kr=", (unsigned long long)kr); return; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
}

// 0.0.264：记录 0x713720 的返回值。
//
// 虚拟机第一次分派（0x712dcc）构造完事件之后调 0x713720，然后按返回值分叉：
// 返回非零走 0x564fec1b（最终到原因码 5），返回 0 走 0x07480f1e。
// 把每个分支的目标放进全局，避开 ±128MB 的分支范围。
uint64_t g_g713720_gt, g_g713720_eq;
static volatile uint64_t g_g713720_n;

__attribute__((noinline, used)) void gate713720_log(uint64_t v) {
    // 0.0.265：构造函数里读 GOT 太早（还是密文），挪到这里——此刻 71ms，已经填好。
    { static int once; if (!once) { once = 1; dump_got(); dump_thunks(); } }
    g_g713720_n++;
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x4737313300000001ULL, v, g_g713720_n, up_ms() - g_t0, 0,
                      (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((naked)) static void gate713720_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x8,  x9,  [sp, #0x20]\n"
        "mov x0, x0\n"
        "bl _gate713720_log\n"
        "ldp x8,  x9,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "cmp w0, #0x0\n"
        "adrp x16, _g_g713720_eq@PAGE\n"
        "ldr x16, [x16, _g_g713720_eq@PAGEOFF]\n"
        "adrp x17, _g_g713720_gt@PAGE\n"
        "ldr x17, [x17, _g_g713720_gt@PAGEOFF]\n"
        "csel x16, x17, x16, ne\n"
        "br x16\n"
    );
}

static int install_gate713720_probe(void) {
    if (!g_base) return 0;
    g_g713720_eq = g_base + 0x712e00ULL;   // w0 == 0：成功分支
    g_g713720_gt = g_base + 0x712e08ULL;   // w0 != 0：失败分支
    uintptr_t addr = g_base + 0x712dfcULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("71桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&gate713720_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("71桩：已装到 ", addr);
    return 1;
}

// 0.0.266：0x713720 读文件失败，是原因码 5 的源头。
//
// 它先用 0x2f5fbc / 0x94580 拼出一个路径字符串，再调 0x693aa0（open 封装，
// 只认 x0=路径、w1=标志），返回负值就切到失败状态。这里把路径和标志记下来，
// 就知道它到底要打开什么。
uint64_t g_open_resume;
static volatile uint64_t g_open_n;

__attribute__((noinline, used)) void open_path_log(uint64_t str, uint64_t flags) {
    g_open_n++;
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x4F50454E00000001ULL, str, flags, g_open_n,
                      up_ms() - g_t0, (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
    if (!str) return;
    for (int i = 0; i < 5; i++) {
        uint64_t w = 0;
        if (!safe_read(str + (uint64_t)i * 8, &w, 8)) break;
        uint64_t q[6] = { 0x4F50454E00000002ULL, (uint64_t)i, w, 0, 0, (uint64_t)g_base };
        raw_write(g_gwfd, q, sizeof(q));
    }
}

__attribute__((naked)) static void open_path_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x60\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x2,  x3,  [sp, #0x20]\n"
        "stp x8,  x9,  [sp, #0x30]\n"
        "str x10,      [sp, #0x40]\n"
        "bl  _open_path_log\n"
        // 参数原样还原后再记录
        "ldp x8,  x9,  [sp, #0x30]\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x10, x11, [sp, #0x10]\n"
        "mov x1, x11\n"
        "mov x0, x10\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x60\n"
        // 重放被覆盖的四条序言
        "sub sp, sp, #0x30\n"
        "stp x29, x30, [sp, #0x20]\n"
        "add x29, sp, #0x20\n"
        "stur x0, [x29, #-0x8]\n"
        "adrp x16, _g_open_resume@PAGE\n"
        "ldr x16, [x16, _g_open_resume@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_open_path_probe(void) {
    if (!g_base) return 0;
    g_open_resume = g_base + 0x693ab0ULL;   // stur w1,[x29,#-0xc]
    uintptr_t addr = g_base + 0x693aa0ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("开文件桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&open_path_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("开文件桩：已装到 ", addr);
    return 1;
}

// 0.0.267：0.693aa0 是整个盾共用的 open 封装，抓到的 16 次不全来自
// 0x713720。0x7138a0（"mov x20, x0"）只在 0x713720 的这条路上执行，
// 在那里记 x0，就是这次 open 的返回值：非负是 fd，负数是 errno 取反。
uint64_t g_fd_resume;
static volatile uint64_t g_fd_n;

__attribute__((noinline, used)) void fd_log(uint64_t fd) {
    g_fd_n++;
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x4644524554000001ULL, fd, g_fd_n, up_ms() - g_t0, 0,
                      (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((naked)) static void fd_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "stp x2,  x3,  [sp, #0x20]\n"
        "bl _fd_log\n"
        "ldp x2,  x3,  [sp, #0x20]\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "mov x20, x0\n"
        "adrp x16, _g_fd_resume@PAGE\n"
        "ldr x16, [x16, _g_fd_resume@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_fd_probe(void) {
    if (!g_base) return 0;
    g_fd_resume = g_base + 0x7138a4ULL;
    uintptr_t addr = g_base + 0x7138a0ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("fd桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&fd_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("fd桩：已装到 ", addr);
    return 1;
}

// 0.0.269：0x713720 里唯一一次 read 在 0x713904：
//   mov x0, x20     ; fd
//   ldr x1, [sp]    ; 缓冲区
//   mov w2, #0x4    ; 长度 4
//   bl  read
//   cmp x0, #0x4    ; 必须刚好读到 4 字节
// 在它前面插桩，把 fd / 缓冲区 / 长度、以及读回来的字节都记下来。
uint64_t g_read_target, g_read_resume;
static volatile uint64_t g_read_n;

__attribute__((noinline, used)) void rd_log(uint64_t fd, uint64_t buf, uint64_t len) {
    g_read_n++;
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x5245414400000001ULL, fd, buf, len, g_read_n, (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((noinline, used)) void rd_ret_log(uint64_t ret, uint64_t buf) {
    if (g_gwfd < 0) return;
    uint32_t head = 0;
    safe_read(buf, &head, 4);
    uint64_t r[6] = { 0x5245414400000002ULL, ret, (uint64_t)head, buf, g_read_n,
                      (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((naked)) static void rd_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x50\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x0,  x1,  [sp, #0x10]\n"
        "str x2,       [sp, #0x20]\n"
        "bl _rd_log\n"
        "ldp x0,  x1,  [sp, #0x10]\n"
        "ldr x2,       [sp, #0x20]\n"
        "adrp x16, _g_read_target@PAGE\n"
        "ldr x16, [x16, _g_read_target@PAGEOFF]\n"
        "blr x16\n"
        "str x0, [sp, #0x28]\n"
        "mov x9, x0\n"
        "ldr x1, [sp, #0x18]\n"
        "mov x0, x9\n"
        "bl _rd_ret_log\n"
        "ldr x0, [sp, #0x28]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x50\n"
        "adrp x16, _g_read_resume@PAGE\n"
        "ldr x16, [x16, _g_read_resume@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_read_probe(void) {
    if (!g_base) return 0;
    g_read_target = g_base + 0x4365d4ULL;   // read 的裸系统调用封装
    g_read_resume = g_base + 0x713908ULL;   // cmp x0, #0x4
    uintptr_t addr = g_base + 0x713904ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("读桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&rd_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("读桩：已装到 ", addr);
    return 1;
}

// 0.0.270：0x713720 自己也是状态机，入口在 0x71378c：
//   71378c: mov x8, x9
//   713790: cmp w9, w24
//   713794: b.le 0x7137e0
// 给它装上分派桩，看它卡在哪个状态——那 800 毫秒究竟花在什么上面。
uint64_t g_vm2_le, g_vm2_gt;
static volatile uint64_t g_vm2_n;
#define VM2_CAP 20000

__attribute__((noinline, used)) void vm2_state_log(uint32_t st) {
    uint64_t n = g_vm2_n;
    if (n >= VM2_CAP) return;
    g_vm2_n = n + 1;
    if (g_gwfd < 0) return;
    uint64_t r[6] = { 0x564D325300000001ULL, (uint64_t)st, n, up_ms() - g_t0, 0,
                      (uint64_t)g_base };
    raw_write(g_gwfd, r, sizeof(r));
}

__attribute__((naked)) static void vm2_stub(void) {
    __asm__ volatile(
        "sub sp, sp, #0x40\n"
        "stp x29, x30, [sp, #0x00]\n"
        "stp x9,  x10, [sp, #0x10]\n"
        "stp x0,  x1,  [sp, #0x20]\n"
        "mov x0, x9\n"
        "bl _vm2_state_log\n"
        "ldp x0,  x1,  [sp, #0x20]\n"
        "ldp x9,  x10, [sp, #0x10]\n"
        "ldp x29, x30, [sp, #0x00]\n"
        "add sp, sp, #0x40\n"
        "mov x8, x9\n"
        "cmp w9, w24\n"
        "b.le 1f\n"
        "adrp x16, _g_vm2_gt@PAGE\n"
        "ldr x16, [x16, _g_vm2_gt@PAGEOFF]\n"
        "br x16\n"
        "1:\n"
        "adrp x16, _g_vm2_le@PAGE\n"
        "ldr x16, [x16, _g_vm2_le@PAGEOFF]\n"
        "br x16\n"
    );
}

static int install_vm2_probe(void) {
    if (!g_base) return 0;
    g_vm2_gt = g_base + 0x713798ULL;
    g_vm2_le = g_base + 0x7137e0ULL;
    uintptr_t addr = g_base + 0x71378cULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("713 分派桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;
    w[1] = 0xd61f0200;
    *lit = (uint64_t)(uintptr_t)&vm2_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("713 分派桩：已装到 ", addr);
    return 1;
}

static int install_vm_desc_probe(void) {
    if (!g_base) return 0;
    g_vm_join = g_base + 0x7133e0ULL;
    uintptr_t addr = g_base + 0x7133d0ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("说明探针：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;                  // ldr x16, #8
    w[1] = 0xd61f0200;                  // br  x16
    *lit = (uint64_t)(uintptr_t)&vm_desc_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("说明探针：已装到 ", addr);
    say_hex("  续行地址=", g_vm_join);
    return 1;
}

#define DO_FAULTPROBE 1
static char g_faultpath[256];

static void fault_handler(int sig, siginfo_t *si, void *ucv) {
    {
        // 40ms 之后原有的文件描述符再也写不出东西，所以这里当场重新打开一个。
        long fd = g_faultpath[0] ? raw_open(g_faultpath, O_WRONLY | O_CREAT | O_APPEND, 0644) : -1;
        if (fd < 0) fd = g_gwfd;
        if (fd >= 0) {
            uint64_t r[6];
            r[0] = 0x4641554c00000001ULL;   // 魔数 "FAUL"
            r[1] = (uint64_t)sig;
            r[2] = 0; r[3] = 0; r[4] = (uint64_t)(uintptr_t)si->si_addr;
            ucontext_t *uc = (ucontext_t *)ucv;
            if (uc && uc->uc_mcontext) {
                r[2] = (uint64_t)uc->uc_mcontext->__ss.__pc;
                r[3] = (uint64_t)uc->uc_mcontext->__ss.__lr;
            }
            r[5] = (uint64_t)g_base;
            raw_write(fd, r, sizeof(r));
            // 顺着帧链往上走，把"谁发起了这个信号"一并记下来。
            if (uc && uc->uc_mcontext) {
                uint64_t fp = (uint64_t)uc->uc_mcontext->__ss.__fp;
                for (int i = 0; i < 10 && fp; i++) {
                    uint64_t nfp = 0, lr = 0;
                    if (!safe_read(fp, &nfp, 8)) break;
                    if (!safe_read(fp + 8, &lr, 8)) break;
                    uint64_t q[6];
                    q[0] = 0x4641554c00000003ULL;   // 回溯记录
                    q[1] = (uint64_t)(i + 1);
                    q[2] = lr;
                    q[3] = nfp;
                    q[4] = 0; q[5] = (uint64_t)g_base;
                    raw_write(fd, q, sizeof(q));
                    if (nfp <= fp) break;
                    fp = nfp;
                }
            }
            if (fd != g_gwfd) raw_close((int)fd);
        }
    }
    if (g_gwfd >= 0) {
        uint64_t r[6];
        r[0] = 0x4641554c00000001ULL;   // 魔数 "FAUL"
        r[1] = (uint64_t)sig;
        r[2] = 0; r[3] = 0; r[4] = (uint64_t)(uintptr_t)si->si_addr;
        ucontext_t *uc = (ucontext_t *)ucv;
        if (uc && uc->uc_mcontext) {
            r[2] = (uint64_t)uc->uc_mcontext->__ss.__pc;
            r[3] = (uint64_t)uc->uc_mcontext->__ss.__lr;
        }
        r[5] = (uint64_t)g_base;
        raw_write(g_gwfd, r, sizeof(r));
    }
    // 0.0.244：盾里 6434 条 brk #1 就是它的"故意陷阱"。以前这里一律重新抛出，
    // 于是每一次都由我们亲手把进程送走。现在辨认指令：如果是 brk / udf，
    // 就把 pc 往后挪一条、直接返回，等于这条陷阱没发生过；其余情况维持原样。
    {
        ucontext_t *uc = (ucontext_t *)ucv;
        if (uc && uc->uc_mcontext) {
            uint64_t pc = (uint64_t)uc->uc_mcontext->__ss.__pc;
            uint32_t w = 0;
            if (safe_read(pc, &w, 4)) {
                int trap = ((w & 0xffe0001fU) == 0xd4200000U) ||   // brk #imm16
                           ((w & 0xffe0001fU) == 0xd4400000U) ||   // hlt #imm16
                           ((w & 0xffff0000U) == 0x00000000U);     // udf #imm16
                if (trap) {
                    static volatile int skipped;
                    if (skipped < 400) {
                        skipped++;
                        uc->uc_mcontext->__ss.__pc = pc + 4;
                        if (g_gwfd >= 0) {
                            uint64_t q[6] = { 0x5452415000000001ULL, pc, w,
                                              (uint64_t)skipped, (uint64_t)g_base, 0 };
                            raw_write(g_gwfd, q, sizeof(q));
                        }
                        return;
                    }
                }
            }
        }
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void arm_fault_probe(void) {
    static const int sigs[] = { SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP };
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        sigaction(sigs[i], &sa, NULL);
    }
}

// 0.0.229：盾安装信号处理器用的是 libSystem 的 sigaction / signal / sigprocmask
// （导入表里都有），走 GOT，不经它自己的网关。所以在 libc 这一层拦：
// 只有当调用者落在盾自己的地址范围里时，才把这次调用吞掉并返回成功。
// 这样盾以为自己装上了处理器，实际上装的还是我们的；它也屏蔽不了任何信号。
// 我们自己的调用来自本库，不在盾的范围里，照常通过。
#define DO_SIGHOOK 1
static int (*g_orig_sigaction)(int, const struct sigaction *, struct sigaction *);
static void (*g_orig_signal)(int, void (*)(int));
static int (*g_orig_sigprocmask)(int, const sigset_t *, sigset_t *);
static volatile uint64_t g_sighook_blocked;

static int sh_caller_is_shield(void *ra) {
    uintptr_t a = (uintptr_t)ra;
    return g_base && a >= g_base && a < g_base + 0x8c0000;
}

static int my_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
    if (sh_caller_is_shield(__builtin_return_address(0))) { g_sighook_blocked++; return 0; }
    return g_orig_sigaction(sig, act, oact);
}
static void my_signal(int sig, void (*h)(int)) {
    if (sh_caller_is_shield(__builtin_return_address(0))) { g_sighook_blocked++; return; }
    g_orig_signal(sig, h);
}
static int my_sigprocmask(int how, const sigset_t *set, sigset_t *oset) {
    if (sh_caller_is_shield(__builtin_return_address(0))) { g_sighook_blocked++; return 0; }
    return g_orig_sigprocmask(how, set, oset);
}

static void install_sighooks(void) {
    MSHookFunction((void *)sigaction, (void *)my_sigaction, (void **)&g_orig_sigaction);
    MSHookFunction((void *)signal,    (void *)my_signal,    (void **)&g_orig_signal);
    MSHookFunction((void *)sigprocmask,(void *)my_sigprocmask,(void **)&g_orig_sigprocmask);
    say("信号钩子：已装（sigaction / signal / sigprocmask）\n");
}

// 0.0.231：把检查表在运行期原样打出来。
//
// 0x5d8ed0 是没有被混淆的干净代码：
//   5d8ef0  bl 0x5d91d0            ; 把单例 +0x10 处的向量复制到 sp+0x8
//   5d8ef4  ldp x8, x9, [sp,#0x8]  ; x8 = 起点, x9 = 终点
//   5d8f04  ldr x0, [x8, x20, lsl #3]   ; 第 x20 项
//   5d8f0c  ldr x8, [x8, #0x10]         ; 判定函数
//   5d8f10  blr x8
//   5d8f14  cbnz w0, 报警
// 所以在 0x5d8ef4 处插桩，就能拿到项数、每一项的虚表和判定函数地址。
// 桩把被覆盖的三条指令原样重放（ldp / cmp / mov x20,#0），再按比较结果跳回去。
void *g_ct_log;
uint64_t g_ct_next, g_ct_done;
static volatile uint64_t g_ct_runs;

__attribute__((used)) static void checktab_log(uint64_t *v) {
    uint64_t begin = v[1], end = v[2];
    uint64_t n = (begin && end > begin && end - begin < 0x10000) ? ((end - begin) >> 3) : 0;
    uint64_t h[6];
    h[0] = 0x4354414200000001ULL;   // 魔数 "CTAB"
    h[1] = begin; h[2] = end; h[3] = n; h[4] = ++g_ct_runs; h[5] = (uint64_t)g_base;
    if (g_gwfd >= 0) raw_write(g_gwfd, h, sizeof(h));
    for (uint64_t i = 0; i < n && i < 8; i++) {
        uint64_t item = 0, vt = 0, j10 = 0, j18 = 0;
        if (!safe_read(begin + i * 8, &item, 8) || !item) continue;
        if (!safe_read(item, &vt, 8) || !vt) continue;
        safe_read(vt + 0x10, &j10, 8);
        safe_read(vt + 0x18, &j18, 8);
        uint64_t r[6];
        r[0] = 0x4354414200000002ULL;   // 一项
        r[1] = i; r[2] = item; r[3] = j10; r[4] = j18; r[5] = (uint64_t)g_base;
        if (g_gwfd >= 0) raw_write(g_gwfd, r, sizeof(r));
    }
}

__attribute__((naked)) static void checktab_stub(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0x10]!\n"
        "add x0, sp, #0x10\n"
        "adrp x16, _g_ct_log@PAGE\n"
        "ldr x16, [x16, _g_ct_log@PAGEOFF]\n"
        "blr x16\n"
        "ldp x29, x30, [sp], #0x10\n"
        "ldp x8, x9, [sp, #0x8]\n"
        "cmp x9, x8\n"
        "adrp x17, _g_ct_done@PAGE\n"
        "ldr x17, [x17, _g_ct_done@PAGEOFF]\n"
        "b.eq 2f\n"
        "mov x20, #0x0\n"
        "adrp x17, _g_ct_next@PAGE\n"
        "ldr x17, [x17, _g_ct_next@PAGEOFF]\n"
        "2:\n"
        "br x17\n"
    );
}

static int install_checktab_log(void) {
    if (!g_base) return 0;
    g_ct_log = (void *)&checktab_log;
    g_ct_next = g_base + 0x5d8f04ULL;
    g_ct_done = g_base + 0x5d8f2cULL;
    uintptr_t addr = g_base + 0x5d8ef4ULL;
    uintptr_t page = addr & ~(uintptr_t)0xfff;
    kern_return_t kr = mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { say_hex("检查表桩：改页失败 kr=", (unsigned long long)kr); return 0; }
    volatile uint32_t *w = (volatile uint32_t *)addr;
    volatile uint64_t *lit = (volatile uint64_t *)(addr + 8);
    w[0] = 0x58000050;                        // ldr x16, #8
    w[1] = 0xd61f0200;                        // br  x16
    *lit = (uint64_t)(uintptr_t)&checktab_stub;
    sys_icache_invalidate((void *)addr, 16);
    mach_vm_protect(mach_task_self(), page, 0x4000, 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    say_hex("检查表桩：已装到 ", addr);
    return 1;
}

static void *ver(void *arg) {
    (void)arg;
    static const uint64_t ts[] = { 12, 25, 40, 55, 70, 90, 120 };
    for (unsigned i = 0; i < sizeof(ts) / sizeof(ts[0]); i++) {
        uint64_t now = up_ms() - g_t0;
        if (ts[i] > now) usleep((useconds_t)((ts[i] - now) * 1000));
        verify_patches();
    }
    return NULL;
}

__attribute__((constructor)) static void ctor(void) {
    NSString *caches = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
    if (!caches) return;
    NSString *lp = [caches stringByAppendingPathComponent:@"hsbchkbypass.log"];
    {
        const char *rp = [lp fileSystemRepresentation];
        size_t k = 0;
        while (rp[k] && k + 1 < sizeof(g_logpath)) { g_logpath[k] = rp[k]; k++; }
        g_logpath[k] = 0;
    }
    g_fd = open([lp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) return;
    {
        // 网关直写用的二进制记录单独一个文件，和文本日志混在一起会没法解析。
        NSString *gp = [caches stringByAppendingPathComponent:@"hsbchkbypass-gw.bin"];
        // 0.0.240：改成追加。这个 App 的构造函数一次启动里会跑好几次，
        // 之前每次都用 O_TRUNC，等于只留下最后一轮写下的记录。
        g_gwfd = open([gp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
        NSString *fp = [caches stringByAppendingPathComponent:@"hsbchkbypass-fault.bin"];
        {
            const char *rp2 = [fp fileSystemRepresentation];
            size_t k2 = 0;
            while (rp2[k2] && k2 + 1 < sizeof(g_faultpath)) { g_faultpath[k2] = rp2[k2]; k2++; }
            g_faultpath[k2] = 0;
        }
        NSString *sp = [caches stringByAppendingPathComponent:@"hsbchkbypass-sig.bin"];
        // 0.0.202：不截断。这个 App 的构造函数在一次启动里会被调用好几次，
        // 每次截断都会把前面已经写下的采样冲掉。
        g_sigfd = open([sp fileSystemRepresentation], O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    g_t0 = up_ms();
    g_ts0 = read_pct();
    say("===== 0.0.270 启动（记录 0x713720 的状态跳转）=====\n");

    try_takeover();
#if DO_HASHBYPASS
    install_hash_bypass();
#if DO_EXITFN_GUARD
    install_exitfn_guard();
#endif
#if DO_VM_DESC_LOG
    install_vm_desc_probe();
#endif
#if DO_VM_STATE_LOG
    install_vm_state_probe();
#endif
#if DO_GATE713720_PROBE
    install_gate713720_probe();
#endif
#if DO_OPEN_PATH_LOG
    install_open_path_probe();
#endif
#if DO_FD_LOG
    install_fd_probe();
#endif
#if DO_READ_LOG
    install_read_probe();
#endif
#if DO_VM2_LOG
    install_vm2_probe();
#endif
#if DO_GATE_RET_ZERO
    patch_word(g_base + OFF_GATE713720,     0x52800000U);   // mov w0, #0
    patch_word(g_base + OFF_GATE713720 + 4, 0xd65f03c0U);   // ret
#endif
#if DO_VM_FORCE_OK
    // 0x712dfc: cmp w0,#0（0x713720 的返回值）
    // 0x712e10: csel w8, w9, w8, ne —— 非零就选 0x564fec1b（失败链的起点）
    // 换成 nop 之后 w8 永远是 0x0748f1e，虚拟机当场结束，不再走原因码 5。
    patch_word(g_base + OFF_VM_CSEL, WORD_NOP);
#endif
#if DO_CHAIN_LOG
    g_ch_cb = g_base + 0x5d884cULL;   // 回调被覆盖四条之后的续行
    g_ch_ct = g_base + 0x5d8ee0ULL;   // 检查表执行器续行
    g_ch_vt = g_base + 0x5d88d4ULL;   // 虚表调用之后
    patch_entry_stub(g_base + 0x5d883cULL, (void *)&ch_cb_stub);
    patch_entry_stub(g_base + 0x5d8ed0ULL, (void *)&ch_ct_stub);
    patch_entry_stub(g_base + 0x5d88d0ULL, (void *)&ch_vt_stub);
    say("链接探针：已装（回调 / 检查表 / 虚表调用）\n");
#endif
    dump_thunks();
    dump_got();
#endif
#if DO_SIGSAMPLE
    arm_sig_sample();
#endif
#if DO_SIGHOOK
    install_sighooks();
#endif
#if DO_CHECKTAB_LOG
    install_checktab_log();
#endif
#if DO_FAULTPROBE
    arm_fault_probe();
    { if (g_gwfd >= 0) { uint64_t r[6] = { 0x4641554c00000002ULL, 0, 0, 0, 0, (uint64_t)g_base }; raw_write(g_gwfd, r, sizeof(r)); } }
#if DO_FAULTTEST
    {
        uint64_t r[6] = { 0x5445535400000001ULL, 0, 0, 0, 0, (uint64_t)g_base };
        if (g_gwfd >= 0) raw_write(g_gwfd, r, sizeof(r));
        raise(SIGILL);
        if (g_gwfd >= 0) { r[0] = 0x5445535400000002ULL; raw_write(g_gwfd, r, sizeof(r)); }
    }
#endif
#endif
#if DO_BUSYPROBE
    { pthread_t bt; pthread_create(&bt, NULL, busy_probe, NULL); }
#endif
    {
        pthread_t vt;
        pthread_create(&vt, NULL, ver, NULL);
    }
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
#if DO_OBJC
    {
        pthread_t ot;
        pthread_create(&ot, NULL, objc_dump_thread, NULL);
    }
#endif
    if (DO_SYMCHK) dump_sym_heads();
#if DO_EXITHOOK
    install_exit_hooks();
#endif
#if DO_KILLHOOK
    install_kill_hooks();
#else
    say("本版不挂 kill/raise/abort（避开 0x1e0dac000 那一页）\n");
#endif
#if DO_ENVHOOK
    install_env_hooks();
#endif
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
