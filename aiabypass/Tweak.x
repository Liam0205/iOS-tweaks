// AIABypass —— 友邦友享（com.aia.china.YoubangHealthRelease）越狱检测绕过
//
// 目标 App 6.9.33 内置 JMCodeProtectKit.framework（com.IPACodeProtectTwoSDk，v3.0.0.
// 20260903.1），这是一个带 RASP 的代码保护 SDK：
//   - 自带越狱 / hook / 调试 / 重签 / 完整性 / 代理 / VPN / 虚拟定位检测；
//   - 命中后不开弹窗，直接把线程 PC 置为非法地址，进程以 SIGSEGV 退出；
//   - 检测面来自其导入符号：dyld 镜像枚举、ObjC 方法表比对、stat/open/fopen 文件检查、
//     sysctl、dladdr/dlsym、SecTrust 证书链。
//
// 本文件当前是第一阶段实验版本：观测 + 隐藏注入库。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld_images.h>
#import <libkern/OSCacheControl.h>
extern int proc_regionfilename(int pid, uint64_t address, void *buffer, uint32_t buffersize);
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdarg.h>
#import <stdio.h>
#import <execinfo.h>
#import <stdlib.h>
#import <signal.h>
#import <pthread.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <mach/exception_types.h>
#import <mach/thread_act.h>
#import <mach/ndr.h>

// 发布默认 0：日志文件写在 App 自己的 Documents 里，"aiabypass.log" 这个名字
// 本身就是一处显眼的痕迹，不值得为了排查能力在正式版里留着。
// 定位问题时用 ADDITIONAL_OBJCFLAGS="-DAIA_DEBUG_LOG=1" 重新构建。
#ifndef AIA_DEBUG_LOG
#define AIA_DEBUG_LOG 0
#endif

// 实验开关：1 = 从 dyld 枚举里隐藏注入库；0 = 只观测不隐藏
#ifndef AIA_HIDE_IMAGES
#define AIA_HIDE_IMAGES 0
#endif

// 最小实验模式：只处理 _dyld_register_func_for_add_image，其余 hook 全部不装
#ifndef AIA_MINIMAL
#define AIA_MINIMAL 0
#endif

// ijm 混淆器的 VM 导入解析器在 0x7c5590 检查 x15；实验表明崩溃时 x15 被 VM 清 0，
// 但 x14 已经是有效的解析结果。打开这个开关把该检查改成 nop，让流程继续走 x14。
#ifndef AIA_PATCH_BINDER
#define AIA_PATCH_BINDER 0
#endif

// 把 dyld 镜像表里本 dylib 的 imageFilePath 指向一个无害路径，
// 用来验证 RASP 是否靠镜像路径判断注入。
#ifndef AIA_FAKE_PATH
#define AIA_FAKE_PATH 0
#endif

// 只装 dyld 枚举相关的 hook（含 dladdr），其余全不装，用来判断 RASP 是否走这些 API。
#ifndef AIA_DYLD_ONLY
#define AIA_DYLD_ONLY 0
#endif

// 隐身组合：dyld 枚举过滤 + dladdr 伪装，两者保持一致的镜像视图。
// 需要同时用 AIA_HIDE_IMAGES=1 编译。
#ifndef AIA_STEALTH
#define AIA_STEALTH 0
#endif

// 实验：只 hook dladdr，把落在越狱镜像里的地址伪装成系统库。
#ifndef AIA_DLADDR_MASK
#define AIA_DLADDR_MASK 0
#endif

// 实验：定期采样所有线程的 PC，用来定位空转位置。
#ifndef AIA_SAMPLE_THREADS
#define AIA_SAMPLE_THREADS 0
#endif

// 实验：安装自己的 Mach 异常处理器，抢在 ellekit 之前拿到故障线程的现场，
// 这样能看到"谁跳到了非法地址"。AIA_KILL_THREAD=1 时只终止故障线程，不杀整个进程。
#ifndef AIA_EXC_HANDLER
#define AIA_EXC_HANDLER 1
#endif
#ifndef AIA_KILL_THREAD
#define AIA_KILL_THREAD 0
#endif
// 1 = hook UIApplication/UIWindow 的 sendEvent: 统计事件数量。
// 注意：App 自己在 sendEvent: 里做埋点，加这层 hook 会改变 swizzle 链，
// 实测会让主线程更早撞上 brk #0xdead，所以默认关闭，只在排查时打开。
#ifndef AIA_EVENT_PROBE
#define AIA_EVENT_PROBE 0
#endif
// 1 = 收到 SIGUSR1 时把所有线程的 PC/LR 和主线程栈打到日志里，用来诊断卡死。
#ifndef AIA_DUMP_ON_SIGNAL
#define AIA_DUMP_ON_SIGNAL 0
#endif
// 1 = 后台线程每 50ms 重新设置一次异常端口，抢在 ellekit / Dynatrace KSCrash 之后。
#ifndef AIA_EXC_WATCHDOG
#define AIA_EXC_WATCHDOG 1
#endif
// 1 = 启动接收线程。0 = 只接管异常端口、不接收，让异常消息永久排队，
// 触发异常的线程会一直等在异常状态，JM 的处决线程随之阻塞。
#ifndef AIA_EXC_SERVER
#define AIA_EXC_SERVER 1
#endif
// 1 = 主线程遇到非法跳转时不挂起，而是把 PC 设成 LR，让这次调用"返回"后继续执行。
// 主线程一挂起，整个界面就再也收不到触摸事件（动画仍由 render server 合成）。
#ifndef AIA_EXC_RECOVER_MAIN
#define AIA_EXC_RECOVER_MAIN 1
#endif
// 1 = 真把主线程 PC 设成 LR（实验性：x0 现场无效时会二次崩溃）。
// 0 = 只记录、仍不回复，用来观察主线程挂住后的完整调用链。
#ifndef AIA_EXC_RECOVER_FAULT
#define AIA_EXC_RECOVER_FAULT 0
#endif

// 1 = 主线程在 JM 的 VM 里跳飞时，沿帧链退回到调用方（Dynatrace），
// 让整次 ijm 埋点调用作废。实测这条路径能避免"返回到 JM+0x186634 必然二次崩溃"。
#ifndef AIA_EXC_UNWIND_JM
#define AIA_EXC_UNWIND_JM 0
#endif
// 1 = 断点类异常（brk 断言桩）回复"PC 前进 4 字节"，让线程继续执行。
// 这是主线程不卡死的关键：主线程撞上 brk 后如果一直不回复，触摸就永久失效。
// 1 = 绑定器的 brk #0xdead 不按"推进 4 字节"处理，而是把线程弹回调用者并返回 nil。
// 推进 4 字节会进 0x7c55fc 的失败续跑路径，而那条路径拿绑定器自己构造的占位描述符
// 0x7c5500 当脚本，解释器必然失败，随后在 +0x7cd0f0 空指针崩溃。
#ifndef AIA_UNWIND_BINDER_BRK
#define AIA_UNWIND_BINDER_BRK 0
#endif

// 1 = 挂上 ijm 导入绑定器入口只做观察：打印 x13（缓存槽）、x14（桩）、
// 调用方 LR，然后原样执行原函数。用来定位到底是哪个导入在失败。
// 与 AIA_HOOK_IJM_BINDER 不同，这个不改行为，可以常开。
#ifndef AIA_TRACE_IJM_BINDER
#define AIA_TRACE_IJM_BINDER 0
#endif

// 1 = 观察主二进制自己的 ijm 解释器（KYHAppStore+0x7c56b8）的每次调用和返回结果。
// 绑定器慢路径就是 bl 到这里；返回值是寄存器结果区，绑定器随后从 [ret+0x70]
// 取解析出的函数地址、从 [ret+0x78] 取成功标志。只有看这两个槽，
// 才能区分"脚本没执行完"和"脚本算出来就是 0"。
#ifndef AIA_TRACE_IJM_VM
#define AIA_TRACE_IJM_VM 0
#endif

// 1 = 用 MSHookFunction 挂住 ijm 导入绑定器入口，让这些导入一律返回 nil。
// 实测不成立：调用方拿到 nil 后仍然解引用该结果，在 KYHAppStore+0x1685010 一带崩溃。
// 说明这个导入不只是埋点，它的返回值会被当作有效对象使用。
#ifndef AIA_HOOK_IJM_BINDER
#define AIA_HOOK_IJM_BINDER 0
#endif

// 1 = 在 JM 的 ijm VM 入口校验脚本描述符。实测每次调用拿到的都是主二进制的
// 0x7c5500，而 JM 的分派表只接受自己脚本的编码，硬解释会越界跳飞。
// 校验失败时按 VM 的正常返回约定把 ctx 交回去。
#ifndef AIA_VM_GUARD
#define AIA_VM_GUARD 0
#endif

// 1 = 在 JM 的 ijm VM 入口挂观察钩子，统计脚本描述符归属。
// 实测 164008 次调用里只有 1 次拿到非 JM 描述符（主二进制的 0x7c5500）。
// 这个探针本身会给热路径加一层跳板，只在排查时打开。
#ifndef AIA_VM_PROBE
#define AIA_VM_PROBE 0
#endif

#ifndef AIA_EXC_SKIP_BRK
#define AIA_EXC_SKIP_BRK 1
#endif
// 1 = 收到非断点异常后不回复，让故障线程永久挂起（不交给 ellekit，也就不会有 exit(1)）。
// 处决跳转的 pc=0x8 如果被回复，线程会重跑同一条非法指令形成死循环，进程随即被杀。
#ifndef AIA_EXC_NO_REPLY
#define AIA_EXC_NO_REPLY 1
#endif
// 1 = 不挂起故障线程，而是把它送到 aia_thread_bail 让 pthread_exit 干净退出，
// 这样线程持有的锁和资源会被释放（挂起会导致后续触摸失效）。
#ifndef AIA_EXC_BAIL
#define AIA_EXC_BAIL 0
#endif

// 非主线程处决跳飞的处理方式：
//   0 = 不回复，线程永久停在异常状态（默认，实测最稳）
//   1 = 把 PC 设成 LR、x0 清零，当作这次调用返回 0
// 1 是为了回答一个具体问题：JM 的检查线程被冻结，检测就永远不完成，
// App 能用的前提正是"检测没跑完"。如果让它继续跑，JM 是会判定通过，
// 还是会在下一步再处决一次，只能实测。
//   2 = 交给 aia_thread_bail 让 pthread_exit 干净退出
// 1 = 异常发生时转储其它 JM/App 线程的 PC/LR 与帧链，用来定位判定点。
// 1 = 在 AIA_EMPTY 模式下连 task_info/exit/_exit/abort 这几个 libc hook 也不装，
// 只保留异常端口。用来回答一个决定性问题：JM 的处决是我们自己的 hook
// 触发的（它可能校验被改写过的代码页），还是它本来就判定失败。
// 1 = 记录 JM 早期检查过的文件路径（access/stat/lstat/open）。
// 这是定位"它到底在看什么"最直接的办法：越狱检测绝大多数落在路径存在性上。
#ifndef AIA_FS_PROBE
#define AIA_FS_PROBE 0
#endif

// 1 = 拦掉 systemhook 的 GOT 重绑定（_litehook_apply_global_rebinds）。
#ifndef AIA_BLOCK_LITEHOOK
#define AIA_BLOCK_LITEHOOK 0
#endif

// 1 = 审计 App 内嵌框架的 __got/__la_symbol_ptr，找指向越狱注入库的条目。
#ifndef AIA_GOT_AUDIT
#define AIA_GOT_AUDIT 0
#endif

// 1 = 跟踪 JM 的检查项求值函数 JM+0x14fc40，转储每一项的内容。
#ifndef AIA_CHECK_TRACE
#define AIA_CHECK_TRACE 0
#endif
#ifndef AIA_DLSYM_PROBE
#define AIA_DLSYM_PROBE 0
#endif
#ifndef AIA_EXTRA_HOOKS
#define AIA_EXTRA_HOOKS 0
#endif
#ifndef AIA_GOT_RESTORE
#define AIA_GOT_RESTORE 0
#endif
#ifndef AIA_KILL_PROBE
#define AIA_KILL_PROBE 0
#endif
#ifndef AIA_EARLY_TRACE
#define AIA_EARLY_TRACE 0
#endif
#ifndef AIA_FREEZE_JM
#define AIA_FREEZE_JM 0
#endif
// 1 = 连 __got 里的 5 个槽也一起还原（实测会让 App 立刻退出）
#ifndef AIA_GOT_RESTORE_GOT
#define AIA_GOT_RESTORE_GOT 0
#endif

// 1 = 拦截发给非法接收者的 objc 消息，记录调用者并返回 nil。
#ifndef AIA_MSGSEND_PROBE
#define AIA_MSGSEND_PROBE 0
#endif

// 1 = 过滤 sysctl(KERN_PROC_ALL) 返回的进程列表，抹掉 Sileo/jailbreakd/sshd 等项。
#ifndef AIA_PROC_FILTER
#define AIA_PROC_FILTER 0
#endif

// 1 = 记录 JM/App 查询的环境变量与 sysctl 项。
#ifndef AIA_ENV_PROBE
#define AIA_ENV_PROBE 0
#endif

// 1 = 记录 csops 查询（代码签名状态），RASP 常用信号。
#ifndef AIA_CSOPS_PROBE
#define AIA_CSOPS_PROBE 0
#endif

// 1 = 探测 JM 是否查询任务的异常端口（RASP 常见手法）。
#ifndef AIA_EXCPORT_PROBE
#define AIA_EXCPORT_PROBE 0
#endif

// 1 = 只装文件系统探针（全量记录查询路径），其余 hook 全不装。
#ifndef AIA_FS_ONLY
#define AIA_FS_ONLY 0
#endif

#ifndef AIA_NO_LIBC_HOOKS
#define AIA_NO_LIBC_HOOKS 0
#endif

#ifndef AIA_DUMP_PEERS
#define AIA_DUMP_PEERS 1
#endif

#ifndef AIA_EXC_NONMAIN
#define AIA_EXC_NONMAIN 0
#endif

// 实验：拦下 exit(1)/_exit(1)，验证是 JM 自己退出还是 ellekit 异常处理器退出。
#ifndef AIA_BLOCK_EXIT
#define AIA_BLOCK_EXIT 0
#endif

// 打印所有非系统镜像的路径，确认注入链路把哪些镜像带进了进程。
#ifndef AIA_LOG_IMAGES
#define AIA_LOG_IMAGES 0
#endif

// 真正什么都不做：不装信号处理器、不枚举模块，只写一行日志。
#ifndef AIA_TRULY_EMPTY
#define AIA_TRULY_EMPTY 0
#endif
#ifndef AIA_TE_HOOK
#define AIA_TE_HOOK 0
#endif

// 空 tweak：只记录构造，不安装任何 hook，用来判断 RASP 是否只检测镜像存在。
#ifndef AIA_EMPTY
#define AIA_EMPTY 1
#endif

// 只装"安全子集"的观测 hook（不含 vm_region / vm_read 等高危项），
// 与异常接管同时开启，用来观察 JM 在判定前后调用了什么。
#ifndef AIA_OBSERVE_ONLY
#define AIA_OBSERVE_ONLY 0
#endif

// 运行时把 0x7c54b0..0x7c5620 的字节和映射来源打出来，用来对比文件里的原始机器码。
#ifndef AIA_DUMP_CODE
#define AIA_DUMP_CODE 0
#endif

// 定时采样 0x7c5000 页的改动，判断这块代码是文件映射还是运行时生成。
#ifndef AIA_SAMPLE_CODE
#define AIA_SAMPLE_CODE 0
#endif

// 1 = 直接把 RASP 的 add_image 注册吞掉，不再转发给 dyld
#ifndef AIA_BLOCK_ADD_IMAGE
#define AIA_BLOCK_ADD_IMAGE 0
#endif

// 日志写 App 数据容器，不写 /tmp 或 /var/jb/tmp。
static void log_backtrace(const char *tag);
static const char *caller_desc(void *ra);
static const char *aia_real_ptr(uintptr_t v, uintptr_t *real_out, uintptr_t *off_out);
static const char *module_for(uintptr_t addr, uintptr_t *offset);
static uintptr_t module_base_for(const char *needle, uintptr_t *size_out);
static __thread bool t_in_safe_read;
static bool caller_is_jb_infra(void *ra);
static void aialog(const char *fmt, ...) {
#if AIA_DEBUG_LOG
    static char path[PATH_MAX];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        if (!dir) dir = NSTemporaryDirectory();
        snprintf(path, sizeof(path), "%s/aiabypass.log", [dir fileSystemRepresentation]);
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "===== aiabypass start %s =====\n", [[NSDate date] description].UTF8String); fclose(f); }
    });
    FILE *f = fopen(path, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
#else
    (void)fmt;
#endif
}

// ============================================================
// MARK: 判定哪些镜像需要从枚举结果里隐藏
// ============================================================

static const char *const kHiddenPatterns[] = {
    "/var/jb/",
    "systemhook.dylib",
    "libinjector.dylib",
    "libsubstrate",
    "TweakInject",
    "ellekit",
    "CydiaSubstrate",
    "SubstrateLoader",
    "frida",
    "FridaGadget",
    "AIABypass",
    NULL,
};

static bool path_is_hidden(const char *p) {
    if (!p) return false;
    for (int i = 0; kHiddenPatterns[i]; i++) {
        if (strstr(p, kHiddenPatterns[i])) return true;
    }
    return false;
}

// ============================================================
// MARK: dyld 镜像枚举过滤
// ============================================================

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_slide)(uint32_t);

static uint32_t g_real_count;
static uint32_t *g_visible;
static uint32_t g_visible_count;
static uint32_t g_visible_cap;

static void rebuild_visible(void) {
    uint32_t n = orig_dyld_image_count();
    if (g_visible && n == g_real_count) return;
    if (g_visible_count && g_visible) {
        // 只增不减的常见情形：在旧表基础上增量补齐
    }
    if (n > g_visible_cap) {
        g_visible_cap = n + 32;
        free(g_visible);
        g_visible = (uint32_t *)malloc(sizeof(uint32_t) * g_visible_cap);
    }
    uint32_t vc = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *name = orig_dyld_get_image_name(i);
        if (AIA_HIDE_IMAGES && path_is_hidden(name)) {
            aialog("[hide] image[%u] %s", i, name ? name : "(null)");
            continue;
        }
        g_visible[vc++] = i;
    }
    g_visible_count = vc;
    g_real_count = n;
}

static uint32_t my_dyld_image_count(void) {
    rebuild_visible();
    return g_visible_count;
}

static uint32_t visible_to_real(uint32_t idx) {
    rebuild_visible();
    if (idx >= g_visible_count) return UINT32_MAX;
    return g_visible[idx];
}

static const char *my_dyld_get_image_name(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_name(real);
}

static const struct mach_header *my_dyld_get_image_header(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return NULL;
    return orig_dyld_get_image_header(real);
}

static intptr_t my_dyld_get_image_slide(uint32_t idx) {
    uint32_t real = visible_to_real(idx);
    if (real == UINT32_MAX) return 0;
    return orig_dyld_get_image_slide(real);
}

// objc_copyImageNames
static CFArrayRef (*orig_objc_copyImageNames)(unsigned int *);
static CFArrayRef my_objc_copyImageNames(unsigned int *outCount) {
    CFArrayRef arr = orig_objc_copyImageNames(outCount);
    if (!arr) return arr;
    CFMutableArrayRef filtered = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFIndex n = CFArrayGetCount(arr);
    for (CFIndex i = 0; i < n; i++) {
        CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(arr, i);
        char buf[PATH_MAX];
        if (CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8) && path_is_hidden(buf)) {
            aialog("[hide] objc_copyImageNames %s", buf);
            continue;
        }
        CFArrayAppendValue(filtered, s);
    }
    if (outCount) *outCount = (unsigned int)CFArrayGetCount(filtered);
    return filtered;
}

// _dyld_register_func_for_add_image：把回调包一层，隐藏镜像不回调
typedef void (*add_image_cb_t)(const struct mach_header *, intptr_t);
static add_image_cb_t g_add_image_cbs[8];
static int g_add_image_cb_count;
static bool g_add_image_registered;

static void my_add_image_cb(const struct mach_header *mh, intptr_t slide) {
    aialog("+ add_image_cb(%p, %#lx)", mh, (unsigned long)slide);
    const char *name = NULL;
    if (orig_dyld_image_count && orig_dyld_get_image_header && orig_dyld_get_image_name) {
        uint32_t n = orig_dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (orig_dyld_get_image_header(i) == mh) { name = orig_dyld_get_image_name(i); break; }
        }
    } else {
        // 最小模式下没有接管 _dyld_image_count 等函数，orig_* 仍是空指针，
        // 这里退回系统（或 ellekit）提供的 _dyld_* 实现。
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (_dyld_get_image_header(i) == mh) { name = _dyld_get_image_name(i); break; }
        }
    }
    if (path_is_hidden(name)) {
        aialog("[hide] add_image cb skipped %s", name ? name : "(null)");
        return;
    }
    for (int i = 0; i < g_add_image_cb_count; i++) g_add_image_cbs[i](mh, slide);
}

static void (*orig_register_add_image)(add_image_cb_t);
static void my_register_add_image(add_image_cb_t cb) {
    aialog("+ _dyld_register_func_for_add_image(%p)", cb);
    if (g_add_image_cb_count < 8) g_add_image_cbs[g_add_image_cb_count++] = cb;
    if (AIA_BLOCK_ADD_IMAGE) { aialog("add_image registration swallowed"); return; }
    if (!g_add_image_registered) {
        g_add_image_registered = true;
        orig_register_add_image(my_add_image_cb);
    }
}

// dladdr：把隐藏库的路径抹掉
static int (*orig_dladdr)(const void *, Dl_info *);
static int my_dladdr(const void *addr, Dl_info *info) {
    int r = orig_dladdr(addr, info);
    if (r && info && info->dli_fname && path_is_hidden(info->dli_fname)) {
        aialog("[hide] dladdr(%p) %s base=%p sname=%s caller=%s", addr, info->dli_fname,
               info->dli_fbase, info->dli_sname ?: "-", caller_desc(__builtin_return_address(0)));
        info->dli_fname = "";
    }
    return r;
}

// ============================================================
// MARK: 文件检查（先只观测，命中的路径写日志）
// ============================================================

static bool path_is_suspicious(const char *p) {
    if (!p) return false;
    static const char *pat[] = {
        "/var/jb", "Cydia", "Sileo", "substrate", "Substrate", "frida",
        "/usr/sbin/sshd", "/bin/bash", "/bin/sh", "/etc/apt", "/private/var/lib/dpkg",
        "MobileSubstrate", "TweakInject", "ellekit", "libhooker", "checkra1n", "unc0ver",
        "dopamine", "Dopamine", "procursus", "jbroot", ".jbroot", NULL
    };
    for (int i = 0; pat[i]; i++) if (strstr(p, pat[i])) return true;
    return false;
}

static int (*orig_stat)(const char *, struct stat *);
static int my_stat(const char *p, struct stat *st) {
    if (path_is_suspicious(p) && !caller_is_jb_infra(__builtin_return_address(0))) aialog("stat(%s) caller=%s", p, caller_desc(__builtin_return_address(0)));
    return orig_stat(p, st);
}

static int (*orig_lstat)(const char *, struct stat *);
static int my_lstat(const char *p, struct stat *st) {
    if (path_is_suspicious(p)) aialog("lstat(%s)", p);
    return orig_lstat(p, st);
}

static int (*orig_access)(const char *, int);
static int my_access(const char *p, int mode) {
    if (path_is_suspicious(p)) aialog("access(%s,%d)", p, mode);
    return orig_access(p, mode);
}

static int (*orig_open)(const char *, int, ...);
static int my_open(const char *p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    if (path_is_suspicious(p)) aialog("open(%s,%d)", p, flags);
    return orig_open(p, flags, mode);
}

static int (*orig_readlink)(const char *, char *, size_t);
static int my_readlink(const char *p, char *buf, size_t sz) {
    if (path_is_suspicious(p)) aialog("readlink(%s)", p);
    return orig_readlink(p, buf, sz);
}

// ============================================================
// MARK: sysctl（观测）
// ============================================================

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (namelen >= 2) {
        aialog("sysctl(mib=%d,%d,%d,%d namelen=%u)", name[0], name[1],
               namelen > 2 ? name[2] : -1, namelen > 3 ? name[3] : -1, namelen);
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}


// ============================================================
// MARK: 调用者定位（用于把检测行为归因到具体模块）
// ============================================================

static const char *caller_desc(void *ra) {
    static char buf[320];
    Dl_info info;
    // 返回地址在 arm64e 上带 PAC 签名，直接用 dladdr 解析会失败。
    // 先还原成真实地址，解析不出来再退回原值。
    uintptr_t real = 0, off = 0;
    if (aia_real_ptr((uintptr_t)ra, &real, &off)) {
        snprintf(buf, sizeof(buf), "%s+0x%lx",
                 strrchr(module_for(real, &off), '/') ? strrchr(module_for(real, &off), '/') + 1
                                                      : module_for(real, &off),
                 (unsigned long)off);
        return buf;
    }
    if (ra && orig_dladdr && orig_dladdr(ra, &info) && info.dli_fname) {
        const char *slash = strrchr(info.dli_fname, '/');
        snprintf(buf, sizeof(buf), "%s+0x%lx", slash ? slash + 1 : info.dli_fname,
                 (unsigned long)((uintptr_t)ra - (uintptr_t)info.dli_fbase));
        return buf;
    }
    snprintf(buf, sizeof(buf), "%p", ra);
    return buf;
}

static bool caller_is_jb_infra(void *ra) {
    const char *d = caller_desc(ra);
    return strstr(d, "libinjector") || strstr(d, "systemhook") || strstr(d, "ellekit")
        || strstr(d, "Choicy") || strstr(d, "AIABypass");
}

// ============================================================
// MARK: VM 检测原语（观测 RASP 如何扫内存）
// ============================================================

static kern_return_t (*orig_vm_region_64)(vm_map_t, vm_address_t *, vm_size_t *, vm_region_flavor_t,
                                           vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
static kern_return_t my_vm_region_64(vm_map_t task, vm_address_t *address, vm_size_t *size,
                                     vm_region_flavor_t flavor, vm_region_info_t info,
                                     mach_msg_type_number_t *infoCnt, mach_port_t *object_name) {
    kern_return_t kr = orig_vm_region_64(task, address, size, flavor, info, infoCnt, object_name);
    aialog("vm_region_64(addr=0x%lx size=0x%lx flavor=%d) -> %d caller=%s",
           address ? (unsigned long)*address : 0, size ? (unsigned long)*size : 0,
           (int)flavor, (int)kr, caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_region_recurse_64)(vm_map_t, vm_address_t *, vm_size_t *, natural_t *,
                                                  vm_region_recurse_info_t, mach_msg_type_number_t *);
static kern_return_t my_vm_region_recurse_64(vm_map_t task, vm_address_t *address, vm_size_t *size,
                                             natural_t *depth, vm_region_recurse_info_t info,
                                             mach_msg_type_number_t *infoCnt) {
    kern_return_t kr = orig_vm_region_recurse_64(task, address, size, depth, info, infoCnt);
    aialog("vm_region_recurse_64(addr=0x%lx size=0x%lx depth=%d) -> %d caller=%s",
           address ? (unsigned long)*address : 0, size ? (unsigned long)*size : 0,
           depth ? (int)*depth : -1, (int)kr, caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static kern_return_t my_vm_read_overwrite(vm_map_t task, vm_address_t address, vm_size_t size,
                                          vm_address_t data, vm_size_t *outsize) {
    kern_return_t kr = orig_vm_read_overwrite(task, address, size, data, outsize);
    if (t_in_safe_read) return kr;
    aialog("vm_read_overwrite(addr=0x%lx size=0x%lx) -> %d caller=%s",
           (unsigned long)address, (unsigned long)size, (int)kr,
           caller_desc(__builtin_return_address(0)));
    return kr;
}

static kern_return_t (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static kern_return_t my_vm_protect(vm_map_t task, vm_address_t address, vm_size_t size,
                                   boolean_t set_max, vm_prot_t prot) {
    kern_return_t kr = orig_vm_protect(task, address, size, set_max, prot);
    aialog("vm_protect(addr=0x%lx size=0x%lx prot=%d) -> %d caller=%s",
           (unsigned long)address, (unsigned long)size, (int)prot, (int)kr,
           caller_desc(__builtin_return_address(0)));
    return kr;
}

static uint8_t *(*orig_getsectiondata)(const struct mach_header *, const char *, const char *, unsigned long *);
static uint8_t *my_getsectiondata(const struct mach_header *mhp, const char *seg, const char *sect, unsigned long *size) {
    uint8_t *r = orig_getsectiondata(mhp, seg, sect, size);
    aialog("getsectiondata(%s,%s) -> %p size=%lu caller=%s", seg ? seg : "?", sect ? sect : "?",
           r, size ? *size : 0, caller_desc(__builtin_return_address(0)));
    return r;
}


// ============================================================
// MARK: RASP 查询面（类名 / 符号 / 环境变量）
// ============================================================

static Class (*orig_NSClassFromString)(NSString *);
static Class my_NSClassFromString(NSString *name) {
    Class c = orig_NSClassFromString(name);
    aialog("NSClassFromString(%s) -> %p caller=%s", name ? [name UTF8String] : "(nil)",
           c, caller_desc(__builtin_return_address(0)));
    return c;
}

static Class (*orig_objc_getClass)(const char *);
static Class my_objc_getClass(const char *name) {
    Class c = orig_objc_getClass(name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("objc_getClass(%s) -> %p caller=%s", name, c, caller_desc(__builtin_return_address(0)));
    return c;
}

static void *(*orig_dlsym)(void *, const char *);
static void *my_dlsym(void *handle, const char *name) {
    void *r = orig_dlsym(handle, name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("dlsym(%s) -> %p caller=%s", name, r, caller_desc(__builtin_return_address(0)));
    return r;
}

static char *(*orig_getenv)(const char *);
static char *my_getenv(const char *name) {
    char *r = orig_getenv(name);
    if (name && !caller_is_jb_infra(__builtin_return_address(0)))
        aialog("getenv(%s) -> %s caller=%s", name, r ? r : "(null)",
               caller_desc(__builtin_return_address(0)));
    return r;
}

// ============================================================
// MARK: 崩溃现场记录（诊断用）
// ============================================================

static int g_logfd = -1;
static uint64_t g_t0 = 0;
static uint64_t up_ms(void) {
    if (!g_t0) return 0;
    return (mach_absolute_time() - g_t0) / 1000000ULL;
}
// 多条日志线程并发写同一个 fd 时会互相穿插，把整行切碎，
// 之前好几处诊断就是因为这个读不出来。加一把锁保证整行原子落盘。
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static void log_raw(const char *s) {
    if (g_logfd < 0) return;
    pthread_mutex_lock(&g_log_lock);
    ssize_t n = strlen(s);
    (void)!write(g_logfd, s, n);
    pthread_mutex_unlock(&g_log_lock);
}

#define AIA_MAX_MODULES 1024
static int g_vm_calls, g_vm_bad, g_vm_guarded;

static struct { uintptr_t base; uintptr_t size; const char *name; } g_mods[AIA_MAX_MODULES];
static int g_mod_count;

static void snapshot_modules(void) {
    extern uint32_t (*orig_dyld_image_count)(void);
    extern const char *(*orig_dyld_get_image_name)(uint32_t);
    extern const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
    uint32_t (*cnt_fn)(void) = orig_dyld_image_count ? orig_dyld_image_count : _dyld_image_count;
    const char *(*name_fn)(uint32_t) = orig_dyld_get_image_name ? orig_dyld_get_image_name : _dyld_get_image_name;
    const struct mach_header *(*hdr_fn)(uint32_t) = orig_dyld_get_image_header ? orig_dyld_get_image_header : _dyld_get_image_header;
    if (!cnt_fn || !hdr_fn) return;
    uint32_t n = cnt_fn();
    if (n > AIA_MAX_MODULES) n = AIA_MAX_MODULES;
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *h = hdr_fn(i);
        if (!h) continue;
        uintptr_t base = (uintptr_t)h;
        uintptr_t size = 0;
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)h;
        if (h64->magic == MH_MAGIC_64) {
            const uint8_t *p = (const uint8_t *)h + sizeof(struct mach_header_64);
            for (uint32_t c = 0; c < h64->ncmds; c++) {
                const struct load_command *lc = (const struct load_command *)p;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                    if (strcmp(seg->segname, "__TEXT") == 0) size = seg->vmsize;
                }
                if (lc->cmdsize == 0) break;
                p += lc->cmdsize;
            }
        }
        g_mods[g_mod_count].base = base;
        g_mods[g_mod_count].size = size ? size : 0x1000;
        g_mods[g_mod_count].name = name_fn(i);
        g_mod_count++;
    }
}

static const char *module_for(uintptr_t addr, uintptr_t *offset) {
    for (int i = 0; i < g_mod_count; i++) {
        if (addr >= g_mods[i].base && addr < g_mods[i].base + g_mods[i].size) {
            *offset = addr - g_mods[i].base;
            return g_mods[i].name;
        }
    }
    *offset = 0;
    return NULL;
}

static __thread bool t_in_safe_read;
static bool safe_read(uintptr_t addr, uintptr_t *out) {
    vm_size_t got = 0;
    t_in_safe_read = true;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr,
                                         sizeof(uintptr_t), (vm_address_t)out, &got);
    t_in_safe_read = false;
    return kr == KERN_SUCCESS && got == sizeof(uintptr_t);
}

static volatile int g_exc_count;      // 收到的异常消息总数
static volatile int g_exc_noreply;    // 其中按"不回复"处理的数量
static void log_exception_port_owners(const char *tag);

static void crash_signal_handler(int sig, siginfo_t *si, void *uctx) {
    ucontext_t *uc = (ucontext_t *)uctx;
    char buf[512];
#if defined(__arm64__)
    uint64_t *x = uc->uc_mcontext->__ss.__x;
    uintptr_t pc = uc->uc_mcontext->__ss.__pc;
    uintptr_t lr = uc->uc_mcontext->__ss.__lr;
    uintptr_t fp = uc->uc_mcontext->__ss.__fp;
    uintptr_t off = 0;
    const char *m = module_for(pc, &off);
    snprintf(buf, sizeof(buf), "SIGNAL t=%llums %d code=%d addr=%p pc=%p(%s+0x%lx) lr=%p sp=%p fp=%p exc=%d noreply=%d\n",
             (unsigned long long)up_ms(), sig, si ? si->si_code : -1, si ? si->si_addr : NULL,
             (void *)pc, m ? m : "?", (unsigned long)off,
             (void *)lr, (void *)uc->uc_mcontext->__ss.__sp, (void *)fp,
             g_exc_count, g_exc_noreply);
    log_raw(buf);
    for (int i = 0; i < 29; i++) {
        uintptr_t voff = 0;
        const char *vm = module_for(x[i], &voff);
        if (vm) {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx %s+0x%lx\n", i, (unsigned long)x[i],
                     vm, (unsigned long)voff);
        } else {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx\n", i, (unsigned long)x[i]);
        }
        log_raw(buf);
    }
    snprintf(buf, sizeof(buf), "  cpsr=%#x\n", uc->uc_mcontext->__ss.__cpsr);
    log_raw(buf);
    {
        uint32_t insn = 0;
        if (safe_read(pc, (uintptr_t *)&insn)) {
            snprintf(buf, sizeof(buf), "  insn@pc=%08x\n", insn);
            log_raw(buf);
        }
    }
    // 运行时字节对比：文件里的桩和内存里的桩可能不同
    {
        uint8_t raw[0x80];
        vm_size_t got = 0;
        if (vm_read_overwrite(mach_task_self(), (vm_address_t)(pc - 0x40), sizeof(raw),
                              (vm_address_t)raw, &got) == KERN_SUCCESS && got == sizeof(raw)) {
            char line[256];
            for (int i = 0; i < 0x80; i += 16) {
                char *w = line;
                w += snprintf(w, 16, "  %c%03x: ", i >= 0x40 ? '+' : '-', i >= 0x40 ? i - 0x40 : 0x40 - i);
                for (int j = 0; j < 16; j++) w += snprintf(w, 4, "%02x", raw[i + j]);
                w += snprintf(w, 8, "  ");
                for (int j = 0; j < 16; j++) {
                    uint8_t c = raw[i + j];
                    *w++ = (c >= 0x20 && c < 0x7f) ? c : '.';
                }
                *w++ = '\n';
                *w = 0;
                log_raw(line);
            }
        }
    }
    // 原始栈扫描：找出落在已知模块里的返回地址
    {
        uintptr_t scan_sp = uc->uc_mcontext->__ss.__sp;
        int found = 0;
        for (int i = 0; i < 0x4000 / sizeof(uintptr_t) && found < 40; i++) {
            uintptr_t v = 0;
            if (!safe_read(scan_sp + i * sizeof(uintptr_t), &v)) break;
            uintptr_t voff = 0;
            const char *vm = module_for(v, &voff);
            if (vm && voff > 0) {
                snprintf(buf, sizeof(buf), "  stack[+0x%x] %p %s+0x%lx\n",
                         i * 8, (void *)v, vm, (unsigned long)voff);
                log_raw(buf);
                found++;
            }
        }
    }
    // fp 链展开
    uintptr_t frame = fp;
    for (int i = 0; i < 24 && frame; i++) {
        uintptr_t next = 0, ra = 0;
        if (!safe_read(frame, &next) || !safe_read(frame + sizeof(uintptr_t), &ra)) break;
        uintptr_t roff = 0;
        const char *rm = module_for(ra, &roff);
        snprintf(buf, sizeof(buf), "  #%d %p %s+0x%lx\n", i, (void *)ra,
                 rm ? rm : "?", (unsigned long)roff);
        log_raw(buf);
        if (next <= frame) break;
        frame = next;
    }
#else
    log_raw("SIGNAL (non-arm64)\n");
#endif
    // brk 断言：内核在把 EXC_BREAKPOINT 交给 Mach 异常端口之后，仍会补发 SIGTRAP。
    // 只靠 Mach 回复推进 PC 挡不住这条路，线程会带着原来的 PC 收到信号。
    // 这里在信号层再推进一次 4 字节，线程继续往下走而不是被 SIGTRAP 打死。
    if (sig == SIGTRAP) {
        uint32_t insn = 0;
        if (safe_read(pc, (uintptr_t *)&insn) && (insn & 0xffe0001f) == 0xd4200000) {
            static int brk_skipped;
            if (brk_skipped < 20) {
                snprintf(buf, sizeof(buf), "  BRKSKIP sigtrap imm=%#x -> +4\n", (insn >> 5) & 0xffff);
                log_raw(buf);
                brk_skipped++;
            }
            uc->uc_mcontext->__ss.__pc = pc + 4;
            return;
        }
    }
    // JM 的处决路径之一是给进程发 SIGUSR1。这个信号的默认动作是终止进程，
    // 收不到终止原因的话看起来就像"静默退出"。这里记录后直接返回，
    // 不把它当作需要放大的致命信号。
    if (sig == SIGUSR1) {
        static int usr1_logged;
        if (usr1_logged < 10) {
            log_raw("  SIGUSR1 ignored (JM 处决信号)\n");
            usr1_logged++;
        }
        return;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

// ============================================================
#if AIA_FS_PROBE
// 只记录，不改变任何返回值。
static int (*orig_access)(const char *, int);
static int my_access(const char *p, int m) {
    int r = orig_access(p, m);
    if (p) aialog("FS access %s %s", r == 0 ? "OK " : "-  ", p);
    return r;
}

static int (*orig_lstat_x)(const char *, void *);
static int my_lstat_x(const char *p, void *b) {
    int r = orig_lstat_x(p, b);
    if (p && r == 0) aialog("FS lstat OK  %s", p);
    return r;
}

static int (*orig_stat_x)(const char *, void *);
static int my_stat_x(const char *p, void *b) {
    int r = orig_stat_x(p, b);
    if (p && r == 0) aialog("FS stat OK  %s", p);
    return r;
}

// open 的调用量很大，只记可疑路径。
static BOOL fs_suspicious(const char *p) {
    static const char *keys[] = {
        "jb", "jail", "cydia", "sileo", "substrate", "Substrate", "ellekit",
        "systemhook", "injector", "procursus", "preboot", "basebin", "TweakInject",
        "frida", "Frida", "libhooker", "Dopamine", "unc0ver", "checkra1n",
        "MobileSubstrate", "Cydia", "dpkg", "bash",
    };
    if (!p) return NO;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
        if (strstr(p, keys[k])) return YES;
    return NO;
}

static int (*orig_open_x)(const char *, int, ...);
static int my_open_x(const char *p, int fl, ...) {
    mode_t mode = 0;
    va_list ap;
    va_start(ap, fl);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    int r = orig_open_x(p, fl, mode);
    if (fs_suspicious(p)) aialog("FS open %s -> %d", p, r);
    return r;
}

static void install_fs_probe(void) {
    MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
    MSHookFunction((void *)lstat, (void *)my_lstat_x, (void **)&orig_lstat_x);
    MSHookFunction((void *)stat, (void *)my_stat_x, (void **)&orig_stat_x);
    MSHookFunction((void *)open, (void *)my_open_x, (void **)&orig_open_x);
    log_raw("FS probe installed\n");
}
#else
__attribute__((unused)) static void install_fs_probe(void) {}
#endif

// MARK: 终止原语（观测是谁在杀进程）
// ============================================================

#if AIA_FS_ONLY
// 只装文件系统探针，把**所有**查询路径都记下来（有上限），不装任何伪造逻辑。
// 目的：看清 JM 在启动阶段到底检查了哪些路径。
static int g_fs2_used;
static int (*fs2_orig_access)(const char *, int);
static int fs2_access(const char *p, int m) {
    int r = fs2_orig_access(p, m);
    if (p && g_fs2_used < 400) {
        aialog("FS access %s %s caller=%s", r == 0 ? "OK " : "-  ", p,
               caller_desc(__builtin_return_address(0)));
        g_fs2_used++;
    }
    return r;
}
static int (*fs2_orig_lstat)(const char *, void *);
static int fs2_lstat(const char *p, void *b) {
    int r = fs2_orig_lstat(p, b);
    if (p && r == 0 && g_fs2_used < 400) {
        aialog("FS lstat OK  %s caller=%s", p, caller_desc(__builtin_return_address(0)));
        g_fs2_used++;
    }
    return r;
}
static int (*fs2_orig_stat)(const char *, void *);
static int fs2_stat(const char *p, void *b) {
    int r = fs2_orig_stat(p, b);
    if (p && r == 0 && g_fs2_used < 400) {
        aialog("FS stat OK  %s caller=%s", p, caller_desc(__builtin_return_address(0)));
        g_fs2_used++;
    }
    return r;
}
static void install_fs_only(void) {
    MSHookFunction((void *)access, (void *)fs2_access, (void **)&fs2_orig_access);
    MSHookFunction((void *)lstat, (void *)fs2_lstat, (void **)&fs2_orig_lstat);
    MSHookFunction((void *)stat, (void *)fs2_stat, (void **)&fs2_orig_stat);
    log_raw("FS-only probe installed\n");
}
#else
__attribute__((unused)) static void install_fs_only(void) {}
#endif

#if AIA_EXCPORT_PROBE
// RASP 常用手法：查询任务的异常端口，看有没有被第三方接管。
// 这里只记录，不改变返回值。
static kern_return_t (*ep_orig_get)(task_t, exception_mask_t, exception_mask_array_t,
                                    mach_msg_type_number_t *, exception_handler_array_t,
                                    exception_behavior_array_t, exception_flavor_array_t);
static kern_return_t ep_get(task_t task, exception_mask_t mask, exception_mask_array_t masks,
                            mach_msg_type_number_t *cnt, exception_handler_array_t handlers,
                            exception_behavior_array_t behs, exception_flavor_array_t flavs) {
    kern_return_t kr = ep_orig_get(task, mask, masks, cnt, handlers, behs, flavs);
    static int n;
    if (n < 20) {
        char b[192];
        snprintf(b, sizeof(b), "EPQUERY mask=%#x -> kr=%d cnt=%u caller=%s\n", mask, kr,
                 cnt ? *cnt : 0, caller_desc(__builtin_return_address(0)));
        log_raw(b);
        n++;
    }
    return kr;
}
static void install_excport_probe(void) {
    MSHookFunction((void *)task_get_exception_ports, (void *)ep_get, (void **)&ep_orig_get);
    log_raw("EPQUERY probe installed\n");
}
#else
__attribute__((unused)) static void install_excport_probe(void) {}
#endif

#if AIA_CSOPS_PROBE
// 越狱进程的代码签名状态与正常进程不同（常见：CS_VALID 缺失、CS_DEBUGGED 存在）。
// 很多 RASP 直接读 csops 判定。这里只记录，暴露 JM 看到的标志位。
static int (*cs_orig_csops)(pid_t, unsigned int, void *, size_t);
static int cs_csops(pid_t pid, unsigned int ops, void *addr, size_t size) {
    int r = cs_orig_csops(pid, ops, addr, size);
    static int n;
    if (n < 30) {
        char b[192];
        unsigned v = 0;
        if (addr && size >= 4) memcpy(&v, addr, 4);
        snprintf(b, sizeof(b), "CSOPS pid=%d ops=%#x -> %d val=%#x caller=%s\n", pid, ops, r, v,
                 caller_desc(__builtin_return_address(0)));
        log_raw(b);
        n++;
    }
    return r;
}
static void install_csops_probe(void) {
    void *f = dlsym(RTLD_DEFAULT, "csops");
    if (f) MSHookFunction(f, (void *)cs_csops, (void **)&cs_orig_csops);
    log_raw(f ? "CSOPS probe installed\n" : "CSOPS symbol not found\n");
}
#else
__attribute__((unused)) static void install_csops_probe(void) {}
#endif

#if AIA_ENV_PROBE
// 注入基座会把 DYLD_INSERT_LIBRARIES 一类的变量留在进程环境里，
// 这是最经典的"被注入"信号。这里只记录 JM 相关线程查了哪些键。
static char *(*env_orig_getenv)(const char *);
static int g_env_used;
static char *env_getenv(const char *k) {
    char *v = env_orig_getenv(k);
    if (k && g_env_used < 60) {
        const char *c = caller_desc(__builtin_return_address(0));
        if (strstr(c, "JMCodeProtectKit") || strstr(c, "KYHAppStore")) {
            aialog("GETENV %s -> %s caller=%s", k, v ? v : "(null)", c);
            g_env_used++;
        }
    }
    return v;
}
static int (*env_orig_sysctl)(int *, unsigned, void *, size_t *, void *, size_t);
static int g_sys_used;
static int env_sysctl(int *name, unsigned n, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = env_orig_sysctl(name, n, oldp, oldlenp, newp, newlen);
    if (g_sys_used < 60 && name) {
        const char *c = caller_desc(__builtin_return_address(0));
        if (strstr(c, "JMCodeProtectKit") || strstr(c, "KYHAppStore")) {
            aialog("SYSCTL [%d,%d] -> %d caller=%s", name[0], n > 1 ? name[1] : -1, r, c);
            g_sys_used++;
        }
    }
    return r;
}
static void install_env_probe(void) {
    MSHookFunction((void *)getenv, (void *)env_getenv, (void **)&env_orig_getenv);
    MSHookFunction((void *)sysctl, (void *)env_sysctl, (void **)&env_orig_sysctl);
    log_raw("ENV probe installed\n");
}
#else
__attribute__((unused)) static void install_env_probe(void) {}
#endif

#if AIA_PROC_FILTER
// JM 在 JM+0x187d60 调 sysctl([CTL_KERN, KERN_PROC_ALL]) 枚举全进程。
// 越狱设备上这里有 Sileo、jailbreakd、sshd 这类明确的越狱进程，
// 是被判定为越狱最直接的证据。
//
// 这里在系统调用返回后把这些进程项整体清零。不改数组长度，只把命中的
// kinfo_proc 抹成 0，调用方遍历到的就是一个 comm 为空的项。
// 项大小不写死：先用 KERN_PROC_PID 查一次单个进程，返回值长度就是项大小。
static int proc_entry_size(void) {
    static int cached;
    if (cached > 0) return cached;
    int mib[4] = { CTL_KERN, KERN_PROC, 4 /* KERN_PROC_PID */, (int)getpid() };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) == 0 && len > 0) cached = (int)len;
    return cached;
}

static BOOL proc_name_suspicious(const char *nm) {
    static const char *keys[] = {
        "Sileo", "Cydia", "Zebra", "jailbreakd", "sshd", "dropbear", "frida",
        "cycript", "bash", "apt", "dpkg", "injector", "ellekit", "systemhook",
        "libhooker", "SileoDemo", "NewTerm", "Filza", "Crane", "Choicy",
    };
    if (!nm || !*nm) return NO;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
        if (strstr(nm, keys[k])) return YES;
    return NO;
}

// 在单个条目里找任意位置的 C 字符串命中，命中即整条清零。
static int proc_filter_entries(void *buf, size_t len) {
    int esz = proc_entry_size();
    if (esz <= 0 || !buf || len < (size_t)esz) return 0;
    int hit = 0;
    size_t n = len / (size_t)esz;
    for (size_t i = 0; i < n; i++) {
        unsigned char *e = (unsigned char *)buf + i * (size_t)esz;
        BOOL bad = NO;
        for (int off = 0; off + 4 < esz && !bad; off++) {
            if (proc_name_suspicious((const char *)e + off)) bad = YES;
        }
        if (bad) { memset(e, 0, (size_t)esz); hit++; }
    }
    return hit;
}

static int (*pf_orig_sysctl)(int *, unsigned, void *, size_t *, void *, size_t);
static int pf_sysctl(int *name, unsigned n, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = pf_orig_sysctl(name, n, oldp, oldlenp, newp, newlen);
    if (r == 0 && name && n >= 3 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == 0 /* KERN_PROC_ALL */ && oldp && oldlenp && *oldlenp > 0) {
        int hit = proc_filter_entries(oldp, *oldlenp);
        static int diag;
        if (diag < 2) {
            char b[256];
            int esz = proc_entry_size();
            const char *raw = (const char *)oldp;
            int hasS = 0, hasJ = 0, hasSh = 0;
            for (size_t k = 0; k + 8 < *oldlenp; k++) {
                if (!hasS && memcmp(raw + k, "Sileo", 5) == 0) hasS = 1;
                if (!hasJ && memcmp(raw + k, "jailbreakd", 10) == 0) hasJ = 1;
                if (!hasSh && memcmp(raw + k, "sshd", 4) == 0) hasSh = 1;
            }
            snprintf(b, sizeof(b),
                     "PROCDIAG len=%zu esz=%d n=%zu hit=%d Sileo=%d jailbreakd=%d sshd=%d\n",
                     *oldlenp, esz, esz > 0 ? *oldlenp / (size_t)esz : 0, hit, hasS, hasJ, hasSh);
            log_raw(b);
            diag++;
        }
        static int logged;
        if (hit > 0 && logged < 6) {
            aialog("PROCFILTER 清掉 %d 个进程项 caller=%s", hit,
                   caller_desc(__builtin_return_address(0)));
            logged++;
        }
    }
    return r;
}
static void install_proc_filter(void) {
    MSHookFunction((void *)sysctl, (void *)pf_sysctl, (void **)&pf_orig_sysctl);
    log_raw("PROCFILTER installed\n");
    // 自检：直接问内核要一次全进程列表，确认这些进程真的能被看到。
    // 若不出现，说明隐藏它们并不是有效的杠杆，不必再往这个方向投入。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{
        int mib[3] = { CTL_KERN, KERN_PROC, 0 };
        size_t len = 0;
        int qr = pf_orig_sysctl(mib, 3, NULL, &len, NULL, 0);
        if (qr != 0 || len == 0) {
            char e[128];
            snprintf(e, sizeof(e), "PROCSELF 查询失败 r=%d errno=%d len=%zu\n",
                     qr, errno, len);
            log_raw(e);
            return;
        }
        void *buf = malloc(len);
        if (!buf) return;
        if (pf_orig_sysctl(mib, 3, buf, &len, NULL, 0) != 0) { free(buf); return; }
        int esz = proc_entry_size();
        int nS = 0, nJ = 0, nSh = 0;
        for (size_t k = 0; k + 12 < len; k++) {
            const char *c = (const char *)buf + k;
            if (memcmp(c, "Sileo", 5) == 0) nS++;
            if (memcmp(c, "jailbreakd", 10) == 0) nJ++;
            if (memcmp(c, "sshd", 4) == 0) nSh++;
        }
        char b[192];
        snprintf(b, sizeof(b), "PROCSELF len=%zu esz=%d Sileo=%d jailbreakd=%d sshd=%d\n",
                 len, esz, nS, nJ, nSh);
        log_raw(b);
        free(buf);
    });
}
#else
__attribute__((unused)) static void install_proc_filter(void) {}
#endif

#if AIA_MSGSEND_PROBE
// 处决现场的共同形状：x0=4、x1=+[NSThread isMainThread]、pc=lr=0x8，
// 也就是"向一个非法接收者发消息"。这里在 objc_msgSend 入口检查接收者，
// 只要它不是一个合法的指针（低于 0x10000），就把发送者记下来。
// 记录是次要目的；主要目的是让这次消息直接返回 nil，使线程不跳飞。
static int g_msg_hits;
static int (*orig_msg_send)(id, SEL, ...);

__attribute__((noinline, used)) static id aia_msg_send_probe(id self, SEL _cmd, ...) {
    if ((uintptr_t)self < 0x10000) {
        if (g_msg_hits < 30) {
            char b[224];
            snprintf(b, sizeof(b), "MSGSEND self=%#lx sel=%s caller=%s\n",
                     (unsigned long)self, _cmd ? sel_getName(_cmd) : "?",
                     caller_desc(__builtin_return_address(0)));
            log_raw(b);
            g_msg_hits++;
        }
        return nil;
    }
    return ((id (*)(id, SEL))orig_msg_send)(self, _cmd);
}

static void install_msgsend_probe(void) {
    MSHookFunction((void *)objc_msgSend, (void *)aia_msg_send_probe, (void **)&orig_msg_send);
    log_raw("MSGSEND probe installed\n");
}
#else
__attribute__((unused)) static void install_msgsend_probe(void) {}
#endif

#if AIA_CHECK_TRACE
// JM 的检查调度循环（JM+0x11a708 一带）对每个检查项调用 0x14fc40 求值：
//   x0 = 上下文, x1 = 检查项 + 0x48, x2 = 另一上下文,
//   x3/x4 = 成对参数, x5 = 参数
// 在这里把每一项的原始字节打出来，就能拿到"它到底在查什么"的清单。
static uint64_t (*ct_orig)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static int g_ct_n;

__attribute__((noinline, used)) static uint64_t ct_entry(uint64_t x0, uint64_t x1, uint64_t x2,
                                                          uint64_t x3, uint64_t x4, uint64_t x5) {
    if (g_ct_n < 120) {
        char b[512];
        size_t n = 0;
        n += (size_t)snprintf(b, sizeof(b), "CHECK #%d x1=%#llx x0=%#llx x2=%#llx x3=%#llx x5=%#llx |",
                              g_ct_n, (unsigned long long)x1, (unsigned long long)x0,
                              (unsigned long long)x2, (unsigned long long)x3,
                              (unsigned long long)x5);
        for (int k = 0; k < 6 && n < sizeof(b) - 24; k++) {
            uintptr_t w = 0;
            if (!safe_read((uintptr_t)x1 + (uintptr_t)k * 8, &w)) break;
            n += (size_t)snprintf(b + n, sizeof(b) - n, " %lx", (unsigned long)w);
        }
        snprintf(b + n, sizeof(b) - n, "\n");
        log_raw(b);
        // 前几个项的邻近字节里若出现可打印串，也记下来。
        for (int k = 0; k < 4; k++) {
            uintptr_t p = 0;
            if (!safe_read((uintptr_t)x1 + (uintptr_t)k * 8, &p)) break;
            char s2[256];
            size_t m = 0;
            int printable = 1;
            for (int j = 0; j < 48; j++) {
                uintptr_t cb = 0;
                if (!safe_read(p + (uintptr_t)j, &cb)) { printable = 0; break; }
                char c = (char)(cb & 0xff);
                if (c == 0) break;
                if (c < 0x20 || c > 0x7e) { printable = 0; break; }
                s2[m++] = c;
            }
            if (printable && m >= 4) {
                s2[m] = 0;
                char b2[320];
                snprintf(b2, sizeof(b2), "  CHECKSTR #%d [%d] \"%s\"\n", g_ct_n, k, s2);
                log_raw(b2);
            }
        }
        g_ct_n++;
    }
    uint64_t rv = ct_orig(x0, x1, x2, x3, x4, x5);
    if (g_ct_n <= 130) {
        char rb[512];
        uintptr_t bo = 0;
        const char *bm = module_for(x2, &bo);
        uintptr_t o0 = 0, o1 = 0, o2 = 0, o3 = 0;
        safe_read((uintptr_t)rv, &o0);
        safe_read((uintptr_t)rv + 8, &o1);
        safe_read((uintptr_t)rv + 0x10, &o2);
        safe_read((uintptr_t)rv + 0x18, &o3);
        snprintf(rb, sizeof(rb), "  CHKRET %s+0x%lx -> %#llx [%lx %lx %lx %lx]\n",
                 bm ? bm : "?", (unsigned long)bo, (unsigned long long)rv,
                 (unsigned long)o0, (unsigned long)o1, (unsigned long)o2, (unsigned long)o3);
        log_raw(rb);
    }
    return rv;
}

static void install_check_trace(void) {
    uintptr_t jm = module_base_for("JMCodeProtectKit", NULL);
    if (!jm) { log_raw("CHECKTRACE no JM base\n"); return; }
    MSHookFunction((void *)(jm + 0x14fc40), (void *)ct_entry, (void **)&ct_orig);
    log_raw("CHECKTRACE installed\n");
}
#else
__attribute__((unused)) static void install_check_trace(void) {}
#endif

#if AIA_GOT_AUDIT
// JM 的检查项是各框架 __got / __la_symbol_ptr 的完整性。
// 这里自己走一遍：把每个 App 内嵌框架的这两个节逐项检查，
// 看有没有条目指向越狱注入库（systemhook / libinjector / libellekit / 我们自己的 dylib）。
// 若有，那就是 JM 判定的直接依据，修法也明确：把条目还原。
static BOOL addr_in_jb(const char *mod) {
    if (!mod) return NO;
    return strstr(mod, "systemhook") || strstr(mod, "libinjector") ||
           strstr(mod, "libellekit") || strstr(mod, "ellekit") ||
           strstr(mod, "AIABypass") || strstr(mod, "TweakInject") ||
           strstr(mod, "procursus") || strstr(mod, "preboot");
}

static void got_audit(void) {
    uint32_t nimg = _dyld_image_count();
    int hits = 0, imgs = 0;
    char b[288];
    for (uint32_t i = 0; i < nimg; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *nm = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh || mh->magic != 0xfeedfacf) continue;
        // 只审 App 内嵌框架与主二进制。
        if (!nm || !strstr(nm, "KYHAppStore.app")) continue;
        imgs++;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0) break;
            if (lc->cmd == 0x19 /* LC_SEGMENT_64 */) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                const struct section_64 *sc = (const struct section_64 *)(sg + 1);
                uint32_t ns = sg->nsects;
                for (uint32_t k = 0; k < ns; k++, sc++) {
                    const char *sect = sc->sectname;
                    if (strncmp(sect, "__got", 6) != 0 &&
                        strncmp(sect, "__la_symbol_ptr", 16) != 0 &&
                        strncmp(sect, "__auth_got", 11) != 0) continue;
                    if (sc->size < 8) continue;
                    uintptr_t base = (uintptr_t)(sc->addr + (uint64_t)slide);
                    // rebase 表的项里存的是没签名的指针，直接读会有 PAC 高位，用 aia_real_ptr 还原。
                    for (uint64_t off = 0; off + 8 <= sc->size; off += 8) {
                        uintptr_t v = 0;
                        if (!safe_read(base + off, &v)) break;
                        uintptr_t real = 0, vo = 0;
                        const char *vm = aia_real_ptr(v, &real, &vo);
                        if (!vm) continue;
                        if (!addr_in_jb(vm)) continue;
                        if (hits < 40) {
                            const char *fn = strrchr(nm, '/');
                            snprintf(b, sizeof(b),
                                     "GOTHIT %s %s+0x%llx raw=%#llx -> %s+0x%lx\n",
                                     fn ? fn + 1 : nm, sect, (unsigned long long)off,
                                     (unsigned long long)v, vm, (unsigned long)vo);
                            log_raw(b);
                            // 跳板的真实机器码在运行时才生成。顺它找到原始函数：
                            // 常见形状是 ldr x16,[pc,#..] / br x16，数据页里存的是原函数地址。
                            uint32_t w[10] = {0};
                            size_t n = 0;
                            char lb[256];
                            n += (size_t)snprintf(lb, sizeof(lb), "  TRAMP:");
                            for (int q = 0; q < 10; q++) {
                                if (!safe_read(real + (uintptr_t)q * 4, (uintptr_t *)&w[q])) break;
                                n += (size_t)snprintf(lb + n, sizeof(lb) - n, " %08x", w[q]);
                            }
                            snprintf(lb + n, sizeof(lb) - n, "\n");
                            log_raw(lb);
                        }
                        hits++;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    uintptr_t ab = 0, sb = 0;
    for (int i = 0; i < g_mod_count; i++) {
        if (g_mods[i].name && strstr(g_mods[i].name, "KYHAppStore.app/KYHAppStore")) ab = g_mods[i].base;
        if (g_mods[i].name && strstr(g_mods[i].name, "systemhook")) sb = g_mods[i].base;
    }
    snprintf(b, sizeof(b), "GOTHIT 汇总：审了 %d 个 App 镜像，命中 %d 条 appBase=%#lx shBase=%#lx\n",
             imgs, hits, (unsigned long)ab, (unsigned long)sb);
    log_raw(b);
}
#else
__attribute__((unused)) static void got_audit(void) {}
#endif

#if AIA_GOT_RESTORE
// 还原实验：把被 systemhook 改写过、指向越狱库的 GOT 槽改回去。
// __got 里那 5 个槽在磁盘上就是 0，直接清零；__la_symbol_ptr 里的 _dlopen
// 换回 dyld 解析出的真实地址。改完看 JM 是否还处决。
static void install_got_restore_dlsym(void) { }

#if AIA_GOT_RESTORE
// 自己走 nlist 找符号的真实地址。不能用 dlsym：它已经被 systemhook 挂过，
// 返回的是 systemhook 的跳板，拿它去还原等于没还原。
static uintptr_t aia_lookup_clean_symbol(const char *want) {
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *nm = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh || mh->magic != 0xfeedfacf || !nm) continue;
        if (strstr(nm, "systemhook") || strstr(nm, "ellekit") || strstr(nm, "injector")) continue;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        const struct symtab_command *st = NULL;
        const struct segment_command_64 *le = NULL;
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0) break;
            if (lc->cmd == 0x2) st = (const struct symtab_command *)lc;
            if (lc->cmd == 0x19) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                if (strncmp(sg->segname, "__LINKEDIT", 11) == 0) le = sg;
            }
            p += lc->cmdsize;
        }
        if (!st || !le || le->filesize == 0) continue;
        // 表偏移是相对于所在文件的；共享缓存里的镜像要把偏移换算成缓存内的地址，
        // 不能直接按镜像头加，否则会读到未映射区域。
        if (st->symoff < le->fileoff || st->symoff >= le->fileoff + le->filesize) continue;
        if (st->stroff < le->fileoff || st->stroff >= le->fileoff + le->filesize) continue;
        if ((uint64_t)st->nsyms * 16 > le->filesize) continue;
        const struct nlist_64 *nl = (const struct nlist_64 *)((uintptr_t)le->vmaddr + (uint64_t)slide
                                                              + (st->symoff - le->fileoff));
        const char *strs = (const char *)((uintptr_t)le->vmaddr + (uint64_t)slide
                                          + (st->stroff - le->fileoff));
        for (uint32_t k = 0; k < st->nsyms; k++) {
            if ((nl[k].n_type & 0x0e) != 0x0e) continue;
            if (nl[k].n_un.n_strx == 0 || nl[k].n_un.n_strx >= st->strsize) continue;
            if (strcmp(strs + nl[k].n_un.n_strx, want) != 0) continue;
            return (uintptr_t)(nl[k].n_value + (uint64_t)slide);
        }
    }
    return 0;
}
#endif

static void got_restore(void) {
    uint32_t nimg = _dyld_image_count();
    int fixed = 0;
    for (uint32_t i = 0; i < nimg; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *nm = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!mh || mh->magic != 0xfeedfacf) continue;
        if (!nm || !strstr(nm, "KYHAppStore.app")) continue;
        const uint8_t *p = (const uint8_t *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0) break;
            if (lc->cmd != 0x19) { p += lc->cmdsize; continue; }
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            const struct section_64 *sc = (const struct section_64 *)(sg + 1);
            for (uint32_t k = 0; k < sg->nsects; k++, sc++) {
                BOOL is_got = strncmp(sc->sectname, "__got", 6) == 0;
                BOOL is_la = strncmp(sc->sectname, "__la_symbol_ptr", 16) == 0;
                if ((!is_got && !is_la) || sc->size < 8) continue;
                uintptr_t base = (uintptr_t)(sc->addr + (uint64_t)slide);
                vm_protect(mach_task_self(), (vm_address_t)(base & ~0xFFFULL),
                           (vm_size_t)(sc->size + 0x2000), FALSE,
                           VM_PROT_READ | VM_PROT_WRITE);
                for (uint64_t off = 0; off + 8 <= sc->size; off += 8) {
                    uintptr_t v = 0;
                    if (!safe_read(base + off, &v)) break;
                    uintptr_t real = 0, vo = 0;
                    const char *vm = aia_real_ptr(v, &real, &vo);
                    if (!vm || !addr_in_jb(vm)) continue;
                    if (is_got && !AIA_GOT_RESTORE_GOT) continue;
                    // 主二进制只导入了 dlopen、dlopen_preflight、fork、posix_spawn、
                    // pthread_atfork、vfork 这几个相关符号；systemhook 把它们换成了
                    // 自己的实现。按偏移把槽映射回符号名，再解析未被劫持的地址。
                    const char *sym = NULL;
                    if (is_la) sym = "_dlopen";
                    else if (strstr(vm, "systemhook")) {
                        switch (vo) {
                            case 0x6ad8: sym = "_dlopen"; break;
                            case 0x6bd0: sym = "_dlopen_preflight"; break;
                            case 0x65a8: sym = "_posix_spawn"; break;
                            case 0x6eb0: sym = "_fork"; break;
                            case 0x6f0c: sym = "_vfork"; break;
                            default: break;
                        }
                    }
                    uintptr_t nv = sym ? aia_lookup_clean_symbol(sym) : 0;
                    if (nv == 0) continue;
                    *(volatile uintptr_t *)(base + off) = nv;
                    char b[192];
                    snprintf(b, sizeof(b), "GOTRESTORE %s %s+0x%llx %#llx -> %#llx\n",
                             strrchr(nm, '/') ? strrchr(nm, '/') + 1 : nm,
                             sc->sectname, (unsigned long long)off,
                             (unsigned long long)v, (unsigned long long)nv);
                    log_raw(b);
                    fixed++;
                }
            }
            p += lc->cmdsize;
        }
    }
    char b[96];
    snprintf(b, sizeof(b), "GOTRESTORE 完成，还原 %d 个槽\n", fixed);
    log_raw(b);
}
#else
__attribute__((unused)) static void got_restore(void) {}
#endif

#if AIA_GOT_AUDIT
// 槽里存的是 systemhook 的地址。systemhook 对自己挂过的符号会返回同一个地址，
// 所以逐个 dlsym 候选符号并比对，就能把这 5 个槽对应到具体函数名。
static void slot_symbol_match(void) {
    static const char *cands[] = {
        "open", "openat", "stat", "stat64", "lstat", "lstat64", "fstatat", "fstatat64",
        "access", "getenv", "sysctl", "csops", "csops_audittoken", "dlopen", "dlsym",
        "posix_spawn", "execve", "readlink", "opendir", "readdir", "closedir", "mkdir",
        "unlinkat", "select", "statfs", "arc4random", "rand", "ptrace", "fork", "vfork",
        "canopen", "getpid", "getppid", "proc_pidpath", "sscanf",
        "execv", "execvp", "execle", "execl", "posix_spawnp", "system", "popen",
        "kill", "task_for_pid", "thread_get_state", "syscall", "ptrace",
        "mach_vm_read_overwrite", "vm_read_overwrite", "mach_vm_protect",
        "csops_audittoken", "task_info", "thread_info", "proc_info", NULL
    };
    for (int i = 0; cands[i]; i++) {
        void *a = dlsym(RTLD_DEFAULT, cands[i]);
        if (!a) continue;
        uintptr_t o = 0;
        const char *m = module_for((uintptr_t)a, &o);
        char b[192];
        snprintf(b, sizeof(b), "SLOTSYM %s -> %s+0x%lx\n", cands[i], m ? m : "?", (unsigned long)o);
        log_raw(b);
    }
}
#else
__attribute__((unused)) static void slot_symbol_match(void) {}
#endif

#if AIA_BLOCK_LITEHOOK
// JM 的检查项是各 App 镜像 __got / __la_symbol_ptr 的完整性。
// systemhook 通过自己导出的 _litehook_apply_global_rebinds 把钩子地址写进这些槽，
// 于是主二进制的 GOT 里会留下直接指向 /usr/lib/systemhook.dylib 的条目——
// 这就是 JM 能看到的越狱证据。
// 这里把这个函数顶成空操作，让重绑定不再发生。
static int (*lh_orig_apply_all)(void *);
static int lh_apply_all(void *hooks) {
    static int n;
    if (n < 5) { aialog("LITEHOOK block apply_global_rebinds(%p)", hooks); n++; }
    return 0;
}
static int (*lh_orig_apply_one)(void *, const char *);
static int lh_apply_one(void *img, const char *sym) {
    static int n;
    if (n < 20) { aialog("LITEHOOK block rebind %s", sym ? sym : "?"); n++; }
    return 0;
}
static void install_litehook_block(void) {
    void *f1 = dlsym(RTLD_DEFAULT, "_litehook_apply_global_rebinds");
    void *f2 = dlsym(RTLD_DEFAULT, "_litehook_rebind_symbol_in_section");
    if (f1) MSHookFunction(f1, (void *)lh_apply_all, (void **)&lh_orig_apply_all);
    if (f2) MSHookFunction(f2, (void *)lh_apply_one, (void **)&lh_orig_apply_one);
    char b[192];
    snprintf(b, sizeof(b), "LITEHOOK rebinds=%p one=%p\n", f1, f2);
    log_raw(b);
}
#else
__attribute__((unused)) static void install_litehook_block(void) {}
#endif

static void log_backtrace(const char *tag) {
    void *frames[32];
    int n = backtrace(frames, 32);
    if (n <= 0) return;
    char **syms = backtrace_symbols(frames, n);
    if (!syms) return;
    aialog("%s bt(%d):", tag, n);
    for (int i = 0; i < n; i++) aialog("    %s", syms[i]);
    free(syms);
}

static void (*orig_exit)(int);
static void my_exit(int code) {
    aialog("EXIT(%d) pid=%d caller=%s", code, getpid(), caller_desc(__builtin_return_address(0)));
    log_backtrace("EXIT");
#if AIA_BLOCK_EXIT
    if (code == 1) { aialog("EXIT blocked"); return; }
#endif
    orig_exit(code);
}

static void (*orig_Exit)(int);
static void my_Exit(int code) {
    aialog("_EXIT(%d) pid=%d caller=%s", code, getpid(), caller_desc(__builtin_return_address(0)));
    log_backtrace("_EXIT");
#if AIA_BLOCK_EXIT
    if (code == 1) { aialog("_EXIT blocked"); return; }
#endif
    orig_Exit(code);
}

static void (*orig_abort)(void);
static void my_abort(void) {
    aialog("ABORT pid=%d", getpid());
    log_backtrace("ABORT");
    orig_abort();
}

static int (*orig_kill)(pid_t, int);
static int my_kill(pid_t pid, int sig) {
    aialog("KILL(pid=%d sig=%d) self=%d", pid, sig, getpid());
    if (pid == getpid()) log_backtrace("KILL");
    return orig_kill(pid, sig);
}

static void (*orig_pthread_exit)(void *);
static void my_pthread_exit(void *ret) {
    aialog("PTHREAD_EXIT");
    log_backtrace("PTHREAD_EXIT");
    orig_pthread_exit(ret);
}


// ============================================================
// MARK: 自建 Mach 异常处理器（抢占 ellekit 的异常端口）
// ============================================================

#if AIA_EXC_HANDLER

// EXCEPTION_STATE_IDENTITY + MACH_EXCEPTION_CODES 对应 mach_exception_raise_state_identity
// （msgh_id 2407）。消息里同时带 thread/task 端口和完整线程状态。
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
} exc_req_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[128];
} exc_reply_t;

// 回复消息线上头部固定 40 字节：Head(24) + NDR(8) + RetCode(4) + new_stateCnt(4)。
// 旧代码写成 8+8+4+4 = 24，少发 16 字节，内核拒收回复，断点异常随即以
// SIGTRAP 重新投递到同一个 PC，进程照样死。
#define EXC_REPLY_HDR_SIZE 40

static mach_port_t g_exc_port = MACH_PORT_NULL;

static uintptr_t app_base(void);

#if AIA_UNWIND_BINDER_BRK
// ijm 导入绑定器 KYHAppStore+0x7c5508 在失败时走到 +0x7c55f8 的 brk #0xdead。
// 它是个尾调用型桩：进入后先把 x15..x28 成对压到原 sp 下方 0x70 字节，
// 再把 nzcv 存到原 sp+0x10，然后用 sub sp,sp,#0x130 开工作区。
// 正常收尾在 0x7c55c0：逐对恢复 x27..x15，从原 sp+0x10 读 nzcv，最后 br 到 import 实现。
// 失败时没有可用的 import 实现，这里照抄同一套恢复，但把返回地址换成调用者的 lr、
// 把 x0 置 0，等价于这个导入返回 nil。
static int binder_brk_unwind(arm_thread_state64_t *st) {
    uintptr_t base = app_base();
    if (!base) return 0;
    uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*st);
    if (pc != base + 0x7c55f8) return 0;
    uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(*st);
    if (!sp) return 0;
    uintptr_t fs = sp + 0x130;          // 绑定器压栈后的 sp
    uintptr_t frame[7][2];
    for (int i = 0; i < 7; i++) {
        if (!safe_read(fs + (uintptr_t)i * 0x10, &frame[i][0])) return 0;
        if (!safe_read(fs + (uintptr_t)i * 0x10 + 8, &frame[i][1])) return 0;
    }
    uintptr_t nzcv = 0;
    if (!safe_read(fs + 0x80, &nzcv)) return 0;
    uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(*st);
    if (!lr) return 0;
    for (int i = 0; i < 7; i++) {
        st->__x[27 - i * 2] = (uint64_t)frame[i][0];
        st->__x[28 - i * 2] = (uint64_t)frame[i][1];
    }
    st->__cpsr = (uint32_t)((st->__cpsr & ~0xf0000000u) | (uint32_t)(nzcv & 0xf0000000u));
    st->__x[0] = 0;
    __darwin_arm_thread_state64_set_sp(*st, (void *)(fs + 0x70));
    __darwin_arm_thread_state64_set_pc_fptr(*st, (void *)lr);
    return 1;
}
#endif
// 消息线上 port descriptor 是 12 字节，和结构体里的 16 字节不一致，
// 所以这里全部按显式字节偏移解析，避免被编译器的对齐填充带偏。
// mach_exception_raise_state_identity 布局：
//   0 header(24) | 24 descriptor_count(4) | 28 thread(12) | 40 task(12)
//   52 NDR(8) | 60 exception(4) | 64 codeCnt(4) | 68 code[2](16)
//   84 flavor(4) | 88 old_stateCnt(4) | 92 old_state
#define EXC_HDR 0
#define EXC_THREAD_OFF 28
#define EXC_TASK_OFF 40
#define EXC_NDR_OFF 52
#define EXC_TYPE_OFF 60
#define EXC_CODECNT_OFF 64
#define EXC_CODE_OFF 68
#define EXC_FLAVOR_OFF 84
#define EXC_STATE_OFF 88
#define EXC_STATE_BODY_OFF 92

// arm64e 的返回地址和帧指针带 PAC 签名。大多数指针的签名在最高 16 位，
// 掩码就够了；但也有把签名混进更高位的情况（实测见过 lr=0x61746d81c1f35be8，
// 真实地址是 0x1c1f35be8）。那种情况下单纯掩码会得到错误地址，于是本该能恢复的
// 主线程被判成"返回地址无效"而挂起——这正是"App 内卡死"的直接原因。
// 优先用编译器内建函数，它按签名密钥正确地剥掉签名。
__attribute__((unused)) static inline uintptr_t aia_strip_pac(uintptr_t v) {
    uintptr_t t = v & 0x0000FFFFFFFFFFFFULL;
    if (t & 0x0000800000000000ULL) t |= 0xFFFF000000000000ULL;
    return t;
}

// 在已知模块表里找出这个指针真正指向哪里。
// 混合签名的指针用掩码剥不干净（签名渗进了 bit32 以上），但低 32 位始终是
// 真实地址的低半部分。iOS 用户态镜像都落在 0x1_00000000 … 0x3_00000000 之间，
// 所以拿低 32 位配上这几个高位段逐个试，命中即说明这个指针是可用的代码地址。
// 与 aia_module_for_ptr 相同，但把重建出的无签名地址一并交出。
// 栈上和帧链里存的返回地址都带 PAC，必须先用它还原，否则一律识别失败，
// 这正是之前栈扫描和帧链几乎打不出东西的原因。
static const char *aia_real_ptr(uintptr_t v, uintptr_t *real_out, uintptr_t *off_out) {
    uintptr_t t = aia_strip_pac(v);
    uintptr_t o = 0;
    const char *m = module_for(t, &o);
    if (m && o) {
        if (real_out) *real_out = t;
        if (off_out) *off_out = o;
        return m;
    }
    uintptr_t lo = v & 0xFFFFFFFFULL;
    for (uintptr_t hi = 0x1; hi <= 0x3; hi++) {
        uintptr_t c = (hi << 32) | lo;
        o = 0;
        m = module_for(c, &o);
        if (m && o) {
            if (real_out) *real_out = c;
            if (off_out) *off_out = o;
            return m;
        }
    }
    return NULL;
}

static const char *aia_module_for_ptr(uintptr_t v, uintptr_t *off_out) {
    uintptr_t cand = aia_strip_pac(v);
    const char *m = module_for(cand, off_out);
    if (m && *off_out) return m;
    uintptr_t lo = v & 0xFFFFFFFFULL;
    for (uintptr_t hi = 0x1; hi <= 0x3; hi++) {
        uintptr_t c = (hi << 32) | lo;
        uintptr_t o = 0;
        const char *mm = module_for(c, &o);
        if (mm && o) { *off_out = o; return mm; }
    }
    return NULL;
}

static uint64_t g_main_tid;
static volatile int g_evt_count;      // UIWindow sendEvent: 累计调用次数
static volatile int g_evt_touch;      // 其中触摸事件
// 每 5 秒记录一次：异常数量、线程数、Mach 端口名称数。
// 目的：区分"触摸失效"是资源累积耗尽，还是 JM 状态机被卡住。
static uint64_t thread_id_of(mach_port_t th);

// 主线程的 Mach 端口：从 task_threads 里找 tid 等于 mainTid 的那个。
static mach_port_t main_thread_port(void) {
    thread_act_array_t l = NULL;
    mach_msg_type_number_t n = 0;
    mach_port_t r = 0;
    if (task_threads(mach_task_self(), &l, &n) != KERN_SUCCESS) return 0;
    for (mach_msg_type_number_t k = 0; k < n; k++) {
        if (thread_id_of(l[k]) == g_main_tid) { r = l[k]; }
        else mach_port_deallocate(mach_task_self(), l[k]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)l, n * sizeof(thread_t));
    return r;
}

static void dump_jm_swizzles(void);
#if AIA_EVENT_PROBE
static void my_app_sendEvent(id self, SEL _cmd, UIEvent *ev);
#endif

__attribute__((unused)) static void *aia_stats(void *arg) {
    (void)arg;
    char b[192];
    for (int i = 0; i < 240; i++) {
        sleep(5);
        thread_act_array_t list = NULL;
        mach_msg_type_number_t cnt = 0;
        int nthreads = -1;
        if (task_threads(mach_task_self(), &list, &cnt) == KERN_SUCCESS) {
            nthreads = (int)cnt;
            for (mach_msg_type_number_t k = 0; k < cnt; k++) mach_port_deallocate(mach_task_self(), list[k]);
            vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(mach_port_t));
        }
        mach_port_name_array_t names = NULL;
        mach_msg_type_number_t ncnt = 0, ntypes = 0;
        mach_port_type_array_t types = NULL;
        int nports = -1;
        if (mach_port_names(mach_task_self(), &names, &ncnt, &types, &ntypes) == KERN_SUCCESS) {
            nports = (int)ncnt;
            vm_deallocate(mach_task_self(), (vm_address_t)names, ncnt * sizeof(mach_port_name_t));
            vm_deallocate(mach_task_self(), (vm_address_t)types, ntypes * sizeof(mach_port_type_t));
        }
        snprintf(b, sizeof(b), "STATS t=%ds exc=%d noreply=%d evt=%d touch=%d threads=%d ports=%d\n",
                 i * 5, g_exc_count, g_exc_noreply, g_evt_count, g_evt_touch, nthreads, nports);
        log_raw(b);
        {
            // ijm 绑定器的共享解析器槽。它在 __DATA 的零填充尾部，ctor 时读到 0；
            // 如果 JM 会在环境检查通过后填它，这里就能看到值随时间变化。
            uintptr_t ab = app_base();
            if (ab) {
                uint64_t s8 = 0, s0 = 0, s10 = 0, s18 = 0;
                safe_read(ab + 0x4058008, (uintptr_t *)&s8);
                safe_read(ab + 0x4058000, (uintptr_t *)&s0);
                safe_read(ab + 0x4058010, (uintptr_t *)&s10);
                safe_read(ab + 0x4058018, (uintptr_t *)&s18);
                snprintf(b, sizeof(b), "  RESV slot=%#llx b0=%#llx b10=%#llx b18=%#llx\n",
                         (unsigned long long)s8, (unsigned long long)s0,
                         (unsigned long long)s10, (unsigned long long)s18);
                log_raw(b);
            }
            {
                snprintf(b, sizeof(b), "  VM calls=%d bad=%d guarded=%d\n", g_vm_calls, g_vm_bad, g_vm_guarded);
                log_raw(b);
            }
            if ((i % 4) == 0) {
                // 端口被别的组件抢回去，故障就会绕过我们直接变成信号。
                log_exception_port_owners("tick");
            }
        }
        {
            // 直接读主线程 PC：判断"点不动"是不是主线程被阻塞。
            mach_port_t mt = main_thread_port();
            arm_thread_state64_t mst;
            mach_msg_type_number_t msc = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(mt, ARM_THREAD_STATE64, (thread_state_t)&mst, &msc) == KERN_SUCCESS) {
                uintptr_t mpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(mst);
                uintptr_t mlr = (uintptr_t)__darwin_arm_thread_state64_get_lr(mst);
                uintptr_t mo1 = 0, mo2 = 0;
                const char *m1 = module_for(mpc, &mo1);
                const char *m2 = module_for(mlr, &mo2);
                snprintf(b, sizeof(b), "  MAIN pc=%s+0x%lx lr=%s+0x%lx\n",
                         m1 ? m1 : "?", (unsigned long)mo1,
                         m2 ? m2 : "?", (unsigned long)mo2);
                log_raw(b);
            } else {
                log_raw("  MAIN getstate failed\n");
            }
        }
        if (i < 3 || i % 12 == 0) {
            // 事件入口是否还指着我们的实现；App 实际的 UIApplication 子类是什么。
            Class ac = objc_getClass("UIApplication");
            id app = ((id (*)(id, SEL))objc_msgSend)((id)ac, sel_registerName("sharedApplication"));
            Class realCls = app ? object_getClass(app) : Nil;
            Method m = ac ? class_getInstanceMethod(ac, sel_registerName("sendEvent:")) : NULL;
            IMP cur = m ? method_getImplementation(m) : NULL;
            uintptr_t mo = 0;
            const char *mn = cur ? module_for((uintptr_t)cur, &mo) : NULL;
            snprintf(b, sizeof(b), "  EVTCHK appCls=%s sendEventIMP=%s+0x%lx\n",
                     realCls ? class_getName(realCls) : "nil", mn ? mn : "?",
                     (unsigned long)mo);
            log_raw(b);
#if AIA_EVENT_PROBE
            if (i == 0) dump_jm_swizzles();
#endif
        }
    }
    return NULL;
}


// 观测事件入口：判断"点击无反应"时事件根本没送到 App，还是送到了但被丢弃。
static void (*orig_app_sendEvent)(id, SEL, UIEvent *);
__attribute__((unused)) static void my_app_sendEvent(id self, SEL _cmd, UIEvent *ev) {
    static int n;
    if (n < 200) {
        char b[160];
        snprintf(b, sizeof(b), "EVT UIApplication sendEvent type=%ld n=%d\n",
                 (long)ev.type, n + 1);
        log_raw(b);
        n++;
    }
    orig_app_sendEvent(self, _cmd, ev);
}

static void (*orig_win_sendEvent)(id, SEL, UIEvent *);
__attribute__((unused)) static void my_win_sendEvent(id self, SEL _cmd, UIEvent *ev) {
    static int n;
    g_evt_count++;
    if (ev && ev.type == UIEventTypeTouches) g_evt_touch++;
    if (n < 200) {
        char b[200];
        snprintf(b, sizeof(b), "EVT UIWindow sendEvent type=%ld win=%s n=%d\n",
                 (long)ev.type, object_getClassName(self), n + 1);
        log_raw(b);
        n++;
    }
    orig_win_sendEvent(self, _cmd, ev);
}

__attribute__((unused)) static void install_event_probe(void) {
    MSHookMessageEx(objc_getClass("UIApplication"),
                    @selector(sendEvent:), (IMP)my_app_sendEvent, (IMP *)&orig_app_sendEvent);
    MSHookMessageEx(objc_getClass("UIWindow"),
                    @selector(sendEvent:), (IMP)my_win_sendEvent, (IMP *)&orig_win_sendEvent);
    log_raw("event probe installed\n");
}

static void start_stats_thread(void) {
#if !AIA_DEBUG_LOG
    // 正式版不跑统计线程：它每 5 秒枚举线程与端口，纯为排查服务。
    return;
#endif
    static int started;
    if (started) return;
    started = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, aia_stats, NULL) == 0) pthread_detach(t);
}
#if AIA_EXC_BAIL
static void aia_thread_bail(void);
#endif
static uint64_t thread_id_of(mach_port_t th) {
    struct thread_identifier_info tii;
    mach_msg_type_number_t cnt = THREAD_IDENTIFIER_INFO_COUNT;
    if (thread_info(th, THREAD_IDENTIFIER_INFO, (thread_info_t)&tii, &cnt) != KERN_SUCCESS) return 0;
    return tii.thread_id;
}

static void dump_peer_threads(const char *tag, thread_t self_port);
static void dump_fault_state(exc_req_t *req) {
    char buf[256];
    const uint8_t *b = (const uint8_t *)req;
    int64_t code0 = 0, code1 = 0;
    memcpy(&code0, b + EXC_CODE_OFF, 8);
    memcpy(&code1, b + EXC_CODE_OFF + 8, 8);
    uint32_t codeCnt = *(const uint32_t *)(b + EXC_CODECNT_OFF);
    uint32_t flavor = *(const uint32_t *)(b + EXC_FLAVOR_OFF);
    uint32_t stateCnt = *(const uint32_t *)(b + EXC_STATE_OFF);
    int etype = (int)*(const uint32_t *)(b + EXC_TYPE_OFF);
    mach_port_t thrPort = *(const uint32_t *)(b + EXC_THREAD_OFF);
    mach_port_t tskPort = *(const uint32_t *)(b + EXC_TASK_OFF);
    uint64_t ftid = thread_id_of(thrPort);
    snprintf(buf, sizeof(buf),
             "EXCFAULT t=%llums main=%d thrId=%llu mainTid=%llu id=%d size=%u thr=%u task=%u type=%d codeCnt=%u code0=%lld code1=%lld flavor=%u stateCnt=%u\n",
             (unsigned long long)up_ms(), (int)(ftid && ftid == g_main_tid),
             (unsigned long long)ftid, (unsigned long long)g_main_tid,
             req->Head.msgh_id, req->Head.msgh_size, thrPort, tskPort, etype, codeCnt,
             (long long)code0, (long long)code1, flavor, stateCnt);
    log_raw(buf);
    if (flavor != 6 || stateCnt < 34) { log_raw("  (state 不可用)\n"); return; }
    arm_thread_state64_t st;
    memcpy(&st, b + EXC_STATE_BODY_OFF, sizeof(st));
    uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
    uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
    uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
    uintptr_t off = 0;
    const char *m = module_for(pc, &off);
    snprintf(buf, sizeof(buf), "  pc=%p(%s+0x%lx) lr=%p sp=%p\n", (void *)pc,
             m ? m : "?", (unsigned long)off, (void *)lr, (void *)sp);
    log_raw(buf);
    for (int i = 0; i < 29; i++) {
        uintptr_t v = (uintptr_t)st.__x[i];
        uintptr_t voff = 0;
        const char *vm = module_for(v, &voff);
        if (vm) {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx %s+0x%lx\n", i,
                     (unsigned long)v, vm, (unsigned long)voff);
        } else {
            snprintf(buf, sizeof(buf), "  x%-2d=%#018lx\n", i, (unsigned long)v);
        }
        log_raw(buf);
    }
    // 帧指针链：栈扫描会给出一堆陈旧值，帧链才是真实调用路径。
    // 主线程之外，凡 PC 落在任何模块之外（跳飞现场）也做一遍，
    // 用来回答"是谁把那根坏指针 blr 出去的"。
    uintptr_t pcv = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
    uintptr_t pcOff = 0;
    BOOL pcDangling = (module_for(pcv, &pcOff) == NULL);
    if (ftid && (ftid == g_main_tid || pcDangling)) {
        uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(st));
        for (int d = 0; d < 64 && fp; d++) {
            uintptr_t prev = 0, ra = 0;
            if (!safe_read(fp, &prev) || !safe_read(fp + 8, &ra)) break;
            uintptr_t po = 0, pReal = 0;
            const char *pm = aia_real_ptr(ra, &pReal, &po);
            if (pm) {
                snprintf(buf, sizeof(buf), "  FP#%02d %s+0x%lx ra=%#lx\n", d, pm,
                         (unsigned long)po, (unsigned long)ra);
                log_raw(buf);
            } else if (pcDangling) {
                snprintf(buf, sizeof(buf), "  FP#%02d ?+0x0 ra=%#lx\n", d, (unsigned long)ra);
                log_raw(buf);
            }
            // 帧指针指向栈，不带代码签名，48 位掩码就够；只有返回地址需要重建。
            prev = aia_strip_pac(prev);
            if (!prev || prev <= fp) break;
            fp = prev;
        }
    }
    // ijm VM 交叉现场：JMCodeProtectKit 的 VM（入口 JM+0x11ee28）拿到了主二进制
    // KYHAppStore 里 ijm 方法的描述符 0x7c5500，于是它的字节码游标变成 0x7c5504，
    // 解出 opcode 0xa2。JM 的分派表只有 107 项（JM+0x11ee78 到 JM+0x11f1d0），
    // 越界后把后面的代码字节当成表项，算出非法地址直接跳飞。
    // 现场布局（x0 = sp + 0x708）：
    //   [sp+0x750] VM 入参 x0 = 描述符 0x7c5500
    //   [sp+0x748] VM 入参 x1 = 上下文结构
    //   [sp+0x740] VM 入参 x2 = 0x7c558c
    // 把这些槽打出来，才能确认结构地址并判断能否安全恢复。
    {
        uintptr_t x0v = (uintptr_t)st.__x[0];
        if (x0v > sp && x0v - sp == 0x708) {
            static const size_t slots[] = { 0x110, 0x118, 0x698, 0x6a0,
                                            0x6b0, 0x6b8, 0x6c0, 0x6c8,
                                            0x740, 0x748, 0x750 };
            for (unsigned si = 0; si < sizeof(slots) / sizeof(slots[0]); si++) {
                uintptr_t v = 0;
                if (!safe_read(sp + slots[si], &v)) continue;
                uintptr_t voff2 = 0;
                const char *vm2 = module_for(v, &voff2);
                snprintf(buf, sizeof(buf), "  VMSLOT +0x%zx = %#018lx %s+0x%lx\n",
                         slots[si], (unsigned long)v, vm2 ? vm2 : "?",
                         (unsigned long)(vm2 ? voff2 : 0));
                log_raw(buf);
            }
        }
    }
    int found = 0;
    int main_thread = (ftid && ftid == g_main_tid);
    int limit = main_thread ? 64 : 24;
    size_t span = main_thread ? 0x4000 : 0x2000;
    for (size_t i = 0; i < span / sizeof(uintptr_t) && found < limit; i++) {
        uintptr_t v = 0;
        if (!safe_read(sp + i * sizeof(uintptr_t), &v)) break;
        uintptr_t voff = 0, vReal = 0;
        const char *vm = aia_real_ptr(v, &vReal, &voff);
        if (!vm || voff == 0) continue;
        // 主线程多打印系统库：需要看清是哪条 App/系统调用路径进了 JM。
        if (!main_thread && !strstr(vm, "JMCodeProtectKit") && !strstr(vm, "KYHAppStore")) continue;
        if (main_thread && strstr(vm, "libsystem_") && voff == 0) continue;
        snprintf(buf, sizeof(buf), "  stack[+0x%zx] %p %s+0x%lx\n",
                 i * 8, (void *)vReal, vm, (unsigned long)voff);
        log_raw(buf);
        found++;
    }
}

#if AIA_EXC_BAIL || (defined(AIA_EXC_NONMAIN) && AIA_EXC_NONMAIN == 2)
// 故障线程被重定向到这里：直接结束该线程，让 pthread 清理路径归还它持有的锁。
__attribute__((noinline, used)) static void aia_thread_bail(void) {
    pthread_exit(NULL);
    for (;;) { }
}
#endif

__attribute__((unused)) static void *aia_exc_server(void *arg) {
    (void)arg;
    mach_msg_size_t rcv = 1024;
    exc_req_t *req = (exc_req_t *)calloc(1, rcv + 2048);
    exc_reply_t *rep = (exc_reply_t *)calloc(1, sizeof(exc_reply_t) + 256);
    if (!req || !rep) return NULL;
    while (1) {
        kern_return_t kr = mach_msg(&req->Head, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
                                    rcv, g_exc_port,
                                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == MACH_RCV_TOO_LARGE) {
            mach_msg_size_t need = 0;
            mach_msg(&req->Head, MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY,
                     0, 0, g_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            need = req->Head.msgh_size;
            if (need < 1024) need = 4096;
            rcv = need + 1024;
            req = (exc_req_t *)realloc(req, rcv + 2048);
            aialog("exc: rcv too large, resized to %u", rcv);
            continue;
        }
        if (kr != KERN_SUCCESS) {
            static int logged;
            if (logged < 5) { aialog("exc: recv failed %d", kr); logged++; }
            usleep(20000);
            continue;
        }
        g_exc_count++;
        dump_fault_state(req);
#if AIA_DUMP_PEERS
        {
            static int peer_dumped;
            if (peer_dumped < 6) {
                dump_peer_threads("exc", *(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF));
                peer_dumped++;
            }
        }
#endif
#if AIA_KILL_THREAD
        {
            mach_port_t tp = *(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF);
            kern_return_t tk = thread_terminate(tp);
            char b[96];
            snprintf(b, sizeof(b), "  terminate thread(%u) -> %d\n", tp, tk);
            log_raw(b);
        }
#endif
#if AIA_EXC_NONMAIN
        // 实验：让非主线程的处决跳飞"当作返回 0"，看 JM 的检查流程能否跑完。
        if (!(g_main_tid && thread_id_of(*(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF)) == g_main_tid)) {
            static char nmst[sizeof(arm_thread_state64_t) + 64];
            memcpy(nmst, (const char *)req + EXC_STATE_BODY_OFF, sizeof(arm_thread_state64_t));
            arm_thread_state64_t *nst = (arm_thread_state64_t *)nmst;
            uintptr_t opc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*nst);
            uintptr_t olr = (uintptr_t)__darwin_arm_thread_state64_get_lr(*nst);
            static int nm_logged;
#if AIA_EXC_NONMAIN == 2
            __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)aia_thread_bail);
#else
            uintptr_t ro = 0, rreal = 0;
            const char *rm = aia_real_ptr(olr, &rreal, &ro);
            if (rm && ro) __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)rreal);
            else {
                // 返回地址不可用，退回挂起，避免把线程送到垃圾地址。
                if (nm_logged < 20) {
                    char b[144];
                    snprintf(b, sizeof(b), "  NONMAIN pc=%#lx lr=%#lx 无可返回地址 -> 挂起\n",
                             (unsigned long)opc, (unsigned long)olr);
                    log_raw(b); nm_logged++;
                }
                memset(req, 0, rcv + 2048);
                continue;
            }
#endif
            nst->__x[0] = 0;
            nst->__x[1] = 0;
            if (nm_logged < 30) {
                char b[176];
                snprintf(b, sizeof(b), "  NONMAIN pc=%#lx -> lr=%s+0x%lx x0:=0\n",
                         (unsigned long)opc, rm ? rm : "?", (unsigned long)ro);
                log_raw(b); nm_logged++;
            }
            rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
            rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
            rep->Head.msgh_local_port = MACH_PORT_NULL;
            rep->Head.msgh_id = req->Head.msgh_id + 100;
            rep->NDR = NDR_record;
            rep->RetCode = KERN_SUCCESS;
            rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
            memcpy(rep->new_state, nmst, sizeof(arm_thread_state64_t));
            rep->Head.msgh_size = EXC_REPLY_HDR_SIZE + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
            mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                     MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            memset(req, 0, rcv + 2048);
            continue;
        }
#endif
#if AIA_EXC_BAIL
        if (!(g_main_tid && thread_id_of(*(const uint32_t *)((const uint8_t *)req + EXC_THREAD_OFF)) == g_main_tid)) {
            // 非主线程：送到一个只做 pthread_exit 的桩函数，让它正常结束。
            static char buf2[sizeof(arm_thread_state64_t) + 64];
            memcpy(buf2, (const char *)req + EXC_STATE_BODY_OFF,
                   sizeof(arm_thread_state64_t));
            arm_thread_state64_t *st = (arm_thread_state64_t *)buf2;
            uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*st);
            __darwin_arm_thread_state64_set_pc_fptr(*st, (void *)aia_thread_bail);
            __darwin_arm_thread_state64_set_lr_fptr(*st, (void *)0);
            st->__x[0] = 0;
            static int bail_logged;
            if (bail_logged < 20) {
                char b[128];
                snprintf(b, sizeof(b), "  bail: pc %#lx -> aia_thread_bail\n",
                         (unsigned long)oldpc);
                log_raw(b);
                bail_logged++;
            }
            rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
            rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
            rep->Head.msgh_local_port = MACH_PORT_NULL;
            rep->Head.msgh_id = req->Head.msgh_id + 100;
            rep->NDR = NDR_record;
            rep->RetCode = KERN_SUCCESS;
            rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
            memcpy(rep->new_state, buf2, sizeof(arm_thread_state64_t));
            rep->Head.msgh_size = EXC_REPLY_HDR_SIZE + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
            kern_return_t sk = mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                                        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (bail_logged < 20) {
                char b[96];
                snprintf(b, sizeof(b), "  bail: reply=%d size=%u\n", sk, rep->Head.msgh_size);
                log_raw(b);
            }
            memset(req, 0, rcv + 2048);
            continue;
        }
#endif
#if AIA_EXC_RECOVER_MAIN
        // 主线程的非法跳转：把 PC 改成 LR，模拟这次调用正常返回。
        // JM 破坏对象 isa 后发消息，最终 blr 到一个被截断的指针（例如 0x99ccd258），
        // 主线程如果一直不回复就永久挂起，界面从此失去响应。
        {
            const uint8_t *bb = (const uint8_t *)req;
            int etype2 = (int)*(const uint32_t *)(bb + EXC_TYPE_OFF);
            uint32_t flavor2 = *(const uint32_t *)(bb + EXC_FLAVOR_OFF);
            uint32_t sc2 = *(const uint32_t *)(bb + EXC_STATE_OFF);
            uint64_t ftid = thread_id_of(*(const uint32_t *)(bb + EXC_THREAD_OFF));
            // 断点类必须交给下面的 AIA_EXC_SKIP_BRK 处理。这里如果也接住，
            // RECOVER_FAULT=0 时只是不回复，主线程会被挂住直到 SIGTRAP 打死进程。
            if (g_main_tid && ftid == g_main_tid && etype2 != 6 && flavor2 == 6 && sc2 >= 34) {
                memcpy(rep->new_state, bb + EXC_STATE_BODY_OFF, sizeof(arm_thread_state64_t));
                arm_thread_state64_t *nst = (arm_thread_state64_t *)rep->new_state;
                uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*nst);
                uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(*nst);
                // LR 必须是已知模块里的可执行地址，否则"设 PC=LR"会把线程送到
                // 垃圾地址。实测有 lr=0x77178a81c1f35be8 这种带垃圾高位的值，
                // 属于签名/损坏的返回地址，不能用它恢复。
                uintptr_t lrOff2 = 0;
                const char *lrMod2 = aia_module_for_ptr(lr, &lrOff2);
                BOOL lrUsable = lrMod2 && lrOff2 >= 0x1000;
                // 重建出的真实地址（可能和 lr 本身不同，后者带着签名）。
                uintptr_t lrReal = aia_strip_pac(lr);
                static int rec_logged;
                if (rec_logged < 40) {
                    char b[192];
                    uintptr_t lo = 0;
                    const char *lm = module_for(lr, &lo);
                    snprintf(b, sizeof(b), "  RECOVERMAIN pc=%#lx -> lr=%s+0x%lx\n",
                             (unsigned long)oldpc, lm ? lm : "?", (unsigned long)lo);
                    log_raw(b);
                    rec_logged++;
                }
#if AIA_EXC_UNWIND_JM
                // ijm VM 交叉现场：不回复就会把主线程永久挂住（evt 计数停止增长），
                // 界面从此失去响应。这里沿帧链退回到调用方（现场是 Dynatrace），
                // 让整次 ijm 埋点调用作废，主线程继续跑 runloop。
                {
                    uintptr_t lrOff = 0;
                    const char *lm = module_for(lr, &lrOff);
                    BOOL vmSite = lm && strstr(lm, "JMCodeProtectKit") &&
                                  lrOff >= 0x186600 && lrOff < 0x186700;
                    if (vmSite) {
                        uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(*nst));
                        uintptr_t prevfp = 0, ra = 0;
                        if (fp && safe_read(fp, &prevfp) && safe_read(fp + 8, &ra)) {
                            uintptr_t rao = 0;
                            uintptr_t raUn = aia_strip_pac(ra);
                            const char *ram = module_for(raUn, &rao);
                            char b[192];
                            snprintf(b, sizeof(b), "  UNWINDJM -> %s+0x%lx fp=%#lx\n",
                                     ram ? ram : "?", (unsigned long)rao, (unsigned long)fp);
                            log_raw(b);
                            if (ram && raUn) {
                                nst->__x[0] = 0;
                                nst->__x[1] = 0;
                                __darwin_arm_thread_state64_set_fp(*nst, (void *)aia_strip_pac(prevfp));
                                __darwin_arm_thread_state64_set_lr_fptr(*nst, (void *)raUn);
                                __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)raUn);
                                __darwin_arm_thread_state64_set_sp(*nst, (void *)(fp + 0x10));
                                rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                                rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
                                rep->Head.msgh_local_port = MACH_PORT_NULL;
                                rep->Head.msgh_id = req->Head.msgh_id + 100;
                                rep->NDR = NDR_record;
                                rep->RetCode = KERN_SUCCESS;
                                rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
                                rep->Head.msgh_size = EXC_REPLY_HDR_SIZE +
                                                      ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
                                mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                                memset(req, 0, rcv + 2048);
                                continue;
                            }
                        }
                    }
                }
#endif
                // 早先的做法是"主线程只要出事就不回复"，结果是主线程永久停在异常里，
                // 界面失去响应（表现为 App 内卡死）。现在改成：有可用返回地址就让它
                // 返回、继续跑 runloop；只有返回地址本身是坏值时才挂起。
                // LR 落在 objc/libdyld 这类运行时库内部时，跳过去等于接着执行
                // 它们的内部代码：objc_msgSend 的中间点并不接受"消息发送失败"这种
                // 上下文，实测会让进程直接结束。这种情况下把返回值清零，让它按
                // "这次消息得到 nil"继续走，是唯一不破坏调用约定的选择。
                BOOL lrInRuntime = lrMod2 && (strstr(lrMod2, "libobjc") ||
                                              strstr(lrMod2, "libdyld"));
                if (lrUsable && lrInRuntime) {
                    static int rt_logged;
                    if (rt_logged < 20) {
                        char b[160];
                        snprintf(b, sizeof(b), "  RTLR pc=%#lx -> %s+0x%lx x0:=0\n",
                                 (unsigned long)oldpc, lrMod2, (unsigned long)lrOff2);
                        log_raw(b);
                        rt_logged++;
                    }
                    nst->__x[0] = 0;
                }
                if (lrUsable) {
                    // 用低 32 位重建出无签名的地址再跳，避免把签名位带进 PC。
                    uintptr_t target = (aia_strip_pac(lr) & 0xFFFFFFFFULL) == (lr & 0xFFFFFFFFULL)
                                       ? aia_strip_pac(lr) : lrReal;
                    uintptr_t to = 0;
                    if (!module_for(target, &to) || !to) {
                        target = ((uintptr_t)0x1 << 32) | (lr & 0xFFFFFFFFULL);
                        for (uintptr_t hi = 0x1; hi <= 0x3; hi++) {
                            uintptr_t c = (hi << 32) | (lr & 0xFFFFFFFFULL);
                            if (module_for(c, &to) && to) { target = c; break; }
                        }
                    }
                    __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)target);
                }
                else {
                    static int deadlr_logged;
                    if (deadlr_logged < 10) {
                        char b[128];
                        snprintf(b, sizeof(b), "  DEADLR pc=%#lx lr=%#lx -> 挂起\n",
                                 (unsigned long)oldpc, (unsigned long)lr);
                        log_raw(b);
                        deadlr_logged++;
                    }
                    memset(req, 0, rcv + 2048);
                    continue;
                }
                rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
                rep->Head.msgh_local_port = MACH_PORT_NULL;
                rep->Head.msgh_id = req->Head.msgh_id + 100;
                rep->NDR = NDR_record;
                rep->RetCode = KERN_SUCCESS;
                rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
                rep->Head.msgh_size = EXC_REPLY_HDR_SIZE + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
                mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                         MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                memset(req, 0, rcv + 2048);
                continue;
            }
        }
#endif
#if AIA_EXC_SKIP_BRK
        // 断点异常（brk / brk #0xdead 断言桩）：把 PC 推到下一条指令再回复，
        // 线程继续执行而不是被永久挂起。这是"能启动 + 主线程不卡死"的关键。
        {
            const uint8_t *bb = (const uint8_t *)req;
            int etype2 = (int)*(const uint32_t *)(bb + EXC_TYPE_OFF);
            uint32_t flavor2 = *(const uint32_t *)(bb + EXC_FLAVOR_OFF);
            uint32_t sc2 = *(const uint32_t *)(bb + EXC_STATE_OFF);
            if (etype2 == 6 && flavor2 == 6 && sc2 >= 34) {
                memcpy(rep->new_state, bb + EXC_STATE_BODY_OFF, sizeof(arm_thread_state64_t));
                arm_thread_state64_t *nst = (arm_thread_state64_t *)rep->new_state;
                uintptr_t oldpc = (uintptr_t)__darwin_arm_thread_state64_get_pc(*nst);
#if AIA_UNWIND_BINDER_BRK
                // KYHAppStore+0x7c55f8 的 brk #0xdead 是 ijm 导入绑定器的失败出口。
                // 推进 4 字节只会进 0x7c55fc 的失败续跑路径，那条路径把绑定器自己
                // 构造的占位描述符 0x7c5500 当脚本交给解释器，必然再次出错。
                // 这里改成按绑定器自己的收尾序列把现场弹回调用者：
                //   0x7c5544 已把 sp 减掉 0x130，原始现场在 sp+0x130；
                //   0x7c55c0 起逐对恢复 x27..x15，再读 nzcv，最后回到调用者。
                // 返回时 x0 = 0，等价于这个被保护的导入返回 nil。
                if (binder_brk_unwind(nst)) {
                    char b[128];
                    snprintf(b, sizeof(b), "  UNWINDBRK pc=%#lx -> caller, x0=0\n",
                             (unsigned long)oldpc);
                    log_raw(b);
                } else
#endif
                __darwin_arm_thread_state64_set_pc_fptr(*nst, (void *)(oldpc + 4));
                static int skip_logged;
                if (skip_logged < 40) {
                    char b[160];
                    uintptr_t so = 0;
                    const char *sm = module_for(oldpc, &so);
                    snprintf(b, sizeof(b), "  SKIPBRK pc=%s+0x%lx -> +4\n",
                             sm ? sm : "?", (unsigned long)so);
                    log_raw(b);
                    skip_logged++;
                }
                rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
                rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
                rep->Head.msgh_local_port = MACH_PORT_NULL;
                rep->Head.msgh_id = req->Head.msgh_id + 100;
                rep->NDR = NDR_record;
                rep->RetCode = KERN_SUCCESS;
                rep->new_stateCnt = ARM_THREAD_STATE64_COUNT;
                rep->Head.msgh_size = EXC_REPLY_HDR_SIZE + ARM_THREAD_STATE64_COUNT * sizeof(natural_t);
                {
                    kern_return_t sk = mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
                    if (sk != KERN_SUCCESS) {
                        char b[96];
                        snprintf(b, sizeof(b), "  SKIPBRK reply failed: %d size=%u\n",
                                 sk, rep->Head.msgh_size);
                        log_raw(b);
                    }
                }
                memset(req, 0, rcv + 2048);
                continue;
            }
        }
#endif
#if AIA_EXC_NO_REPLY
        // 不回复：故障线程留在异常状态，内核不会让它继续执行，JM 的处决也不会生效。
        g_exc_noreply++;
        memset(req, 0, rcv + 2048);
        continue;
#endif
        rep->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        rep->Head.msgh_remote_port = req->Head.msgh_remote_port;
        rep->Head.msgh_local_port = MACH_PORT_NULL;
        rep->Head.msgh_id = req->Head.msgh_id + 100;
        rep->NDR = NDR_record;
        rep->RetCode = KERN_SUCCESS;
        rep->new_stateCnt = req->old_stateCnt;
        memcpy(rep->new_state, req->old_state, req->old_stateCnt * sizeof(natural_t));
        rep->Head.msgh_size = EXC_REPLY_HDR_SIZE + req->old_stateCnt * sizeof(natural_t);
        mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    return NULL;
}

#if AIA_SAMPLE_THREADS
__attribute__((unused)) static void *aia_sampler(void *arg) {
    (void)arg;
    char buf[256];
    for (int round = 0; round < 30; round++) {
        sleep(2);
        thread_act_array_t list = NULL;
        mach_msg_type_number_t cnt = 0;
        if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) continue;
        snprintf(buf, sizeof(buf), "SAMPLE round=%d threads=%u\n", round, cnt);
        log_raw(buf);
        for (mach_msg_type_number_t i = 0; i < cnt && i < 24; i++) {
            struct thread_basic_info tb = {0};
            mach_msg_type_number_t tbc = THREAD_BASIC_INFO_COUNT;
            int cpu = -1;
            if (thread_info(list[i], THREAD_BASIC_INFO, (thread_info_t)&tb, &tbc) == KERN_SUCCESS)
                cpu = tb.cpu_usage;
            arm_thread_state64_t st;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            kern_return_t gs = thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc);
            if (gs != KERN_SUCCESS) {
                snprintf(buf, sizeof(buf), "  t%u cpu=%d getstate=%d\n", i, cpu, gs);
                log_raw(buf);
                continue;
            }
            uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
            uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
            uintptr_t voff = 0, loff = 0;
            const char *vm = module_for(pc, &voff);
            const char *lm = module_for(lr, &loff);
            snprintf(buf, sizeof(buf), "  t%u cpu=%d pc=%p %s+0x%lx lr=%p %s+0x%lx\n", i, cpu,
                     (void *)pc, vm ? vm : "?", (unsigned long)voff,
                     (void *)lr, lm ? lm : "?", (unsigned long)loff);
            log_raw(buf);
            if (i == 0) {
                uintptr_t sp = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
                int got = 0;
                for (int k = 0; k < 0x800 / 8 && got < 14; k++) {
                    uintptr_t v = 0;
                    if (!safe_read(sp + k * 8, &v)) break;
                    uintptr_t o2 = 0;
                    const char *m2 = module_for(v, &o2);
                    if (!m2 || o2 == 0) continue;
                    snprintf(buf, sizeof(buf), "    [%02d] %s+0x%lx\n", k, m2, (unsigned long)o2);
                    log_raw(buf);
                    got++;
                }
            }
        }
        vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    }
    return NULL;
}
static void start_sampler(void) {
    pthread_t th;
    pthread_create(&th, NULL, aia_sampler, NULL);
}
#endif

#if AIA_EXC_WATCHDOG
static void *aia_exc_watchdog(void *arg) {
    (void)arg;
    // 必须一直跑：JM 会在运行期间反复检测，端口一旦被别人抢回去就会再次触发处决。
    for (;;) {
        task_set_exception_ports(mach_task_self(),
                                 EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                                 g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64);
        usleep(50000);
    }
    return NULL;
}
#endif

// 判断某个地址是否落在 JMCodeProtectKit 里：JM 若 swizzle 了事件入口，
// 对应方法的 IMP 就会指向这个镜像。
static int jm_contains(uintptr_t a, uintptr_t *off) {
    uintptr_t lo = 0;
    const char *m = module_for(a, &lo);
    if (m && strstr(m, "JMCodeProtectKit")) { if (off) *off = lo; return 1; }
    return 0;
}

// 扫描一组与触摸/事件相关的类，列出 IMP 落在 JM 里的方法。
__attribute__((unused)) static void dump_jm_swizzles(void) {
    char buf[256];
    const char *names[] = {
        "UIApplication", "UIWindow", "UIView", "UIResponder", "UIControl",
        "UIEvent", "UITouch", "UIGestureRecognizer", "UIGestureEnvironment",
        "UIScreen", "UIWindowScene", "UIApplicationSceneSettings", NULL
    };
    int hits = 0;
    for (int i = 0; names[i]; i++) {
        Class c = objc_getClass(names[i]);
        if (!c) continue;
        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass((id)c) : c;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(target, &n);
            for (unsigned int k = 0; k < n; k++) {
                IMP imp = method_getImplementation(ms[k]);
                uintptr_t off = 0;
                if (!jm_contains((uintptr_t)imp, &off)) continue;
                snprintf(buf, sizeof(buf), "  SWZ %s%s%s -> JM+0x%lx\n",
                         meta ? "+" : "-", names[i],
                         sel_getName(method_getName(ms[k])), (unsigned long)off);
                log_raw(buf);
                hits++;
            }
            if (ms) free(ms);
        }
    }
    snprintf(buf, sizeof(buf), "  SWZ total=%d\n", hits);
    log_raw(buf);
}

// 异常发生时把其它线程的 PC/LR 也打出来。
// 故障线程自己在做什么已经知道；要定位 JM 的判定点，必须看"同一时刻其它 JM 线程
// 停在哪"。只处理落在 JMCodeProtectKit 里的线程，避免日志被无关线程淹没。
static void dump_peer_threads(const char *tag, thread_t self_port) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    char buf[256];
    int shown = 0;
    snprintf(buf, sizeof(buf), "  PEERS (%s) total=%u\n", tag, cnt);
    log_raw(buf);
    for (mach_msg_type_number_t i = 0; i < cnt && shown < 24; i++) {
        if (list[i] == self_port) continue;
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS)
            continue;
        uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
        uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
        uintptr_t po = 0, lo = 0, preal = 0, lreal = 0;
        const char *pm = aia_real_ptr(pc, &preal, &po);
        const char *lm = aia_real_ptr(lr, &lreal, &lo);
        BOOL pcInJm = pm && strstr(pm, "JMCodeProtectKit");
        BOOL lrInJm = lm && strstr(lm, "JMCodeProtectKit");
        BOOL pcInApp = pm && strstr(pm, "KYHAppStore");
        BOOL lrInApp = lm && strstr(lm, "KYHAppStore");
        if (!pcInJm && !lrInJm && !pcInApp && !lrInApp) continue;
        snprintf(buf, sizeof(buf), "  PEER t%u pc=%s+0x%lx lr=%s+0x%lx\n", i,
                 pm ? pm : "?", (unsigned long)po, lm ? lm : "?", (unsigned long)lo);
        log_raw(buf);
        shown++;
        // 栈窗口：JM 的检查派发循环把"检查项表"指针放在 [sp+0x30] 与
        // [sp+0x50]，项数在 [table+0x40]，步长来自 w28。把这段原样打出来，
        // 就能在离线分析里把整张检查项表还原。
        {
            uintptr_t spv = (uintptr_t)__darwin_arm_thread_state64_get_sp(st);
            char line[192];
            size_t n = 0;
            n += (size_t)snprintf(line, sizeof(line), "    sp=%#lx:", (unsigned long)spv);
            for (int k = 0; k < 14 && n < sizeof(line) - 20; k++) {
                uintptr_t w = 0;
                if (!safe_read(spv + (uintptr_t)k * 8, &w)) break;
                n += (size_t)snprintf(line + n, sizeof(line) - n, " %lx", (unsigned long)w);
            }
            snprintf(line + n, sizeof(line) - n, "\n");
            log_raw(line);
        }
        // JM 线程的帧链能说明它停在哪一层、调用者是谁。
        if (pcInJm || lrInJm || pcInApp || lrInApp) {
            uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(st));
            for (int d = 0; d < 12 && fp; d++) {
                uintptr_t prev = 0, ra = 0;
                if (!safe_read(fp, &prev) || !safe_read(fp + 8, &ra)) break;
                uintptr_t ro = 0, rreal = 0;
                const char *rm = aia_real_ptr(ra, &rreal, &ro);
                if (rm && (strstr(rm, "JMCodeProtectKit") || strstr(rm, "KYHAppStore") ||
                           strstr(rm, "UIKit") || strstr(rm, "libobjc"))) {
                    snprintf(buf, sizeof(buf), "    pt%u#%02d %s+0x%lx\n", i, d, rm,
                             (unsigned long)ro);
                    log_raw(buf);
                }
                prev = aia_strip_pac(prev);
                if (!prev || prev <= fp) break;
                fp = prev;
            }
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
}

#if AIA_DUMP_ON_SIGNAL

static void dump_view(UIView *v, int depth) {
    if (depth > 3) return;
    char buf[320];
    NSString *cls = NSStringFromClass([v class]);
    snprintf(buf, sizeof(buf), "    %*s%s fr=(%.0f,%.0f %.0fx%.0f) hidden=%d alpha=%.2f "
             "inter=%d clips=%d layer=%.2f\n", depth * 2, "", cls.UTF8String,
             v.frame.origin.x, v.frame.origin.y, v.frame.size.width, v.frame.size.height,
             (int)v.hidden, (double)v.alpha, (int)v.userInteractionEnabled,
             (int)v.clipsToBounds, (double)v.layer.opacity);
    log_raw(buf);
    for (UIView *sub in v.subviews) dump_view(sub, depth + 1);
}

static void dump_ui_main(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    UIApplication *app = [UIApplication sharedApplication];
    char buf[320];
    snprintf(buf, sizeof(buf), "=== UI: %u windows ===\n",
             (unsigned)app.windows.count);
    log_raw(buf);
    for (UIWindow *w in app.windows) {
        snprintf(buf, sizeof(buf), "  window %s level=%.0f hidden=%d alpha=%.2f inter=%d\n",
                 NSStringFromClass([w class]).UTF8String, (double)w.windowLevel,
                 (int)w.hidden, (double)w.alpha, (int)w.userInteractionEnabled);
        log_raw(buf);
        dump_view(w, 1);
        CGPoint c = CGPointMake(w.bounds.size.width / 2, w.bounds.size.height / 2);
        UIView *hit = [w hitTest:c withEvent:nil];
        snprintf(buf, sizeof(buf), "  hitTest(中心) -> %s inter=%d\n",
                 hit ? NSStringFromClass([hit class]).UTF8String : "(nil)",
                 hit ? (int)hit.userInteractionEnabled : -1);
        log_raw(buf);
    }
    dump_jm_swizzles();
    log_raw("=== UI END ===\n");
#pragma clang diagnostic pop
}

static void dump_ui_signal(int sig) {
    (void)sig;
    dispatch_async(dispatch_get_main_queue(), ^{ dump_ui_main(); });
}

static void dump_all_threads(int sig) {
    (void)sig;
    char buf[256];
    log_raw("=== DUMP ALL THREADS ===\n");
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return;
    for (mach_msg_type_number_t i = 0; i < cnt && i < 64; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS) continue;
        uintptr_t pc = (uintptr_t)__darwin_arm_thread_state64_get_pc(st);
        uintptr_t lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(st);
        uintptr_t vo = 0, lo = 0;
        const char *vm = module_for(pc, &vo);
        const char *lm = module_for(lr, &lo);
        snprintf(buf, sizeof(buf), "  t%u pc=%p %s+0x%lx lr=%p %s+0x%lx\n", i,
                 (void *)pc, vm ? vm : "?", (unsigned long)vo,
                 (void *)lr, lm ? lm : "?", (unsigned long)lo);
        log_raw(buf);
        if (i == 0) {
            // x29 帧链比栈扫描可靠：fp[0] 是上一帧 fp，fp[1] 是返回地址
            uintptr_t fp = aia_strip_pac((uintptr_t)__darwin_arm_thread_state64_get_fp(st));
            for (int d = 0; d < 40 && fp; d++) {
                uintptr_t prev = 0, ra = 0;
                if (!safe_read(fp, &prev) || !safe_read(fp + 8, &ra)) break;
                prev = aia_strip_pac(prev);
                ra = aia_strip_pac(ra);
                uintptr_t o2 = 0;
                const char *m2 = module_for(ra, &o2);
                snprintf(buf, sizeof(buf), "    fp#%02d %s+0x%lx (%p)\n", d,
                         m2 ? m2 : "?", (unsigned long)o2, (void *)ra);
                log_raw(buf);
                if (prev <= fp) break;
                fp = prev;
            }
            snprintf(buf, sizeof(buf), "    x0=%#lx x1=%#lx x16=%#lx\n",
                     (unsigned long)st.__x[0], (unsigned long)st.__x[1],
                     (unsigned long)st.__x[16]);
            log_raw(buf);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
    log_raw("=== DUMP END ===\n");
}
#endif

__attribute__((unused)) // 观测 task_info：JM 可能用 TASK_DYLD_INFO 直接读原始镜像表，绕过全部 _dyld_* hook。
static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static kern_return_t my_task_info(task_name_t target, task_flavor_t flavor, task_info_t info, mach_msg_type_number_t *cnt) {
    kern_return_t r = orig_task_info(target, flavor, info, cnt);
    const char *who = caller_desc(__builtin_return_address(0));
    if (flavor == TASK_DYLD_INFO) {
        aialog("task_info(TASK_DYLD_INFO) -> %d caller=%s", r, who);
    }
    return r;
}

// 记录接管之前谁持有异常端口。JM 若自己也装了处理器，抢走它可能破坏它的控制流。
__attribute__((unused)) __attribute__((unused)) static void log_exception_port_owners(const char *tag) {
    struct { const char *name; exception_mask_t mask; } items[] = {
        {"BAD_ACCESS", EXC_MASK_BAD_ACCESS},
        {"BAD_INSTRUCTION", EXC_MASK_BAD_INSTRUCTION},
        {"BREAKPOINT", EXC_MASK_BREAKPOINT},
        {"CORPSE_NOTIFY", EXC_MASK_CORPSE_NOTIFY},
        {"SYS", EXC_MASK_SYSCALL},
        {"GUARD", EXC_MASK_GUARD},
    };
    char b[192];
    for (unsigned i = 0; i < sizeof(items)/sizeof(items[0]); i++) {
        exception_mask_t masks[8] = {0};
        mach_msg_type_number_t cnt = 8;
        exception_handler_t handlers[8] = {0};
        exception_behavior_t behaviors[8] = {0};
        thread_state_flavor_t flavors[8] = {0};
        kern_return_t kr = task_get_exception_ports(mach_task_self(), items[i].mask,
                                                    masks, &cnt, handlers, behaviors, flavors);
        if (kr != KERN_SUCCESS) {
            snprintf(b, sizeof(b), "EXCPORT %s %s: query=%d\n", tag, items[i].name, kr);
            log_raw(b);
            continue;
        }
        snprintf(b, sizeof(b), "EXCPORT %s %s: cnt=%u", tag, items[i].name, (unsigned)cnt);
        log_raw(b);
        for (mach_msg_type_number_t k = 0; k < cnt && k < 8; k++) {
            snprintf(b, sizeof(b), "    port=%u beh=%d flavor=%d mask=%#x\n",
                     (unsigned)handlers[k], (int)behaviors[k], (int)flavors[k],
                     (unsigned)masks[k]);
            log_raw(b);
        }
    }
}


// ============================================================
// 阻断 Dynatrace 的 swizzle
// ============================================================
// Dynatrace 是纯埋点框架，它会 swizzle App 的方法去采集数据。被 swizzle 的
// App 方法如果由 JMCodeProtectKit 保护，调用会走 ijm 导入绑定器进 VM，
// 而 VM 在本进程里解出越界操作码直接跳飞（主线程一挂，界面就再没有触摸响应）。
// 这里把来源在 Dynatrace 里的 IMP 全部拒掉，让它的埋点装不上。
#ifndef AIA_BLOCK_DYNATRACE
// 默认关闭。这三个拦截是为了在 ijm 解析器槽被 JM 占用时挡住主线程进 VM；
// 现在槽已清零、绑定器改走 App 自己的解析器，主线程不再跳飞，它们不再必需。
// 实测三个同时打开会让进程在 ctor 阶段就卡住（连 2 秒后安装槽清零的任务都跑不到），
// 单独打开任意一个则正常，属组合效应。保留为实验开关。
#define AIA_BLOCK_DYNATRACE 0
#endif

#if AIA_BLOCK_DYNATRACE
// 1 = 只拦"目标是 ijm 桩"的 swizzle，而不是把 Dynatrace 的配置器整个关掉。
// 全关会让 Dynatrace 自身状态不自洽，App 完全不响应触摸（视图树只剩三层系统容器）。
// 精准拦截既能阻止 ijm 方法被包装后调用，又不影响 Dynatrace 的其它埋点。
#ifndef AIA_BLOCK_IJM_SWIZZLE
// 默认关闭。这三个拦截是为了在 ijm 解析器槽被 JM 占用时挡住主线程进 VM；
// 现在槽已清零、绑定器改走 App 自己的解析器，主线程不再跳飞，它们不再必需。
// 实测三个同时打开会让进程在 ctor 阶段就卡住（连 2 秒后安装槽清零的任务都跑不到），
// 单独打开任意一个则正常，属组合效应。保留为实验开关。
#define AIA_BLOCK_IJM_SWIZZLE 0
#endif

#if AIA_BLOCK_IJM_SWIZZLE
// ijm 导入桩的固定开头：
//   str  x13, [sp, #-0x30]!
//   adrp x13, <thunk 页>
//   add  x13, x13, #<槽偏移>
//   br   x13
// 后面经 thunk 一路跳到 KYHAppStore+0x7c5508 的导入绑定器。只要第一个 IMP
// 长这个样子，这个方法就是由 ijm 保护实现的。
static int imp_is_ijm_stub(IMP imp) {
    if (!imp) return 0;
    uintptr_t base = app_base();
    uintptr_t a = (uintptr_t)imp;
    if (!base || a < base || a - base >= 0x35dc000) return 0;
    uint32_t w0 = 0, w3 = 0;
    if (!safe_read(a, (uintptr_t *)&w0)) return 0;
    if (!safe_read(a + 12, (uintptr_t *)&w3)) return 0;
    return w0 == 0xf81d0fed && w3 == 0xd61f01a0;
}
#else
static int imp_is_ijm_stub(IMP imp) { (void)imp; return 0; }
#endif

// 1 = 只拦 Dynatrace 对"App 自身实现的方法"装 hook，系统类照常放行。
// 实测 ijm 保护的方法在 App 里是普通编译代码（例如 KYHAppStore+0xf3426c），
// 内部再调用 ijm 导入，所以没法靠 IMP 形状识别。但被 Dynatrace 包装后调用时，
// 这些导入会在错误的上下文里失败，最终撞 brk #0xdead。
// 把拦截范围收窄到"原实现就在 App 主二进制里"，既断掉这条路径，又不影响
// Dynatrace 对系统类的埋点——整份关闭配置器（AIA_KILL_DT_SWIZZLE）会让
// Dynatrace 自身状态不自洽，App 从此完全不响应触摸。
#ifndef AIA_BLOCK_DT_APP_SWIZZLE
// 默认关闭。这三个拦截是为了在 ijm 解析器槽被 JM 占用时挡住主线程进 VM；
// 现在槽已清零、绑定器改走 App 自己的解析器，主线程不再跳飞，它们不再必需。
// 实测三个同时打开会让进程在 ctor 阶段就卡住（连 2 秒后安装槽清零的任务都跑不到），
// 单独打开任意一个则正常，属组合效应。保留为实验开关。
#define AIA_BLOCK_DT_APP_SWIZZLE 0
#endif

#if AIA_BLOCK_DT_APP_SWIZZLE
static int g_dt_app_blocked;

// 沿调用链判断这段代码最终会不会进到 ijm 导入绑定器。
// 被保护的方法本身是普通编译代码（例如 KYHAppStore+0xf3426c），
// 但它内部会调用 adrp x14,#0x7c5000 / add x14,x14,#0x508 / br x14 这种导入桩。
// 逐个精确地反汇编整段不现实，这里用两个廉价特征：
//   1) 实现落在 App 主二进制里；并且
//   2) 方法名不是 App 自己追加前缀的业务 swizzle（tyc_/autoLog_/h5_/mt_ 等）。
// 后者用于避开 App 自己的业务 hook，把它们拦掉会让 App 启动即退出。
static int imp_is_ijm_protected(IMP imp) {
    if (!imp) return 0;
    uintptr_t off = 0;
    const char *m = module_for((uintptr_t)imp, &off);
    return m && (strstr(m, "KYHAppStore") || strstr(m, "YoubangHealth"));
}

// 方法所属的类。arm64 上 Method 结构的前 8 字节就是 class 指针。
__attribute__((unused)) static Class class_from_method(Method m) { return m ? *(Class *)m : NULL; }

// 这个类本身是否定义在 App 主二进制里。
__attribute__((unused)) static int class_is_app_class(Class c) {
    if (!c) return 0;
    uintptr_t off = 0;
    const char *m = module_for((uintptr_t)c, &off);
    return m && (strstr(m, "KYHAppStore") || strstr(m, "YoubangHealth"));
}

// 方法的当前实现是否位于 App 主二进制里。
static int imp_is_app_code(IMP imp) {
    if (!imp) return 0;
    uintptr_t off = 0;
    const char *m = module_for((uintptr_t)imp, &off);
    return m && (strstr(m, "KYHAppStore") || strstr(m, "YoubangHealth"));
}

// 这个方法是否出现在 c（或其元类）自己的方法列表里，而不是从父类继承来的。
static int method_is_own(Class c, SEL sel) {
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    if (ms) {
        for (unsigned int i = 0; i < n; i++) {
            if (method_getName(ms[i]) == sel) { free(ms); return 1; }
        }
        free(ms);
    }
    Class meta = object_getClass((id)c);
    if (meta && meta != c) {
        ms = class_copyMethodList(meta, &n);
        if (ms) {
            for (unsigned int i = 0; i < n; i++) {
                if (method_getName(ms[i]) == sel) { free(ms); return 1; }
            }
            free(ms);
        }
    }
    return 0;
}

static void log_dt_app_block(const char *api, Method m) {
    if (g_dt_app_blocked >= 60) return;
    char b[224];
    snprintf(b, sizeof(b), "  DT-APPBLOCK %s %s\n",
             api, m ? sel_getName(method_getName(m)) : "?");
    log_raw(b);
    g_dt_app_blocked++;
}
#endif

static int imp_from_dynatrace(IMP imp) {
    if (!imp) return 0;
    uintptr_t off = 0;
    const char *m = module_for((uintptr_t)imp, &off);
    return m && strstr(m, "Dynatrace");
}

static IMP (*orig_method_setImplementation)(Method, IMP);
static IMP my_method_setImplementation(Method m, IMP imp) {
#if AIA_BLOCK_DT_APP_SWIZZLE
    if (m && imp_is_ijm_protected(method_getImplementation(m))) {
        log_dt_app_block("setImplementation", m);
        return method_getImplementation(m);
    }
#endif
    if (m && imp_is_ijm_stub(method_getImplementation(m))) {
        char b[224];
        snprintf(b, sizeof(b), "  DT-IJMBLOCK setImplementation %s\n",
                 sel_getName(method_getName(m)));
        log_raw(b);
        return method_getImplementation(m);
    }
    if (imp_from_dynatrace(imp)) {
        char b[224];
        uintptr_t off = 0;
        const char *mod = module_for((uintptr_t)imp, &off);
        snprintf(b, sizeof(b), "  DT-BLOCK method_setImplementation %s %s+0x%lx\n",
                 m ? sel_getName(method_getName(m)) : "?", mod ? mod : "?",
                 (unsigned long)off);
        log_raw(b);
        return m ? method_getImplementation(m) : NULL;
    }
    return orig_method_setImplementation(m, imp);
}

static void (*orig_method_exchangeImplementations)(Method, Method);
static void my_method_exchangeImplementations(Method a, Method b) {
#if AIA_BLOCK_DT_APP_SWIZZLE
    if (a && (imp_is_ijm_protected(method_getImplementation(a)))) {
        log_dt_app_block("exchange", a);
        return;
    }
#endif
    if (a && b && (imp_is_ijm_stub(method_getImplementation(a)) ||
                   imp_is_ijm_stub(method_getImplementation(b)))) {
        char b2[224];
        snprintf(b2, sizeof(b2), "  DT-IJMBLOCK exchange %s <-> %s\n",
                 sel_getName(method_getName(a)), sel_getName(method_getName(b)));
        log_raw(b2);
        return;
    }
    if (a && b && (imp_from_dynatrace(method_getImplementation(a)) ||
                   imp_from_dynatrace(method_getImplementation(b)))) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK exchange %s <-> %s\n",
                 sel_getName(method_getName(a)), sel_getName(method_getName(b)));
        log_raw(buf);
        return;
    }
    orig_method_exchangeImplementations(a, b);
}

static BOOL (*orig_class_addMethod)(Class, SEL, IMP, const char *);
static BOOL my_class_addMethod(Class c, SEL sel, IMP imp, const char *types) {
    if (imp_is_ijm_stub(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-IJMBLOCK addMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return NO;
    }
    if (imp_from_dynatrace(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK class_addMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return NO;
    }
    return orig_class_addMethod(c, sel, imp, types);
}

static IMP (*orig_class_replaceMethod)(Class, SEL, IMP, const char *);
static IMP my_class_replaceMethod(Class c, SEL sel, IMP imp, const char *types) {
#if AIA_BLOCK_DT_APP_SWIZZLE
    // 注意不能用 class_getInstanceMethod：它在子类上也会返回从父类继承来的方法，
    // 那样会把 App 自己的业务 swizzle（tyc_*、autoLog_*、mt_*、h5_* 等）一并拦掉，
    // 实测会让 App 在启动阶段就退出。这里只认"这个方法就声明在 c 自己的方法列表里"。
    if (c && sel && method_is_own(c, sel) && imp_is_app_code(imp)) {
        Method ex = class_getInstanceMethod(c, sel);
        if (!ex) ex = class_getClassMethod(c, sel);
        if (ex) {
            log_dt_app_block("replaceMethod", ex);
            return method_getImplementation(ex);
        }
    }
#endif
    if (imp_is_ijm_stub(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-IJMBLOCK replaceMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return (IMP)NULL;
    }
    if (imp_from_dynatrace(imp)) {
        char buf[224];
        snprintf(buf, sizeof(buf), "  DT-BLOCK class_replaceMethod %s %s\n",
                 c ? class_getName(c) : "?", sel ? sel_getName(sel) : "?");
        log_raw(buf);
        return c ? (IMP)class_getMethodImplementation(c, sel) : (IMP)NULL;
    }
    return orig_class_replaceMethod(c, sel, imp, types);
}

__attribute__((unused)) static void install_dynatrace_block(void) {
    MSHookFunction((void *)method_setImplementation, (void *)my_method_setImplementation,
                   (void **)&orig_method_setImplementation);
    MSHookFunction((void *)method_exchangeImplementations, (void *)my_method_exchangeImplementations,
                   (void **)&orig_method_exchangeImplementations);
    MSHookFunction((void *)class_addMethod, (void *)my_class_addMethod,
                   (void **)&orig_class_addMethod);
    MSHookFunction((void *)class_replaceMethod, (void *)my_class_replaceMethod,
                   (void **)&orig_class_replaceMethod);
    aialog("dynatrace block installed");
}
#endif


static uintptr_t app_base(void);

// ============================================================
// 让 App 的 ijm 保护埋点方法直接返回 nil
// ============================================================
// App 在埋点里调用 requstQueryTaskStateInfo / requstQueryUserOtherInfo 这类方法，
// 它们的实现由 JMCodeProtectKit 的 ijm VM 接管。VM 在本进程里把导入绑定器的代码区
// 当成字节码解释，解出越界的跳转表项后跳飞。这些方法只是埋点，直接返回 nil 即可。
#ifndef AIA_NEUTER_IJM
// 默认关闭。这个功能会在运行 3 秒后遍历所有类、把落在 ijm 绑定器区域的
// 方法实现替换成返回空值的桩。在 arm64e 上这样做会破坏方法缓存的一致性，
// 实测主线程随即在 objc_msgSend 里 PAC 认证失败（pc=libobjc+0x7f8c）。
#define AIA_NEUTER_IJM 0
#endif

#if AIA_NEUTER_IJM
static id aia_return_nil(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return nil;
}

static BOOL aia_return_no(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return NO;
}

// 一个方法的实现是否落在 ijm 保护桩区域（KYHAppStore 里那段导入绑定器）。
static int imp_in_binder_region(IMP imp, uintptr_t *off_out) {
    uintptr_t a = (uintptr_t)imp;
    uintptr_t base = app_base();
    if (!base || a < base) return 0;
    uintptr_t off = a - base;
    if (off_out) *off_out = off;
    return off >= 0x7c5400 && off < 0x7c5700;
}

__attribute__((unused)) static void neuter_ijm_telemetry(void) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return;
    Class *classes = (Class *)calloc((size_t)total, sizeof(Class));
    if (!classes) return;
    total = objc_getClassList(classes, total);
    char b[256];
    int hit = 0;
    for (int i = 0; i < total; i++) {
        Class c = classes[i];
        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass((id)c) : c;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(target, &n);
            if (!ms) continue;
            for (unsigned int k = 0; k < n; k++) {
                IMP imp = method_getImplementation(ms[k]);
                uintptr_t off = 0;
                if (!imp_in_binder_region(imp, &off)) continue;
                const char *name = sel_getName(method_getName(ms[k]));
                BOOL isBool = strstr(name, "is") == name || strstr(name, "has") == name;
                snprintf(b, sizeof(b), "  IJM %s%s%s stub=+0x%lx\n",
                         meta ? "+" : "-", class_getName(c), name, (unsigned long)off);
                log_raw(b);
                if (!meta) {
                    MSHookMessageEx(c, method_getName(ms[k]),
                                    isBool ? (IMP)aia_return_no : (IMP)aia_return_nil, NULL);
                    hit++;
                }
            }
            free(ms);
        }
    }
    snprintf(b, sizeof(b), "IJM total methods neutered=%d\n", hit);
    log_raw(b);
    free(classes);
}
#endif


// ============================================================
// ijm 导入绑定器：把非法桩值改写为合法值
// ============================================================
// KYHAppStore 里所有 ijm 保护的导入都走同一段绑定器：
//   adr x15, #0x7c54b0     ; 元数据表
//   ...
//   cbz x15, #0x7c55f8     ; 绑定失败 -> brk #0xdead
//   cbz x14, #0x7c55f8
// x15 来自绑定器回调的返回值，为 0 就断言。观测到的失败现场里 x15 一直是 0，
// 而 VM 继续拿着 0 当游标去解字节码，最终跳飞。
// 这里 hook 绑定器入口，把 0 换成元数据表里记录的合法桩地址。
#ifndef AIA_PATCH_BINDER_VALUE
#define AIA_PATCH_BINDER_VALUE 1
#endif

// 1 = 把 ijm 导入绑定器真正使用的解析器换成我们自己的。
//
// 绑定器 KYHAppStore+0x7c5508 在缓存槽为空时，先看 [meta+0x48]。这个位置存的是
// 偏移 0x4058008，指向 __DATA 尾部的一个槽；运行时该槽被填成某个别的 ijm 运行时的
// 入口（实测主线程从这里进去后，会拿着主二进制的字节码用 JMCodeProtectKit 的
// 分派表和密钥去解释，opcode 越界直接跳到未映射地址）。
//
// 槽在 __DATA，可写，改它不会像改 __TEXT 那样让代码页失去执行权限。
// 解析器契约（从 0x7c5600 逆出）：调用时 sp 已下移，返回时必须在 sp 上留一个
// 0x30 字节的帧、[sp] 放返回地址，并用 x14 给出实现地址、x15 给出成功标志。
// 1 = 我们自己的解析器桩；2 = 把槽清零，让绑定器回退到元数据里的 0x7c5600
// （App 自己的解析器 + 自己的 VM + 自己的描述符，ABI 天然一致）。
// JM 的 ijm 解释器在 JM+0x11f1dc 读全局 JM+0x1b9678：
//   cmp x8, #1 ; b.lt 用 0 作密钥 ; 否则 mvn 取反用 0xff
// 现场观测到 x8=0xff，此时原始字节 0x5d ^ 0xff = 0xa2，而分派表只有 107 项，越界跳飞。
// 换成密钥 0，同一字节解出 0x5d = 93，是合法表项。也就是说 0xff 是异常态，
// 由某个检测结果把全局置成了非 0。
//   0 = 不干预   1 = 只观测   2 = 持续把它压回 0
#ifndef AIA_IJM_KEY
#define AIA_IJM_KEY 0
#endif

#ifndef AIA_IJM_RESOLVER
#define AIA_IJM_RESOLVER 2
#endif
// 1 = 把 ijm 绑定器失败出口的 brk #0xdead 补成 NOP。
// 实测有害：brk 之后 0x7c55fc 的上下文恢复依赖一个并不存在的现场，
// 补掉后失败路径会继续跑到无效代码，App 启动即闪退。
// 正确做法是让异常端口接住这条 brk（AIA_EXC_SKIP_BRK）。
#ifndef AIA_NOP_IJM_BRK
#define AIA_NOP_IJM_BRK 0
#endif

#if AIA_PATCH_BINDER_VALUE
// 绑定器慢路径：元数据表 +0x10 存的是 0x7c5600，绑定器用它 `blr` 出去做真正的导入解析。
// 那个"解析器"把 0x7c5500 当脚本交给解释器，但该处按密钥 0 解释两条指令后就出现越界
// opcode，按密钥 0xff 解释第一条就越界——它不是脚本，是给失败路径准备的占位数据。
// 于是每次慢路径都必然失败，最后撞 brk #0xdead。
//
// 这里把 +0x10 改指向自己的函数。绑定器调用它之后会检查 x15/x14 是否非零，再
// 把 x14 写进缓存槽并跳过去；跳转前绑定器会自己恢复 x15..x28 和 nzcv，所以这里
// 只需要设置 x14（真正的目标）和 x15（非零标志），参数寄存器不用管。
// 目标选成"返回 nil"的桩：这个导入是埋点用的，返回空值即可。
static id aia_import_nil(void);

// 绑定器入口的替代实现：直接把 x0 置 0 返回，等价于这个 ijm 导入返回 nil。
// 绑定器是由桩尾跳进来的，lr 已经是桩调用方的返回地址，所以正常返回即可。
__attribute__((noinline, used)) static id aia_binder_entry(void) {
    static int logged;
    if (logged < 20) {
        char b[96];
        snprintf(b, sizeof(b), "  IMPORTNIL hit #%d\n", logged);
        log_raw(b);
        logged++;
    }
    return nil;
}

__attribute__((unused)) static id aia_import_nil(void) { return nil; }

#if AIA_TRACE_IJM_BINDER
// 绑定器是尾调用进来的：进来时 x0/x1/x2 是调用方留下的寄存器，
// x13 是缓存槽地址、x14 是桩地址。这里只记录不改写，然后调原函数。
static int g_binder_traced;
static void (*g_orig_binder_entry)(void);
__attribute__((noinline, used)) static void aia_binder_trace(void) {
    if (g_binder_traced < 40) {
        uintptr_t sp, x13v, x14v, lr;
        __asm__ volatile("mov %0, sp" : "=r"(sp));
        __asm__ volatile("mov %0, x13" : "=r"(x13v));
        __asm__ volatile("mov %0, x14" : "=r"(x14v));
        __asm__ volatile("mov %0, x30" : "=r"(lr));
        uintptr_t o1 = 0, o2 = 0, o3 = 0;
        const char *m1 = module_for(lr, &o1);
        const char *m2 = module_for(x14v, &o2);
        const char *m3 = module_for(x13v, &o3);
        char b[256];
        snprintf(b, sizeof(b), "  BNDTRACE #%d lr=%s+0x%lx stub=%s+0x%lx slot=%s+0x%lx\n",
                 g_binder_traced, m1 ? m1 : "?", (unsigned long)o1,
                 m2 ? m2 : "?", (unsigned long)o2, m3 ? m3 : "?", (unsigned long)o3);
        log_raw(b);
        g_binder_traced++;
    }
    ((void (*)(void))g_orig_binder_entry)();
}
#endif

#if AIA_TRACE_IJM_VM
static uint64_t (*g_orig_app_vm)(uint64_t, uint64_t, uint64_t);
static int g_appvm_log;

// 与解释器同样的 C 调用约定：x0=描述符、x1=寄存器结果区、x2=返回地址。
__attribute__((noinline, used)) static uint64_t aia_app_vm_trace(uint64_t x0, uint64_t x1,
                                                                  uint64_t x2) {
    (void)x2;
    uint64_t r = g_orig_app_vm(x0, x1, x2);
    if (g_appvm_log < 60) {
        uint64_t d0 = 0, d4 = 0, v0 = 0, v8 = 0, v70 = 0, v78 = 0, v110 = 0;
        safe_read((uintptr_t)x0, (uintptr_t *)&d0);
        safe_read((uintptr_t)x0 + 4, (uintptr_t *)&d4);
        safe_read((uintptr_t)r, (uintptr_t *)&v0);
        safe_read((uintptr_t)r + 8, (uintptr_t *)&v8);
        safe_read((uintptr_t)r + 0x70, (uintptr_t *)&v70);
        safe_read((uintptr_t)r + 0x78, (uintptr_t *)&v78);
        safe_read((uintptr_t)r + 0x110, (uintptr_t *)&v110);
        char b[288];
        snprintf(b, sizeof(b),
                 "  APPVM #%d desc=%#llx [d0]=%#llx [d4]=%#llx ret=%#llx"
                 " r0=%#llx r8=%#llx r70=%#llx r78=%#llx r110=%#llx\n",
                 g_appvm_log, (unsigned long long)x0,
                 (unsigned long long)d0, (unsigned long long)d4,
                 (unsigned long long)r, (unsigned long long)v0,
                 (unsigned long long)v8, (unsigned long long)v70,
                 (unsigned long long)v78, (unsigned long long)v110);
        log_raw(b);
        g_appvm_log++;
    }
    return r;
}
#endif

static void install_vm_probe(void);

__attribute__((unused)) static void patch_binder_slow_path(void) {
    uintptr_t base = app_base();
    if (!base) return;
    // 直接改 __TEXT 里的元数据会让该页失去执行权限（iOS 不允许代码页可写），
    // 绑定器自己也跟着无法执行。改成用 MSHookFunction 挂绑定器入口：
    // 它由桩尾跳到，lr 就是桩调用方的返回地址，直接返回等价于"这个导入返回 nil"。
#if AIA_TRACE_IJM_BINDER
    MSHookFunction((void *)(base + 0x7c5508), (void *)aia_binder_trace,
                   (void **)&g_orig_binder_entry);
    log_raw("BINDER trace installed\n");
#endif
#if AIA_HOOK_IJM_BINDER
    static void (*orig_binder)(void);
    MSHookFunction((void *)(base + 0x7c5508), (void *)aia_binder_entry, (void **)&orig_binder);
    char b[128];
    snprintf(b, sizeof(b), "BINDER hook at %#lx orig=%p\n",
             (unsigned long)(base + 0x7c5508), (void *)orig_binder);
    log_raw(b);
#else
    (void)aia_binder_entry;
#endif
#if AIA_TRACE_IJM_VM
    MSHookFunction((void *)(base + 0x7c56b8), (void *)aia_app_vm_trace,
                   (void **)&g_orig_app_vm);
    log_raw("APPVM hook installed\n");
#endif
#if AIA_VM_PROBE
    install_vm_probe();
#endif
}

// ============================================================
// JM 的 ijm VM 入口观察
// ============================================================
// VM 入口 JM+0x11ee28 的第一个参数 x0 是"脚本描述符"，游标 = x0 + 4。
// 正常情况下这个描述符应该落在 JMCodeProtectKit 自己的代码区里。
// 故障现场拿到的是主二进制的 0x7c5500，说明调用方给的是别的东西。
// 这里只观察不改写：统计每次调用的描述符归属，看看非 JM 描述符是偶发还是常态。
static void *g_orig_vm_entry;

static uintptr_t module_base_for(const char *needle, uintptr_t *size_out) {
    for (int i = 0; i < g_mod_count; i++) {
        if (g_mods[i].name && strstr(g_mods[i].name, needle)) {
            if (size_out) *size_out = g_mods[i].size;
            return g_mods[i].base;
        }
    }
    return 0;
}

// 与 VM 入口同样的 C 调用约定：x0/x1/x2 是前三个参数，返回值就是 x0。
__attribute__((unused)) static uint64_t aia_vm_probe_entry(uint64_t x0, uint64_t x1, uint64_t x2) {
    uintptr_t jm = 0, jmsz = 0;
    jm = module_base_for("JMCodeProtectKit", &jmsz);
    g_vm_calls++;
    if (jm && !(x0 >= jm && x0 < jm + jmsz)) {
        if (g_vm_bad < 40) {
            uintptr_t off = 0;
            const char *m = module_for((uintptr_t)x0, &off);
            char b[192];
            snprintf(b, sizeof(b), "  VMBAD #%d desc=%#llx %s+0x%lx ctx=%#llx\n",
                     g_vm_bad, (unsigned long long)x0, m ? m : "?",
                     (unsigned long)off, (unsigned long long)x1);
            log_raw(b);
            g_vm_bad++;
        }
    }
#if AIA_VM_GUARD
    // 描述符不属于 JM 自己的代码区，说明这个 VM 调用不是 JM 的脚本。
    // 硬解释会把游标走到越界的分派表项上，算出未映射地址直接跳飞。
    // 这里按 VM 自己的正常返回约定收尾：x0 = ctx。
    // VM 的返回路径（JM+0x11f264）就是把 ctx 原样交回去，由外层壳从 ctx 里
    // 恢复寄存器并返回，因此这样收尾对调用方是合法的。
    if (jm && !(x0 >= jm && x0 < jm + jmsz) && x1) {
        g_vm_guarded++;
        return x1;
    }
#endif
    uint64_t (*orig)(uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t))g_orig_vm_entry;
    return orig(x0, x1, x2);
}

__attribute__((unused)) static void install_vm_probe(void) {
    uintptr_t jm = module_base_for("JMCodeProtectKit", NULL);
    if (!jm) { log_raw("VMPROBE no JM base\n"); return; }
    MSHookFunction((void *)(jm + 0x11ee28), (void *)aia_vm_probe_entry, (void **)&g_orig_vm_entry);
    char b[128];
    snprintf(b, sizeof(b), "VMPROBE hook at %#lx orig=%p\n",
             (unsigned long)(jm + 0x11ee28), (void *)g_orig_vm_entry);
    log_raw(b);
}

// 绑定器入口在 KYHAppStore+0x7c5508，调用者用 x13=元数据槽、x14=桩、x15=期望值。
// 直接在 0x7c5590 的 cbz x15 上做不了（静态代码不可改，__TEXT 只读），
// 所以改为 hook 绑定器回调 0x7c5588 里 blr 出去的那个函数——它是 ijm 运行时的
// 导入解析器。解析失败的判据是返回 0，我们改成返回元数据表里的 PTR。
#if AIA_IJM_KEY
// 这个全局在 __DATA，文件里初值 0；运行期一旦变成非 0，之后每次 VM 分派都会
// 用取反的密钥，脚本解出来全是乱码。观测它的取值能直接回答"检测是否失败"。
static volatile uint64_t *g_ijm_key_flag(void) {
    uintptr_t jm = module_base_for("JMCodeProtectKit", NULL);
    return jm ? (volatile uint64_t *)(jm + 0x1b9678) : NULL;
}

static void start_ijm_key_watch(void) {
    dispatch_queue_t q = dispatch_get_global_queue(0, 0);
    dispatch_async(q, ^{
        volatile uint64_t *p = g_ijm_key_flag();
        if (!p) { log_raw("IJMKEY no JM base\n"); return; }
        char b[160];
        uint64_t last = ~0ULL;
        int changes = 0;
        // 采样必须很低频。先前按 5 ms 轮询 5 分钟，累计唤醒次数触发了系统的
        // wakeups_resource 限制，App 直接被杀掉（CrashReporter 里有
        // KYHAppStore.wakeups_resource-*.ips）。改成 1 秒一次、只跑 60 次。
        for (int i = 0; i < 60; i++) {
            uint64_t v = *p;
            if (v != last) {
                snprintf(b, sizeof(b), "IJMKEY t=%ds = %#llx\n", i, (unsigned long long)v);
                log_raw(b);
                last = v;
                if (++changes > 40) break;
            }
#if AIA_IJM_KEY >= 2
            if (v) { *p = 0; }
#endif
            sleep(1);
        }
        snprintf(b, sizeof(b), "IJMKEY watch end value=%#llx\n", (unsigned long long)*p);
        log_raw(b);
    });
}
#else
__attribute__((unused)) static void start_ijm_key_watch(void) {}
#endif

#if AIA_IJM_RESOLVER
// 我们给出的"实现"：被那批 ijm 桩当成真实函数调用。这些桩都是 App 的埋点类方法，
// 返回空值即可；x0 清零保证返回 nil，而不是把上一个调用的残留值当对象用。
__attribute__((naked, used)) static void aia_ijm_impl_stub(void) {
    __asm__ volatile("mov x0, #0\n\t"
                     "ret\n\t");
}

// 非 static：naked 函数里的汇编要按符号名引用它，符号必须留在符号表里。
__attribute__((used)) void *aia_ijm_impl_ptr = (void *)&aia_ijm_impl_stub;

// 绑定器 blr 解析器时期望的收尾方式：sp 上留 0x30 字节帧。
// 少了这一步，绑定器在 0x7c558c 的 ldr x30,[sp],#0x30 会读回垃圾返回地址。
__attribute__((naked, used)) static void aia_ijm_resolver(void) {
    __asm__ volatile("sub sp, sp, #0x30\n\t"
                     "str x30, [sp]\n\t"
                     "adrp x14, _aia_ijm_impl_ptr@PAGE\n\t"
                     "add  x14, x14, _aia_ijm_impl_ptr@PAGEOFF\n\t"
                     "ldr  x14, [x14]\n\t"
                     "mov  x15, #1\n\t"
                     "ret\n\t");
}

// 槽的运行时地址 = 镜像基址 + 0x4058008（绑定器用 x28=基址 做 add）。
static void *g_ijm_slot_addr(void) {
    uintptr_t base = app_base();
    return base ? (void *)(base + 0x4058008) : NULL;
}

static void install_ijm_resolver(void) {
    void *slot = g_ijm_slot_addr();
    if (!slot) { log_raw("IJMRES no app base\n"); return; }
    uintptr_t cur = 0;
    if (!safe_read((uintptr_t)slot, &cur)) { log_raw("IJMRES unreadable slot\n"); return; }
    uintptr_t coff = 0;
    const char *cm = module_for(cur, &coff);
    char b[224];
    snprintf(b, sizeof(b), "IJMRES slot=%p cur=%#lx %s+0x%lx\n", slot,
             (unsigned long)cur, cm ? cm : "?", (unsigned long)coff);
    log_raw(b);
    if (vm_protect(mach_task_self(), (vm_address_t)((uintptr_t)slot & ~0xFFFULL), 0x4000,
                   FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        snprintf(b, sizeof(b), "IJMRES vm_protect failed\n");
        log_raw(b);
        return;
    }
#if AIA_IJM_RESOLVER == 2
    // 清零后绑定器走 cbz x16 -> [meta+0x10] = 0x7c5600 的回退分支。
    *(volatile uintptr_t *)slot = 0;
    snprintf(b, sizeof(b), "IJMRES -> 0 (回退到 %#lx)\n",
             (unsigned long)(app_base() + 0x7c5600));
#else
    *(volatile uintptr_t *)slot = (uintptr_t)&aia_ijm_resolver;
    snprintf(b, sizeof(b), "IJMRES -> resolver=%p impl=%p\n",
             (void *)&aia_ijm_resolver, (void *)&aia_ijm_impl_stub);
#endif
    log_raw(b);
    // 槽会被 dyld 或 JM 重新填回，必须持续压住。
    // 采样间隔放慢到 300 ms（唤醒预算有限），共 100 次，覆盖启动与首屏。
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        int refills = 0;
        for (int i = 0; i < 100; i++) {
            usleep(300000);
            uintptr_t cur2 = 0;
            if (!safe_read((uintptr_t)slot, &cur2)) continue;
            if (cur2 != 0) {
                uintptr_t co2 = 0;
                const char *cm2 = module_for(cur2, &co2);
                char b2[224];
                snprintf(b2, sizeof(b2), "IJMREFILL #%d t=%.1fs = %s+0x%lx -> 再清零\n",
                         refills, i * 0.3, cm2 ? cm2 : "?", (unsigned long)co2);
                log_raw(b2);
                refills++;
                *(volatile uintptr_t *)slot = 0;
            }
        }
        char b3[128];
        snprintf(b3, sizeof(b3), "IJMREFILL 结束，共回收 %d 次\n", refills);
        log_raw(b3);
    });
}
#else
__attribute__((unused)) static void install_ijm_resolver(void) {}
#endif

__attribute__((unused)) static void patch_binder_zero_values(void) {
    uintptr_t base = app_base();
    if (!base) { log_raw("BINDER no app base\n"); return; }
    // 元数据表在 0x7c54b0：+0x0 BOFF +0x8 ?? +0x10 PTR +0x18 SUPERV +0x20 SLOT
    const uint64_t *meta = (const uint64_t *)(base + 0x7c54b0);
    char b[224];
    snprintf(b, sizeof(b), "BINDER meta boff=%#llx a=%#llx ptr=%#llx sup=%#llx slot=%#llx\n",
             (unsigned long long)meta[0], (unsigned long long)meta[1],
             (unsigned long long)meta[2], (unsigned long long)meta[3],
             (unsigned long long)meta[4]);
    log_raw(b);
    // 解析器槽 [meta+0x48] 指向 __LINKEDIT 里的 0x4058008，由 dyld 在运行时填充。
    // 这里读出三个相关槽的真实值：绑定器就是用它们算重定位基数的。
    uintptr_t resolver_off = (uintptr_t)meta[9];   // meta[0x48]
    snprintf(b, sizeof(b), "BINDER resolver_off=%#lx\n", (unsigned long)resolver_off);
    log_raw(b);
    for (int i = 0; i < 4; i++) {
        uintptr_t a = base + resolver_off + (uintptr_t)i * 8;
        uintptr_t v = 0;
        if (safe_read(a, &v)) {
            snprintf(b, sizeof(b), "BINDER slot[%d] @%#lx = %#lx\n",
                     i, (unsigned long)(resolver_off + i * 8), (unsigned long)v);
            log_raw(b);
        }
    }
    // x28 = 0x7c55fc - resolver(0x4058008)，即绑定器用的重定位基数。
    uintptr_t x28 = (uintptr_t)0x7c55fc - resolver_off;
    snprintf(b, sizeof(b), "BINDER x28=%#lx\n", (unsigned long)x28);
    log_raw(b);
    patch_binder_slow_path();
}
#endif


// ============================================================
// 关掉 Dynatrace 的 swizzle 配置器
// ============================================================
// Dynatrace 通过 +[DTXSwizzleDetectionConfigurator addClass:selectors:detector:
// updateImplementation:] 这类方法批量往 App 的类上装 IMP。被装上的 App 方法如果由
// ijm VM 实现，Dynatrace 回调原实现时会走导入绑定器，而绑定器在本进程里解析失败，
// 主线程直接撞 brk #0xdead 或跳飞。
// 这里把这个配置器的 add* 类方法全部变成空操作，Dynatrace 就一个 hook 都装不上。
// 实测有害：把 add* 变空操作会破坏 Dynatrace 的自洽状态，App 能起但界面不再
// 响应触摸（视图树只剩三层系统容器）。默认关闭。
#ifndef AIA_KILL_DT_SWIZZLE
#define AIA_KILL_DT_SWIZZLE 0
#endif

#if AIA_KILL_DT_SWIZZLE
static int g_dt_swizzle_killed;

static void aia_noop_void(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    if (g_dt_swizzle_killed < 80) {
        char b[160];
        snprintf(b, sizeof(b), "  DT-KILL %s\n", sel_getName(_cmd));
        log_raw(b);
        g_dt_swizzle_killed++;
    }
}

__attribute__((unused)) static void kill_dt_swizzle(void) {
    // 1) 配置器上的所有 add* 类方法
    Class cfg = objc_getClass("DTXSwizzleDetectionConfigurator");
    int n_hooked = 0;
    if (cfg) {
        Class meta = object_getClass((id)cfg);
        unsigned int n = 0;
        Method *ms = class_copyMethodList(meta, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = sel_getName(method_getName(ms[i]));
            if (strncmp(nm, "add", 3) != 0) continue;
            MSHookMessageEx(cfg, method_getName(ms[i]), (IMP)aia_noop_void, NULL);
            n_hooked++;
        }
        if (ms) free(ms);
    }
    // 2) 首屏启动时批量 swizzle UIKit 的那一步
    Class sm = objc_getClass("DTXStartupMeasurements");
    if (sm) {
        SEL sel = sel_registerName("swizzleUIKitClasses");
        if (class_getClassMethod(sm, sel))
            MSHookMessageEx(sm, sel, (IMP)aia_noop_void, NULL);
    }
    char b[160];
    snprintf(b, sizeof(b), "DT-KILL installed cfg=%s hooked=%d\n",
             cfg ? "yes" : "no", n_hooked);
    log_raw(b);
}
#endif

__attribute__((unused)) static void install_exc_handler(void) {
    log_exception_port_owners("pre");
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) { aialog("exc: port_allocate %d", kr); return; }
    mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);
    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT,
                                  g_exc_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                                  ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { aialog("exc: set_exception_ports %d", kr); return; }
#if AIA_EXC_SERVER
    pthread_t th;
    pthread_create(&th, NULL, aia_exc_server, NULL);
    aialog("exc: handler installed port=%u (server on)", g_exc_port);
    log_exception_port_owners("post");
#else
    aialog("exc: handler installed port=%u (server off, exceptions will queue)", g_exc_port);
#endif
#if AIA_EXC_WATCHDOG
    pthread_t wt;
    pthread_create(&wt, NULL, aia_exc_watchdog, NULL);
#endif
}
#endif

// ============================================================
// MARK: 初始化
// ============================================================

// ellekit 会改写 _dyld_* 的编号，_dyld_get_image_header(0) 在这个进程里返回的是
// systemhook.dylib 而不是主程序。这里改为在模块表里按主可执行文件路径查找。
static uintptr_t app_base(void) {
    char exe[PATH_MAX] = {0};
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0) exe[0] = 0;
    if (exe[0]) {
        for (int i = 0; i < g_mod_count; i++) {
            if (g_mods[i].name && strcmp(g_mods[i].name, exe) == 0) return g_mods[i].base;
        }
    }
    for (int i = 0; i < g_mod_count; i++) {
        const char *nm = g_mods[i].name;
        if (!nm) continue;
        const char *slash = strrchr(nm, '/');
        const char *leaf = slash ? slash + 1 : nm;
        if (strncmp(leaf, "KYHAppStore", 11) == 0) return g_mods[i].base;
    }
    return (uintptr_t)_dyld_get_image_header(0);
}

__attribute__((unused)) static void patch_app_code(uintptr_t offset, uint32_t expect, uint32_t new_insn, const char *tag) {
    uintptr_t b = app_base();
    if (!b) { aialog("patch %s: no app base", tag); return; }
    uintptr_t addr = b + offset;
    uintptr_t page = addr & ~(uintptr_t)0x3fff;
    uint32_t old = *(volatile uint32_t *)addr;
    if (old != expect) {
        aialog("patch %s @%#lx: unexpected %08x (want %08x)", tag, (unsigned long)offset, old, expect);
        return;
    }
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { aialog("patch %s: vm_protect failed %d", tag, kr); return; }
    *(volatile uint32_t *)addr = new_insn;
    sys_icache_invalidate((void *)addr, 4);
    aialog("patch %s @%#lx: %08x -> %08x ok", tag, (unsigned long)offset, old, new_insn);
}

#if AIA_FAKE_PATH
static void fake_own_image_path(void) {
    Dl_info di = {0};
    if (!dladdr((void *)aialog, &di) || !di.dli_fbase) { aialog("fake_path: dladdr self failed"); return; }
    struct task_dyld_info td = {0};
    mach_msg_type_number_t tcount = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&td, &tcount) != KERN_SUCCESS ||
        !td.all_image_info_addr) {
        aialog("fake_path: task_info failed");
        return;
    }
    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)(uintptr_t)td.all_image_info_addr;
    if (!infos->infoArray) { aialog("fake_path: no all_image_infos"); return; }
    struct dyld_image_info *arr = (struct dyld_image_info *)(uintptr_t)infos->infoArray;
    static char fake[8][64];
    static const char *names[8] = {
        "/usr/lib/libz.1.dylib", "/usr/lib/libsqlite3.dylib", "/usr/lib/libxml2.2.dylib",
        "/usr/lib/libbz2.1.0.dylib", "/usr/lib/liblzma.5.dylib", "/usr/lib/libarchive.2.dylib",
        "/usr/lib/libcompression.dylib", "/usr/lib/libicucore.A.dylib",
    };
    int hit = 0;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)((uintptr_t)arr & ~0x3fffUL),
                                  ((infos->infoArrayCount * sizeof(*arr)) & ~0x3fffUL) + 0x4000,
                                  false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    aialog("fake_path: vm_protect=%d count=%u", kr, infos->infoArrayCount);
    for (uint32_t i = 0; i < infos->infoArrayCount && hit < 8; i++) {
        const char *old = arr[i].imageFilePath;
        if (!old) continue;
        if (!strstr(old, "/var/jb") && !strstr(old, "TweakInject") &&
            !strstr(old, "preboot") && !strstr(old, "basebin") &&
            !strstr(old, "procursus") && !strstr(old, "ellekit") &&
            !strstr(old, "libinjector") && !strstr(old, "systemhook")) continue;
        snprintf(fake[hit], sizeof(fake[hit]), "%s", names[hit]);
        aialog("fake_path: idx=%u %s -> %s%s", i, old, fake[hit],
               arr[i].imageLoadAddress == di.dli_fbase ? " (self)" : "");
        arr[i].imageFilePath = fake[hit];
        hit++;
    }
    aialog("fake_path: patched %d images", hit);
}
#endif

#if AIA_DLADDR_MASK || AIA_STEALTH
static void *g_orig_dladdr_fn;
static const char *g_mask_names[] = {
    "/usr/lib/libz.1.dylib", "/usr/lib/libsqlite3.dylib", "/usr/lib/libxml2.2.dylib",
    "/usr/lib/libbz2.1.0.dylib", "/usr/lib/liblzma.5.dylib", "/usr/lib/libcrypto.44.dylib",
    "/usr/lib/libcompression.dylib", "/usr/lib/libicucore.A.dylib",
};
static char g_mask_store[8][64];
static int g_mask_used;

static int my_dladdr_mask(const void *addr, Dl_info *info) {
    int (*orig)(const void *, Dl_info *) = (int (*)(const void *, Dl_info *))g_orig_dladdr_fn;
    int r = orig(addr, info);
    if (!r || !info || !info->dli_fname) return r;
    const char *p = info->dli_fname;
    if (!strstr(p, "/var/jb") && !strstr(p, "preboot") && !strstr(p, "basebin") &&
        !strstr(p, "procursus") && !strstr(p, "TweakInject") && !strstr(p, "ellekit") &&
        !strstr(p, "systemhook") && !strstr(p, "libinjector") && !strstr(p, "AIABypass")) {
        return r;
    }
    if (g_mask_used >= 8) { g_mask_used = 0; }
    strlcpy(g_mask_store[g_mask_used], g_mask_names[g_mask_used], sizeof(g_mask_store[0]));
    aialog("[mask] dladdr(%p) %s -> %s (caller %s)", addr, p,
           g_mask_store[g_mask_used], caller_desc(__builtin_return_address(0)));
    info->dli_fname = g_mask_store[g_mask_used];
    g_mask_used++;
    return r;
}

// 通过 __DATA_CONST 的懒绑定指针找到 dladdr 的真实实现
static void install_dladdr_mask(void) {
    void *fn = dlsym(RTLD_DEFAULT, "dladdr");
    if (!fn) { aialog("mask: dlsym dladdr failed"); return; }
    g_orig_dladdr_fn = fn;
    Dl_info di = {0};
    if (dladdr(fn, &di) && di.dli_fname) aialog("mask: dladdr impl in %s", di.dli_fname);
    MSHookFunction(fn, (void *)my_dladdr_mask, (void **)&g_orig_dladdr_fn);
    aialog("mask: dladdr hooked, orig=%p", g_orig_dladdr_fn);
}
#endif

#if AIA_EXTRA_HOOKS
// 判定实验用的透传 hook：只把调用转给原函数，不做任何改变。
static int (*xh_orig_stat)(const char *, struct stat *);
static int xh_stat(const char *p, struct stat *b) { return xh_orig_stat(p, b); }
static int (*xh_orig_access)(const char *, int);
static int xh_access(const char *p, int m) { return xh_orig_access(p, m); }
static char *(*xh_orig_getenv)(const char *);
static char *xh_getenv(const char *n) { return xh_orig_getenv(n); }
static int (*xh_orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int xh_sysctl(int *n, u_int l, void *o, size_t *ol, void *nw, size_t nl) {
    return xh_orig_sysctl(n, l, o, ol, nw, nl);
}
#endif

#if AIA_KILL_PROBE
// JM 处决的第二种形态是给线程发 SIGUSR1（现场 pc=lr=0xeee1）。
// 把发信号这一端挂住，就能拿到 JM 内部发起处决的返回地址。
static int (*kp_orig_kill)(pid_t, int);
static int kp_kill(pid_t pid, int sig) {
    static int n;
    if (n < 30) {
        char b[256];
        uintptr_t o = 0;
        const char *m = module_for((uintptr_t)__builtin_return_address(0), &o);
        snprintf(b, sizeof(b), "KILLPROBE kill(pid=%d sig=%d) caller=%s+0x%lx\n",
                 (int)pid, sig, m ? m : "?", (unsigned long)o);
        log_raw(b);
        n++;
    }
    return kp_orig_kill(pid, sig);
}
static int (*kp_orig_raise)(int);
static int kp_raise(int sig) {
    static int n;
    if (n < 30) {
        char b[256];
        uintptr_t o = 0;
        const char *m = module_for((uintptr_t)__builtin_return_address(0), &o);
        snprintf(b, sizeof(b), "KILLPROBE raise(%d) caller=%s+0x%lx\n", sig, m ? m : "?", (unsigned long)o);
        log_raw(b);
        n++;
    }
    return kp_orig_raise(sig);
}
static int (*kp_orig_pkill)(pthread_t, int);
static int kp_pkill(pthread_t th, int sig) {
    static int n;
    if (n < 30) {
        char b[256];
        uintptr_t o = 0;
        const char *m = module_for((uintptr_t)__builtin_return_address(0), &o);
        snprintf(b, sizeof(b), "KILLPROBE pthread_kill(%p %d) caller=%s+0x%lx\n",
                 (void *)th, sig, m ? m : "?", (unsigned long)o);
        log_raw(b);
        n++;
    }
    return kp_orig_pkill(th, sig);
}
static void install_kill_probe(void) {
    MSHookFunction((void *)kill, (void *)kp_kill, (void **)&kp_orig_kill);
    MSHookFunction((void *)raise, (void *)kp_raise, (void **)&kp_orig_raise);
    MSHookFunction((void *)pthread_kill, (void *)kp_pkill, (void **)&kp_orig_pkill);
    log_raw("KILLPROBE installed\n");
}
#else
__attribute__((unused)) static void install_kill_probe(void) {}
#endif

#if AIA_EARLY_TRACE
// dyld 在绑定阶段就会把别处对这些符号的引用重定向到 __interpose 里的替代函数，
// 比任何构造函数都早。用它来观察"构造函数之前"到底发生过什么。
struct aia_early_rec { uint64_t t; const char *name; uintptr_t ra; };
static struct aia_early_rec g_early[96];
static int g_early_n;
static void aia_early_note(const char *name, uintptr_t ra) {
    int i = __atomic_fetch_add(&g_early_n, 1, __ATOMIC_RELAXED);
    if (i < 96) { g_early[i].t = mach_absolute_time(); g_early[i].name = name; g_early[i].ra = ra; }
}

static uint32_t ip_image_count(void) {
    aia_early_note("dyld_image_count", (uintptr_t)__builtin_return_address(0));
    return _dyld_image_count();
}
static const char *ip_image_name(uint32_t i) {
    aia_early_note("dyld_get_image_name", (uintptr_t)__builtin_return_address(0));
    return _dyld_get_image_name(i);
}
static const struct mach_header *ip_image_header(uint32_t i) {
    aia_early_note("dyld_get_image_header", (uintptr_t)__builtin_return_address(0));
    return _dyld_get_image_header(i);
}
static char *ip_getenv(const char *n) {
    aia_early_note("getenv", (uintptr_t)__builtin_return_address(0));
    return getenv(n);
}
static int ip_sysctl(int *a, u_int b, void *c, size_t *d, void *e, size_t f) {
    aia_early_note("sysctl", (uintptr_t)__builtin_return_address(0));
    return sysctl(a, b, c, d, e, f);
}
static void *ip_dlsym(void *h, const char *n) {
    aia_early_note("dlsym", (uintptr_t)__builtin_return_address(0));
    return dlsym(h, n);
}

__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *repl; const void *orig; } g_early_interpose[] = {
    { (const void *)ip_image_count,  (const void *)_dyld_image_count },
    { (const void *)ip_image_name,   (const void *)_dyld_get_image_name },
    { (const void *)ip_image_header, (const void *)_dyld_get_image_header },
    { (const void *)ip_getenv,       (const void *)getenv },
    { (const void *)ip_sysctl,       (const void *)sysctl },
    { (const void *)ip_dlsym,        (const void *)dlsym },
};

static void dump_early(void) {
    char b[256];
    snprintf(b, sizeof(b), "EARLY now=%llu n=%d\n", (unsigned long long)mach_absolute_time(), g_early_n);
    log_raw(b);
    for (int i = 0; i < g_early_n && i < 96; i++) {
        uintptr_t o = 0;
        const char *m = module_for(g_early[i].ra, &o);
        snprintf(b, sizeof(b), "  EARLY#%d t=%llu %s caller=%s+0x%lx\n", i,
                 (unsigned long long)g_early[i].t, g_early[i].name, m ? m : "?", (unsigned long)o);
        log_raw(b);
    }
}
#else
__attribute__((unused)) static void dump_early(void) {}
#endif

#if AIA_FREEZE_JM
// 判定发生在我们的构造函数之前，改内存已经来不及；但执行处决的是 JM 自己的线程。
// 这里在构造函数里把这些线程停住，让处决根本不会发生。
static int freeze_jm_threads(void) {
    uintptr_t jm = module_base_for("JMCodeProtectKit", NULL);
    if (!jm) { log_raw("FREEZEJM 找不到 JM 基址\n"); return 0; }
    uintptr_t jmend = jm + 0x1a8000;
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) return 0;
    int frozen = 0;
    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) != KERN_SUCCESS) continue;
        uintptr_t pc = aia_strip_pac((uintptr_t)st.__pc);
        if (pc < jm || pc >= jmend) continue;
        if (thread_suspend(list[i]) == KERN_SUCCESS) {
            frozen++;
            char b[128];
            snprintf(b, sizeof(b), "FREEZEJM 停住线程 %u pc=+0x%lx\n",
                     (unsigned)list[i], (unsigned long)(pc - jm));
            log_raw(b);
        }
    }
    for (mach_msg_type_number_t i = 0; i < cnt; i++) mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_act_t));
    char b[96];
    snprintf(b, sizeof(b), "FREEZEJM 共停住 %d 个线程\n", frozen);
    log_raw(b);
    return frozen;
}
#else
__attribute__((unused)) static int freeze_jm_threads(void) { return 0; }
#endif

__attribute__((constructor)) static void aiabypass_init(void) {
    aialog("===== ctor in %s =====", [[[NSBundle mainBundle] bundleIdentifier] UTF8String]);
#if AIA_TRULY_EMPTY
    aialog("truly empty mode");
#if AIA_GOT_AUDIT
    // 零 hook 对照：只开日志和 GOT 审计，看越狱基座自己会不会改 App 的 GOT。
    {
        NSString *dir0 = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *lp0 = [dir0 stringByAppendingPathComponent:@"aiabypass.log"];
        g_logfd = open([lp0 fileSystemRepresentation], O_WRONLY | O_APPEND);
    }
#if AIA_TE_HOOK
    // 对照实验：零 hook 基线里只装一个 task_info，看是否会引出 GOT 重绑定。
    log_raw("GOTPHASE te-pre-hook\n");
    got_audit();
    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
    log_raw("GOTPHASE te-post-hook\n");
#endif
    got_audit();
#endif
    return;
#endif

    {
#if AIA_DEBUG_LOG
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *lp = [dir stringByAppendingPathComponent:@"aiabypass.log"];
        g_logfd = open([lp fileSystemRepresentation], O_WRONLY | O_APPEND);
#endif
        struct sigaction sa = {0};
        sa.sa_sigaction = crash_signal_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sigaction(SIGTRAP, &sa, NULL);
        // JM 用 SIGUSR1 处决进程，必须由我们接住。
        sigaction(SIGUSR1, &sa, NULL);
    }
#if AIA_GOT_AUDIT
    log_raw("GOTPHASE post-logfile\n");
    got_audit();
#endif
    if (!g_t0) g_t0 = mach_absolute_time();
#if AIA_EARLY_TRACE
    dump_early();
#endif
    snapshot_modules();
#if AIA_GOT_RESTORE
    install_got_restore_dlsym();
    log_raw("GOTPHASE pre-restore\n");
    got_audit();
    got_restore();
    log_raw("GOTPHASE post-restore\n");
    got_audit();
#endif
#if AIA_GOT_AUDIT
    log_raw("GOTPHASE post-snapshot\n");
    got_audit();
    slot_symbol_match();
#endif
    {
        struct thread_identifier_info tii;
        mach_msg_type_number_t c = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(mach_thread_self(), THREAD_IDENTIFIER_INFO, (thread_info_t)&tii, &c) == KERN_SUCCESS)
            g_main_tid = tii.thread_id;
    }
    aialog("module snapshot: %d mainTid=%llu", g_mod_count, (unsigned long long)g_main_tid);
#if AIA_EXC_HANDLER
    install_exc_handler();
#if AIA_GOT_AUDIT
    log_raw("GOTPHASE post-exchandler\n");
    got_audit();
#endif
#endif
#if AIA_SAMPLE_THREADS
    start_sampler();
#endif
#if AIA_DUMP_ON_SIGNAL
    signal(SIGUSR1, dump_all_threads);
    signal(SIGUSR2, dump_ui_signal);
    aialog("dump-on-signal: SIGUSR1 已注册");
#endif
#if AIA_LOG_IMAGES
    for (int i = 0; i < g_mod_count; i++) {
        const char *nm = g_mods[i].name;
        if (!nm) continue;
        if (strncmp(nm, "/System/", 8) == 0 || strncmp(nm, "/usr/lib/", 9) == 0) continue;
        aialog("img[%d/%d] %s", i, g_mod_count, nm);
    }
#endif
#if AIA_FAKE_PATH
    fake_own_image_path();
#endif
#if AIA_STEALTH
    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    install_dladdr_mask();
    aialog("stealth mode: dyld filter + dladdr mask");
    return;
#endif
#if AIA_DLADDR_MASK
    install_dladdr_mask();
    aialog("dladdr-mask mode");
    return;
#endif
#if AIA_OBSERVE_ONLY
    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
    MSHookFunction((void *)open, (void *)my_open, (void **)&orig_open);
    MSHookFunction((void *)readlink, (void *)my_readlink, (void **)&orig_readlink);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)getsectiondata, (void *)my_getsectiondata, (void **)&orig_getsectiondata);
    MSHookFunction((void *)NSClassFromString, (void *)my_NSClassFromString, (void **)&orig_NSClassFromString);
    MSHookFunction((void *)objc_getClass, (void *)my_objc_getClass, (void **)&orig_objc_getClass);
    MSHookFunction((void *)dlsym, (void *)my_dlsym, (void **)&orig_dlsym);
    MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&orig_exit);
    MSHookFunction((void *)_exit, (void *)my_Exit, (void **)&orig_Exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&orig_abort);
    MSHookFunction((void *)kill, (void *)my_kill, (void **)&orig_kill);
    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
    aialog("observe-only mode: safe hook subset installed");
    return;
#endif
#if AIA_EMPTY
    // 观测模式：不装任何会改变行为的 hook，只额外记录 task_info 与资源统计。
#if AIA_GOT_AUDIT
    log_raw("GOTPHASE pre-taskinfo\n");
    got_audit();
#endif
    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
#if AIA_GOT_AUDIT
    log_raw("GOTPHASE post-taskinfo\n");
    got_audit();
#endif
#if AIA_EXTRA_HOOKS
    // 判定实验：多挂几个 libc 函数。若 JM 真在查 __got 完整性，
    // 命中数会随之增加，处决次数（exc）也应同步上升。
    MSHookFunction((void *)getenv, (void *)xh_getenv, (void **)&xh_orig_getenv);
    MSHookFunction((void *)sysctl, (void *)xh_sysctl, (void **)&xh_orig_sysctl);
    MSHookFunction((void *)stat, (void *)xh_stat, (void **)&xh_orig_stat);
    MSHookFunction((void *)access, (void *)xh_access, (void **)&xh_orig_access);
    log_raw("EXTRA hooks installed\n");
#endif
#if AIA_EVENT_PROBE
    install_event_probe();
    aialog("empty mode: no hooks (含事件观测)");
#else
    aialog("empty mode: no hooks (无事件观测)");
#endif
#if AIA_FS_ONLY
    install_fs_only();
#endif
#if AIA_ENV_PROBE
    install_env_probe();
#endif
#if AIA_PROC_FILTER
    install_proc_filter();
#endif
#if AIA_BLOCK_LITEHOOK
    install_litehook_block();
#endif
#if AIA_GOT_AUDIT
    // 分三个时间点看：槽是 App 自己的绑定器填的，还是越狱基座在启动后改的。
    log_raw("GOTPHASE t=0\n");
    got_audit();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{ log_raw("GOTPHASE t=1s\n"); got_audit(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{ log_raw("GOTPHASE t=4s\n"); got_audit(); });
#endif
#if AIA_MSGSEND_PROBE
    install_msgsend_probe();
#endif
#if AIA_EXCPORT_PROBE
    install_excport_probe();
#endif
#if AIA_CSOPS_PROBE
    install_csops_probe();
#endif
#if AIA_FS_PROBE
    install_fs_probe();
#endif
#if AIA_BLOCK_DYNATRACE
    install_dynatrace_block();
#endif
#if !AIA_NO_LIBC_HOOKS
    // 只记录，不改变行为：确认进程是被 exit() 正常结束还是被信号打死。
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&orig_exit);
    MSHookFunction((void *)_exit, (void *)my_Exit, (void **)&orig_Exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&orig_abort);
#else
    log_raw("NO-LIBC-HOOKS: 只保留异常端口\n");
#endif
#if AIA_KILL_DT_SWIZZLE
    kill_dt_swizzle();
#endif
#if AIA_PATCH_BINDER_VALUE
    patch_binder_zero_values();
#endif
#if AIA_IJM_KEY
    start_ijm_key_watch();
#endif
#if AIA_FREEZE_JM
    freeze_jm_threads();
#endif
#if AIA_IJM_RESOLVER
    // 槽要等 App 自己的初始化写完之后再换，否则会被覆盖回原值。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{ install_ijm_resolver(); });
#endif
#if AIA_NOP_IJM_BRK
    // 绑定器失败出口 KYHAppStore+0x7c55f8 是 brk #0xdead，主线程撞上就会被 SIGTRAP 打死。
    // 补成 NOP 后继续走 0x7c55fc 的 nop 和 0x7c5600 的上下文恢复代码。
    patch_app_code(0x7c55f8, 0xd43bd5a0, 0xd503201f, "ijm-brk");
#endif
#if AIA_KILL_PROBE
    install_kill_probe();
#endif
#if AIA_DLSYM_PROBE
    // App 的 ijm 代码会在运行期解析 libc 函数并存进自己的 __got 槽。
    // 只要它走 dlsym，我们就能看到它到底要哪些函数。
    MSHookFunction((void *)dlsym, (void *)my_dlsym, (void **)&orig_dlsym);
    log_raw("DLSYM probe installed\n");
#endif
#if AIA_NEUTER_IJM
    // 稍等片刻：App 的类和分类要等首屏建起来才齐。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ neuter_ijm_telemetry(); });
#endif
#if AIA_CHECK_TRACE
    install_check_trace();
#endif
    start_stats_thread();
    return;
#endif

#if AIA_SAMPLE_CODE
    {
        const struct mach_header *h0 = _dyld_get_image_header(0);
        aialog("sample: image0=%p name=%s", h0, _dyld_get_image_name(0) ?: "?");
        for (int k = 0; k < 12; k++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(k * 100) * NSEC_PER_MSEC),
                           dispatch_get_global_queue(0, 0), ^{
                uintptr_t b = app_base();
                uint32_t w0 = *(volatile uint32_t *)(b + 0x7c5590);
                uint32_t w1 = *(volatile uint32_t *)(b + 0x7c55f8);
                uint64_t hsh = 0;
                const uint64_t *pg = (const uint64_t *)(b + 0x7c5000);
                for (int i = 0; i < 512; i++) hsh = hsh * 1099511628211ULL ^ pg[i];
                aialog("sample t=%d00ms w5590=%08x w55f8=%08x pagehash=%016llx",
                       k, w0, w1, (unsigned long long)hsh);
            });
        }
    }
#endif

#if AIA_DUMP_CODE
    {
        uintptr_t base = app_base();
        aialog("dump: app_base=%#lx image0=%s", (unsigned long)base,
               _dyld_get_image_name(0) ?: "?");
        char path[512] = {0};
        uint32_t rp = proc_regionfilename(getpid(), (uint64_t)(base + 0x7c5590), path, sizeof(path) - 1);
        aialog("region file for +0x7c5590: len=%u path=%s", rp, path);
        const uint8_t *p = (const uint8_t *)(base + 0x7c5490);
        char line[200];
        for (int i = 0; i < 0x190; i += 16) {
            char *w = line;
            w += snprintf(w, 24, "  +%05x: ", 0x7c5490 + i);
            for (int j = 0; j < 16; j++) w += snprintf(w, 4, "%02x", p[i + j]);
            *w++ = '\n'; *w = 0;
            log_raw(line);
        }
    }
#endif

#if AIA_PATCH_BINDER
    // 0x7c5590: cbz x15 -> nop
    patch_app_code(0x7c5590, 0xb400034f, 0xd503201f, "binder-x15");
#endif

#if AIA_DYLD_ONLY
    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    aialog("dyld-only mode");
    return;
#endif

#if AIA_MINIMAL
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    aialog("minimal mode: only add_image hook");
    return;
#endif

    MSHookFunction((void *)_dyld_image_count, (void *)my_dyld_image_count, (void **)&orig_dyld_image_count);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_get_image_header, (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    MSHookFunction((void *)_dyld_get_image_vmaddr_slide, (void *)my_dyld_get_image_slide, (void **)&orig_dyld_get_image_slide);
    MSHookFunction((void *)_dyld_register_func_for_add_image, (void *)my_register_add_image, (void **)&orig_register_add_image);
    MSHookFunction((void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
    MSHookFunction((void *)open, (void *)my_open, (void **)&orig_open);
    MSHookFunction((void *)readlink, (void *)my_readlink, (void **)&orig_readlink);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)exit, (void *)my_exit, (void **)&orig_exit);
    MSHookFunction((void *)_exit, (void *)my_Exit, (void **)&orig_Exit);
    MSHookFunction((void *)abort, (void *)my_abort, (void **)&orig_abort);
    MSHookFunction((void *)kill, (void *)my_kill, (void **)&orig_kill);
    MSHookFunction((void *)pthread_exit, (void *)my_pthread_exit, (void **)&orig_pthread_exit);
    MSHookFunction((void *)vm_region_64, (void *)my_vm_region_64, (void **)&orig_vm_region_64);
    MSHookFunction((void *)vm_region_recurse_64, (void *)my_vm_region_recurse_64, (void **)&orig_vm_region_recurse_64);
    MSHookFunction((void *)vm_read_overwrite, (void *)my_vm_read_overwrite, (void **)&orig_vm_read_overwrite);
    MSHookFunction((void *)vm_protect, (void *)my_vm_protect, (void **)&orig_vm_protect);
    MSHookFunction((void *)getsectiondata, (void *)my_getsectiondata, (void **)&orig_getsectiondata);
    MSHookFunction((void *)NSClassFromString, (void *)my_NSClassFromString, (void **)&orig_NSClassFromString);
    MSHookFunction((void *)objc_getClass, (void *)my_objc_getClass, (void **)&orig_objc_getClass);
    MSHookFunction((void *)dlsym, (void *)my_dlsym, (void **)&orig_dlsym);
    MSHookFunction((void *)getenv, (void *)my_getenv, (void **)&orig_getenv);

    MSHookFunction((void *)task_info, (void *)my_task_info, (void **)&orig_task_info);
    aialog("hooks installed; image_count=%u", orig_dyld_image_count ? orig_dyld_image_count() : 0);
    start_stats_thread();
}
