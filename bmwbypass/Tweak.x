// BMWBypass — 绕过 My BMW（de.bmw.connected.mobile20.cn）的越狱检测弹窗
//
// 检测链（见 analysis.md）：
// - App 集成标准开源 IOSSecuritySuite。启动时主 binary 调用 ISS 检测入口，结果经 Flutter
//   platform channel 上报 Dart 层；Dart 侧据此做 attestation pre-check，失败则弹
//   「App访问受限 / 检测到可能存在越狱行为」并要求关闭 App（进程不自杀，等用户点按钮）。
// - 运行时探针证明：BMW 启动实际只调用两个 ISS 入口 —— amIJailbroken() 与
//   amIReverseEngineered()。其中 amIReverseEngineered() 命中注入库/hook 导致 pre-check 失败，
//   是弹窗根因（仅 hook amIJailbroken 仍会弹）。
//
// 方案：hook ISS 全部「() -> Bool」顶层检测入口，命中即返回「安全」值（false）。
// - amIJailbroken / amIReverseEngineered 是当前必需项；其余 6 个语义相同（检测到危险返回
//   true），统一返回 false 无副作用，作为冗余覆盖以扛 App 版本升级可能启用的检测。
// - ISS 是检测工具、无内存完整性自检，inline-hook 其导出符号安全（不同于农行 mPaaS/汇丰 Promon）。
// - tuple 返回的入口（amIJailbrokenWithFailedChecks 等）ABI 复杂且 BMW 未调用，不处理。

#import <Foundation/Foundation.h>
#import <substrate.h>

// 诊断日志开关：发布版关闭。日志写 App 数据容器（沙箱内可写），不写 /tmp 或 /var/jb/tmp。
#ifndef BMW_DEBUG_LOG
#define BMW_DEBUG_LOG 0
#endif

#if BMW_DEBUG_LOG
#import <stdio.h>
static void bmwlog(const char *fmt, ...) {
    static NSString *path = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"bmwbypass.log"];
    });
    FILE *f = fopen([path fileSystemRepresentation], "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}
#else
#define bmwlog(...) do {} while (0)
#endif

// ISS 全部「无参、返回单 Bool」的顶层检测入口（Swift mangled 符号）。
// 语义统一：检测到危险返回 true。我们全部替换为恒返回 false。
typedef bool (*iss_bool_fn)(void);

static bool (*orig_amIJailbroken)(void);
static bool (*orig_amIProxied)(void);
static bool (*orig_amIDebugged)(void);
static bool (*orig_amIRunInEmulator)(void);
static bool (*orig_amIReverseEngineered)(void);
static bool (*orig_amIInLockdownMode)(void);
static bool (*orig_isParentPidUnexpected)(void);
static bool (*orig_hasWatchpoint)(void);

#define MK_HOOK(nm, orig_ptr) \
static bool hooked_##orig_ptr(void) { \
    bmwlog("[BMWBypass] " nm "() -> false"); \
    return false; \
}
MK_HOOK("amIJailbroken",        orig_amIJailbroken)
MK_HOOK("amIProxied",           orig_amIProxied)
MK_HOOK("amIDebugged",          orig_amIDebugged)
MK_HOOK("amIRunInEmulator",     orig_amIRunInEmulator)
MK_HOOK("amIReverseEngineered", orig_amIReverseEngineered)
MK_HOOK("amIInLockdownMode",    orig_amIInLockdownMode)
MK_HOOK("isParentPidUnexpected",orig_isParentPidUnexpected)
MK_HOOK("hasWatchpoint",        orig_hasWatchpoint)

typedef struct {
    const char *sym;
    void *replacement;
    iss_bool_fn *orig;
} iss_hook_t;

static const iss_hook_t kHooks[] = {
    { "_$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ",        (void*)hooked_orig_amIJailbroken,        (iss_bool_fn*)&orig_amIJailbroken },
    { "_$s16IOSSecuritySuiteAAC20amIReverseEngineeredSbyFZ", (void*)hooked_orig_amIReverseEngineered, (iss_bool_fn*)&orig_amIReverseEngineered },
    { "_$s16IOSSecuritySuiteAAC10amIProxiedSbyFZ",           (void*)hooked_orig_amIProxied,           (iss_bool_fn*)&orig_amIProxied },
    { "_$s16IOSSecuritySuiteAAC11amIDebuggedSbyFZ",          (void*)hooked_orig_amIDebugged,          (iss_bool_fn*)&orig_amIDebugged },
    { "_$s16IOSSecuritySuiteAAC16amIRunInEmulatorSbyFZ",     (void*)hooked_orig_amIRunInEmulator,     (iss_bool_fn*)&orig_amIRunInEmulator },
    { "_$s16IOSSecuritySuiteAAC17amIInLockdownModeSbyFZ",    (void*)hooked_orig_amIInLockdownMode,    (iss_bool_fn*)&orig_amIInLockdownMode },
    { "_$s16IOSSecuritySuiteAAC21isParentPidUnexpectedSbyFZ",(void*)hooked_orig_isParentPidUnexpected,(iss_bool_fn*)&orig_isParentPidUnexpected },
    { "_$s16IOSSecuritySuiteAAC13hasWatchpointSbyFZ",        (void*)hooked_orig_hasWatchpoint,        (iss_bool_fn*)&orig_hasWatchpoint },
};

%ctor {
    @autoreleasepool {
        bmwlog("[BMWBypass] ==== ctor: install ISS hooks ====");
        int n = sizeof(kHooks)/sizeof(kHooks[0]);
        for (int i = 0; i < n; i++) {
            void *addr = MSFindSymbol(NULL, kHooks[i].sym);
            if (!addr) {
                bmwlog("[BMWBypass] symbol NOT found: %s", kHooks[i].sym);
                continue;
            }
            MSHookFunction(addr, kHooks[i].replacement, (void **)kHooks[i].orig);
            bmwlog("[BMWBypass] hooked %s @ %p", kHooks[i].sym, addr);
        }
    }
}
