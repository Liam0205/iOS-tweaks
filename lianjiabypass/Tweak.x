// LianJiaBypass — 探测版 (v0.0.1)
// 本轮目标：确认注入成功 + 观察秒退退出机制（不阻断，仅记录）
// 目标 App：链家 com.exmart.HomeLink 9.86.91（Flutter + JGBSDK 检测引擎）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <signal.h>
#import <string.h>
#import <execinfo.h>
#import <mach-o/dyld.h>
#import <pthread.h>
#import "fishhook.h"

#define LJ_DEBUG_LOG 1

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

// ========== Logging ==========

static char g_log_path[512];
static CFAbsoluteTime g_start;

static void lj_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void lj_log(const char *fmt, ...) {
#if LJ_DEBUG_LOG
    FILE *f = fopen(g_log_path, "a");
    if (!f) return;
    double elapsed = CFAbsoluteTimeGetCurrent() - g_start;
    fprintf(f, "[%6.2f] ", elapsed);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
#endif
}

// 记录调用点回溯栈（帮助定位是谁触发了退出）
static void lj_log_backtrace(const char *tag) {
#if LJ_DEBUG_LOG
    void *cs[32];
    int n = backtrace(cs, 32);
    char **syms = backtrace_symbols(cs, n);
    lj_log("%s: backtrace (%d frames):", tag, n);
    if (syms) {
        for (int i = 0; i < n; i++) lj_log("    [%d] %s", i, syms[i]);
        free(syms);
    }
#endif
}

// ========== 退出链路观察 hook（只记录，不阻断本轮） ==========

static void (*orig_exit)(int);
static void (*orig__exit)(int);
static void (*orig_abort)(void);
static int  (*orig_kill)(pid_t, int);

static void hooked_exit(int code) {
    lj_log("EXIT observed: exit(%d) on %s", code, pthread_main_np() ? "main" : "bg");
    lj_log_backtrace("exit");
    orig_exit(code);
}

static void hooked__exit(int code) {
    lj_log("EXIT observed: _exit(%d) on %s", code, pthread_main_np() ? "main" : "bg");
    lj_log_backtrace("_exit");
    orig__exit(code);
}

static void hooked_abort(void) {
    lj_log("EXIT observed: abort() on %s", pthread_main_np() ? "main" : "bg");
    lj_log_backtrace("abort");
    orig_abort();
}

static int hooked_kill(pid_t pid, int sig) {
    lj_log("EXIT observed: kill(pid=%d, sig=%d) self=%d", pid, sig, getpid());
    lj_log_backtrace("kill");
    return orig_kill(pid, sig);
}

// ========== 观察 JGBSDK / LJBRProtectManager 是否加载及检测触发 ==========

static void log_loaded_detection_modules(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "JGBSDK") || strstr(name, "/du.") ||
            strstr(name, "/a.framework") || strstr(name, "senseid")) {
            lj_log("MODULE loaded: %s", name);
        }
    }

    Class jgb = objc_getClass("LJBRProtectManager");
    lj_log("LJBRProtectManager class %s", jgb ? "PRESENT" : "absent");
    Class jgbp = objc_getClass("JGBProtect");
    lj_log("JGBProtect class %s", jgbp ? "PRESENT" : "absent");
}

// 观察检测回调：hook LJBRProtectManager 的 receiveProtectEventWithCode:reason:
// 只记录 code/reason，不改变行为，判断秒退是否由此回调触发
static void install_protect_event_observer(void) {
    Class cls = objc_getClass("LJBRProtectManager");
    if (!cls) {
        lj_log("PROTECT observer: LJBRProtectManager not found, skip");
        return;
    }
    SEL sel = sel_registerName("receiveProtectEventWithCode:reason:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        lj_log("PROTECT observer: selector not found on LJBRProtectManager");
        return;
    }
    lj_log("PROTECT observer: found receiveProtectEventWithCode:reason:, ready to hook (deferred)");
}

// ========== ctor ==========

__attribute__((constructor))
static void lianjia_init(void) {
    g_start = CFAbsoluteTimeGetCurrent();
    // 普通 App 沙箱只能可靠写自己的 Data 容器；用 NSTemporaryDirectory 拿沙箱内 tmp/
    NSString *dir = NSTemporaryDirectory();
    snprintf(g_log_path, sizeof(g_log_path), "%s/lianjiabypass.log",
             dir ? dir.UTF8String : "/tmp");
    FILE *f = fopen(g_log_path, "w");
    if (f) {
        NSString *appVer = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        fprintf(f, "[  0.00] [INIT] LianJiaBypass v0.0.1 (probe) / LianJia %s ctor started, pid=%d\n",
                appVer ? appVer.UTF8String : "?", getpid());
        fclose(f);
    }

    // 观察退出链路（只记录，不阻断）
    struct rebinding rebs[] = {
        {"exit",  (void *)hooked_exit,  (void **)&orig_exit},
        {"_exit", (void *)hooked__exit, (void **)&orig__exit},
        {"abort", (void *)hooked_abort, (void **)&orig_abort},
        {"kill",  (void *)hooked_kill,  (void **)&orig_kill},
    };
    rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
    lj_log("exit-path fishhooks installed (observe-only)");

    // 记录检测模块加载情况（延迟到主 App 起来后再看一次）
    log_loaded_detection_modules();
    install_protect_event_observer();

    lj_log("ctor done — waiting to observe exit mechanism");
}

