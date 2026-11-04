// CITICBypass —— 中信银行（com.citic.mobile）越狱检测绕过
//
// 检测引擎是梆梆 Everisk（BCES = Bangcle Everisk Security 的缩写），
// 与国家网络身份认证（whbypass）同源，静态链入主二进制，没有独立框架。
//
// 两条关键经验直接沿用自 whbypass：
//
//   1. 不要用 %hook。Everisk 自带注入自检，BCESCheckerInject 上就有
//      inlineHookedInfo 和 swizzleHookedInfo 两个方法专门查这个。
//      %hook 底层是 MSHookFunction，会改函数序言字节。实测 0.0.4/0.0.5 用
//      15 个 %hook 之后，主线程立刻 EXC_BAD_ACCESS：SP 里是含 DEAD 的哨兵值，
//      PC 落在 0xb5a98000，位于 __PAGEZERO 区间内——与 whbypass 记录过的毒地址
//      0xb5a01000 是同一手法。改用 method_setImplementation 只动 ObjC 方法表，
//      不碰指令字节，这个问题就消失了。
//
//   2. 每个检测项都是一个同时实现 -(check) 和 +(name) 的 ObjC 类。把 -(check)
//      换成空实现后，检测照常被“跑过”，但不产生任何结论。中信的二进制里这类类
//      有 23 个（21 个混淆名，加上 BCESCheckerEnvironment 和 BCESCheckerInject）。
//      whbypass 那次还额外验证过：不能对整个类表做 respondsToSelector，
//      四万多个类会把启动拖过 watchdog 的 20 秒预算。这里只遍历主二进制里的类。
//
// 中信自己的风控层另有一条路径：+[CBAppRiskEvent jailBreakJudge] 在判定越狱后
// 用内联加密的文案「监测到您的系统已越狱，继续使用可能造成安全隐患」弹一个
// 单按钮对话框，并上报埋点 rootOpen。它是 void 函数，返回值无人使用，
// 所以直接置空等于把这项判定判为无风险。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

#define CB_LOG_PATH [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/citicbypass.log"]

static void cb_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:[NSString stringWithUTF8String:fmt] arguments:ap];
    va_end(ap);
    NSString *line = [msg stringByAppendingString:@"\n"];
    NSString *path = CB_LOG_PATH;
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        [line writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:nil];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    }
}

static void cb_noop(id self, SEL _cmd) { (void)self; (void)_cmd; }
static BOOL cb_no(id self, SEL _cmd) { (void)self; (void)_cmd; return NO; }

// 替换某个类的一个方法。isMeta 指定是类方法还是实例方法。
// requireBool 为真时先校验返回类型，避免把非 BOOL 的方法改坏。
static BOOL cb_swap(const char *cls, const char *sel, IMP imp,
                    BOOL isMeta, BOOL requireBool) {
    Class c = objc_getClass(cls);
    if (!c) return NO;
    Class target = isMeta ? object_getClass(c) : c;
    Method m = class_getInstanceMethod(target, sel_registerName(sel));
    if (!m) return NO;
    if (requireBool) {
        char rt[8] = {0};
        method_getReturnType(m, rt, sizeof(rt));
        if (rt[0] != 'B' && rt[0] != 'c') return NO;
    }
    method_setImplementation(m, imp);
    return YES;
}

// 短路 everisk 的全部检测项。
static int cb_neuter_checkers(void) {
    NSString *exe = [[NSBundle mainBundle] executablePath];
    const char *img = exe ? [exe fileSystemRepresentation] : _dyld_get_image_name(0);
    unsigned int count = 0;
    const char **names = objc_copyClassNamesForImage(img, &count);
    if (!names) return 0;

    int n = 0;
    for (unsigned int i = 0; i < count; i++) {
        Class c = objc_getClass(names[i]);
        if (!c) continue;
        if (!class_respondsToSelector(c, @selector(check))) continue;
        if (!class_respondsToSelector(object_getClass(c), @selector(name))) continue;
        Method m = class_getInstanceMethod(c, @selector(check));
        if (!m || method_getImplementation(m) == (IMP)cb_noop) continue;
        method_setImplementation(m, (IMP)cb_noop);
        n++;
    }
    free(names);
    return n;
}

__attribute__((constructor)) static void cb_init(void) {
    @autoreleasepool {
        cb_log("===== CITICBypass 0.0.6 载入，pid=%d =====", getpid());

        // 先短路检测项，再处理应用层的判定逻辑。
        cb_log("checker 短路 %d 个", cb_neuter_checkers());

        // 中信自己的越狱判定，唯一副作用是弹窗和 rootOpen 埋点。
        if (cb_swap("CBAppRiskEvent", "jailBreakJudge", (IMP)cb_noop, YES, NO))
            cb_log("CBAppRiskEvent +jailBreakJudge 已置空");

        // 另外两条独立的越狱判定，返回值参与业务分支。
        if (cb_swap("GMRZIsJailBreak", "isJailBreak", (IMP)cb_no, YES, YES))
            cb_log("GMRZIsJailBreak +isJailBreak 已置否");
        if (cb_swap("exJailBreak", "isJailBreak", (IMP)cb_no, YES, YES))
            cb_log("exJailBreak +isJailBreak 已置否");

        cb_log("初始化完成");
    }
}
