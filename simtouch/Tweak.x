#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include <unistd.h>
#include <fcntl.h>
#import "SocketServer.h"
#import "ScreenCapture.h"
#import "TouchInjector.h"

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)
#define PREFS_DOMAIN @"page.0x01.simtouch"
#define PREFS_NOTIFICATION CFSTR("page.0x01.simtouch.prefsChanged")
#define DEFAULT_SCREENSHOT_DIR @"/var/jb/tmp/simtouch"
#define BB_CMD_PATH      "/var/jb/tmp/simtouch-cmd"
#define BB_CMD_NOTIFY    "page.0x01.simtouch.cmd"
#define BB_PING_NOTIFY   "page.0x01.simtouch.bb.ping"
#define BB_RECORD_PATH   "/tmp/simtouch-record.bin"
#define BB_RECORD_START  "page.0x01.simtouch.record.start"
#define BB_RECORD_STOP   "page.0x01.simtouch.record.stop"
#define BB_REPLAY_NOTIFY "page.0x01.simtouch.replay"

#define ST_MAX_CHILDREN 5

#pragma pack(push, 1)
typedef struct {
    uint8_t phase;
    float x;
    float y;
} STTouchCmd;

typedef struct {
    uint32_t time_ms;
    uint32_t phase;
    float x, y;
    uint32_t event_mask;
    int32_t touch, range;
    float pressure;
    uint8_t child_count;
    struct {
        float x, y, pressure;
        int32_t touch, range;
        uint32_t phase;
    } children[ST_MAX_CHILDREN];
} STRecordEntry;
#pragma pack(pop)

static NSTimeInterval g_maxAge = 3600.0;
static unsigned long long g_maxSize = 50ULL * 1024 * 1024;

static BOOL readBoolPref(NSString *key, BOOL fallback) {
    NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:PREFS_DOMAIN];
    id val = [d objectForKey:key];
    return val ? [val boolValue] : fallback;
}

static void loadPrefs(void) {
    NSUserDefaults *d = [[NSUserDefaults alloc] initWithSuiteName:PREFS_DOMAIN];
    id age = [d objectForKey:@"maxScreenshotAge"];
    id size = [d objectForKey:@"maxScreenshotSize"];
    g_maxAge = age ? [age doubleValue] : 3600.0;
    g_maxSize = size ? [size unsignedLongLongValue] * 1024 * 1024 : 50ULL * 1024 * 1024;
}

static void onPrefsChanged(CFNotificationCenterRef center, void *observer,
                           CFStringRef name, const void *object, CFDictionaryRef info) {
    BOOL enabled = readBoolPref(@"enabled", NO);
    loadPrefs();
    LOG(@"prefs changed: enabled=%d maxAge=%.0f maxSize=%lluMB", enabled, g_maxAge, g_maxSize / (1024 * 1024));

    STSocketServer *server = [STSocketServer sharedInstance];
    if (enabled && !server.isRunning) {
        [server start];
    } else if (!enabled && server.isRunning) {
        [server stop];
    }
}

static void registerCommands(void) {
    [[STSocketServer sharedInstance] registerCommand:@"info" handler:^NSString *(NSArray<NSString *> *args) {
        CGSize size = [UIScreen mainScreen].bounds.size;
        CGFloat scale = [UIScreen mainScreen].scale;
        STTouchInjector *ti = [STTouchInjector sharedInstance];
        NSString *conn = ti.isUserDeviceReady ? @"connected" : @"none";
        return [NSString stringWithFormat:@"OK %.0fx%.0f @%.0fx conn=%@ hook=%@",
            size.width, size.height, scale, conn, ti.bbState];
    }];

    [[STSocketServer sharedInstance] registerCommand:@"bbstatus" handler:^NSString *(NSArray<NSString *> *args) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFSTR(BB_PING_NOTIFY), NULL, NULL, true);
        usleep(200000);
        STTouchInjector *ti = [STTouchInjector sharedInstance];
        return [NSString stringWithFormat:@"OK conn=%s hook=%@",
            ti.isUserDeviceReady ? "connected" : "none", ti.bbState];
    }];

    [[STSocketServer sharedInstance] registerCommand:@"screenshot" handler:^NSString *(NSArray<NSString *> *args) {
        NSString *path;
        BOOL useDefaultDir;

        if (args.count > 0 && args[0].length > 0) {
            path = args[0];
            useDefaultDir = NO;
        } else {
            NSString *name = [NSString stringWithFormat:@"screen_%lld.jpg", (long long)([[NSDate date] timeIntervalSince1970] * 1000)];
            path = [DEFAULT_SCREENSHOT_DIR stringByAppendingPathComponent:name];
            useDefaultDir = YES;
        }

        __block NSString *result;
        dispatch_sync(dispatch_get_main_queue(), ^{
            result = [STScreenCapture captureToPath:path];
        });

        if (useDefaultDir && [result hasPrefix:@"OK"]) {
            [STScreenCapture cleanupDirectory:DEFAULT_SCREENSHOT_DIR maxAge:g_maxAge maxSize:g_maxSize];
        }

        return result;
    }];

    [[STSocketServer sharedInstance] registerCommand:@"tap" handler:^NSString *(NSArray<NSString *> *args) {
        if (args.count < 2) return @"ERR usage: tap <x> <y>";
        STTouchInjector *ti = [STTouchInjector sharedInstance];
        CGFloat x = [args[0] floatValue];
        CGFloat y = [args[1] floatValue];
        dispatch_async(dispatch_get_main_queue(), ^{ [ti tapAtX:x y:y]; });
        return [NSString stringWithFormat:@"OK bb=%s", ti.isUserDeviceReady ? "connected" : "disconnected"];
    }];

    [[STSocketServer sharedInstance] registerCommand:@"swipe" handler:^NSString *(NSArray<NSString *> *args) {
        if (args.count < 4) return @"ERR usage: swipe <x1> <y1> <x2> <y2> [ms]";
        STTouchInjector *ti = [STTouchInjector sharedInstance];
        CGFloat x1 = [args[0] floatValue];
        CGFloat y1 = [args[1] floatValue];
        CGFloat x2 = [args[2] floatValue];
        CGFloat y2 = [args[3] floatValue];
        NSInteger ms = args.count > 4 ? [args[4] integerValue] : 300;
        dispatch_async(dispatch_get_main_queue(), ^{ [ti swipeFromX:x1 y:y1 toX:x2 y:y2 durationMs:ms]; });
        return [NSString stringWithFormat:@"OK bb=%s", ti.isUserDeviceReady ? "connected" : "disconnected"];
    }];

    [[STSocketServer sharedInstance] registerCommand:@"diag" handler:^NSString *(NSArray<NSString *> *args) {
        NSMutableString *r = [NSMutableString stringWithString:@"OK\n"];
        struct { const char *name; } syms[] = {
            {"IOHIDUserDeviceCreate"},
            {"IOHIDUserDeviceCreateWithProperties"},
            {"IOHIDUserDeviceScheduleWithRunLoop"},
            {"IOHIDUserDeviceHandleReport"},
            {"IOHIDUserDeviceHandleReportAsync"},
            {"IOHIDUserDeviceHandleReportWithTimeStamp"},
            {"IOHIDUserDeviceCopyProperty"},
            {"GSSendEvent"},
            {"GSSendSystemEvent"},
            {"GSCopyPurpleNamedPort"},
            {"GSGetPurpleSystemEventPort"},
            {"GSMainScreenPixelSize"},
            {"GSMainScreenSize"},
            {"IOHIDEventSystemConnectionDispatchEvent"},
            {"IOHIDEventSystemClientCopyProperty"},
            {"IOHIDEventSystemClientSetProperty"},
            {NULL}
        };
        for (int i = 0; syms[i].name; i++) {
            void *p = dlsym(RTLD_DEFAULT, syms[i].name);
            [r appendFormat:@"  %s: %s\n", syms[i].name, p ? "YES" : "no"];
        }

        unsigned int clsCount = 0;
        Class *classes = objc_copyClassList(&clsCount);
        NSMutableArray *relevant = [NSMutableArray array];
        for (unsigned int i = 0; i < clsCount; i++) {
            NSString *name = NSStringFromClass(classes[i]);
            if ([name containsString:@"UIEventFetcher"] ||
                [name containsString:@"UIEventDispatcher"] ||
                [name containsString:@"UIEventEnvironment"] ||
                [name containsString:@"BKSHIDEvent"]) {
                [relevant addObject:name];
            }
        }
        free(classes);
        [r appendFormat:@"  classes: %@\n", [relevant componentsJoinedByString:@", "]];

        UIApplication *app = [UIApplication sharedApplication];
        SEL sels[] = {
            NSSelectorFromString(@"_handleHIDEvent:"),
            NSSelectorFromString(@"_enqueueHIDEvent:"),
            NSSelectorFromString(@"eventFetcher"),
            NSSelectorFromString(@"_eventFetcher"),
            NSSelectorFromString(@"_eventEnvironment"),
            NULL
        };
        for (int i = 0; sels[i]; i++) {
            [r appendFormat:@"  UIApp %s: %s\n",
                sel_getName(sels[i]),
                [app respondsToSelector:sels[i]] ? "YES" : "no"];
        }
        return r;
    }];

    [[STSocketServer sharedInstance] registerCommand:@"longpress" handler:^NSString *(NSArray<NSString *> *args) {
        if (args.count < 2) return @"ERR usage: longpress <x> <y> [ms]";
        STTouchInjector *ti = [STTouchInjector sharedInstance];
        CGFloat x = [args[0] floatValue];
        CGFloat y = [args[1] floatValue];
        NSInteger ms = args.count > 2 ? [args[2] integerValue] : 500;
        dispatch_async(dispatch_get_main_queue(), ^{ [ti longPressAtX:x y:y durationMs:ms]; });
        return [NSString stringWithFormat:@"OK bb=%s", ti.isUserDeviceReady ? "connected" : "disconnected"];
    }];

    [[STSocketServer sharedInstance] registerCommand:@"record" handler:^NSString *(NSArray<NSString *> *args) {
        if (args.count < 1) return @"ERR usage: record <start|stop|dump>";
        NSString *sub = args[0];

        if ([sub isEqualToString:@"start"] || [sub isEqualToString:@"stop"]) {
            STTouchCmd cmd = {0};
            cmd.phase = [sub isEqualToString:@"start"] ? 0xF0 : 0xF1;
            int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) return @"ERR open cmd file failed";
            write(fd, &cmd, sizeof(cmd));
            close(fd);
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);

            if ([sub isEqualToString:@"stop"]) {
                usleep(200000);
                NSData *data = [NSData dataWithContentsOfFile:@(BB_RECORD_PATH)];
                size_t count = data.length / sizeof(STRecordEntry);
                uint32_t duration = 0;
                if (count > 0) {
                    const STRecordEntry *entries = (const STRecordEntry *)data.bytes;
                    duration = entries[count - 1].time_ms;
                }
                return [NSString stringWithFormat:@"OK stopped, %zu events, %ums", count, duration];
            }
            return @"OK recording started";
        } else if ([sub isEqualToString:@"dump"]) {
            NSData *data = [NSData dataWithContentsOfFile:@(BB_RECORD_PATH)];
            if (!data || data.length == 0) return @"ERR no recording";
            size_t count = data.length / sizeof(STRecordEntry);
            const STRecordEntry *entries = (const STRecordEntry *)data.bytes;
            size_t displayCount = MIN(count, (size_t)200);
            NSMutableString *r = [NSMutableString stringWithFormat:@"OK %zu events\n", count];
            for (size_t i = 0; i < displayCount; i++) {
                const char *pname = "?";
                switch (entries[i].phase) {
                    case 1: pname = "began"; break;
                    case 2: pname = "changed"; break;
                    case 4: pname = "ended"; break;
                    case 0: pname = "none"; break;
                }
                [r appendFormat:@"#%zu +%ums %s(%u) xy=(%.4f,%.4f) mask=0x%x t=%d r=%d p=%.2f c=%u\n",
                    i, entries[i].time_ms, pname, entries[i].phase,
                    entries[i].x, entries[i].y, entries[i].event_mask,
                    entries[i].touch, entries[i].range, entries[i].pressure,
                    entries[i].child_count];
                for (uint8_t j = 0; j < entries[i].child_count && j < ST_MAX_CHILDREN; j++) {
                    const char *cpname = "?";
                    switch (entries[i].children[j].phase) {
                        case 1: cpname = "began"; break;
                        case 2: cpname = "changed"; break;
                        case 4: cpname = "ended"; break;
                        case 0: cpname = "none"; break;
                    }
                    [r appendFormat:@"  c[%u] xy=(%.4f,%.4f) p=%.2f t=%d r=%d %s(%u)\n",
                        j, entries[i].children[j].x, entries[i].children[j].y,
                        entries[i].children[j].pressure,
                        entries[i].children[j].touch, entries[i].children[j].range,
                        cpname, entries[i].children[j].phase];
                }
            }
            if (count > 200) [r appendFormat:@"... (%zu more events)\n", count - 200];
            return r;
        }
        return @"ERR unknown subcommand (start|stop|dump)";
    }];

    [[STSocketServer sharedInstance] registerCommand:@"replay" handler:^NSString *(NSArray<NSString *> *args) {
        if (![[STTouchInjector sharedInstance] isUserDeviceReady]) {
            return @"ERR backboardd not connected";
        }
        NSData *data = [NSData dataWithContentsOfFile:@(BB_RECORD_PATH)];
        if (!data || data.length == 0) return @"ERR no recording";
        size_t count = data.length / sizeof(STRecordEntry);
        const STRecordEntry *entries = (const STRecordEntry *)data.bytes;
        uint32_t duration = count > 1 ? entries[count - 1].time_ms - entries[0].time_ms : 0;

        STTouchCmd cmd = {0};
        cmd.phase = 0xF2;
        int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return @"ERR open cmd file failed";
        write(fd, &cmd, sizeof(cmd));
        close(fd);
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);

        return [NSString stringWithFormat:@"OK replaying %zu events over %ums", count, duration];
    }];

}

%ctor {
    if (![[[NSProcessInfo processInfo] processName] isEqualToString:@"SpringBoard"]) return;

    LOG(@"loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);

    loadPrefs();
    registerCommands();

    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        onPrefsChanged, PREFS_NOTIFICATION, NULL,
        CFNotificationSuspensionBehaviorCoalesce);

    if (readBoolPref(@"enabled", NO)) {
        [[STSocketServer sharedInstance] start];
    } else {
        LOG(@"disabled, waiting for enable");
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [STTouchInjector sharedInstance];
        LOG(@"TouchInjector ready, bb=%s",
            [STTouchInjector sharedInstance].isUserDeviceReady ? "connected" : "disconnected");
    });
}
