#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SocketServer.h"
#import "ScreenCapture.h"

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)
#define PREFS_DOMAIN @"page.0x01.simtouch"
#define PREFS_NOTIFICATION CFSTR("page.0x01.simtouch.prefsChanged")
#define DEFAULT_SCREENSHOT_DIR @"/var/jb/tmp/simtouch"

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
        return [NSString stringWithFormat:@"OK %.0fx%.0f @%.0fx", size.width, size.height, scale];
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

}

%ctor {
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
}
