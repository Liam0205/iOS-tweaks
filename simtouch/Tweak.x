#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SocketServer.h"
#import "ScreenCapture.h"

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)
#define DEFAULT_SCREENSHOT_DIR @"/var/jb/tmp/simtouch"
#define DEFAULT_MAX_AGE 3600.0
#define DEFAULT_MAX_SIZE (50ULL * 1024 * 1024)

static void registerInfoCommand(void) {
    [[STSocketServer sharedInstance] registerCommand:@"info" handler:^NSString *(NSArray<NSString *> *args) {
        CGSize size = [UIScreen mainScreen].bounds.size;
        CGFloat scale = [UIScreen mainScreen].scale;
        return [NSString stringWithFormat:@"OK %.0fx%.0f @%.0fx", size.width, size.height, scale];
    }];
}

static void registerScreenshotCommand(void) {
    [[STSocketServer sharedInstance] registerCommand:@"screenshot" handler:^NSString *(NSArray<NSString *> *args) {
        NSString *path;
        BOOL useDefaultDir;

        if (args.count > 0 && args[0].length > 0) {
            path = args[0];
            useDefaultDir = NO;
        } else {
            NSString *name = [NSString stringWithFormat:@"screen_%lld.png", (long long)([[NSDate date] timeIntervalSince1970] * 1000)];
            path = [DEFAULT_SCREENSHOT_DIR stringByAppendingPathComponent:name];
            useDefaultDir = YES;
        }

        __block NSString *result;
        dispatch_sync(dispatch_get_main_queue(), ^{
            result = [STScreenCapture captureToPath:path];
        });

        if (useDefaultDir && [result hasPrefix:@"OK"]) {
            [STScreenCapture cleanupDirectory:DEFAULT_SCREENSHOT_DIR maxAge:DEFAULT_MAX_AGE maxSize:DEFAULT_MAX_SIZE];
        }

        return result;
    }];
}

%ctor {
    LOG(@"loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);

    registerInfoCommand();
    registerScreenshotCommand();

    STSocketServer *server = [STSocketServer sharedInstance];
    [server start];
}
