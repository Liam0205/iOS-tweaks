#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SocketServer.h"

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)

static void registerInfoCommand(void) {
    [[STSocketServer sharedInstance] registerCommand:@"info" handler:^NSString *(NSArray<NSString *> *args) {
        CGSize size = [UIScreen mainScreen].bounds.size;
        CGFloat scale = [UIScreen mainScreen].scale;
        return [NSString stringWithFormat:@"OK %.0fx%.0f @%.0fx", size.width, size.height, scale];
    }];
}

%ctor {
    LOG(@"loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);

    registerInfoCommand();

    STSocketServer *server = [STSocketServer sharedInstance];
    [server start];
}
