#import <Foundation/Foundation.h>

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)

%ctor {
    LOG(@"loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);
}
