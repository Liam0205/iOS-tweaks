#import "TouchInjector.h"
#import <UIKit/UIKit.h>
#include <unistd.h>
#include <fcntl.h>

#define LOG(fmt, ...) do { \
    NSString *_msg = [NSString stringWithFormat:@"[SimTouch:Touch] " fmt @"\n", ##__VA_ARGS__]; \
    NSLog(@"%@", _msg); \
    NSFileHandle *_fh = [NSFileHandle fileHandleForWritingAtPath:@"/var/jb/tmp/simtouch.log"]; \
    if (!_fh) { \
        [@"" writeToFile:@"/var/jb/tmp/simtouch.log" atomically:YES encoding:NSUTF8StringEncoding error:nil]; \
        _fh = [NSFileHandle fileHandleForWritingAtPath:@"/var/jb/tmp/simtouch.log"]; \
    } \
    if (_fh) { [_fh seekToEndOfFile]; [_fh writeData:[_msg dataUsingEncoding:NSUTF8StringEncoding]]; [_fh closeFile]; } \
} while(0)

#define BB_CMD_PATH     "/var/jb/tmp/simtouch-cmd"
#define BB_CMD_NOTIFY   "page.0x01.simtouch.cmd"
#define BB_READY_NOTIFY "page.0x01.simtouch.bb.ready"
#define BB_ACK_NOTIFY   "page.0x01.simtouch.bb.ack"
#define BB_PING_NOTIFY  "page.0x01.simtouch.bb.ping"

enum {
    kSTPhaseDown = 0,
    kSTPhaseMove = 1,
    kSTPhaseUp   = 2,
    kSTPhaseSwipe = 3,
};

#pragma pack(push, 1)
typedef struct {
    uint8_t phase;
    float x;
    float y;
    uint32_t edge_mask;
} STTouchCmd;

typedef struct {
    uint8_t phase;
    float x1, y1, x2, y2;
    uint32_t duration_ms;
    uint32_t edge_mask;
} STSwipeCmd;
#pragma pack(pop)

@implementation STTouchInjector {
    CGFloat _screenWPx;
    CGFloat _screenHPx;
    BOOL _bbReady;
    NSString *_bbState;
}

+ (instancetype)sharedInstance {
    static STTouchInjector *inst;
    static dispatch_once_t token;
    dispatch_once(&token, ^{ inst = [[self alloc] init]; });
    return inst;
}

static void onBBReady(CFNotificationCenterRef center, void *observer,
                      CFStringRef name, const void *object, CFDictionaryRef info) {
    STTouchInjector *self = (__bridge STTouchInjector *)observer;
    self->_bbReady = YES;
    LOG(@"backboardd hook READY");
}

static void onBBState(CFNotificationCenterRef center, void *observer,
                      CFStringRef name, const void *object, CFDictionaryRef info) {
    STTouchInjector *self = (__bridge STTouchInjector *)observer;
    NSString *n = (__bridge NSString *)name;
    if ([n hasSuffix:@"captured+edge"]) {
        self->_bbState = @"captured+edge";
    } else if ([n hasSuffix:@"captured"]) {
        self->_bbState = @"captured";
    } else if ([n hasSuffix:@"sender"]) {
        self->_bbState = @"sender";
    } else if ([n hasSuffix:@"hooked"]) {
        self->_bbState = @"hooked";
    } else if ([n hasSuffix:@"nohook"]) {
        self->_bbState = @"nohook";
    }
    LOG(@"BB state: %@", self->_bbState);
}

static void onBBDiag(CFNotificationCenterRef center, void *observer,
                     CFStringRef name, const void *object, CFDictionaryRef info) {
    NSString *n = (__bridge NSString *)name;
    NSString *data = [n stringByReplacingOccurrencesOfString:@"page.0x01.simtouch.bb.diag." withString:@""];
    LOG(@"BB DIAG: %@", data);
}

- (instancetype)init {
    self = [super init];
    if (self) {
        CGSize pt = [UIScreen mainScreen].bounds.size;
        CGFloat scale = [UIScreen mainScreen].scale;
        _screenWPx = pt.width * scale;
        _screenHPx = pt.height * scale;
        _bbReady = NO;
        _bbState = @"unknown";
        LOG(@"screen: %.0fx%.0f px", _screenWPx, _screenHPx);

        CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBReady, CFSTR(BB_READY_NOTIFY), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBDiag, CFSTR(BB_ACK_NOTIFY), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBState, CFSTR("page.0x01.simtouch.bb.state.captured+edge"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBState, CFSTR("page.0x01.simtouch.bb.state.captured"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBState, CFSTR("page.0x01.simtouch.bb.state.sender"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBState, CFSTR("page.0x01.simtouch.bb.state.hooked"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBState, CFSTR("page.0x01.simtouch.bb.state.nohook"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);

        CFNotificationCenterPostNotification(nc,
            CFSTR(BB_PING_NOTIFY), NULL, NULL, true);
        LOG(@"pinged backboardd");
    }
    return self;
}

- (BOOL)isSenderIDReady { return YES; }
- (BOOL)isUserDeviceReady { return _bbReady; }
- (NSString *)bbState { return _bbState; }
- (void)captureSenderIDFromEvent:(void *)event {}

#pragma mark - Send to Backboardd

- (BOOL)_sendPhase:(uint8_t)phase pixelX:(CGFloat)px pixelY:(CGFloat)py edgeMask:(uint32_t)edgeMask {
    STTouchCmd cmd = {0};
    cmd.phase = phase;
    cmd.x = (float)(px / _screenWPx);
    cmd.y = (float)(py / _screenHPx);
    cmd.edge_mask = edgeMask;

    int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG(@"open cmd file failed: %d", errno);
        return NO;
    }
    write(fd, &cmd, sizeof(cmd));
    close(fd);

    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);
    return YES;
}

#pragma mark - Public API

- (void)tapAtX:(CGFloat)pixelX y:(CGFloat)pixelY {
    LOG(@"tap: (%.0f, %.0f)", pixelX, pixelY);
    [self _sendPhase:kSTPhaseDown pixelX:pixelX pixelY:pixelY edgeMask:0];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 80 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [self _sendPhase:kSTPhaseUp pixelX:pixelX pixelY:pixelY edgeMask:0];
    });
}

- (void)longPressAtX:(CGFloat)pixelX y:(CGFloat)pixelY durationMs:(NSInteger)ms {
    if (ms <= 0) ms = 500;
    [self _sendPhase:kSTPhaseDown pixelX:pixelX pixelY:pixelY edgeMask:0];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ms * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [self _sendPhase:kSTPhaseUp pixelX:pixelX pixelY:pixelY edgeMask:0];
    });
}

- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2 durationMs:(NSInteger)ms {
    [self swipeFromX:x1 y:y1 toX:x2 y:y2 durationMs:ms edgeMask:0];
}

- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2 durationMs:(NSInteger)ms edgeMask:(uint32_t)edgeMask {
    if (ms <= 0) ms = 300;
    STSwipeCmd cmd = {0};
    cmd.phase = kSTPhaseSwipe;
    cmd.x1 = (float)(x1 / _screenWPx);
    cmd.y1 = (float)(y1 / _screenHPx);
    cmd.x2 = (float)(x2 / _screenWPx);
    cmd.y2 = (float)(y2 / _screenHPx);
    cmd.duration_ms = (uint32_t)ms;
    cmd.edge_mask = edgeMask;

    int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG(@"open cmd file failed: %d", errno);
        return;
    }
    write(fd, &cmd, sizeof(cmd));
    close(fd);

    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);
}

- (void)homeGesture {
    [self swipeFromX:_screenWPx * 0.5f y:_screenHPx * 0.985f
                toX:_screenWPx * 0.5f y:_screenHPx * 0.86f
         durationMs:150 edgeMask:0x1040000];
}

- (void)notificationCenter {
    [self swipeFromX:_screenWPx * 0.5f y:_screenHPx * 0.015f
                toX:_screenWPx * 0.5f y:_screenHPx * 0.4f
         durationMs:200 edgeMask:0x2040000];
}

- (void)controlCenter {
    [self swipeFromX:_screenWPx * 0.9f y:_screenHPx * 0.015f
                toX:_screenWPx * 0.9f y:_screenHPx * 0.4f
         durationMs:200 edgeMask:0x2040000];
}

- (void)appSwitcher {
    [self swipeFromX:_screenWPx * 0.5f y:_screenHPx * 0.985f
                toX:_screenWPx * 0.5f y:_screenHPx * 0.7f
         durationMs:400 edgeMask:0x1040000];
}

@end
