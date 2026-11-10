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
    kSTPhaseKeyboard = 4,
    kSTPhasePinch = 5,
};

enum {
    kSTCurveLinear    = 0,
    kSTCurveEaseIn    = 1,
    kSTCurveEaseOut   = 2,
    kSTCurveEaseInOut = 3,
    kSTCurveBezier    = 4,
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
    uint8_t curve_type;
    float bz_x1, bz_y1, bz_x2, bz_y2;
} STSwipeCmd;

typedef struct {
    uint8_t phase;
    uint8_t key_count;
    struct {
        uint16_t usage;
        uint8_t down;
    } keys[8];
} STKeyCmd;

typedef struct {
    uint8_t phase;
    float cx, cy;
    float scale;
    uint32_t duration_ms;
} STPinchCmd;
#pragma pack(pop)

@implementation STTouchInjector {
    CGFloat _screenWPx;
    CGFloat _screenHPx;
    CGFloat _screenScale;
    BOOL _bbReady;
    NSString *_bbState;
}

// 屏幕尺寸推迟到第一次用到时再取，而且必须在主线程取。
// 原因：sharedInstance 是在 socket 队列上被调用的，dispatch_once 的块里抛出的
// 任何异常都会被 _dispatch_client_callout 接住并直接 terminate —— 调用者就算
// 包了 @try 也轮不到。SpringBoard 刚启动、界面子系统还没就绪时，
// [UIScreen mainScreen] 会抛异常，进程当场 abort。
- (BOOL)ensureScreenMetrics {
    if (_screenWPx > 0 && _screenHPx > 0) return YES;
    void (^read)(void) = ^{
        @try {
            UIScreen *screen = [UIScreen mainScreen];
            CGSize pt = screen.bounds.size;
            CGFloat scale = screen.scale;
            if (pt.width > 0 && pt.height > 0 && scale > 0) {
                _screenWPx = pt.width * scale;
                _screenHPx = pt.height * scale;
                _screenScale = scale;
                LOG(@"screen: %.0fx%.0f px @%.0fx", _screenWPx, _screenHPx, scale);
            }
        } @catch (NSException *e) {
            LOG(@"screen metrics unavailable: %@", e.reason);
        }
    };
    if ([NSThread isMainThread]) read();
    else dispatch_sync(dispatch_get_main_queue(), read);
    return (_screenWPx > 0 && _screenHPx > 0);
}

- (CGSize)screenPixelSize {
    [self ensureScreenMetrics];
    return CGSizeMake(_screenWPx, _screenHPx);
}

- (CGFloat)screenScale {
    [self ensureScreenMetrics];
    return _screenScale;
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
    if ([n hasSuffix:@"captured"]) {
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
        _bbReady = NO;
        _bbState = @"unknown";
        // 这里不读 UIScreen：init 跑在 dispatch_once 的块里，见 ensureScreenMetrics 的说明。

        CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBReady, CFSTR(BB_READY_NOTIFY), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(nc, (__bridge const void *)self,
            onBBDiag, CFSTR(BB_ACK_NOTIFY), NULL,
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
    if (![self ensureScreenMetrics]) {
        LOG(@"tap skipped: screen metrics not ready");
        return NO;
    }
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
    [self swipeFromX:x1 y:y1 toX:x2 y:y2 durationMs:ms curveType:kSTCurveLinear bz_x1:0 bz_y1:0 bz_x2:0 bz_y2:0];
}

- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2
        durationMs:(NSInteger)ms curveType:(uint8_t)curve
            bz_x1:(float)bx1 bz_y1:(float)by1 bz_x2:(float)bx2 bz_y2:(float)by2 {
    if (ms <= 0) ms = 300;
    if (![self ensureScreenMetrics]) return;
    STSwipeCmd cmd = {0};
    cmd.phase = kSTPhaseSwipe;
    cmd.x1 = (float)(x1 / _screenWPx);
    cmd.y1 = (float)(y1 / _screenHPx);
    cmd.x2 = (float)(x2 / _screenWPx);
    cmd.y2 = (float)(y2 / _screenHPx);
    cmd.duration_ms = (uint32_t)ms;
    cmd.edge_mask = 0;
    cmd.curve_type = curve;
    cmd.bz_x1 = bx1;
    cmd.bz_y1 = by1;
    cmd.bz_x2 = bx2;
    cmd.bz_y2 = by2;

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

- (void)sendKeyUsage:(uint16_t)usage {
    STKeyCmd cmd = {0};
    cmd.phase = kSTPhaseKeyboard;
    cmd.key_count = 2;
    cmd.keys[0].usage = usage;
    cmd.keys[0].down = 1;
    cmd.keys[1].usage = usage;
    cmd.keys[1].down = 0;

    int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    write(fd, &cmd, sizeof(cmd));
    close(fd);

    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);
}

- (void)sendKeyCombination:(NSArray<NSNumber *> *)usages {
    if (usages.count == 0 || usages.count > 4) return;

    STKeyCmd cmd = {0};
    cmd.phase = kSTPhaseKeyboard;
    uint8_t idx = 0;
    for (NSNumber *u in usages) {
        cmd.keys[idx].usage = [u unsignedShortValue];
        cmd.keys[idx].down = 1;
        idx++;
    }
    for (NSInteger i = usages.count - 1; i >= 0; i--) {
        cmd.keys[idx].usage = [usages[i] unsignedShortValue];
        cmd.keys[idx].down = 0;
        idx++;
    }
    cmd.key_count = idx;

    int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    write(fd, &cmd, sizeof(cmd));
    close(fd);

    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);
}

- (void)pinchAtX:(CGFloat)pixelX y:(CGFloat)pixelY scale:(float)scale durationMs:(NSInteger)ms {
    if (ms <= 0) ms = 300;
    if (![self ensureScreenMetrics]) return;
    STPinchCmd cmd = {0};
    cmd.phase = kSTPhasePinch;
    cmd.cx = (float)(pixelX / _screenWPx);
    cmd.cy = (float)(pixelY / _screenHPx);
    cmd.scale = scale;
    cmd.duration_ms = (uint32_t)ms;

    int fd = open(BB_CMD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    write(fd, &cmd, sizeof(cmd));
    close(fd);

    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(BB_CMD_NOTIFY), NULL, NULL, true);
}

@end
