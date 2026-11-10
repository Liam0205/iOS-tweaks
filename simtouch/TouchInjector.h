#import <Foundation/Foundation.h>

@interface STTouchInjector : NSObject
@property (nonatomic, readonly, getter=isSenderIDReady) BOOL senderIDReady;
@property (nonatomic, readonly, getter=isUserDeviceReady) BOOL userDeviceReady;
@property (nonatomic, readonly) NSString *bbState;
+ (instancetype)sharedInstance;
// 屏幕尺寸在 Main Thread 上惰性获取；调用方不要自己去碰 [UIScreen mainScreen]。
- (BOOL)ensureScreenMetrics;
- (CGSize)screenPixelSize;
- (CGFloat)screenScale;
- (void)captureSenderIDFromEvent:(void *)event;
- (void)tapAtX:(CGFloat)pixelX y:(CGFloat)pixelY;
- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2 durationMs:(NSInteger)ms;
- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2
        durationMs:(NSInteger)ms curveType:(uint8_t)curve
            bz_x1:(float)bx1 bz_y1:(float)by1 bz_x2:(float)bx2 bz_y2:(float)by2;
- (void)longPressAtX:(CGFloat)pixelX y:(CGFloat)pixelY durationMs:(NSInteger)ms;
- (void)sendKeyUsage:(uint16_t)usage;
- (void)sendKeyCombination:(NSArray<NSNumber *> *)usages;
- (void)pinchAtX:(CGFloat)pixelX y:(CGFloat)pixelY scale:(float)scale durationMs:(NSInteger)ms;
@end
