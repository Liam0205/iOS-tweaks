#import <Foundation/Foundation.h>

@interface STTouchInjector : NSObject
@property (nonatomic, readonly, getter=isSenderIDReady) BOOL senderIDReady;
@property (nonatomic, readonly, getter=isUserDeviceReady) BOOL userDeviceReady;
@property (nonatomic, readonly) NSString *bbState;
+ (instancetype)sharedInstance;
- (void)captureSenderIDFromEvent:(void *)event;
- (void)tapAtX:(CGFloat)pixelX y:(CGFloat)pixelY;
- (void)swipeFromX:(CGFloat)x1 y:(CGFloat)y1 toX:(CGFloat)x2 y:(CGFloat)y2 durationMs:(NSInteger)ms;
- (void)longPressAtX:(CGFloat)pixelX y:(CGFloat)pixelY durationMs:(NSInteger)ms;
@end
