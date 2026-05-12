#import <Foundation/Foundation.h>

@interface STSocketServer : NSObject

@property (nonatomic, readonly, getter=isRunning) BOOL running;

+ (instancetype)sharedInstance;

- (void)start;
- (void)stop;

- (void)registerCommand:(NSString *)name handler:(NSString *(^)(NSArray<NSString *> *args))handler;

@end
