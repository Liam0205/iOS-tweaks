#import <Foundation/Foundation.h>

@interface STScreenCapture : NSObject

+ (NSString *)captureToPath:(NSString *)path;
+ (void)cleanupDirectory:(NSString *)dir maxAge:(NSTimeInterval)maxAge maxSize:(unsigned long long)maxSize;

@end
