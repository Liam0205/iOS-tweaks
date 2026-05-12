#import "ScreenCapture.h"
#import <UIKit/UIKit.h>
#import <IOSurface/IOSurfaceRef.h>
#import <CoreImage/CoreImage.h>
#import <sys/stat.h>

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)

extern void CARenderServerRenderDisplay(kern_return_t
, CFStringRef, IOSurfaceRef, int, int);

@implementation STScreenCapture

+ (NSString *)captureToPath:(NSString *)path {
    CGSize screenSize = [UIScreen mainScreen].bounds.size;
    CGFloat scale = [UIScreen mainScreen].scale;
    int width = (int)(screenSize.width * scale);
    int height = (int)(screenSize.height * scale);

    NSDictionary *props = @{
        (__bridge NSString *)kIOSurfaceWidth: @(width),
        (__bridge NSString *)kIOSurfaceHeight: @(height),
        (__bridge NSString *)kIOSurfaceBytesPerRow: @(width * 4),
        (__bridge NSString *)kIOSurfaceBytesPerElement: @(4),
        (__bridge NSString *)kIOSurfacePixelFormat: @(0x42475241), // BGRA
    };

    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surface) return @"ERR IOSurfaceCreate failed";

    IOSurfaceLock(surface, 0, NULL);
    CARenderServerRenderDisplay(0, CFSTR("LCD"), surface, 0, 0);
    IOSurfaceUnlock(surface, 0, NULL);

    CIImage *ciImage = [CIImage imageWithIOSurface:surface];
    CFRelease(surface);

    if (!ciImage) return @"ERR CIImage creation failed";

    CIContext *ctx = [CIContext context];
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    NSData *pngData = [ctx PNGRepresentationOfImage:ciImage format:kCIFormatBGRA8 colorSpace:cs options:@{}];
    CGColorSpaceRelease(cs);

    if (!pngData || pngData.length == 0) return @"ERR PNG encoding failed";

    NSString *dir = [path stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSError *writeErr = nil;
    if (![pngData writeToFile:path options:NSDataWritingAtomic error:&writeErr]) {
        return [NSString stringWithFormat:@"ERR write failed: %@", writeErr.localizedDescription];
    }

    return [NSString stringWithFormat:@"OK %@ %dx%d", path, width, height];
}

+ (void)cleanupDirectory:(NSString *)dir maxAge:(NSTimeInterval)maxAge maxSize:(unsigned long long)maxSize {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *files = [fm contentsOfDirectoryAtPath:dir error:nil];
    if (!files) return;

    NSDate *now = [NSDate date];
    NSMutableArray<NSDictionary *> *entries = [NSMutableArray new];
    unsigned long long totalSize = 0;

    for (NSString *name in files) {
        NSString *fullPath = [dir stringByAppendingPathComponent:name];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        if (!attrs) continue;

        NSDate *mtime = attrs[NSFileModificationDate];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];

        if ([now timeIntervalSinceDate:mtime] > maxAge) {
            [fm removeItemAtPath:fullPath error:nil];
            continue;
        }

        [entries addObject:@{@"path": fullPath, @"mtime": mtime, @"size": @(size)}];
        totalSize += size;
    }

    if (totalSize <= maxSize) return;

    [entries sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"mtime"] compare:b[@"mtime"]];
    }];

    for (NSDictionary *entry in entries) {
        if (totalSize <= maxSize) break;
        [fm removeItemAtPath:entry[@"path"] error:nil];
        totalSize -= [entry[@"size"] unsignedLongLongValue];
    }
}

@end
