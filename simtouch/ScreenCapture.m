#import "ScreenCapture.h"
#import <UIKit/UIKit.h>
#import <IOSurface/IOSurfaceRef.h>
#import <sys/stat.h>

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)

extern UIImage *_UICreateScreenUIImage(void) __attribute__((weak_import));

@implementation STScreenCapture

+ (NSString *)captureToPath:(NSString *)path {
    UIImage *image = nil;

    if (_UICreateScreenUIImage) {
        image = _UICreateScreenUIImage();
    }

    if (!image) {
        UIScreen *screen = [UIScreen mainScreen];
        UIGraphicsBeginImageContextWithOptions(screen.bounds.size, YES, screen.scale);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
#pragma clang diagnostic pop
            [window drawViewHierarchyInRect:window.bounds afterScreenUpdates:NO];
        }
        image = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
    }

    if (!image) return @"ERR capture failed";

    int width = (int)(image.size.width * image.scale);
    int height = (int)(image.size.height * image.scale);

    NSData *imgData;
    BOOL usePNG = [[path.pathExtension lowercaseString] isEqualToString:@"png"];
    if (usePNG) {
        imgData = UIImagePNGRepresentation(image);
    } else {
        // _UICreateScreenUIImage may return CIImage-backed UIImage without CGImage;
        // UIImageJPEGRepresentation needs CGImage, so redraw into bitmap context first
        UIGraphicsBeginImageContextWithOptions(image.size, YES, image.scale);
        [image drawAtPoint:CGPointZero];
        UIImage *bitmapImage = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
        imgData = UIImageJPEGRepresentation(bitmapImage, 0.8);
    }
    if (!imgData || imgData.length == 0) return @"ERR image encoding failed";

    NSString *dir = [path stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSError *writeErr = nil;
    if (![imgData writeToFile:path options:NSDataWritingAtomic error:&writeErr]) {
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
