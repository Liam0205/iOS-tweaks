#import <Foundation/Foundation.h>

@interface KeyManager : NSObject

+ (BOOL)keyExistsAtPath:(NSString *)path;
+ (void)generateKeyAtPath:(NSString *)path completion:(void (^)(BOOL success, NSString *error))completion;
+ (NSString *)publicKeyForPath:(NSString *)path;

@end
