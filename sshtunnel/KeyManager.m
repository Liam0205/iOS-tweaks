#import "KeyManager.h"
#import <spawn.h>
#import <sys/wait.h>

@implementation KeyManager

+ (BOOL)keyExistsAtPath:(NSString *)path {
    return [[NSFileManager defaultManager] fileExistsAtPath:path];
}

+ (void)generateKeyAtPath:(NSString *)path completion:(void (^)(BOOL, NSString *))completion {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *dir = [path stringByDeletingLastPathComponent];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:dir]) {
            NSError *err;
            [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&err];
            if (err) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(NO, [NSString stringWithFormat:@"mkdir failed: %@", err.localizedDescription]);
                });
                return;
            }
        }

        if ([fm fileExistsAtPath:path]) {
            [fm removeItemAtPath:path error:nil];
        }
        NSString *pubPath = [path stringByAppendingString:@".pub"];
        if ([fm fileExistsAtPath:pubPath]) {
            [fm removeItemAtPath:pubPath error:nil];
        }

        char *argv[] = {
            "/usr/bin/ssh-keygen",
            "-t", "ed25519",
            "-f", (char *)path.UTF8String,
            "-N", "",
            "-q",
            NULL
        };

        extern char **environ;
        pid_t pid = 0;
        int ret = posix_spawn(&pid, "/usr/bin/ssh-keygen", NULL, NULL, argv, environ);
        if (ret != 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(NO, [NSString stringWithFormat:@"spawn failed: %s", strerror(ret)]);
            });
            return;
        }

        int status = 0;
        waitpid(pid, &status, 0);

        BOOL ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                completion(YES, nil);
            } else {
                completion(NO, [NSString stringWithFormat:@"ssh-keygen exited %d", WEXITSTATUS(status)]);
            }
        });
    });
}

+ (NSString *)publicKeyForPath:(NSString *)path {
    NSString *pubPath = [path stringByAppendingString:@".pub"];
    return [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];
}

@end
