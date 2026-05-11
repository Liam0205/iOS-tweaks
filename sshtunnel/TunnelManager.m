#import "TunnelManager.h"
#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>
#import <fcntl.h>

static NSString *const kHost = @"SSHTunnel_Host";
static NSString *const kPort = @"SSHTunnel_Port";
static NSString *const kUser = @"SSHTunnel_User";
static NSString *const kRemotePort = @"SSHTunnel_RemotePort";
static NSString *const kLocalPort = @"SSHTunnel_LocalPort";
static NSString *const kIdentity = @"SSHTunnel_Identity";

@implementation TunnelManager {
    pid_t _sshPid;
    dispatch_source_t _monitor;
    int _stderrReadFd;
}

+ (instancetype)shared {
    static TunnelManager *mgr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mgr = [[TunnelManager alloc] init]; });
    return mgr;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _state = TunnelStateDisconnected;
        _sshPid = 0;
        _serverPort = 22;
        _remotePort = 2222;
        _localPort = 22;
        _identityFile = @"/var/jb/var/mobile/.ssh/id_rsa";
        [self loadSettings];
    }
    return self;
}

- (void)saveSettings {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (_serverHost) [d setObject:_serverHost forKey:kHost];
    [d setInteger:_serverPort forKey:kPort];
    if (_username) [d setObject:_username forKey:kUser];
    [d setInteger:_remotePort forKey:kRemotePort];
    [d setInteger:_localPort forKey:kLocalPort];
    if (_identityFile) [d setObject:_identityFile forKey:kIdentity];
    [d synchronize];
}

- (void)loadSettings {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *h = [d stringForKey:kHost];
    if (h) _serverHost = h;
    NSInteger p = [d integerForKey:kPort];
    if (p > 0) _serverPort = p;
    NSString *u = [d stringForKey:kUser];
    if (u) _username = u;
    NSInteger rp = [d integerForKey:kRemotePort];
    if (rp > 0) _remotePort = rp;
    NSInteger lp = [d integerForKey:kLocalPort];
    if (lp > 0) _localPort = lp;
    NSString *id_ = [d stringForKey:kIdentity];
    if (id_) _identityFile = id_;
}

- (void)setState:(TunnelState)state message:(NSString *)msg {
    _state = state;
    if (_onStateChange) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_onStateChange(state, msg);
        });
    }
}

- (void)connect {
    if (_state != TunnelStateDisconnected) return;
    if (!_serverHost.length || !_username.length) {
        [self setState:TunnelStateDisconnected message:@"Server and username required"];
        return;
    }

    [self setState:TunnelStateConnecting message:@"Connecting..."];
    [self saveSettings];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [self spawnSSH];
    });
}

static NSString *findBinary(NSString *name) {
    NSString *jb = [@"/var/jb/usr/bin" stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:jb]) return jb;
    return [@"/usr/bin" stringByAppendingPathComponent:name];
}

- (void)spawnSSH {
    NSString *tunnel = [NSString stringWithFormat:@"%ld:localhost:%ld",
                        (long)_remotePort, (long)_localPort];
    NSString *port = [NSString stringWithFormat:@"%ld", (long)_serverPort];
    NSString *target = [NSString stringWithFormat:@"%@@%@", _username, _serverHost];

    NSString *sshPath = findBinary(@"ssh");

    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithArray:@[
        sshPath,
        @"-N",
        @"-R", tunnel,
        @"-p", port,
        @"-o", @"StrictHostKeyChecking=no",
        @"-o", @"ServerAliveInterval=15",
        @"-o", @"ServerAliveCountMax=3",
        @"-o", @"ExitOnForwardFailure=yes",
        @"-o", @"BatchMode=yes",
    ]];

    if (_identityFile.length && [[NSFileManager defaultManager] fileExistsAtPath:_identityFile]) {
        [args addObject:@"-i"];
        [args addObject:_identityFile];
    }
    [args addObject:target];

    int argc = (int)args.count;
    char **argv = calloc(argc + 1, sizeof(char *));
    for (int i = 0; i < argc; i++) {
        argv[i] = strdup(args[i].UTF8String);
    }
    argv[argc] = NULL;

    extern char **environ;
    pid_t pid = 0;

    int stderrPipe[2];
    pipe(stderrPipe);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, stderrPipe[0]);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    int ret = posix_spawn(&pid, sshPath.UTF8String, &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    close(stderrPipe[1]);

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);

    if (ret != 0) {
        close(stderrPipe[0]);
        [self setState:TunnelStateDisconnected
               message:[NSString stringWithFormat:@"spawn failed: %s", strerror(ret)]];
        return;
    }

    _sshPid = pid;
    _stderrReadFd = stderrPipe[0];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (self->_sshPid == pid && self->_state == TunnelStateConnecting) {
            [self setState:TunnelStateConnected
                   message:[NSString stringWithFormat:@"PID %d — tunnel %@@%@:%ld → localhost:%ld",
                            pid, self->_username, self->_serverHost,
                            (long)self->_remotePort, (long)self->_localPort]];
        }
    });

    _monitor = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, pid,
                                      DISPATCH_PROC_EXIT, dispatch_get_main_queue());
    dispatch_source_set_event_handler(_monitor, ^{
        int status = 0;
        waitpid(pid, &status, WNOHANG);
        self->_sshPid = 0;
        self->_monitor = nil;

        NSMutableData *stderrData = [NSMutableData data];
        char buf[1024];
        ssize_t n;
        while ((n = read(self->_stderrReadFd, buf, sizeof(buf))) > 0)
            [stderrData appendBytes:buf length:n];
        close(self->_stderrReadFd);
        NSString *stderrContent = [[NSString alloc] initWithData:stderrData
                                                        encoding:NSUTF8StringEncoding];

        NSString *reason;
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 0) {
                reason = @"Disconnected";
            } else {
                NSString *detail = [self lastLines:10 of:stderrContent];
                if (detail.length) {
                    reason = [NSString stringWithFormat:@"SSH exited %d:\n%@", code, detail];
                } else {
                    reason = [NSString stringWithFormat:@"SSH exited with code %d", code];
                }
            }
        } else if (WIFSIGNALED(status)) {
            reason = [NSString stringWithFormat:@"SSH killed by signal %d", WTERMSIG(status)];
        } else {
            reason = @"SSH terminated";
        }
        [self setState:TunnelStateDisconnected message:reason];
    });
    dispatch_resume(_monitor);
}

- (NSString *)lastLines:(int)n of:(NSString *)str {
    if (!str.length) return nil;
    NSArray *lines = [str componentsSeparatedByString:@"\n"];
    NSMutableArray *meaningful = [NSMutableArray array];
    for (NSString *line in lines) {
        if ([line stringByTrimmingCharactersInSet:
             [NSCharacterSet whitespaceAndNewlineCharacterSet]].length > 0) {
            [meaningful addObject:line];
        }
    }
    if (!meaningful.count) return nil;
    NSInteger start = meaningful.count > n ? meaningful.count - n : 0;
    return [[meaningful subarrayWithRange:NSMakeRange(start, meaningful.count - start)]
            componentsJoinedByString:@"\n"];
}

- (void)disconnect {
    if (_sshPid > 0) {
        kill(_sshPid, SIGTERM);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                       dispatch_get_global_queue(0, 0), ^{
            if (self->_sshPid > 0) {
                kill(self->_sshPid, SIGKILL);
            }
        });
    }
}

@end
