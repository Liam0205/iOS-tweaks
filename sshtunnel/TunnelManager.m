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

static NSString *const kStateDir = @"/var/jb/var/mobile/.sshtunnel";

static NSString *statePath(NSString *name) {
    return [kStateDir stringByAppendingPathComponent:name];
}

@implementation TunnelManager {
    pid_t _pid;
    dispatch_source_t _monitor;
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
        _pid = 0;
        _serverPort = 22;
        _remotePort = 2222;
        _localPort = 22;
        _identityFile = @"/var/jb/var/mobile/.ssh/id_rsa";
        [self loadSettings];
        [self probe];
    }
    return self;
}

#pragma mark - Settings

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

#pragma mark - State

- (void)setState:(TunnelState)state message:(NSString *)msg {
    _state = state;
    _lastMessage = msg;
    if (_onStateChange) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_onStateChange(state, msg);
        });
    }
}

#pragma mark - State files

- (void)ensureStateDir {
    [[NSFileManager defaultManager] createDirectoryAtPath:kStateDir
                              withIntermediateDirectories:YES attributes:nil error:nil];
}

- (void)writePidFile:(pid_t)pid {
    [self ensureStateDir];
    [[NSString stringWithFormat:@"%d", pid]
     writeToFile:statePath(@"autossh.pid") atomically:YES
        encoding:NSUTF8StringEncoding error:nil];
}

- (pid_t)readPidFile {
    NSString *s = [NSString stringWithContentsOfFile:statePath(@"autossh.pid")
                                            encoding:NSUTF8StringEncoding error:nil];
    return s ? (pid_t)s.intValue : 0;
}

- (void)writeConfigFile {
    NSDictionary *config = @{
        @"host": _serverHost ?: @"",
        @"port": @(_serverPort),
        @"user": _username ?: @"",
        @"remotePort": @(_remotePort),
        @"localPort": @(_localPort),
        @"identity": _identityFile ?: @"",
        @"autossh": @(_usingAutossh),
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:config options:0 error:nil];
    [self ensureStateDir];
    [data writeToFile:statePath(@"tunnel.json") atomically:YES];
}

- (NSDictionary *)readConfigFile {
    NSData *data = [NSData dataWithContentsOfFile:statePath(@"tunnel.json")];
    if (!data) return nil;
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
}

- (NSString *)readLogTail {
    NSString *log = [NSString stringWithContentsOfFile:statePath(@"stderr.log")
                                              encoding:NSUTF8StringEncoding error:nil];
    return [self lastLines:10 of:log];
}

- (void)cleanupStateFiles {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:statePath(@"autossh.pid") error:nil];
    [fm removeItemAtPath:statePath(@"tunnel.json") error:nil];
}

#pragma mark - Probe

- (void)probe {
    pid_t pid = [self readPidFile];
    if (pid <= 0) return;

    if (kill(pid, 0) != 0) {
        NSString *log = [self readLogTail];
        [self cleanupStateFiles];
        if (log.length) {
            _lastMessage = [NSString stringWithFormat:@"Tunnel ended:\n%@", log];
        }
        return;
    }

    NSDictionary *config = [self readConfigFile];
    _pid = pid;
    _usingAutossh = [config[@"autossh"] boolValue];

    NSString *host = config[@"host"] ?: @"?";
    NSString *user = config[@"user"] ?: @"?";
    NSInteger rp = [config[@"remotePort"] integerValue];
    NSInteger lp = [config[@"localPort"] integerValue];

    _lastMessage = [NSString stringWithFormat:@"PID %d — tunnel %@@%@:%ld → localhost:%ld",
                    pid, user, host, (long)rp, (long)lp];
    _state = TunnelStateConnected;
    [self attachMonitor:pid];
}

#pragma mark - Connect / Disconnect

- (void)connect {
    if (_state != TunnelStateDisconnected) return;
    if (!_serverHost.length || !_username.length) {
        [self setState:TunnelStateDisconnected message:@"Server and username required"];
        return;
    }

    [self setState:TunnelStateConnecting message:@"Connecting..."];
    [self saveSettings];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [self spawnTunnel];
    });
}

static NSString *findBinary(NSString *name) {
    NSString *jb = [@"/var/jb/usr/bin" stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:jb]) return jb;
    return [@"/usr/bin" stringByAppendingPathComponent:name];
}

- (void)spawnTunnel {
    NSString *autosshPath = findBinary(@"autossh");
    BOOL hasAutossh = [[NSFileManager defaultManager] fileExistsAtPath:autosshPath];
    NSString *sshPath = findBinary(@"ssh");
    NSString *binary = hasAutossh ? autosshPath : sshPath;
    _usingAutossh = hasAutossh;

    NSString *tunnel = [NSString stringWithFormat:@"%ld:localhost:%ld",
                        (long)_remotePort, (long)_localPort];
    NSString *port = [NSString stringWithFormat:@"%ld", (long)_serverPort];
    NSString *target = [NSString stringWithFormat:@"%@@%@", _username, _serverHost];

    NSMutableArray<NSString *> *args = [NSMutableArray array];
    [args addObject:binary];
    if (hasAutossh) {
        [args addObjectsFromArray:@[@"-M", @"0"]];
    }
    [args addObjectsFromArray:@[
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

    [self ensureStateDir];
    NSString *logPath = statePath(@"stderr.log");
    int logFd = open(logPath.UTF8String, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (logFd >= 0) {
        posix_spawn_file_actions_adddup2(&actions, logFd, STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, logFd);
    }

    if (hasAutossh) {
        setenv("AUTOSSH_GATETIME", "0", 1);
        setenv("AUTOSSH_PATH", sshPath.UTF8String, 1);
    }

    extern char **environ;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    pid_t pid = 0;
    int ret = posix_spawn(&pid, binary.UTF8String, &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    if (logFd >= 0) close(logFd);

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);

    if (ret != 0) {
        [self setState:TunnelStateDisconnected
               message:[NSString stringWithFormat:@"spawn failed: %s", strerror(ret)]];
        return;
    }

    _pid = pid;
    [self writePidFile:pid];
    [self writeConfigFile];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (self->_pid == pid && self->_state == TunnelStateConnecting) {
            NSString *msg = [NSString stringWithFormat:@"PID %d — tunnel %@@%@:%ld → localhost:%ld%@",
                             pid, self->_username, self->_serverHost,
                             (long)self->_remotePort, (long)self->_localPort,
                             hasAutossh ? @" (autossh)" : @""];
            [self setState:TunnelStateConnected message:msg];
        }
    });

    [self attachMonitor:pid];
}

- (void)attachMonitor:(pid_t)pid {
    if (_monitor) {
        dispatch_source_cancel(_monitor);
        _monitor = nil;
    }

    _monitor = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, pid,
                                      DISPATCH_PROC_EXIT, dispatch_get_main_queue());
    dispatch_source_set_event_handler(_monitor, ^{
        int status = 0;
        pid_t wp = waitpid(pid, &status, WNOHANG);
        self->_pid = 0;
        self->_monitor = nil;

        NSString *log = [self readLogTail];
        [self cleanupStateFiles];

        NSString *reason;
        if (wp > 0) {
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 0) {
                    reason = @"Disconnected";
                } else {
                    reason = log.length
                        ? [NSString stringWithFormat:@"Exited %d:\n%@", code, log]
                        : [NSString stringWithFormat:@"Exited with code %d", code];
                }
            } else if (WIFSIGNALED(status)) {
                reason = [NSString stringWithFormat:@"Killed by signal %d", WTERMSIG(status)];
            } else {
                reason = @"Terminated";
            }
        } else {
            reason = log.length
                ? [NSString stringWithFormat:@"Tunnel ended:\n%@", log]
                : @"Tunnel process ended";
        }
        [self setState:TunnelStateDisconnected message:reason];
    });
    dispatch_resume(_monitor);
}

- (void)disconnect {
    if (_pid > 0) {
        kill(_pid, SIGTERM);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                       dispatch_get_global_queue(0, 0), ^{
            if (self->_pid > 0) {
                kill(self->_pid, SIGKILL);
            }
        });
    }
}

#pragma mark - Helpers

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

@end
