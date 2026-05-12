#import "TunnelManager.h"
#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <fcntl.h>

static NSString *const kHost = @"SSHTunnel_Host";
static NSString *const kPort = @"SSHTunnel_Port";
static NSString *const kUser = @"SSHTunnel_User";
static NSString *const kRemotePort = @"SSHTunnel_RemotePort";
static NSString *const kLocalPort = @"SSHTunnel_LocalPort";
static NSString *const kIdentity = @"SSHTunnel_Identity";
static NSString *const kAutoReconnect = @"SSHTunnel_AutoReconnect";
static NSString *const kAutoStart = @"SSHTunnel_AutoStart";

static NSString *const kStateDir = @"/var/jb/var/mobile/.sshtunnel";
static NSString *const kBootCmdPath = @"/var/jb/var/mobile/.sshtunnel/boot-cmd";
static NSString *const kDaemonPlistPath = @"/var/jb/Library/LaunchDaemons/page.0x01.sshtunnel.plist";
static NSString *const kDaemonLabel = @"page.0x01.sshtunnel";

static NSString *statePath(NSString *name) {
    return [kStateDir stringByAppendingPathComponent:name];
}

static NSString *findBinary(NSString *name) {
    NSString *jb = [@"/var/jb/usr/bin" stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:jb]) return jb;
    return [@"/usr/bin" stringByAppendingPathComponent:name];
}

@implementation TunnelManager {
    pid_t _pid;
    dispatch_source_t _monitor;
    dispatch_source_t _healthTimer;
    int _reconnectBackoff;
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
        _autoReconnect = YES;
        _autoStartOnBoot = NO;
        _reconnectBackoff = 0;
        _healthCheckFailures = 0;
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
    [d setBool:_autoReconnect forKey:kAutoReconnect];
    [d setBool:_autoStartOnBoot forKey:kAutoStart];
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

    // autoReconnect defaults to YES if never set
    if ([d objectForKey:kAutoReconnect]) {
        _autoReconnect = [d boolForKey:kAutoReconnect];
    } else {
        _autoReconnect = YES;
    }
    _autoStartOnBoot = [d boolForKey:kAutoStart];
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

#pragma mark - Orphan Process Detection

- (pid_t)findOrphanTunnelPid {
    if (!_serverHost.length || _remotePort <= 0 || _localPort <= 0) return 0;

    NSString *needle = [NSString stringWithFormat:@"-R %ld:localhost:%ld",
                        (long)_remotePort, (long)_localPort];

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) return 0;

    struct kinfo_proc *procs = malloc(size);
    if (!procs) return 0;
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return 0;
    }

    int count = (int)(size / sizeof(struct kinfo_proc));
    pid_t found = 0;
    pid_t myPid = getpid();

    for (int i = 0; i < count && found == 0; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid <= 0 || pid == myPid) continue;

        int argsMib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
        size_t argsSize = 0;
        if (sysctl(argsMib, 3, NULL, &argsSize, NULL, 0) != 0) continue;

        char *argsBuf = malloc(argsSize);
        if (!argsBuf) continue;
        if (sysctl(argsMib, 3, argsBuf, &argsSize, NULL, 0) != 0) {
            free(argsBuf);
            continue;
        }

        // KERN_PROCARGS2: argc(4B) + exec_path + NUL-separated argv
        // Replace NULs with spaces so we can search as a single string
        for (size_t j = 0; j < argsSize; j++) {
            if (argsBuf[j] == '\0') argsBuf[j] = ' ';
        }
        NSString *argsStr = [[NSString alloc] initWithBytes:argsBuf
                                                     length:argsSize
                                                   encoding:NSUTF8StringEncoding];
        free(argsBuf);

        if (argsStr && [argsStr containsString:needle] &&
            [argsStr containsString:@"ssh"]) {
            if (kill(pid, 0) == 0) {
                found = pid;
            }
        }
    }

    free(procs);
    return found;
}

- (void)killOrphanTunnel {
    pid_t orphan = [self findOrphanTunnelPid];
    if (orphan <= 0) return;
    kill(orphan, SIGTERM);
    usleep(300000);
    if (kill(orphan, 0) == 0) kill(orphan, SIGKILL);
    usleep(200000);
}

#pragma mark - TCP Health Check

- (BOOL)tcpConnectTestWithTimeout:(NSTimeInterval)timeout {
    if (!_serverHost.length) return NO;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    NSString *portStr = [NSString stringWithFormat:@"%ld", (long)_serverPort];
    int err = getaddrinfo(_serverHost.UTF8String, portStr.UTF8String, &hints, &res);
    if (err != 0 || !res) return NO;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return NO;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    BOOL success = NO;
    if (ret == 0) {
        success = YES;
    } else if (errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        struct timeval tv;
        tv.tv_sec = (long)timeout;
        tv.tv_usec = (long)((timeout - (long)timeout) * 1000000);

        int sel = select(sock + 1, NULL, &writefds, NULL, &tv);
        if (sel > 0) {
            int optval = 0;
            socklen_t optlen = sizeof(optval);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
            success = (optval == 0);
        }
    }

    close(sock);
    return success;
}

#pragma mark - Health Check Timer

- (void)startHealthCheck {
    [self stopHealthCheck];

    _healthTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                          dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    dispatch_source_set_timer(_healthTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
                              30 * NSEC_PER_SEC, 5 * NSEC_PER_SEC);

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_healthTimer, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        [self performHealthCheck];
    });
    dispatch_resume(_healthTimer);
}

- (void)stopHealthCheck {
    if (_healthTimer) {
        dispatch_source_cancel(_healthTimer);
        _healthTimer = nil;
    }
}

- (void)performHealthCheck {
    if (_state != TunnelStateConnected) return;

    pid_t pid = _pid;
    if (pid <= 0 || kill(pid, 0) != 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self handleTunnelDeath:@"Process exited unexpectedly"];
        });
    }
}

#pragma mark - Auto-Reconnect

- (void)handleTunnelDeath:(NSString *)reason {
    pid_t pid = _pid;
    _pid = 0;
    if (_monitor) {
        dispatch_source_cancel(_monitor);
        _monitor = nil;
    }
    [self stopHealthCheck];
    [self cleanupStateFiles];

    if (pid > 0) {
        waitpid(pid, NULL, WNOHANG);
    }

    if (_autoReconnect && _serverHost.length && _username.length) {
        [self setState:TunnelStateReconnecting message:reason];
        int delay = 3 * (1 << (_reconnectBackoff < 4 ? _reconnectBackoff : 4));
        if (delay > 60) delay = 60;
        _reconnectBackoff++;

        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            if (self->_state == TunnelStateReconnecting) {
                [self setState:TunnelStateConnecting message:@"Reconnecting..."];
                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                    [self spawnTunnel];
                });
            }
        });
    } else {
        _reconnectBackoff = 0;
        [self setState:TunnelStateDisconnected message:reason];
    }
}

#pragma mark - Connection Verification

- (void)verifyConnection:(pid_t)pid attempt:(int)attempt {
    if (_pid != pid || _state != TunnelStateConnecting) return;

    if (kill(pid, 0) != 0) {
        [self handleTunnelDeath:@"Process died during connection"];
        return;
    }

    // ExitOnForwardFailure=yes ensures ssh exits quickly on bind failure.
    // Process surviving 5s means tunnel is established.
    if (attempt < 5) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            [self verifyConnection:pid attempt:attempt + 1];
        });
    } else {
        _reconnectBackoff = 0;
        _healthCheckFailures = 0;
        NSString *msg = [NSString stringWithFormat:@"PID %d — %@@%@:%ld → localhost:%ld%@",
                         pid, _username, _serverHost,
                         (long)_remotePort, (long)_localPort,
                         _usingAutossh ? @" (autossh)" : @""];
        [self setState:TunnelStateConnected message:msg];
        [self startHealthCheck];
        if (_autoStartOnBoot) {
            [self writeBootCmd];
        }
    }
}

#pragma mark - Probe

- (void)probe {
    pid_t pid = [self readPidFile];

    if (pid <= 0) {
        pid = [self findOrphanTunnelPid];
        if (pid <= 0) return;
    }

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

    [self writePidFile:pid];
    [self writeConfigFile];
    [self attachMonitor:pid];

    NSString *host = config[@"host"] ?: _serverHost ?: @"?";
    NSString *user = config[@"user"] ?: _username ?: @"?";
    NSInteger rp = config[@"remotePort"] ? [config[@"remotePort"] integerValue] : _remotePort;
    NSInteger lp = config[@"localPort"] ? [config[@"localPort"] integerValue] : _localPort;
    NSString *msg = [NSString stringWithFormat:@"PID %d — %@@%@:%ld → localhost:%ld",
                     pid, user, host, (long)rp, (long)lp];
    [self setState:TunnelStateConnected message:msg];
    [self startHealthCheck];
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
        [self killOrphanTunnel];
        [self spawnTunnel];
    });
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
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attr, 0);

    pid_t pid = 0;
    int ret = posix_spawn(&pid, binary.UTF8String, &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    if (logFd >= 0) close(logFd);

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);

    if (ret != 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setState:TunnelStateDisconnected
                   message:[NSString stringWithFormat:@"spawn failed: %s", strerror(ret)]];
        });
        return;
    }

    _pid = pid;
    [self writePidFile:pid];
    [self writeConfigFile];
    [self attachMonitor:pid];

    // Verify connection via TCP polling instead of blind 3s wait
    dispatch_async(dispatch_get_main_queue(), ^{
        [self verifyConnection:pid attempt:0];
    });
}

- (void)attachMonitor:(pid_t)pid {
    if (_monitor) {
        dispatch_source_cancel(_monitor);
        _monitor = nil;
    }

    _monitor = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, pid,
                                      DISPATCH_PROC_EXIT, dispatch_get_main_queue());
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_monitor, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;

        int status = 0;
        pid_t wp = waitpid(pid, &status, WNOHANG);

        NSString *log = [self readLogTail];

        NSString *reason;
        if (wp > 0) {
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 0) {
                    reason = @"Disconnected normally";
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

        [self handleTunnelDeath:reason];
    });
    dispatch_resume(_monitor);
}

- (void)disconnect {
    [self stopHealthCheck];
    if (_autoStartOnBoot) [self removeBootCmd];

    pid_t pid = _pid;
    _pid = 0;
    if (_monitor) {
        dispatch_source_cancel(_monitor);
        _monitor = nil;
    }
    [self cleanupStateFiles];
    _reconnectBackoff = 0;
    [self setState:TunnelStateDisconnected message:@"Disconnected"];

    if (pid > 0) {
        kill(pid, SIGTERM);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                       dispatch_get_global_queue(0, 0), ^{
            kill(pid, SIGKILL);
        });
    }
}

#pragma mark - Boot Persistence

- (void)writeBootCmd {
    [self ensureStateDir];

    NSString *sshPath = findBinary(@"ssh");
    NSString *autosshPath = findBinary(@"autossh");
    BOOL hasAutossh = [[NSFileManager defaultManager] fileExistsAtPath:autosshPath];

    NSMutableString *script = [NSMutableString string];
    [script appendString:@"#!/bin/sh\n"];
    [script appendString:@"export HOME=/var/mobile\n"];
    [script appendString:@"export AUTOSSH_GATETIME=0\n"];

    if (hasAutossh) {
        [script appendFormat:@"export AUTOSSH_PATH=%@\n", sshPath];
    }

    [script appendFormat:@"echo $$ > %@\n", statePath(@"autossh.pid")];

    NSString *binary = hasAutossh ? autosshPath : sshPath;
    NSMutableString *cmd = [NSMutableString stringWithFormat:@"exec %@", binary];
    if (hasAutossh) [cmd appendString:@" -M 0"];
    [cmd appendFormat:@" -N -R %ld:localhost:%ld -p %ld",
     (long)_remotePort, (long)_localPort, (long)_serverPort];
    [cmd appendString:@" -o StrictHostKeyChecking=no -o ServerAliveInterval=15 -o ServerAliveCountMax=3"];
    [cmd appendString:@" -o ExitOnForwardFailure=yes -o BatchMode=yes"];
    if (_identityFile.length) [cmd appendFormat:@" -i %@", _identityFile];
    [cmd appendFormat:@" %@@%@\n", _username, _serverHost];
    [script appendString:cmd];

    [script writeToFile:kBootCmdPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    chmod(kBootCmdPath.UTF8String, 0755);
}

- (void)removeBootCmd {
    [[NSFileManager defaultManager] removeItemAtPath:kBootCmdPath error:nil];
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
