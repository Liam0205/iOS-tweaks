#import "TunnelManager.h"
#import <spawn.h>
#import <signal.h>
#import <sys/wait.h>

static NSString *const kHost = @"SSHTunnel_Host";
static NSString *const kPort = @"SSHTunnel_Port";
static NSString *const kUser = @"SSHTunnel_User";
static NSString *const kRemotePort = @"SSHTunnel_RemotePort";
static NSString *const kLocalPort = @"SSHTunnel_LocalPort";
static NSString *const kIdentity = @"SSHTunnel_Identity";

@implementation TunnelManager {
    pid_t _sshPid;
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
        _sshPid = 0;
        _serverPort = 22;
        _remotePort = 2222;
        _localPort = 22;
        _identityFile = @"/var/root/.ssh/id_rsa";
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

- (void)spawnSSH {
    NSString *tunnel = [NSString stringWithFormat:@"%ld:localhost:%ld",
                        (long)_remotePort, (long)_localPort];
    NSString *port = [NSString stringWithFormat:@"%ld", (long)_serverPort];
    NSString *target = [NSString stringWithFormat:@"%@@%@", _username, _serverHost];

    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithArray:@[
        @"/usr/bin/ssh",
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

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    int ret = posix_spawn(&pid, "/usr/bin/ssh", NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);

    if (ret != 0) {
        [self setState:TunnelStateDisconnected
               message:[NSString stringWithFormat:@"spawn failed: %s", strerror(ret)]];
        return;
    }

    _sshPid = pid;
    [self setState:TunnelStateConnected
           message:[NSString stringWithFormat:@"PID %d — tunnel %@@%@:%ld → localhost:%ld",
                    pid, _username, _serverHost, (long)_remotePort, (long)_localPort]];

    _monitor = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, pid,
                                      DISPATCH_PROC_EXIT, dispatch_get_main_queue());
    dispatch_source_set_event_handler(_monitor, ^{
        int status = 0;
        waitpid(pid, &status, WNOHANG);
        self->_sshPid = 0;
        self->_monitor = nil;
        NSString *reason;
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            reason = code == 0 ? @"Disconnected"
                : [NSString stringWithFormat:@"SSH exited with code %d", code];
        } else {
            reason = @"SSH terminated";
        }
        [self setState:TunnelStateDisconnected message:reason];
    });
    dispatch_resume(_monitor);
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
