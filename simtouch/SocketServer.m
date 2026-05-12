#import "SocketServer.h"
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <unistd.h>

#define LOG(fmt, ...) NSLog(@"[SimTouch] " fmt, ##__VA_ARGS__)
#define SOCKET_PATH "/var/jb/tmp/simtouch.sock"
#define MAX_LINE 4096

@implementation STSocketServer {
    int _listenFd;
    dispatch_source_t _listenSource;
    dispatch_queue_t _queue;
    NSMutableDictionary<NSString *, NSString *(^)(NSArray<NSString *> *)> *_handlers;
}

+ (instancetype)sharedInstance {
    static STSocketServer *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[STSocketServer alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        _listenFd = -1;
        _queue = dispatch_queue_create("page.0x01.simtouch.socket", DISPATCH_QUEUE_SERIAL);
        _handlers = [NSMutableDictionary new];
    }
    return self;
}

- (void)registerCommand:(NSString *)name handler:(NSString *(^)(NSArray<NSString *> *))handler {
    _handlers[name.lowercaseString] = [handler copy];
}

- (void)start {
    if (_running) return;

    unlink(SOCKET_PATH);

    _listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_listenFd < 0) {
        LOG(@"socket() failed: %s", strerror(errno));
        return;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path));

    if (bind(_listenFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(@"bind() failed: %s", strerror(errno));
        close(_listenFd);
        _listenFd = -1;
        return;
    }

    chmod(SOCKET_PATH, 0666);

    if (listen(_listenFd, 4) < 0) {
        LOG(@"listen() failed: %s", strerror(errno));
        close(_listenFd);
        _listenFd = -1;
        return;
    }

    _listenSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, _listenFd, 0, _queue);
    dispatch_source_set_event_handler(_listenSource, ^{
        int clientFd = accept(self->_listenFd, NULL, NULL);
        if (clientFd < 0) return;
        [self handleClient:clientFd];
    });
    dispatch_source_set_cancel_handler(_listenSource, ^{
        close(self->_listenFd);
        self->_listenFd = -1;
        unlink(SOCKET_PATH);
    });
    dispatch_resume(_listenSource);

    _running = YES;
    LOG(@"listening on %s", SOCKET_PATH);
}

- (void)stop {
    if (!_running) return;
    _running = NO;

    if (_listenSource) {
        dispatch_source_cancel(_listenSource);
        _listenSource = nil;
    }
    LOG(@"stopped");
}

- (void)handleClient:(int)fd {
    dispatch_source_t clientSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, _queue);

    __block NSMutableData *buffer = [NSMutableData new];

    dispatch_source_set_event_handler(clientSource, ^{
        char buf[MAX_LINE];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            dispatch_source_cancel(clientSource);
            return;
        }
        [buffer appendBytes:buf length:n];

        NSData *newline = [@"\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange range;
        while ((range = [buffer rangeOfData:newline options:0 range:NSMakeRange(0, buffer.length)]).location != NSNotFound) {
            NSData *lineData = [buffer subdataWithRange:NSMakeRange(0, range.location)];
            [buffer replaceBytesInRange:NSMakeRange(0, range.location + 1) withBytes:NULL length:0];

            NSString *line = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
            if (!line || line.length == 0) continue;

            NSString *response = [self processCommand:line];
            NSString *out = [response stringByAppendingString:@"\n"];
            NSData *outData = [out dataUsingEncoding:NSUTF8StringEncoding];
            write(fd, outData.bytes, outData.length);
        }
    });

    dispatch_source_set_cancel_handler(clientSource, ^{
        close(fd);
    });

    dispatch_resume(clientSource);
}

- (NSString *)processCommand:(NSString *)line {
    NSArray<NSString *> *parts = [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    parts = [parts filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];

    if (parts.count == 0) return @"ERR empty command";

    NSString *cmd = parts[0].lowercaseString;
    NSArray<NSString *> *args = parts.count > 1 ? [parts subarrayWithRange:NSMakeRange(1, parts.count - 1)] : @[];

    NSString *(^handler)(NSArray<NSString *> *) = _handlers[cmd];
    if (!handler) return [NSString stringWithFormat:@"ERR unknown command: %@", cmd];

    @try {
        return handler(args);
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"ERR exception: %@", e.reason];
    }
}

@end
