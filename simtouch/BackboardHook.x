#import <Foundation/Foundation.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <substrate.h>

#pragma mark - IOHIDEvent Private API

typedef struct __IOHIDEvent *IOHIDEventRef;

#ifdef __LP64__
typedef double IOHIDFloat;
#else
typedef float IOHIDFloat;
#endif

enum {
    kIOHIDDigitizerEventRange    = 1 << 0,
    kIOHIDDigitizerEventTouch    = 1 << 1,
    kIOHIDDigitizerEventPosition = 1 << 2,
    kIOHIDDigitizerEventIdentity = 1 << 5,
};

enum {
    kIOHIDEventFieldDigitizerX                  = (11 << 16) | 0,
    kIOHIDEventFieldDigitizerY                  = (11 << 16) | 1,
    kIOHIDEventFieldDigitizerEventMask          = (11 << 16) | 7,
    kIOHIDEventFieldDigitizerRange              = (11 << 16) | 8,
    kIOHIDEventFieldDigitizerTouch              = (11 << 16) | 9,
    kIOHIDEventFieldDigitizerCollection         = (11 << 16) | 14,
    kIOHIDEventFieldDigitizerTipPressure        = (11 << 16) | 15,
    kIOHIDEventFieldDigitizerMajorRadius        = (11 << 16) | 20,
    kIOHIDEventFieldDigitizerMinorRadius        = (11 << 16) | 21,
    kIOHIDEventFieldDigitizerIsDisplayIntegrated = (11 << 16) | 24,
    kIOHIDEventFieldIsBuiltIn                   = 4,
};

extern IOHIDEventRef IOHIDEventCreateDigitizerEvent(CFAllocatorRef, uint64_t,
    uint32_t type, uint32_t index, uint32_t identity,
    uint32_t eventMask, uint32_t buttonMask,
    IOHIDFloat x, IOHIDFloat y, IOHIDFloat z,
    IOHIDFloat tipPressure, IOHIDFloat barrelPressure,
    Boolean range, Boolean touch, uint32_t options);

extern IOHIDEventRef IOHIDEventCreateDigitizerFingerEvent(CFAllocatorRef, uint64_t,
    uint32_t index, uint32_t identity, uint32_t eventMask,
    IOHIDFloat x, IOHIDFloat y, IOHIDFloat z,
    IOHIDFloat tipPressure, IOHIDFloat twist,
    Boolean range, Boolean touch, uint32_t options);

extern void IOHIDEventAppendEvent(IOHIDEventRef, IOHIDEventRef);
extern void IOHIDEventSetSenderID(IOHIDEventRef, uint64_t);
extern void IOHIDEventSetIntegerValue(IOHIDEventRef, uint32_t field, int value);
extern void IOHIDEventSetFloatValue(IOHIDEventRef, uint32_t field, IOHIDFloat value);
extern int IOHIDEventGetIntegerValue(IOHIDEventRef, uint32_t field);
extern IOHIDFloat IOHIDEventGetFloatValue(IOHIDEventRef, uint32_t field);
extern int IOHIDEventGetType(IOHIDEventRef);
extern uint64_t IOHIDEventGetSenderID(IOHIDEventRef);
extern IOHIDEventRef IOHIDEventCreateCopy(CFAllocatorRef, IOHIDEventRef);
extern CFArrayRef IOHIDEventGetChildren(IOHIDEventRef);
extern void IOHIDEventSetPhase(IOHIDEventRef, uint32_t);
extern uint32_t IOHIDEventGetPhase(IOHIDEventRef);

extern void IOHIDEventSetTimeStamp(IOHIDEventRef, uint64_t);

#define BB_CMD_PATH     "/var/jb/tmp/simtouch-cmd"
#define BB_CMD_NOTIFY   "page.0x01.simtouch.cmd"
#define BB_READY_NOTIFY "page.0x01.simtouch.bb.ready"
#define BB_ACK_NOTIFY   "page.0x01.simtouch.bb.ack"
#define BB_PING_NOTIFY  "page.0x01.simtouch.bb.ping"

#define BB_RECORD_PATH    "/tmp/simtouch-record.bin"
#define BB_RECORD_START   "page.0x01.simtouch.record.start"
#define BB_RECORD_STOP    "page.0x01.simtouch.record.stop"
#define BB_REPLAY_NOTIFY  "page.0x01.simtouch.replay"

#define DIAG_NOTIFY(tag) CFNotificationCenterPostNotification( \
    CFNotificationCenterGetDarwinNotifyCenter(), \
    CFSTR("page.0x01.simtouch.bb.diag." tag), NULL, NULL, true)

enum {
    kSTPhaseDown = 0,
    kSTPhaseMove = 1,
    kSTPhaseUp   = 2,
    kSTPhaseRecordStart = 0xF0,
    kSTPhaseRecordStop  = 0xF1,
    kSTPhaseReplay      = 0xF2,
};

// IOHIDEvent phase values
enum {
    kIOHIDEventPhaseUndefined = 0,
    kIOHIDEventPhaseBegan     = 1 << 0,
    kIOHIDEventPhaseChanged   = 1 << 1,
    kIOHIDEventPhaseEnded     = 1 << 2,
};

#pragma pack(push, 1)
typedef struct {
    uint8_t phase;
    float x;
    float y;
} STTouchCmd;
#pragma pack(pop)

#define ST_MAX_CHILDREN 5

#pragma pack(push, 1)
typedef struct {
    uint32_t time_ms;
    uint32_t phase;
    float x, y;
    uint32_t event_mask;
    int32_t touch, range;
    float pressure;
    uint8_t child_count;
    struct {
        float x, y, pressure;
        int32_t touch, range;
        uint32_t phase;
    } children[ST_MAX_CHILDREN];
} STRecordEntry;
#pragma pack(pop)

static BOOL _recording = NO;
static BOOL _replaying = NO;
static uint64_t _recordStartMach = 0;
static int _recordFd = -1;

#pragma mark - Hook _BKHandleIOHIDEventFromSender

typedef void (*HandleFromSender_t)(void *, void *, void *, void *);
static HandleFromSender_t orig_HandleFromSender = NULL;

static void *_capturedSender = NULL;
static IOHIDEventRef _capturedEvent = NULL;
static uint64_t _capturedSenderID = 0;
static BOOL _injecting = NO;

static void hook_HandleFromSender(void *a, void *b, void *c, void *d) {
    if (_injecting) {
        orig_HandleFromSender(a, b, c, d);
        return;
    }

    if (_recording) {
        @try {
            IOHIDEventRef ev = (IOHIDEventRef)a;
            int evType = IOHIDEventGetType(ev);
            if (evType == 11 && _recordFd >= 0) {
                static mach_timebase_info_data_t tb;
                if (tb.denom == 0) mach_timebase_info(&tb);
                uint64_t delta = mach_absolute_time() - _recordStartMach;
                uint32_t ms = (uint32_t)((delta * tb.numer / tb.denom) / 1000000);

                STRecordEntry entry = {0};
                entry.time_ms = ms;
                entry.phase = IOHIDEventGetPhase(ev);
                entry.x = IOHIDEventGetFloatValue(ev, kIOHIDEventFieldDigitizerX);
                entry.y = IOHIDEventGetFloatValue(ev, kIOHIDEventFieldDigitizerY);
                entry.event_mask = IOHIDEventGetIntegerValue(ev, kIOHIDEventFieldDigitizerEventMask);
                entry.touch = IOHIDEventGetIntegerValue(ev, kIOHIDEventFieldDigitizerTouch);
                entry.range = IOHIDEventGetIntegerValue(ev, kIOHIDEventFieldDigitizerRange);
                entry.pressure = IOHIDEventGetFloatValue(ev, kIOHIDEventFieldDigitizerTipPressure);

                CFArrayRef children = IOHIDEventGetChildren(ev);
                if (children) {
                    entry.child_count = (uint8_t)MIN(CFArrayGetCount(children), ST_MAX_CHILDREN);
                    for (uint8_t ci = 0; ci < entry.child_count; ci++) {
                        IOHIDEventRef child = (IOHIDEventRef)CFArrayGetValueAtIndex(children, ci);
                        entry.children[ci].x = IOHIDEventGetFloatValue(child, kIOHIDEventFieldDigitizerX);
                        entry.children[ci].y = IOHIDEventGetFloatValue(child, kIOHIDEventFieldDigitizerY);
                        entry.children[ci].pressure = IOHIDEventGetFloatValue(child, kIOHIDEventFieldDigitizerTipPressure);
                        entry.children[ci].touch = IOHIDEventGetIntegerValue(child, kIOHIDEventFieldDigitizerTouch);
                        entry.children[ci].range = IOHIDEventGetIntegerValue(child, kIOHIDEventFieldDigitizerRange);
                        entry.children[ci].phase = IOHIDEventGetPhase(child);
                    }
                }
                write(_recordFd, &entry, sizeof(entry));
            }
        } @catch(...) {}
    }

    if (!_capturedSender || !_capturedEvent) {
        @try {
            int type = IOHIDEventGetType((IOHIDEventRef)a);
            if (type == 11 && b) {
                if (!_capturedSender) {
                    _capturedSender = b;
                    CFRetain(b);
                    _capturedSenderID = IOHIDEventGetSenderID((IOHIDEventRef)a);
                    DIAG_NOTIFY("sender.captured");
                }
                // Capture a touch-down event (phase has Touch bit set)
                int touchVal = IOHIDEventGetIntegerValue((IOHIDEventRef)a, kIOHIDEventFieldDigitizerTouch);
                if (touchVal && !_capturedEvent) {
                    _capturedEvent = IOHIDEventCreateCopy(kCFAllocatorDefault, (IOHIDEventRef)a);
                    DIAG_NOTIFY("event.captured");
                }
            }
        } @catch(...) {}
    }

    orig_HandleFromSender(a, b, c, d);
}

#pragma mark - Dispatch via cloned event

static void updateTimestamps(IOHIDEventRef event) {
    uint64_t ts = mach_absolute_time();
    IOHIDEventSetTimeStamp(event, ts);
    CFArrayRef children = IOHIDEventGetChildren(event);
    if (children) {
        for (CFIndex i = 0; i < CFArrayGetCount(children); i++) {
            IOHIDEventRef child = (IOHIDEventRef)CFArrayGetValueAtIndex(children, i);
            IOHIDEventSetTimeStamp(child, ts);
        }
    }
}

static void setChildCoords(IOHIDEventRef event, float nx, float ny, BOOL touch, float pressure) {
    IOHIDEventSetFloatValue(event, kIOHIDEventFieldDigitizerX, nx);
    IOHIDEventSetFloatValue(event, kIOHIDEventFieldDigitizerY, ny);

    CFArrayRef children = IOHIDEventGetChildren(event);
    if (children) {
        for (CFIndex i = 0; i < CFArrayGetCount(children); i++) {
            IOHIDEventRef child = (IOHIDEventRef)CFArrayGetValueAtIndex(children, i);
            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerX, nx);
            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerY, ny);
            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerTipPressure, pressure);
            IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerTouch, touch ? 1 : 0);
            IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerRange, touch ? 1 : 0);
        }
    }
}

static void dispatchTouch(uint8_t phase, float nx, float ny) {
    if (!_capturedEvent || !_capturedSender || !orig_HandleFromSender) {
        DIAG_NOTIFY("no.capture");
        return;
    }

    IOHIDEventRef clone = IOHIDEventCreateCopy(kCFAllocatorDefault, _capturedEvent);
    if (!clone) {
        DIAG_NOTIFY("clone.fail");
        return;
    }

    updateTimestamps(clone);

    BOOL touch = (phase != kSTPhaseUp);
    float pressure = touch ? 1.0f : 0.0f;

    uint32_t mask;
    switch (phase) {
        case kSTPhaseDown:
            mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity;
            IOHIDEventSetPhase(clone, kIOHIDEventPhaseBegan);
            break;
        case kSTPhaseMove:
            mask = kIOHIDDigitizerEventPosition;
            IOHIDEventSetPhase(clone, kIOHIDEventPhaseChanged);
            break;
        default:
            mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch |
                   kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition;
            IOHIDEventSetPhase(clone, kIOHIDEventPhaseEnded);
            break;
    }

    setChildCoords(clone, nx, ny, touch, pressure);
    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerEventMask, mask);
    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerRange, touch ? 1 : 0);
    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerTouch, touch ? 1 : 0);
    IOHIDEventSetSenderID(clone, _capturedSenderID);

    _injecting = YES;
    orig_HandleFromSender(clone, _capturedSender, NULL, NULL);
    _injecting = NO;

    CFRelease(clone);
    DIAG_NOTIFY("injected");
}

#pragma mark - Darwin Notification Handlers

static void onTouchCommand(CFNotificationCenterRef center, void *observer,
                           CFStringRef name, const void *object, CFDictionaryRef info) {
    int fd = open(BB_CMD_PATH, O_RDONLY);
    if (fd < 0) return;

    STTouchCmd cmd;
    ssize_t n = read(fd, &cmd, sizeof(cmd));
    close(fd);

    if (n < (ssize_t)sizeof(cmd)) return;

    CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();

    if (cmd.phase == kSTPhaseRecordStart) {
        if (_recording && _recordFd >= 0) { close(_recordFd); _recordFd = -1; }
        unlink(BB_RECORD_PATH);
        _recordFd = open(BB_RECORD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (_recordFd < 0) {
            DIAG_NOTIFY("record.open.fail");
            CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
            return;
        }
        _recordStartMach = mach_absolute_time();
        _recording = YES;
        DIAG_NOTIFY("record.started");
        CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
        return;
    }

    if (cmd.phase == kSTPhaseRecordStop) {
        _recording = NO;
        if (_recordFd >= 0) { close(_recordFd); _recordFd = -1; }
        DIAG_NOTIFY("record.stopped");
        CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
        return;
    }

    if (cmd.phase == kSTPhaseReplay) {
        if (!_capturedEvent || !_capturedSender || !orig_HandleFromSender) {
            DIAG_NOTIFY("replay.no.capture");
            CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
            return;
        }
        if (_replaying) {
            DIAG_NOTIFY("replay.busy");
            CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
            return;
        }
        if (_recording) {
            _recording = NO;
            if (_recordFd >= 0) { close(_recordFd); _recordFd = -1; }
        }

        int rfd = open(BB_RECORD_PATH, O_RDONLY);
        if (rfd < 0) { DIAG_NOTIFY("replay.no.file"); CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true); return; }

        off_t fileSize = lseek(rfd, 0, SEEK_END);
        lseek(rfd, 0, SEEK_SET);
        if (fileSize <= 0) { close(rfd); DIAG_NOTIFY("replay.empty"); CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true); return; }

        size_t count = fileSize / sizeof(STRecordEntry);
        STRecordEntry *entries = (STRecordEntry *)malloc(fileSize);
        if (!entries) { close(rfd); CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true); return; }
        read(rfd, entries, fileSize);
        close(rfd);

        _replaying = YES;
        DIAG_NOTIFY("replay.start");
        CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);

        NSData *recordData = [NSData dataWithBytesNoCopy:entries length:fileSize freeWhenDone:YES];
        const STRecordEntry *ep = (const STRecordEntry *)recordData.bytes;
        uint32_t baseTime = ep[0].time_ms;

        for (size_t i = 0; i < count; i++) {
            uint32_t delay = ep[i].time_ms - baseTime;
            NSUInteger idx = i;
            NSUInteger total = count;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay * NSEC_PER_MSEC),
                dispatch_get_main_queue(), ^{
                    const STRecordEntry *e = &((const STRecordEntry *)recordData.bytes)[idx];

                    IOHIDEventRef clone = IOHIDEventCreateCopy(kCFAllocatorDefault, _capturedEvent);
                    if (!clone) return;

                    updateTimestamps(clone);
                    IOHIDEventSetFloatValue(clone, kIOHIDEventFieldDigitizerX, e->x);
                    IOHIDEventSetFloatValue(clone, kIOHIDEventFieldDigitizerY, e->y);
                    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerEventMask, e->event_mask);
                    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerTouch, e->touch);
                    IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerRange, e->range);
                    IOHIDEventSetPhase(clone, e->phase);
                    IOHIDEventSetSenderID(clone, _capturedSenderID);

                    CFArrayRef children = IOHIDEventGetChildren(clone);
                    if (children) {
                        CFIndex cc = MIN(CFArrayGetCount(children), (CFIndex)e->child_count);
                        for (CFIndex j = 0; j < cc; j++) {
                            IOHIDEventRef child = (IOHIDEventRef)CFArrayGetValueAtIndex(children, j);
                            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerX, e->children[j].x);
                            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerY, e->children[j].y);
                            IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerTipPressure, e->children[j].pressure);
                            IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerTouch, e->children[j].touch);
                            IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerRange, e->children[j].range);
                            IOHIDEventSetPhase(child, e->children[j].phase);
                        }
                    }

                    _injecting = YES;
                    orig_HandleFromSender(clone, _capturedSender, NULL, NULL);
                    _injecting = NO;
                    CFRelease(clone);

                    if (idx == total - 1) {
                        _replaying = NO;
                        DIAG_NOTIFY("replay.done");
                    }
                });
        }
        return;
    }

    dispatchTouch(cmd.phase, cmd.x, cmd.y);

    CFNotificationCenterPostNotification(nc,
        CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
}

static void onPing(CFNotificationCenterRef center, void *observer,
                   CFStringRef name, const void *object, CFDictionaryRef info) {
    CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();

    if (_capturedEvent) {
        CFNotificationCenterPostNotification(nc,
            CFSTR("page.0x01.simtouch.bb.state.captured"), NULL, NULL, true);
    } else if (_capturedSender) {
        CFNotificationCenterPostNotification(nc,
            CFSTR("page.0x01.simtouch.bb.state.sender"), NULL, NULL, true);
    } else if (orig_HandleFromSender) {
        CFNotificationCenterPostNotification(nc,
            CFSTR("page.0x01.simtouch.bb.state.hooked"), NULL, NULL, true);
    } else {
        CFNotificationCenterPostNotification(nc,
            CFSTR("page.0x01.simtouch.bb.state.nohook"), NULL, NULL, true);
    }

    CFNotificationCenterPostNotification(nc, CFSTR(BB_READY_NOTIFY), NULL, NULL, true);
}

#pragma mark - Record / Replay Handlers

static void onRecordStart(CFNotificationCenterRef center, void *observer,
                          CFStringRef name, const void *object, CFDictionaryRef info) {
    if (_recording) {
        if (_recordFd >= 0) { close(_recordFd); _recordFd = -1; }
    }
    unlink(BB_RECORD_PATH);
    _recordFd = open(BB_RECORD_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (_recordFd < 0) {
        DIAG_NOTIFY("record.open.fail");
        return;
    }
    _recordStartMach = mach_absolute_time();
    _recording = YES;
    DIAG_NOTIFY("record.started");
}

static void onRecordStop(CFNotificationCenterRef center, void *observer,
                         CFStringRef name, const void *object, CFDictionaryRef info) {
    _recording = NO;
    if (_recordFd >= 0) {
        close(_recordFd);
        _recordFd = -1;
    }
    DIAG_NOTIFY("record.stopped");
}

static void onReplay(CFNotificationCenterRef center, void *observer,
                     CFStringRef name, const void *object, CFDictionaryRef info) {
    if (!_capturedEvent || !_capturedSender || !orig_HandleFromSender) {
        DIAG_NOTIFY("replay.no.capture");
        return;
    }
    if (_replaying) {
        DIAG_NOTIFY("replay.busy");
        return;
    }
    if (_recording) {
        _recording = NO;
        if (_recordFd >= 0) { close(_recordFd); _recordFd = -1; }
    }

    int fd = open(BB_RECORD_PATH, O_RDONLY);
    if (fd < 0) { DIAG_NOTIFY("replay.no.file"); return; }

    off_t fileSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (fileSize <= 0) { close(fd); DIAG_NOTIFY("replay.empty"); return; }

    size_t count = fileSize / sizeof(STRecordEntry);
    STRecordEntry *entries = (STRecordEntry *)malloc(fileSize);
    if (!entries) { close(fd); DIAG_NOTIFY("replay.alloc.fail"); return; }
    read(fd, entries, fileSize);
    close(fd);

    _replaying = YES;
    DIAG_NOTIFY("replay.start");

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        for (size_t i = 0; i < count; i++) {
            if (i > 0) {
                uint32_t delta = entries[i].time_ms - entries[i-1].time_ms;
                if (delta > 0) usleep(delta * 1000);
            }

            IOHIDEventRef clone = IOHIDEventCreateCopy(kCFAllocatorDefault, _capturedEvent);
            if (!clone) continue;

            updateTimestamps(clone);
            IOHIDEventSetFloatValue(clone, kIOHIDEventFieldDigitizerX, entries[i].x);
            IOHIDEventSetFloatValue(clone, kIOHIDEventFieldDigitizerY, entries[i].y);
            IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerEventMask, entries[i].event_mask);
            IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerTouch, entries[i].touch);
            IOHIDEventSetIntegerValue(clone, kIOHIDEventFieldDigitizerRange, entries[i].range);
            IOHIDEventSetPhase(clone, entries[i].phase);
            IOHIDEventSetSenderID(clone, _capturedSenderID);

            CFArrayRef children = IOHIDEventGetChildren(clone);
            if (children) {
                CFIndex cc = MIN(CFArrayGetCount(children), (CFIndex)entries[i].child_count);
                for (CFIndex j = 0; j < cc; j++) {
                    IOHIDEventRef child = (IOHIDEventRef)CFArrayGetValueAtIndex(children, j);
                    IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerX, entries[i].children[j].x);
                    IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerY, entries[i].children[j].y);
                    IOHIDEventSetFloatValue(child, kIOHIDEventFieldDigitizerTipPressure, entries[i].children[j].pressure);
                    IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerTouch, entries[i].children[j].touch);
                    IOHIDEventSetIntegerValue(child, kIOHIDEventFieldDigitizerRange, entries[i].children[j].range);
                    IOHIDEventSetPhase(child, entries[i].children[j].phase);
                }
            }

            _injecting = YES;
            orig_HandleFromSender(clone, _capturedSender, NULL, NULL);
            _injecting = NO;
            CFRelease(clone);
        }

        free(entries);
        _replaying = NO;
        DIAG_NOTIFY("replay.done");
    });
}

%ctor {
    NSString *proc = [NSProcessInfo processInfo].processName;
    if (![proc isEqualToString:@"backboardd"]) return;

    void *sym = dlsym(RTLD_DEFAULT, "_BKHandleIOHIDEventFromSender");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HandleFromSender, (void **)&orig_HandleFromSender);
        DIAG_NOTIFY("hook.ok");
    } else {
        DIAG_NOTIFY("hook.nosym");
    }

    CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(nc, NULL, onTouchCommand,
        CFSTR(BB_CMD_NOTIFY), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(nc, NULL, onPing,
        CFSTR(BB_PING_NOTIFY), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(nc, NULL, onRecordStart,
        CFSTR(BB_RECORD_START), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(nc, NULL, onRecordStop,
        CFSTR(BB_RECORD_STOP), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(nc, NULL, onReplay,
        CFSTR(BB_REPLAY_NOTIFY), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterPostNotification(nc, CFSTR(BB_READY_NOTIFY), NULL, NULL, true);
}
