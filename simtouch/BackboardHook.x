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

#define DIAG_NOTIFY(tag) CFNotificationCenterPostNotification( \
    CFNotificationCenterGetDarwinNotifyCenter(), \
    CFSTR("page.0x01.simtouch.bb.diag." tag), NULL, NULL, true)

enum {
    kSTPhaseDown = 0,
    kSTPhaseMove = 1,
    kSTPhaseUp   = 2,
    kSTPhaseSwipe = 3,
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
    uint32_t edge_mask;
} STTouchCmd;

enum {
    kSTCurveLinear    = 0,
    kSTCurveEaseIn    = 1,
    kSTCurveEaseOut   = 2,
    kSTCurveEaseInOut = 3,
    kSTCurveBezier    = 4,
};

typedef struct {
    uint8_t phase;
    float x1, y1, x2, y2;
    uint32_t duration_ms;
    uint32_t edge_mask;
    uint8_t curve_type;
    float bz_x1, bz_y1, bz_x2, bz_y2;
} STSwipeCmd;
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
static void *_capturedC = NULL;
static void *_capturedD = NULL;
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
                    _capturedC = c;
                    _capturedD = d;
                    DIAG_NOTIFY("sender.captured");
                }
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
            mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch |
                   kIOHIDDigitizerEventIdentity;
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
    orig_HandleFromSender(clone, _capturedSender, _capturedC, _capturedD);
    _injecting = NO;

    CFRelease(clone);
    DIAG_NOTIFY("injected");
}

#pragma mark - Cubic Bezier Easing

static float cubicBezierSample(float t, float a, float b) {
    return ((1.0f - 3.0f*b + 3.0f*a)*t*t*t + (3.0f*b - 6.0f*a)*t*t + 3.0f*a*t);
}

static float cubicBezierSolveX(float x, float x1, float x2) {
    float t = x;
    for (int i = 0; i < 8; i++) {
        float err = cubicBezierSample(t, x1, x2) - x;
        if (fabsf(err) < 1e-6f) break;
        float d = (3.0f*(1.0f - 3.0f*x2 + 3.0f*x1)*t*t + 2.0f*(3.0f*x2 - 6.0f*x1)*t + 3.0f*x1);
        if (fabsf(d) < 1e-6f) break;
        t -= err / d;
    }
    return t;
}

static float cubicBezierEase(float x, float x1, float y1, float x2, float y2) {
    if (x <= 0.0f) return 0.0f;
    if (x >= 1.0f) return 1.0f;
    float t = cubicBezierSolveX(x, x1, x2);
    return cubicBezierSample(t, y1, y2);
}

static float applyEasing(float t, uint8_t curveType, float bx1, float by1, float bx2, float by2) {
    switch (curveType) {
        case kSTCurveEaseIn:    return cubicBezierEase(t, 0.42f, 0.0f, 1.0f, 1.0f);
        case kSTCurveEaseOut:   return cubicBezierEase(t, 0.0f, 0.0f, 0.58f, 1.0f);
        case kSTCurveEaseInOut: return cubicBezierEase(t, 0.42f, 0.0f, 0.58f, 1.0f);
        case kSTCurveBezier:    return cubicBezierEase(t, bx1, by1, bx2, by2);
        default:                return t;
    }
}

#pragma mark - Darwin Notification Handlers

static void performSwipe(STSwipeCmd *sc) {
    uint32_t durationMs = sc->duration_ms;
    if (durationMs == 0) durationMs = 300;
    NSInteger steps = MAX((NSInteger)(durationMs / 16), 2);

    float x1 = sc->x1, y1 = sc->y1, x2 = sc->x2, y2 = sc->y2;
    uint8_t curveType = sc->curve_type;
    float bx1 = sc->bz_x1, by1 = sc->bz_y1, bx2 = sc->bz_x2, by2 = sc->bz_y2;

    dispatchTouch(kSTPhaseDown, x1, y1);

    for (NSInteger i = 1; i <= steps; i++) {
        float tLinear = (float)i / (float)steps;
        float tEased = applyEasing(tLinear, curveType, bx1, by1, bx2, by2);
        float cx = x1 + (x2 - x1) * tEased;
        float cy = y1 + (y2 - y1) * tEased;
        BOOL last = (i == steps);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)i * 16 * NSEC_PER_MSEC),
            dispatch_get_main_queue(), ^{
                if (last) {
                    dispatchTouch(kSTPhaseUp, cx, cy);
                } else {
                    dispatchTouch(kSTPhaseMove, cx, cy);
                }
            });
    }
}

static void onTouchCommand(CFNotificationCenterRef center, void *observer,
                           CFStringRef name, const void *object, CFDictionaryRef info) {
    int fd = open(BB_CMD_PATH, O_RDONLY);
    if (fd < 0) return;

    uint8_t buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n < 1) return;

    uint8_t phase = buf[0];
    CFNotificationCenterRef nc = CFNotificationCenterGetDarwinNotifyCenter();

    if (phase == kSTPhaseSwipe) {
        if (n < (ssize_t)sizeof(STSwipeCmd)) return;
        STSwipeCmd *sc = (STSwipeCmd *)buf;
        performSwipe(sc);
        CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
        return;
    }

    if (phase == kSTPhaseRecordStart) {
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

    if (phase == kSTPhaseRecordStop) {
        _recording = NO;
        if (_recordFd >= 0) { close(_recordFd); _recordFd = -1; }
        DIAG_NOTIFY("record.stopped");
        CFNotificationCenterPostNotification(nc, CFSTR(BB_ACK_NOTIFY), NULL, NULL, true);
        return;
    }

    if (phase == kSTPhaseReplay) {
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

                    uint8_t stPhase;
                    BOOL prevTouch = (idx > 0) ?
                        ((const STRecordEntry *)recordData.bytes)[idx - 1].touch : NO;
                    BOOL curTouch = e->touch;

                    if (curTouch && !prevTouch) {
                        stPhase = kSTPhaseDown;
                    } else if (curTouch && prevTouch) {
                        stPhase = kSTPhaseMove;
                    } else if (!curTouch && prevTouch) {
                        stPhase = kSTPhaseUp;
                    } else {
                        if (idx == total - 1) { _replaying = NO; DIAG_NOTIFY("replay.done"); }
                        return;
                    }

                    dispatchTouch(stPhase, e->x, e->y);

                    if (idx == total - 1) {
                        _replaying = NO;
                        DIAG_NOTIFY("replay.done");
                    }
                });
        }
        return;
    }

    if (n < (ssize_t)sizeof(STTouchCmd)) return;
    STTouchCmd *cmd = (STTouchCmd *)buf;
    dispatchTouch(cmd->phase, cmd->x, cmd->y);

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
    CFNotificationCenterPostNotification(nc, CFSTR(BB_READY_NOTIFY), NULL, NULL, true);
}
