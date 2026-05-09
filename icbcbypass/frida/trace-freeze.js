// Frida script to diagnose ICBC welcome page freeze
// Usage: frida -H <ip>:<port> -n ICBCBankTest -l trace-freeze.js

'use strict';

const MAX_TRACES = 20;
let traceCount = 0;

// === 1. Trace setAnimationsEnabled:NO with backtrace ===
const UIView = ObjC.classes.UIView;
Interceptor.attach(UIView['+ setAnimationsEnabled:'].implementation, {
    onEnter(args) {
        const enabled = args[2].toInt32();
        if (enabled === 0 && traceCount < MAX_TRACES) {
            traceCount++;
            console.log(`\n[setAnimationsEnabled:NO] #${traceCount}`);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    }
});

// === 2. Trace ICBCMotionRecognizingWindow sendEvent ===
const motionWinClass = ObjC.classes['ICBCMotionRecognizingWindow'];
if (motionWinClass) {
    const sendEventSel = motionWinClass['- sendEvent:'];
    if (sendEventSel) {
        let sendEventCount = 0;
        Interceptor.attach(sendEventSel.implementation, {
            onEnter(args) {
                sendEventCount++;
                if (sendEventCount <= 5) {
                    const event = new ObjC.Object(args[2]);
                    console.log(`[ICBCMotionRecognizingWindow sendEvent:] type=${event.type()} subtype=${event.subtype()}`);
                }
            },
            onLeave(retval) {}
        });
        console.log('[+] Hooked ICBCMotionRecognizingWindow sendEvent:');
    }

    const hitTestSel = motionWinClass['- hitTest:withEvent:'];
    if (hitTestSel) {
        let hitTestNilCount = 0;
        Interceptor.attach(hitTestSel.implementation, {
            onEnter(args) {},
            onLeave(retval) {
                if (retval.isNull() && hitTestNilCount < 10) {
                    hitTestNilCount++;
                    console.log(`[ICBCMotionRecognizingWindow hitTest:] returned nil (#${hitTestNilCount})`);
                }
            }
        });
        console.log('[+] Hooked ICBCMotionRecognizingWindow hitTest:withEvent:');
    }
} else {
    console.log('[!] ICBCMotionRecognizingWindow class not found');
}

// === 3. Trace CALayer animation operations ===
const CALayer = ObjC.classes.CALayer;

// removeAllAnimations
Interceptor.attach(CALayer['- removeAllAnimations'].implementation, {
    onEnter(args) {
        const layer = new ObjC.Object(args[0]);
        const delegate = layer.delegate();
        const delegateClass = delegate ? delegate.$className : 'nil';
        // Only log if delegate is a view in the main window
        if (delegateClass.indexOf('ICBC') !== -1 || delegateClass.indexOf('Welcome') !== -1 ||
            delegateClass.indexOf('Guide') !== -1) {
            console.log(`[CALayer removeAllAnimations] delegate=${delegateClass}`);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    }
});

// setSpeed:0
Interceptor.attach(CALayer['- setSpeed:'].implementation, {
    onEnter(args) {
        const speed = args[2]; // float passed as pointer value on arm64
        // On arm64, float args are in SIMD registers, not general purpose
        // Use frida's float conversion
    }
});

// === 4. Trace beginIgnoringInteractionEvents ===
const UIApp = ObjC.classes.UIApplication;
Interceptor.attach(UIApp['- beginIgnoringInteractionEvents'].implementation, {
    onEnter(args) {
        console.log('[beginIgnoringInteractionEvents]');
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});

// === 5. After 5 seconds, dump view hierarchy ===
setTimeout(() => {
    console.log('\n=== 5-second UI State Dump ===');
    const app = ObjC.classes.UIApplication.sharedApplication();
    const windows = app.windows();
    for (let i = 0; i < windows.count(); i++) {
        const win = windows.objectAtIndex_(i);
        console.log(`Window[${i}]: ${win.$className} level=${win.windowLevel()} hidden=${win.isHidden()} userInteraction=${win.isUserInteractionEnabled()}`);
        const rootVC = win.rootViewController();
        if (rootVC) {
            console.log(`  rootVC: ${rootVC.$className}`);
            const presented = rootVC.presentedViewController();
            if (presented) {
                console.log(`  presentedVC: ${presented.$className}`);
            }
            // Check visible VC
            if (rootVC.$className === 'UINavigationController') {
                const topVC = rootVC.topViewController();
                if (topVC) {
                    console.log(`  topVC: ${topVC.$className}`);
                    // Check if view has userInteractionEnabled
                    const view = topVC.view();
                    if (view) {
                        console.log(`  topVC.view: userInteraction=${view.isUserInteractionEnabled()} alpha=${view.alpha()} hidden=${view.isHidden()}`);
                        console.log(`  topVC.view.layer: speed=${view.layer().speed()}`);
                        // Check subviews for any disabled elements
                        const subs = view.subviews();
                        for (let j = 0; j < Math.min(subs.count(), 10); j++) {
                            const sub = subs.objectAtIndex_(j);
                            if (!sub.isUserInteractionEnabled() || sub.isHidden()) {
                                console.log(`    subview[${j}]: ${sub.$className} userInteraction=${sub.isUserInteractionEnabled()} hidden=${sub.isHidden()}`);
                            }
                        }
                    }
                }
            }
        }
    }

    // Check CADisplayLink
    console.log('\n=== Animation State ===');
    console.log(`areAnimationsEnabled: ${UIView.areAnimationsEnabled()}`);
    console.log(`isIgnoringInteractionEvents: ${app.isIgnoringInteractionEvents()}`);
}, 5000);

// === 6. After 8 seconds, check what's happening on main thread ===
setTimeout(() => {
    console.log('\n=== 8-second check: trying to find freeze source ===');
    // Enumerate all timers/dispatch sources on main
    const mainRL = ObjC.classes.NSRunLoop.mainRunLoop();
    console.log(`mainRunLoop currentMode: ${mainRL.currentMode()}`);
}, 8000);

console.log('[*] ICBC Freeze Tracer loaded. Waiting for events...');
