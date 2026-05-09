// Minimal Frida script - only observe methods NOT already hooked by tweak
// Focus: find what else the freeze loop does besides setAnimationsEnabled:NO

'use strict';

// === 1. Trace CALayer removeAllAnimations ===
const CALayer = ObjC.classes.CALayer;
let removeAnimCount = 0;
Interceptor.attach(CALayer['- removeAllAnimations'].implementation, {
    onEnter(args) {
        removeAnimCount++;
        if (removeAnimCount <= 5) {
            const layer = new ObjC.Object(args[0]);
            const delegate = layer.delegate();
            console.log(`[removeAllAnimations] #${removeAnimCount} delegate=${delegate ? delegate.$className : 'nil'}`);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    }
});

// === 2. Trace CATransaction operations ===
const CATx = ObjC.classes.CATransaction;
if (CATx['+ setDisableActions:']) {
    let disableActionsCount = 0;
    Interceptor.attach(CATx['+ setDisableActions:'].implementation, {
        onEnter(args) {
            const disable = args[2].toInt32();
            if (disable && disableActionsCount < 5) {
                disableActionsCount++;
                console.log(`[CATransaction setDisableActions:YES] #${disableActionsCount}`);
            }
        }
    });
}

// === 3. After 3 seconds, dump UI hierarchy ===
setTimeout(() => {
    ObjC.schedule(ObjC.mainQueue, () => {
        console.log('\n=== UI State Dump ===');
        const app = ObjC.classes.UIApplication.sharedApplication();
        const windows = app.windows();
        console.log(`isIgnoring: ${app.isIgnoringInteractionEvents()}`);
        console.log(`animEnabled: ${ObjC.classes.UIView.areAnimationsEnabled()}`);

        for (let i = 0; i < windows.count(); i++) {
            const win = windows.objectAtIndex_(i);
            console.log(`\nWindow[${i}]: ${win.$className} level=${win.windowLevel()} hidden=${win.isHidden()} key=${win.isKeyWindow()}`);
            const rootVC = win.rootViewController();
            if (rootVC) {
                console.log(`  rootVC: ${rootVC.$className}`);
                if (rootVC.$className === 'UINavigationController') {
                    const nav = rootVC;
                    const vcs = nav.viewControllers();
                    console.log(`  vc stack (${vcs.count()}):`);
                    for (let j = 0; j < vcs.count(); j++) {
                        const vc = vcs.objectAtIndex_(j);
                        console.log(`    [${j}] ${vc.$className}`);
                    }
                    const topVC = nav.topViewController();
                    if (topVC) {
                        const view = topVC.view();
                        console.log(`  topVC.view: ${view.$className}`);
                        console.log(`    userInteraction=${view.isUserInteractionEnabled()} alpha=${view.alpha()} hidden=${view.isHidden()}`);
                        console.log(`    layer.speed=${view.layer().speed()} layer.opacity=${view.layer().opacity()}`);

                        // Recursively check first few subviews
                        const subs = view.subviews();
                        console.log(`    subviews (${subs.count()}):`);
                        for (let k = 0; k < Math.min(subs.count(), 15); k++) {
                            const sub = subs.objectAtIndex_(k);
                            const frame = sub.frame();
                            console.log(`      [${k}] ${sub.$className} interaction=${sub.isUserInteractionEnabled()} hidden=${sub.isHidden()} alpha=${sub.alpha().toFixed(2)} layer.speed=${sub.layer().speed()}`);
                        }
                    }
                }
            }
        }
    });
}, 3000);

console.log('[*] Minimal freeze tracer loaded (no conflict with tweak hooks)');
