import sys, os, time, glob, frida

HERE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(HERE, 'logs')
os.makedirs(LOGDIR, exist_ok=True)

# 自动递增 attempt 编号
existing = glob.glob(os.path.join(LOGDIR, 'attempt-*.log'))
nums = []
for p in existing:
    try:
        nums.append(int(os.path.basename(p).split('-')[1].split('.')[0]))
    except Exception:
        pass
ATTEMPT = (max(nums) + 1) if nums else 1
PREFIX = 'A%03d' % ATTEMPT
LOGPATH = os.path.join(LOGDIR, 'attempt-%03d.log' % ATTEMPT)
_logf = open(LOGPATH, 'w')

def out(line):
    s = '[%s] %s' % (PREFIX, line)
    print(s)
    _logf.write(s + '\n')
    _logf.flush()

DEVICE = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
BUNDLE = 'com.exmart.HomeLink'
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 12

# frida 17 不再自动注入 ObjC bridge。前置 frida_tools 自带的 objc bridge，
# 用 CommonJS 包装暴露为 globalThis.ObjC（probe.js 只读 globalThis.ObjC，不调 require）
import frida_tools
BRIDGE = os.path.join(os.path.dirname(frida_tools.__file__), 'bridges', 'objc.js')
bridge_src = ''
if os.path.exists(BRIDGE):
    with open(BRIDGE) as bf:
        bmod = bf.read()
    bridge_src = (
        'var __ObjC_ready = (function(){\n'
        '  try {\n'
        '    var module = { exports: {} }; var exports = module.exports;\n'
        '    var require = function(){ return {}; };\n'
        + bmod +
        '\n    var b = module.exports;\n'
        '    var obj = (b && b.available !== undefined) ? b : (b && b.default) ? b.default : b;\n'
        '    globalThis.ObjC = obj;\n'
        '    return true;\n'
        '  } catch (e) { console.log("[bridge] load failed: " + e); return false; }\n'
        '})();\n'
    )

with open(os.path.join(HERE, 'probe.js')) as f:
    src = bridge_src + f.read()

def on_msg(msg, data):
    if msg['type'] == 'send':
        out(str(msg['payload']))
    elif msg['type'] == 'error':
        out('[ERROR] ' + str(msg.get('stack') or msg.get('description')))

def on_log(level, text):
    out(text)

MODE = sys.argv[2] if len(sys.argv) > 2 else 'spawn'
out('=== attempt %d / bundle %s / mode %s / dur %ds ===' % (ATTEMPT, BUNDLE, MODE, DUR))

if MODE == 'attach':
    # 等 App 自己启动后再 attach（对照：排除 frida spawn 早期被反调试抓）
    out('waiting for %s to appear...' % BUNDLE)
    pid = None
    for _ in range(50):
        for p in DEVICE.enumerate_processes():
            if p.name in ('LianJiaShell', '链家'):
                pid = p.pid; break
        if pid:
            break
        time.sleep(0.1)
    if not pid:
        out('[driver] target not running — 请先手动启动 App，或用 spawn 模式')
        _logf.close(); sys.exit(1)
    out('attaching to pid %d' % pid)
    session = DEVICE.attach(pid)
    script = session.create_script(src)
    script.on('message', on_msg)
    script.set_log_handler(on_log)
    script.load()
    out('attached, collecting %ds' % DUR)
else:
    out('spawning ' + BUNDLE)
    pid = DEVICE.spawn([BUNDLE])
    session = DEVICE.attach(pid)
    script = session.create_script(src)
    script.on('message', on_msg)
    script.set_log_handler(on_log)
    script.load()
    DEVICE.resume(pid)
    out('resumed pid %d — collecting %ds' % (pid, DUR))

t0 = time.time()
while time.time() - t0 < DUR:
    try:
        alive = pid in [p.pid for p in DEVICE.enumerate_processes()]
    except Exception:
        alive = True
    if not alive:
        out('[driver] process exited at +%.1fs' % (time.time() - t0))
        break
    time.sleep(0.3)
out('[driver] done — log saved to %s' % LOGPATH)
_logf.close()
