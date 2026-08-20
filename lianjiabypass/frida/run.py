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

with open(os.path.join(HERE, 'probe.js')) as f:
    src = f.read()

def on_msg(msg, data):
    if msg['type'] == 'send':
        out(str(msg['payload']))
    elif msg['type'] == 'error':
        out('[ERROR] ' + str(msg.get('stack') or msg.get('description')))

def on_log(level, text):
    out(text)

out('=== attempt %d / bundle %s / dur %ds ===' % (ATTEMPT, BUNDLE, DUR))
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
