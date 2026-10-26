import sys, time, json
import frida

BID = "com.aia.china.YoubangHealthRelease"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/var/tmp/aia/probe.log"
WAIT = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid = dev.spawn([BID])
print("spawned pid", pid)
sess = dev.attach(pid)
script = sess.create_script(open("/var/tmp/aia/probe.js").read())
out = open(OUT, "w", encoding="utf-8")

def on_msg(msg, data):
    if msg["type"] == "send":
        p = msg["payload"]
        line = "[%s] %s" % (p.get("t", ""), p.get("m", ""))
        print(line)
        out.write(line + "\n"); out.flush()
    else:
        print("ERR", msg)
        out.write("ERR %s\n" % msg); out.flush()

script.on("message", on_msg)
script.load()
dev.resume(pid)
t0 = time.time()
while time.time() - t0 < WAIT:
    time.sleep(0.2)
    try:
        if not dev.get_process(pid):
            print("process gone after %.2fs" % (time.time() - t0)); out.write("process gone\n"); break
    except Exception:
        print("process gone (exc) after %.2fs" % (time.time() - t0)); out.write("process gone\n"); break
try:
    sess.detach()
except Exception:
    pass
out.close()
