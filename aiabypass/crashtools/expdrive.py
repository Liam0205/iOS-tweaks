import frida,time,sys
dev=frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid=dev.spawn(["com.aia.china.YoubangHealthRelease"])
s=dev.attach(pid); sc=s.create_script(open(sys.argv[1]).read())
sc.on("message", lambda m,d: print(str(m)[:200]))
sc.load(); dev.resume(pid)
t0=time.time(); last=0
while time.time()-t0<8:
    time.sleep(0.25)
    procs=[p for p in dev.enumerate_processes() if p.pid==pid]
    if not procs:
        print("GONE at %.2f"%(time.time()-t0)); sys.exit(0)
    last=time.time()-t0
print("SURVIVED %.1fs"%last)
try: dev.kill(pid)
except Exception: pass
