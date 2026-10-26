import frida,time,sys
BID="com.aia.china.YoubangHealthRelease"
dev=frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid=dev.spawn([BID])
s=dev.attach(pid)
sc=s.create_script(open("/var/tmp/aia/probe3.js").read())
sc.on("message", lambda m,d: print("MSG",str(m)[:300]))
sc.load()
print("script loaded, resuming pid",pid)
dev.resume(pid)
time.sleep(6)
print("done sleeping")
