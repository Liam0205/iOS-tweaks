import frida,time
dev=frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid=dev.spawn(["com.aia.china.YoubangHealthRelease"])
s=dev.attach(pid); sc=s.create_script(open("/var/tmp/aia/probe5.js").read())
sc.on("message", lambda m,d: print(str(m)[:400]))
sc.load(); dev.resume(pid); time.sleep(3)
