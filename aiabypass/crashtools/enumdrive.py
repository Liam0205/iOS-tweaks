import frida,time
dev=frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid=dev.spawn(["com.aia.china.YoubangHealthRelease"])
s=dev.attach(pid); sc=s.create_script(open("/var/tmp/aia/enum.js").read())
sc.on("message", lambda m,d: print(m["payload"]["m"] if m.get("type")=="send" else m))
sc.load(); print("loaded"); dev.resume(pid); time.sleep(4)
