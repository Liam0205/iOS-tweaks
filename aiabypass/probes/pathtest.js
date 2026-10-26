const cands=['/var/mobile/Containers/Data/Application/A7D7B11F-8AAF-47E1-8DC7-F86B81B50CFA/Documents/aia_probe.log',
             '/var/mobile/Containers/Data/Application/A7D7B11F-8AAF-47E1-8DC7-F86B81B50CFA/tmp/aia_probe.log',
             '/var/mobile/Library/Caches/aia_probe.log',
             '/var/tmp/aia_probe.log'];
for (const p of cands){
  try { const f=new File(p,'a'); f.write('x\n'); f.flush(); f.close(); send({m:'OK '+p}); }
  catch(e){ send({m:'FAIL '+p+' : '+e}); }
}
