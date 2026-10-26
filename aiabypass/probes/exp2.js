'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
function mod(p){try{const m=Process.findModuleByAddress(p);return m?(m.name+'+0x'+p.sub(m.base).toString(16)):'?'}catch(e){return '?'}}
const sysctl=R('sysctl');
Interceptor.attach(sysctl,{onEnter(a){
  const c=this.returnAddress;
  try{
    this.caller=mod(c);
    if(this.caller.indexOf('JMCodeProtectKit')<0) return;
    const name=a[0], namelen=a[1].toInt32(), oldp=a[2], oldlenp=a[3];
    let mib=[];
    for(let i=0;i<namelen;i++) mib.push(name.add(i*4).readS32());
    let len=null; try{ len=oldlenp.readU64().toNumber(); }catch(e){}
    send({m:'sysctl mib=['+mib.join(',')+'] namelen='+namelen+' oldp='+oldp+' len='+len+' caller='+this.caller});
    this.oldp=oldp; this.oldlenp=oldlenp; this.mib=mib; this.logged=true;
  }catch(e){ send({m:'sysctl err '+e}); }
},onLeave(r){
  if(!this.logged) return;
  try{
    const n=this.oldlenp.readU64().toNumber();
    let bytes=''; if(n>0&&n<256) bytes=this.oldp.readByteArray(n);
    send({m:'sysctl ret='+r+' outlen='+n+' out='+bytes});
  }catch(e){ send({m:'leave err '+e}); }
}});
const dlsym=R('dlsym');
Interceptor.attach(dlsym,{onEnter(a){this.n=a[1].readCString();this.c=mod(this.returnAddress)},onLeave(r){ if(this.n&&this.n.length<40) send({m:'dlsym("'+this.n+'")='+r+' <- '+this.c});}});
