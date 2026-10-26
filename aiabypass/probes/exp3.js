'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
function mod(p){try{const m=Process.findModuleByAddress(p);return m?(m.name+'+0x'+p.sub(m.base).toString(16)):'?'}catch(e){return '?'}}
const sysctl=R('sysctl');
Interceptor.attach(sysctl,{onEnter(a){
  this.hit=false;
  try{
    if(mod(this.returnAddress).indexOf('JMCodeProtectKit')<0) return;
    this.hit=true; this.oldp=a[2]; this.oldlenp=a[3];
  }catch(e){}
},onLeave(r){
  if(!this.hit) return;
  try{ const n=this.oldlenp.readU64().toNumber(); if(n>0&&n<2048){
    const b=new Uint8Array(this.oldp.readByteArray(n));
    let hex=''; for(let i=0;i<Math.min(n,160);i++) hex+=('0'+b[i].toString(16)).slice(-2);
    send({m:'kinfo len='+n+' hex='+hex});
  }}catch(e){send({m:'dump err '+e})}
}});
