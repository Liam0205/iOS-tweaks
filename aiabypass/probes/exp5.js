'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
const m=Process.findModuleByName('JMCodeProtectKit');
function inJM(p){ try{ return p.compare(m.base)>=0 && p.compare(m.base.add(m.size))<0; }catch(e){return false;} }
const pc=R('pthread_create');
const orig=new NativeFunction(pc,'int',['pointer','pointer','pointer','pointer']);
const stub=new NativeCallback(function(t,a,s,arg){
  const ra=this.returnAddress;
  if(inJM(ra)){ send({m:'VM thread create BLOCKED from +0x'+ra.sub(m.base).toString(16)}); return -11; }
  return orig(t,a,s,arg);
},'int',['pointer','pointer','pointer','pointer']);
Interceptor.replace(pc,stub);
send({m:'pthread_create replaced'});
