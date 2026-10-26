'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
const m=Process.findModuleByName('JMCodeProtectKit');
function inJM(p){ try{ return p.compare(m.base)>=0 && p.compare(m.base.add(m.size))<0; }catch(e){return false;} }
function S(p){try{return p.readCString()}catch(e){return ''}}
// block fopen of the main executable if caller is RASP
const fp=R('fopen');
const orig=new NativeFunction(fp,'pointer',['pointer','pointer']);
const stub=new NativeCallback(function(path,mode){
  const ra=this.returnAddress;
  let s=''; try{s=path.readCString()}catch(e){}
  if(inJM(ra) && s && s.indexOf('KYHAppStore.app/KYHAppStore')>=0){
    send({m:'fopen(main) BLOCKED from +0x'+ra.sub(m.base).toString(16)});
    return ptr(0);
  }
  return orig(path,mode);
},'pointer',['pointer','pointer']);
Interceptor.replace(fp,stub);
// block open of the main executable if caller is RASP
const op=R('open');
const origO=new NativeFunction(op,'int',['pointer','int','int']);
const stubO=new NativeCallback(function(path,flags,mode){
  const ra=this.returnAddress;
  let s=''; try{s=path.readCString()}catch(e){}
  if(inJM(ra) && s && s.indexOf('KYHAppStore.app/KYHAppStore')>=0){
    send({m:'open(main) BLOCKED from +0x'+ra.sub(m.base).toString(16)});
    return -1;
  }
  return origO(path,flags,mode);
},'int',['pointer','int','int']);
Interceptor.replace(op,stubO);
send({m:'ready'});
