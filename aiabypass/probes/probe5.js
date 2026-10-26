'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
function log(s){send({m:s})}
const fopen=R('fopen');
Interceptor.attach(fopen,{onEnter(a){
  const p=a[0];
  let info='ptr='+p+' null='+p.isNull();
  try{ const r=Process.findRangeByAddress(p); info+=' range='+(r?r.base+'+0x'+r.size.toString(16):'none'); }catch(e){info+=' rangeerr';}
  try{ info+=' bytes='+p.readByteArray(24); }catch(e){info+=' byteserr:'+e;}
  try{ info+=' utf8='+p.readUtf8String(); }catch(e){ info+=' utf8err:'+e; }
  try{ info+=' cstr='+p.readCString(); }catch(e){ info+=' cstrerr:'+e; }
  log('fopen '+info);
}});
const open_=R('open');
Interceptor.attach(open_,{onEnter(a){
  const p=a[0];
  let info='ptr='+p;
  try{ info+=' utf8='+p.readUtf8String(256); }catch(e){ info+=' utf8err:'+e; }
  log('open '+info);
}});
