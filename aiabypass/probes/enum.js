'use strict';
function log(s){send({m:s})}
function clsList(){
  const out=[];
  // enumerate objc classes via objc_getClassList
  const R=(n)=>{try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}};
  const getList=R('objc_getClassList');
  const buf=Memory.alloc(4*20000);
  const n=new NativeFunction(getList,'int',['pointer','int'])(buf,20000);
  const clsArr=buf.readPointer;
  const class_getName=new NativeFunction(R('class_getName'),'pointer',['pointer']);
  const class_copyMethodList=new NativeFunction(R('class_copyMethodList'),'pointer',['pointer','pointer']);
  const method_getName=new NativeFunction(R('method_getName'),'pointer',['pointer']);
  const sel_getName=R('sel_getName');
  const selname=new NativeFunction(sel_getName,'pointer',['pointer']);
  const class_getSuperclass=new NativeFunction(R('class_getSuperclass'),'pointer',['pointer']);
  let cnt=0;
  for(let i=0;i<n;i++){
    const c=clsArr.call(buf,i*Process.pointerSize);
    const nm=class_getName(c).readCString();
    if(!nm) continue;
    const sup=class_getSuperclass(c);
    const supn=sup.isNull()?'':class_getName(sup).readCString();
    if(/^(JM|MPISD|MPIDRS|JMCedar|JMRiver|JMWillow|JMHarbor|JMMaple)/.test(nm) || (supn&&/^JM/.test(supn))){
      cnt++;
      log('CLASS '+nm+' : '+(supn||'-'));
      const pcnt=Memory.alloc(4);
      const ml=class_copyMethodList(c,pcnt);
      const mc=pcnt.readS32();
      for(let j=0;j<mc;j++){
        const m=ml.add(j*Process.pointerSize).readPointer();
        log('   - '+selname(method_getName(m)).readCString());
      }
    }
  }
  log('matched '+cnt+' classes, total '+n);
}
setTimeout(function(){ try{ log('enum start'); clsList(); }catch(e){ log('enum err '+e+' '+e.stack); } }, 30);
