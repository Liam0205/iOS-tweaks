'use strict';
function R(n){try{return Module.getGlobalExportByName(n)}catch(e){try{return Module.getExportByName(null,n)}catch(e2){return null}}}
const p=R('_dyld_register_func_for_add_image');
const noop=new NativeCallback(function(fn){ send({m:'add_image suppressed fn='+fn}); },'void',['pointer']);
Interceptor.replace(p,noop);
send({m:'replace installed'});
