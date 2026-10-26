'use strict';
const m=Process.findModuleByName('JMCodeProtectKit');
send({m:'base='+m.base});
const addr=m.base.add(0x155028);
const stub=new NativeCallback(function(){ send({m:'pthread_create wrapper blocked'}); return -22; },'int',['pointer','pointer','pointer','pointer']);
Interceptor.replace(addr,stub);
send({m:'replaced 0x155028'});
