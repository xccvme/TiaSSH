const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
// The client is a browser script with immediate DOM handlers, not a module.
// A minimal DOM/network boundary runs the actual unmodified script in a VM.
function client() {
  const elements = new Map(), storage = new Map(), timers = new Map(), sockets = [];
  let nextTimer = 1;
  function element() { return { value: '', style: {}, dataset: {}, textContent: '', innerHTML: '', classList: {add(){},remove(){},toggle(){},contains(){return false;}}, addEventListener(){}, appendChild(){}, remove(){}, click(){}, querySelector(){return element();}, querySelectorAll(){return [];} }; }
  const document = { getElementById(id){if(!elements.has(id))elements.set(id,element());return elements.get(id);}, createElement: element, querySelector: element, querySelectorAll(){return [];}, body: element() };
  class WebSocket { constructor(url){this.url=url;this.readyState=0;this.sent=[];sockets.push(this);} send(s){this.sent.push(JSON.parse(s));} close(){this.readyState=3;} }
  const location = { protocol:'https:', host:'localhost', origin:'https://localhost', reload(){} };
  const context = vm.createContext({ document, location, window:{location,addEventListener(){}}, navigator:{userAgent:'Android'}, localStorage:{getItem(k){return storage.get(k)||null;},setItem(k,v){storage.set(k,String(v));},removeItem(k){storage.delete(k);}}, WebSocket, TextEncoder, TextDecoder, Uint8Array, Blob, URL, crypto:require('node:crypto').webcrypto, atob, btoa, console, setTimeout(fn,ms){const id=nextTimer++;timers.set(id,{fn,ms});return id;}, clearTimeout(id){timers.delete(id);}, fetch:async()=>({ok:true,json:async()=>({items:[],serverTime:1})}), prompt(){return null;} });
  for(const file of ['vendor/sha256.js','vendor/aesjs.js','app.js']) vm.runInContext(fs.readFileSync(path.join(root,'web',file),'utf8'),context,{filename:file});
  return { context, elements, storage, timers, sockets, run(code){return vm.runInContext(code,context);}, tick(ms){for(const [id,t] of [...timers])if(t.ms<=ms){timers.delete(id);t.fn();}} };
}
test('SSH opens made before WS readiness are restored exactly once on open',()=>{
  const c=client(); c.run("state.token='token'; state.tabs.set('h1',{id:'h1',host:{host:'example',user:'root'},term:{cols:80,rows:24,write(){}},sftp:{opened:false},view:'term'}); openWs(); connectSsh(state.tabs.get('h1'));");
  assert.equal(c.sockets[0].sent.length,0);
  c.sockets[0].readyState=1; c.sockets[0].onopen();
  assert.equal(c.sockets[0].sent.filter(m=>m.type==='ssh-open').length,1);
});
test('SSH and SFTP use separate routing tags to avoid map overwrite',()=>{
  const c=client();
  c.run("state.token='token'; const h={id:'h1',host:'example',user:'root',port:22,auth:'password',password:'x'}; state.tabs.set('h1',{id:'h1',host:h,term:{cols:80,rows:24,write(){}},sftp:{opened:false},view:'sftp',sftpDiv:document.createElement('div'),_sftpOpened:false}); openWs(); state.ws.readyState=1; state.ws.onopen();");
  const sent=c.sockets[0].sent;
  const sshOpen=sent.find(m=>m.type==='ssh-open');
  const sftpOpen=sent.find(m=>m.type==='sftp-open');
  assert.equal(sshOpen.data._tag,'h1');
  assert.equal(sftpOpen.data._tag,'sf:h1');
});
test('SFTP waits for ready before listing and routes only the matching tab',()=>{
  const c=client(); c.run("state.token='token'; openWs(); state.ws.readyState=1; const r={id:'h1',host:{host:'x',user:'root'},sftp:{opened:false},sftpDiv:document.createElement('div')}; state.tabs.set('h1',r); ensureSftp(r);");
  c.tick(1200);
  assert.equal(c.sockets[0].sent.filter(m=>m.type==='sftp-op').length,0);
  c.run("onWsMessage({data:JSON.stringify({type:'sftp-ready',data:{_tag:'sf:h1'}})});");
  assert.equal(c.sockets[0].sent.filter(m=>m.type==='sftp-op').length,1);
  c.run("onWsMessage({data:JSON.stringify({type:'ssh-error',data:{_tag:'missing',error:'oops'}})});");
});
test('uploads send one chunk at a time and resolve only after final acknowledgment',async()=>{
  const c=client(); c.context.FileReader=class { readAsDataURL(){this.result='data:application/octet-stream;base64,YQ==';this.onload();} };
  c.run("state.token='t';openWs();state.ws.readyState=1;globalThis.r={id:'h',sftp:{cwd:'/'},$sf:{foot:{}}}; state.tabs.set('h',r);");
  let done=false;const upload=c.run("sftpUpload(r,{name:'x',size:524289,slice(){return new Blob(['a']);}})").then(()=>{done=true;});
  await new Promise(setImmediate);
  assert.equal(c.sockets[0].sent.length,1);assert.equal(done,false);
  c.run("routeMsg(r,{type:'sftp-ok',data:{path:'/x'}})"); await new Promise(setImmediate);
  assert.equal(c.sockets[0].sent.length,2);assert.equal(done,false);
  c.run("routeMsg(r,{type:'sftp-ok',data:{path:'/x'}})");await upload;assert.equal(c.run('r._up'),null);
});
test('WebSocket reconnect uses bounded backoff and reports actionable status',()=>{
  const c=client();
  c.run("state.token='t'; openWs(); state.ws.onclose({code:1006,reason:'net'});");
  const delays=[...c.timers.values()].map(t=>t.ms);
  assert.equal(delays.length,1);
  assert.equal(delays[0],1000);
  c.tick(1000); c.run("state.ws.onclose({code:1006,reason:'net2'});");
  const delays2=[...c.timers.values()].map(t=>t.ms);
  assert.equal(delays2[0],2000);
});
test('SFTP timed out operation clears callback and poisons channel until reopened',async()=>{
  const c=client();c.run("state.token='t';openWs();state.ws.readyState=1;globalThis.r={id:'h',sftp:{opened:true},$sf:{foot:{}}};");
  const result=c.run("sftpOp(r,{op:'mkdir',path:'/x'})"); c.tick(15000);
  assert.equal(await result,false);assert.equal(c.run('r._sftpPending'),null);
  assert.equal(c.run('r.sftp.opened'),false);
});
test('download chunks are base64-decoded per chunk (padding-safe)',()=>{
  const c=client();
  const out=c.run("bytesToB64(decodeB64Chunks(['YQ==','Yg==']))");
  assert.equal(out,'YWI=');
});
test('logout stops reconnect loop and clears ws retry timer',()=>{
  const c=client();
  c.run("state.token='t'; openWs(); state.ws.onclose({code:1006});");
  assert.equal(c.timers.size,1);
  // Logout manual kini lewat dialog konfirmasi (anti klik-tak-sengaja).
  c.run("$('logoutBtn').onclick()");
  assert.equal(c.timers.size,1); // belum keluar sebelum dikonfirmasi
  c.run("$('cxOk').onclick()");
  assert.equal(c.timers.size,0);
  assert.equal(c.run('state.wsStopped'),true);
});

test('logout confirm cancel does not log out',()=>{
  const c=client();
  c.run("state.token='t'; openWs(); state.ws.onclose({code:1006});");
  assert.equal(c.timers.size,1);
  c.run("$('logoutBtn').onclick()");
  c.run("$('cxCancel').onclick()");
  assert.equal(c.timers.size,1); // batal -> sesi & retry timer tetap ada
  assert.equal(c.run('state.wsStopped'),false);
});

test('offline mode toggles host-write button disabled state',()=>{
  const c=client();
  c.run("setOfflineMode(true)");
  assert.equal(c.run("$('addHostBtn').disabled"), true);
  c.run("setOfflineMode(false)");
  assert.equal(c.run("$('addHostBtn').disabled"), false);
});

test('websocket close while lease valid enters offline read-only mode',()=>{
  const c=client();
  const now=Date.now();
  c.context.now = now;
  c.run("state.token='t'; state.issuedAt=now-1000; state.expiresAt=now+100000; state.key={}; openWs(); state.ws.onclose({code:1006});");
  assert.equal(c.run('state.offlineMode'), true);
  assert.equal(c.run('state.readOnly'), true);
});

test('host add modal does not open while read-only',()=>{
  const c=client();
  c.run("$('modal').innerHTML='sentinel'; state.readOnly=true; hostModal(null);");
  assert.equal(c.run("$('modal').innerHTML"), 'sentinel');
});
test('Android secure local WebView explicitly permits self-hosted cleartext mixed content',()=>{
  const config=JSON.parse(fs.readFileSync(path.join(root,'android/capacitor.config.json')));
  assert.equal(config.server.androidScheme,'https');
  assert.equal(config.android.allowMixedContent,true);
});
test('Android backup is disabled in manifest',()=>{
  const manifest=fs.readFileSync(path.join(root,'android/android/app/src/main/AndroidManifest.xml'),'utf8');
  assert.match(manifest,/android:allowBackup=\"false\"/);
});
test('recovery leaves writes locked while complete snapshot request is pending',async()=>{
  const c=client(); let release;
  c.context.fetch=async url=>({ok:true,json:async()=>url.endsWith('/api/me')?c.run('({email:state.email,salt:state.salt,issuedAt:state.issuedAt,expiresAt:state.expiresAt})'):new Promise(r=>release=r)});
  c.run("state.token='t';state.email='u@e';state.salt='salt';state.key={};state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()+100000;setOfflineMode(true)");
  const pending=c.run('recoverOnlineIfPossible()');await new Promise(setImmediate);
  assert.equal(c.run('state.readOnly'),true); assert.equal(c.run('state.offlineMode'),true);
  release({items:[],serverTime:1}); assert.equal(await pending,true);
});
test('snapshot response pending at logout cannot resurrect hosts or cache',async()=>{
 const c=client();let release;
 c.context.fetch=()=>new Promise(r=>release=r);
 c.run("state.token='t';state.key={};state.hosts.set('h',{id:'h'});");
 const p=c.run('pullSnapshot()'); c.run('logoutSession()');
 release({ok:true,json:async()=>({items:[],serverTime:5})});await p.catch(()=>{});
 assert.equal(c.storage.has('tiassh_snapshot_cache'),false);assert.equal(c.run('state.lastSync'),0);
});
test('native auth screen has no register button and gives web signup guidance',()=>{
  const html=fs.readFileSync(path.join(root,'web/index.html'),'utf8');
  assert.equal(html.includes('id="authRegBtn"'),false);
  assert.match(html,/\/api\/web\/register|web signup|daftar lewat web/i);
});
