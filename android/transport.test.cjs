const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const file = require('node:path').resolve(__dirname, '../web/android-transport.js');
const javaFile = require('node:path').resolve(__dirname, 'android/app/src/main/java/com/tiassh/app/SshTransportPlugin.java');
const java = () => fs.readFileSync(javaFile, 'utf8');
test('Java logout fences queued work and disconnects pending connects without command queue', () => {
 const src = java();
 const closeAll = src.slice(src.indexOf('public void closeAll('), src.indexOf('private void handleSend('));
 assert.doesNotMatch(closeAll, /commandExecutor\.execute/);
 assert.match(src, /generation\+\+/);
 assert.match(src, /pendingSessions\.put\(tag, session\)/);
 assert.match(src, /requireCurrent\(work\);\s*session\.connect/);
 assert.match(src, /session\.connect\(SSH_CONNECT_TIMEOUT_MS\)/);
 assert.match(src, /if \(isCurrent\(work\)\) notifyListeners/);
 assert.match(src, /destroyed = true/);
});
test('Java offset writes account for JSch RESUME adding existing size', () => {
 const src = java();
 assert.match(src, /long existingSize = sftp\.lstat\(path\)\.getSize\(\)/);
 assert.match(src, /long resumeDelta = start - existingSize/);
 assert.match(src, /ChannelSftp\.RESUME, resumeDelta/);
 assert.doesNotMatch(src, /ChannelSftp\.OVERWRITE, start/);
});
test('Java emits under generation fence and validates malformed operations', () => {
 const src = java();
 assert.match(src, /if \(isCurrent\(work\)\) notifyListeners/);
 assert.match(src, /if \(op\.isEmpty\(\)\) \{/);
 assert.match(src, /op required/);
 assert.match(src, /rename target required/);
 assert.match(src, /invalid read range/);
 assert.match(src, /invalid write offset/);
});
test('Java validates tag length, path length, SSH input size, SFTP payload size, read window', () => {
 const src = java();
 assert.match(src, /MAX_TAG_LEN.*256/);
 assert.match(src, /MAX_PATH_LEN.*4096/);
 assert.match(src, /MAX_SSH_INPUT_BYTES.*256.*1024/);
 assert.match(src, /MAX_SFTP_WRITE_BYTES.*2.*1024.*1024/);
 assert.match(src, /MAX_SFTP_READ_WINDOW.*128.*1024.*1024/);
 assert.match(src, /tag\.length\(\) > MAX_TAG_LEN/);
 assert.match(src, /path\.length\(\) > MAX_PATH_LEN/);
 assert.match(src, /decodeBase64.*MAX_SSH_INPUT_BYTES/);
 assert.match(src, /decodeBase64.*MAX_SFTP_WRITE_BYTES/);
 assert.match(src, /end - start > MAX_SFTP_READ_WINDOW/);
});
test('Android bridge waits for listener and sends contract without websocket', async () => {
 const calls = []; let listener;
 const plugin = { addListener: async (name, fn) => { assert.equal(name,'transportEvent'); listener=fn; return {remove(){}}; }, open: async m=>calls.push(['open',m]), send: async m=>calls.push(['send',m]), close: async m=>calls.push(['close',m]), closeAll: async ()=>calls.push(['closeAll']) };
 const window={Capacitor:{getPlatform:()=> 'android',registerPlugin:name=>{assert.equal(name,'SshTransport');return plugin;}}};
 assert.ok(fs.existsSync(file), 'Android transport adapter is implemented');
 vm.runInNewContext(fs.readFileSync(file,'utf8'), {window});
 const bridge=window.tiasshNativeTransport;
 const events=[]; bridge.onEvent(m=>events.push(m));
 const message={type:'ssh-open',data:{_tag:'h',host:'localhost',username:'test'}};
 await bridge.send(message); await bridge.send({type:'ssh-input',data:{_tag:'h',data:'YQ=='}}); await bridge.send({type:'sftp-close',data:{_tag:'sf:h'}});
 assert.deepEqual(calls.map(c=>c[0]),['open','send','close']); assert.equal(calls[0][1],message);
 const event={type:'ssh-ready',data:{_tag:'h'}};listener(event); assert.equal(events[0],event);
 await bridge.closeAll(); assert.equal(calls.at(-1)[0],'closeAll');
});
test('closeAll fences sends waiting for listener registration', async () => {
 let ready; const calls=[];
 const plugin={addListener:()=>new Promise(r=>ready=r),open:async m=>calls.push(m),closeAll:async()=>{}};
 const window={Capacitor:{getPlatform:()=> 'android',registerPlugin:()=>plugin}};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{window});
 const bridge=window.tiasshNativeTransport;
 const pending=bridge.send({type:'ssh-open',data:{_tag:'h'}});
 await bridge.closeAll(); ready({remove(){}});
 await assert.rejects(pending,/closed|cancel/i);
 assert.equal(calls.length,0);
});
test('Android bridge falls back to Capacitor.Plugins when registerPlugin is unavailable', async () => {
 const calls = [];
 const plugin = {
  addListener: (_name, fn) => ({ remove() {}, _fn: fn }),  // Sync return, not Promise
  send: async (m) => calls.push(m),
  closeAll: async () => calls.push({ type: 'closeAll' })
 };
 const window = { Capacitor: { getPlatform: () => 'android', registerPlugin: undefined, Plugins: { SshTransport: plugin } } };
 vm.runInNewContext(fs.readFileSync(file,'utf8'), {window});
 assert.equal(typeof window.tiasshNativeTransport, 'object');
 await window.tiasshNativeTransport.send({ type: 'ssh-input', data: { _tag: 'x', data: 'YQ==' } });
 await window.tiasshNativeTransport.closeAll();
 assert.equal(calls[0].type, 'ssh-input');
 assert.equal(calls[1].type, 'closeAll');
});


test('Browser does not acquire native capabilities',()=>{
 const window={}; assert.ok(fs.existsSync(file),'adapter exists');
 vm.runInNewContext(fs.readFileSync(file,'utf8'), {window}); assert.equal(window.tiasshNativeTransport,undefined);
});
