const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { EventEmitter } = require('node:events');

test('preload exposes only transport methods and never passes IPC event to renderer', () => {
  const ipc = new EventEmitter(); const sent = [];
  ipc.send = (...args) => sent.push(args);
  let api;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../preload.js'), 'utf8'), { require: () => ({ contextBridge: { exposeInMainWorld(name, value) { assert.equal(name, 'tiasshNativeTransport'); api = value; } }, ipcRenderer: ipc }) });
  assert.throws(() => api.send({ type: 'execute', data: { _tag: 'x' } }), /unsupported/);
  api.send({ type: 'ssh-open', data: { _tag: 'x' } });
  assert.equal(sent[0][0], 'native-transport:send');
  const received = []; const unsubscribe = api.onEvent((...args) => received.push(args));
  ipc.emit('native-transport:event', { sender: 'secret' }, { type: 'ssh-ready', data: { _tag: 'x' } });
  assert.equal(received[0].length, 1);
  unsubscribe(); assert.equal(ipc.listenerCount('native-transport:event'), 0);
});

function loadPreload(ipc, window = {}) {
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../preload.js'), 'utf8'), {
    require(name) {
      assert.equal(name, 'electron');
      return { contextBridge: { exposeInMainWorld(name, api) { window[name] = api; } }, ipcRenderer: ipc };
    }
  });
  return window.tiasshNativeTransport;
}

function renderer(native = true, ipc = new EventEmitter()) {
  const sent = [], sockets = [];
  if (!ipc.send) ipc.send = (channel, message) => { if (channel === 'native-transport:send') sent.push(message); };
  function element() { return { value:'', style:{}, dataset:{}, classList:{ add(){}, remove(){}, toggle(){} }, addEventListener(){}, appendChild(){}, querySelector:element, querySelectorAll(){return [];}, remove(){} }; }
  const elements = new Map();
  const document = { getElementById(id){ if(!elements.has(id))elements.set(id,element());return elements.get(id); }, createElement:element, querySelector:element, querySelectorAll(){return [];}, body:element() };
  const location = { protocol:'file:', host:'', origin:'null', reload(){} };
  const window = { location, addEventListener(){} };
  if (native) window.tiasshNativeTransport = loadPreload(ipc, window);
  class WebSocket { constructor(){this.readyState=0;this.sent=[];sockets.push(this);} send(m){this.sent.push(JSON.parse(m));} close(){this.readyState=3;} }
  const context = vm.createContext({ window, document, location, navigator:{userAgent:'Desktop'}, localStorage:{getItem(){return null;},setItem(){},removeItem(){}}, WebSocket, TextEncoder, TextDecoder, Uint8Array, Blob, URL, crypto:require('node:crypto').webcrypto, atob, btoa, setTimeout(){return 1;},clearTimeout(){},fetch:async()=>({ok:true,json:async()=>({items:[]})}) });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8'),context);
  return {
    sent,
    sockets,
    ipc,
    run:code=>vm.runInContext(code,context),
    emit:m=>ipc.emit('native-transport:event', { sender: 'test' }, m)
  };
}

test('desktop offline shell and SFTP use native transport; WS recovery does not replace them', () => {
  const c = renderer();
  c.run("state.token='t'; state.issuedAt=Date.now()-1000; state.expiresAt=Date.now()+100000; state.offlineMode=true; state.nativeTransportActive=true; globalThis.output=[]; globalThis.rec={id:'x',host:{host:'host',user:'user'},term:{cols:80,rows:24,write(s){output.push(s);}},view:'sftp',sftp:{opened:false},sftpDiv:document.createElement('div')};state.tabs.set('x',rec);connectSsh(rec);ensureSftp(rec);");
  assert.deepEqual(c.sent.map(m=>m.type), ['ssh-open','sftp-open']);
  assert.deepEqual(c.sent.map(m=>m.data._tag), ['x','sf:x']);
  c.emit({type:'ssh-data',data:{_tag:'x',data:'YQ=='}});
  assert.equal(c.run('output.at(-1)'), 'a');
  c.emit({type:'sftp-ready',data:{_tag:'sf:x'}});
  assert.equal(c.sent.at(-1).type, 'sftp-op');
  c.run("state.offlineMode=false;openWs();");
  assert.equal(c.sent.filter(m=>m.type==='ssh-open').length,2);
  assert.equal(c.sent.filter(m=>m.type==='sftp-open').length,2);
  assert.equal(c.sockets.length, 0);
  c.run("wsSend({type:'ssh-close',data:{_tag:'x'}});wsSend({type:'sftp-close',data:{_tag:'sf:x'}});");
  assert.deepEqual(c.sent.slice(-2).map(m=>m.type), ['ssh-close','sftp-close']);
});

test('main rejects other windows and subframes, handles closeAll IPC, and disposes on reload', () => {
  const ipcMain = new EventEmitter(); const windows = []; let handled = 0, disposed = 0, transportOptions;
  class BrowserWindow extends EventEmitter {
    constructor(options) { super(); this.options = options; this.webContents = new EventEmitter(); this.webContents.mainFrame = { url: require('node:url').pathToFileURL(path.join(__dirname, '../web/index.html')).href }; this.webContents.send = () => {}; this.webContents.setWindowOpenHandler = () => {}; windows.push(this); }
    loadFile() {} isDestroyed() { return false; }
    static getAllWindows() { return windows; }
  }
  const app = new EventEmitter(); app.getPath = () => '/test/userData'; app.requestSingleInstanceLock = () => true; app.whenReady = () => ({ then(fn) { fn(); } });
  const electron = { app, BrowserWindow, Menu: { setApplicationMenu() {} }, ipcMain };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../main.js'), 'utf8'), { __dirname:path.join(__dirname,'..'), process, URL, require(name) { if(name==='electron')return electron; if(name==='path')return path; if(name==='ssh2')return { Client:class {} }; if(name==='./transport')return { CHANNELS:['ssh-open'], createTransport(options){transportOptions=options;return { handle(){handled++;},dispose(){disposed++;} };} }; } });
  const win = windows[0]; const message = {type:'ssh-open',data:{_tag:'x'}};
  ipcMain.emit('native-transport:send',{sender:{},senderFrame:{}},message);
  ipcMain.emit('native-transport:send',{sender:win.webContents,senderFrame:{}},message);
  assert.equal(handled,0);
  ipcMain.emit('native-transport:send',{sender:win.webContents,senderFrame:win.webContents.mainFrame},message);
  assert.equal(handled,1);
  assert.equal(transportOptions.pinStorePath, '/test/userData/ssh-host-pins.json');
  win.webContents.mainFrame.url = 'file:///untrusted.html';
  ipcMain.emit('native-transport:send',{sender:win.webContents,senderFrame:win.webContents.mainFrame},message);
  assert.equal(handled,1);
  win.webContents.mainFrame.url = 'https://evil.example/';
  ipcMain.emit('native-transport:send',{sender:win.webContents,senderFrame:win.webContents.mainFrame},message);
  assert.equal(handled,1);
  const ipc = new EventEmitter();
  ipc.send = (channel, ...args) => ipcMain.emit(channel, {sender:win.webContents,senderFrame:win.webContents.mainFrame}, ...args);
  const preload = loadPreload(ipc);
  assert.equal(typeof preload.closeAll, 'function');
  // Rejected callers and documents must never be able to dispose this window.
  ipcMain.emit('native-transport:close-all',{sender:{},senderFrame:win.webContents.mainFrame});
  ipcMain.emit('native-transport:close-all',{sender:win.webContents,senderFrame:{url:win.webContents.mainFrame.url}});
  assert.equal(disposed,0);
  // Trusted preload call returns Promise and disposes active sessions immediately.
  win.webContents.mainFrame.url = require('node:url').pathToFileURL(path.join(__dirname, '../web/index.html')).href;
  const completion = preload.closeAll();
  assert.equal(typeof completion.catch, 'function');
  assert.equal(disposed,1); // immediate session disposal, not window transport teardown
  // Channel remains live: user can login again and open a new session without recreating window.
  preload.send(message);
  assert.equal(handled,2);
  win.webContents.emit('did-start-navigation',{},'file:///index.html',false,true);
  assert.equal(disposed,2);
  assert.equal(win.options.webPreferences.nodeIntegration,false);
  assert.equal(win.options.webPreferences.contextIsolation,true);
  assert.equal(win.options.webPreferences.sandbox,true);
  let prevented = false;
  win.webContents.emit('will-navigate', { preventDefault(){prevented=true;} }, 'https://evil.example/');
  assert.equal(prevented,true);
  app.emit('before-quit');
  win.emit('closed');
  assert.equal(disposed,3);
  assert.equal(ipcMain.listenerCount('native-transport:send'),0);
  assert.equal(ipcMain.listenerCount('native-transport:close-all'),0);
});

function mainBridge() {
  const ipcMain = new EventEmitter(), ipc = new EventEmitter(), clients = [], windows = [];
  class Client extends EventEmitter {
    connect(config) { this.config = config; }
    end() { this.ended = true; this.emit('close'); }
  }
  class BrowserWindow extends EventEmitter {
    constructor() {
      super(); windows.push(this);
      this.webContents = new EventEmitter();
      this.webContents.mainFrame = { url: require('node:url').pathToFileURL(path.join(__dirname, '../web/index.html')).href };
      this.webContents.send = (channel, payload) => ipc.emit(channel, {}, payload);
      this.webContents.setWindowOpenHandler = () => {};
    }
    loadFile() {} isDestroyed() { return false; }
    static getAllWindows() { return windows; }
  }
  const app = new EventEmitter();
  app.getPath = () => process.env.TMPDIR; app.requestSingleInstanceLock = () => true;
  app.whenReady = () => ({ then(fn) { fn(); } });
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../main.js'), 'utf8'), {
    __dirname: path.join(__dirname, '..'), process, URL,
    require(name) {
      if (name === 'electron') return { app, BrowserWindow, ipcMain, Menu: { setApplicationMenu() {} } };
      if (name === 'path') return path;
      if (name === 'ssh2') return { Client: class extends Client { constructor() { super(); clients.push(this); } } };
      if (name === './transport') return require('../transport');
      throw new Error('unexpected module: ' + name);
    }
  });
  const win = windows[0];
  ipc.send = (channel, ...args) => ipcMain.emit(channel, { sender: win.webContents, senderFrame: win.webContents.mainFrame }, ...args);
  return { ipc, clients, win };
}

test('shared logout through actual preload and main immediately closes SSH and SFTP and permits login again', () => {
  const bridge = mainBridge(), c = renderer(true, bridge.ipc);
  c.run("state.token='t';state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()+100000;state.nativeTransportActive=true;wsSend({type:'ssh-open',data:{_tag:'x',host:'h',username:'u'}});wsSend({type:'sftp-open',data:{_tag:'sf:x',host:'h',username:'u'}});");
  assert.equal(bridge.clients.length, 2);
  assert.doesNotThrow(() => c.run('logoutSession()'));
  assert.ok(bridge.clients.every(client => client.ended));
  assert.equal(c.run('state.token'), null);
  c.run("state.token='new';state.wsStopped=false;state.nativeTransportActive=true;state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()+100000;wsSend({type:'ssh-open',data:{_tag:'new',host:'h',username:'u'}});");
  assert.equal(bridge.clients.length, 3);
  assert.equal(bridge.clients[2].ended, undefined);
  bridge.win.emit('closed');
});

test('native SSH and SFTP sends require token, running session, and valid lease even offline', () => {
  const c = renderer();
  for (const stateSetup of [
    "state.token=null;state.wsStopped=false;state.nativeTransportActive=true;state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()+100000;",
    "state.token='t';state.wsStopped=true;state.nativeTransportActive=true;",
    "state.token='t';state.wsStopped=false;state.nativeTransportActive=true;state.expiresAt=Date.now()-1;",
    "state.token='t';state.wsStopped=false;state.nativeTransportActive=true;state.issuedAt=null;state.expiresAt=null;"
  ]) {
    c.run(stateSetup + "wsSend({type:'ssh-open',data:{_tag:'x'}});wsSend({type:'sftp-op',data:{_tag:'sf:x'}});");
    assert.equal(c.sent.length, 0, stateSetup);
  }
  c.run("state.token='t';state.wsStopped=false;state.nativeTransportActive=true;state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()+100000;state.offlineMode=true;wsSend({type:'ssh-input',data:{_tag:'x'}});");
  assert.equal(c.sent.length, 1);
  c.run('logoutSession()');
  c.run("wsSend({type:'ssh-open',data:{_tag:'new'}});wsSend({type:'sftp-open',data:{_tag:'sf:new'}});");
  assert.equal(c.sent.length, 1);
});

test('native openWs does not mark an expired lease connected', () => {
  const c = renderer();
  c.run("state.token='t';state.issuedAt=Date.now()-1000;state.expiresAt=Date.now()-1;openWs();");
  assert.notEqual(c.run("$('syncText').textContent"), 'sync aktif');
  assert.equal(c.sent.length, 0);
});

test('browser without native bridge keeps WebSocket protocol', () => {
  const c = renderer(false);
  c.run("state.token='t';openWs();state.ws.readyState=1;wsSend({type:'ssh-open',data:{_tag:'x',host:'h',username:'u'}});");
  assert.equal(c.sockets[0].sent[0].type,'ssh-open');
});
