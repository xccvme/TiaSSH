const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
function client() {
 const messages=[], sockets=[], events={};
 function el(){return {value:'',style:{},dataset:{},classList:{add(){},remove(){},toggle(){}},addEventListener(){},appendChild(){},querySelector:el,querySelectorAll(){return []}};}
 const elements=new Map();const location={protocol:'https:',host:'localhost',origin:'https://localhost'};
 const bridge={available:true,onEvent(fn){events.listener=fn},send(m){messages.push(m);return Promise.resolve()},closeAll(){events.closed=true;return Promise.resolve()},addListener(name,fn){events.listener=fn;return {remove(){}}}};
 const context=vm.createContext({window:{location,tiasshNativeTransport:bridge,addEventListener(){}},location,document:{getElementById(id){if(!elements.has(id))elements.set(id,el());return elements.get(id)},createElement:el,querySelector:el,querySelectorAll(){return []}},localStorage:{getItem(){return null},setItem(){},removeItem(){}},navigator:{userAgent:'Android'},WebSocket:class{constructor(){sockets.push(this);this.readyState=0;}},TextEncoder,TextDecoder,Uint8Array,Blob,URL,crypto:require('node:crypto').webcrypto,atob,btoa,console,setTimeout(){return 1},clearTimeout(){},fetch:async()=>({ok:true,json:async()=>({items:[]})})});
 for(const file of ['vendor/sha256.js','vendor/aesjs.js','app.js'])vm.runInContext(fs.readFileSync(path.resolve(__dirname,'../web',file),'utf8'),context);
 return {messages,sockets,events,run:s=>vm.runInContext(s,context)};
}
test('Android client opens local SSH and SFTP without a ready websocket',()=>{
 const c=client();c.run("state.offlineMode=true;state.token='t';globalThis.rec={id:'h',host:{host:'localhost',user:'test',password:'p',auth:'password'},term:{cols:80,rows:24,write(){}},sftp:{opened:false},sftpDiv:document.createElement('div')};state.tabs.set('h',rec);connectSsh(rec);ensureSftp(rec)");
 assert.deepEqual(c.messages.map(m=>m.type),['ssh-open','sftp-open']);
 assert.equal(c.messages[1].data._tag,'sf:h');
 assert.equal(typeof c.events.listener,'function');
 c.events.listener({type:'ssh-ready',data:{_tag:'h'}});
 assert.match(c.run("document.getElementById('connText').textContent"), /connected/);
});
test('Logout closes native transport sessions',()=>{
 const c=client();c.run('logoutSession()');assert.equal(c.events.closed,true);
});
