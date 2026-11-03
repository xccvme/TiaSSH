'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const sec = require('../account-security');

let child;
let dir;
let base;
let db;
let token;

const email = 'review@example.test';
const password = 'Review-test-password-123!';

async function api(url, opts = {}) {
  const response = await fetch(base + url, {
    method: opts.method || (opts.body ? 'POST' : 'GET'),
    headers: {
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data, cookie: response.headers.get('set-cookie'), cacheControl: response.headers.get('cache-control') };
}

function auth() {
  return { Authorization: `Bearer ${token}` };
}

async function pushItems(items) {
  const res = await api('/api/sync/push', { method: 'POST', body: { items }, headers: auth() });
  assert.equal(res.status, 200);
  return res;
}

test.before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'security-review-'));
  const port = String(24000 + Math.floor(Math.random() * 2000));
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      DATA_DIR: dir,
      PORT: port,
      PUBLIC_URL: `https://portal.example.test:${port}`,
      WEB_ORIGIN: `https://portal.example.test:${port}`,
      NATIVE_ORIGINS: '', // Exercise defaults, regardless of the caller's env.
    },
  });

  let output = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(output)), 10000);
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.includes('listening on 0.0.0.0')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.once('exit', (code) => reject(new Error(`exit ${code}: ${output}`)));
  });

  base = `http://127.0.0.1:${port}`;
  db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  db.prepare('INSERT INTO users(email,pass_hash,salt,totp_secret,last_otp,auth_revision) VALUES(?,?,?,?,?,?)')
    .run(email, bcrypt.hashSync(password, 8), 'fixed-salt', sec.base32(Buffer.alloc(20, 3)), -1, 1);
  token = sec.issueSession(db, 1, 'client');
});

test.after(() => {
  db?.close();
  child?.kill();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('browser origin cannot mint a password-only native token', async () => {
  const login = await api('/api/login', {
    method: 'POST',
    body: { email, password },
    headers: { Origin: `https://portal.example.test:${base.split(':').pop()}` },
  });
  assert.equal(login.status, 403);
});

test('default native origins allow Electron/Capacitor headers while portal origin is denied', async () => {
  const allowed = ['tauri://localhost', 'null', 'https://localhost', 'http://localhost'];
  for (const origin of allowed) {
    const login = await api('/api/login', { method: 'POST', body: { email, password }, headers: { Origin: origin } });
    assert.equal(login.status, 200, origin);
    assert.ok(login.data.token, origin);
  }

  const denied = await api('/api/login', {
    method: 'POST',
    body: { email, password },
    headers: { Origin: `https://portal.example.test:${base.split(':').pop()}` },
  });
  assert.equal(denied.status, 403);
});

test('sync HTTP and WS accept native origins but reject portal origin', { timeout: 10000 }, async () => {
  const seed = await api('/api/login', { method: 'POST', body: { email, password }, headers: { Origin: 'null' } });
  assert.equal(seed.status, 200);
  const nativeToken = seed.data.token;

  for (const origin of ['null', 'https://localhost', 'http://localhost']) {
    const preflight = await fetch(base + '/api/sync/push', {
      method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'Authorization,Content-Type' },
    });
    assert.equal(preflight.status, 204, origin);
    assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
    const pull = await api('/api/sync/pull?since=0', { headers: { Authorization: `Bearer ${nativeToken}`, Origin: origin } });
    assert.equal(pull.status, 200, origin);
    assert.equal((await api('/api/sync/snapshot', { headers: { Authorization: `Bearer ${nativeToken}`, Origin: origin } })).status, 200, origin);
    assert.equal((await api('/api/sync/push', { body: { items: [] }, headers: { Authorization: `Bearer ${nativeToken}`, Origin: origin } })).status, 200, origin);

    const ws = new WebSocket(`${base.replace('http', 'ws')}/ws?token=${encodeURIComponent(nativeToken)}`, { origin });
    try {
      // Upgrade alone is not acceptance: denied origins also upgrade then close.
      const reply = await new Promise((resolve, reject) => {
        ws.once('error', reject);
        ws.once('close', () => reject(new Error(`native socket rejected: ${origin}`)));
        ws.once('message', msg => resolve(JSON.parse(msg)));
        ws.once('open', () => ws.send(JSON.stringify({ type: 'ssh-open', data: { _tag: 'origin-check' } })));
      });
      assert.equal(reply.type, 'ssh-error');
      assert.equal(reply.data._tag, 'origin-check');
      assert.equal(reply.data.error, 'host+username required');
    } finally { ws.terminate(); }
  }

  const portalOrigin = `https://portal.example.test:${base.split(':').pop()}`;
  const forbiddenPull = await api('/api/sync/pull?since=0', { headers: { Authorization: `Bearer ${nativeToken}`, Origin: portalOrigin } });
  assert.equal(forbiddenPull.status, 403);
  assert.equal((await api('/api/sync/snapshot', { headers: { ...auth(), Origin: portalOrigin } })).status, 403);
  assert.equal((await api('/api/sync/push', { body: { items: [] }, headers: { ...auth(), Origin: portalOrigin } })).status, 403);

  const deniedWs = new WebSocket(`${base.replace('http', 'ws')}/ws?token=${encodeURIComponent(nativeToken)}`, { origin: portalOrigin });
  const closeCode = await new Promise((resolve) => {
    deniedWs.once('close', (code) => resolve(code));
    deniedWs.once('error', () => resolve(1006));
  });
  assert.equal(closeCode, 1008);
});

test('pull includes deletion tombstones while snapshot excludes them', async () => {
  await pushItems([{ category: 'hosts', key: 'deleted-host', value: null }]);

  const pull = await api('/api/sync/pull?since=0', { headers: auth() });
  assert.equal(pull.status, 200);
  assert.deepEqual(pull.data.items.map((item) => [item.key, item.value]), [['deleted-host', null]]);

  const snapshot = await api('/api/sync/snapshot', { headers: auth() });
  assert.equal(snapshot.status, 200);
  assert.equal(snapshot.data.items.some((item) => item.key === 'deleted-host'), false);
});

test('cursor pagination does not drop items beyond first page', async () => {
  const batch1 = Array.from({ length: 500 }, (_, idx) => ({
    category: 'hosts',
    key: `bulk-${String(idx).padStart(3, '0')}`,
    value: Buffer.from(`v-${idx}`).toString('base64'),
  }));
  const batch2 = Array.from({ length: 120 }, (_, idx) => ({
    category: 'hosts',
    key: `bulk-${String(idx + 500).padStart(3, '0')}`,
    value: Buffer.from(`v-${idx + 500}`).toString('base64'),
  }));
  await pushItems(batch1);
  await pushItems(batch2);

  const first = await api('/api/sync/pull?since=0&limit=500', { headers: auth() });
  assert.equal(first.status, 200);
  assert.equal(first.data.items.length, 500);

  const second = await api(`/api/sync/pull?since=${first.data.serverTime}&limit=500`, { headers: auth() });
  assert.equal(second.status, 200);
  assert.equal(second.data.items.length, 121);
});

test('server revision remains monotonic even with stale client rev values', async () => {
  await pushItems([{ category: 'hosts', key: 'rev-key', value: Buffer.from('one').toString('base64'), rev: 99 }]);
  await pushItems([{ category: 'hosts', key: 'rev-key', value: Buffer.from('two').toString('base64'), rev: 1 }]);

  const snapshot = await api('/api/sync/snapshot', { headers: auth() });
  assert.equal(snapshot.status, 200);
  const row = snapshot.data.items.find((item) => item.key === 'rev-key');
  assert.ok(row);
  assert.equal(row.rev, 2);
});

test('snapshot cursor covers logical timestamps ahead of the wall clock', async () => {
  const future = Date.now() + 60000;
  db.prepare('UPDATE sync_items SET updated_at=? WHERE key=?').run(future, 'rev-key');
  const snapshot = await api('/api/sync/snapshot', { headers: auth() });
  assert.ok(snapshot.data.serverTime >= future);
  await pushItems([{category:'hosts',key:'rev-key',value:Buffer.from('three').toString('base64')}]);
  const pull = await api(`/api/sync/pull?since=${snapshot.data.serverTime}`, {headers:auth()});
  assert.equal(pull.data.items.length,1);
  assert.ok(pull.data.items[0].ts > snapshot.data.serverTime);
});

test('legacy equal timestamp rows are not skipped at a page boundary', async () => {
  const ts=Date.now()+120000;
  const insert=db.prepare('INSERT INTO sync_items(user_id,category,key,value_enc,updated_at) VALUES(?,?,?,?,?)');
  for(let i=0;i<510;i++) insert.run(1,'legacy',String(i),Buffer.from('opaque'),ts);
  const first=await api(`/api/sync/pull?since=${ts-1}&limit=500`,{headers:auth()});
  const second=await api(`/api/sync/pull?since=${first.data.serverTime}&limit=500`,{headers:auth()});
  assert.equal(new Set([...first.data.items,...second.data.items].map(i=>i.category+':'+i.key)).size,510);
});

test('browser origin cannot fetch sync even with a stolen native bearer',async()=>{
  for(const url of ['/api/sync/pull','/api/sync/snapshot']) {
    assert.equal((await api(url,{headers:{...auth(),Origin:'https://evil.test'}})).status,403);
  }
});

test('HTTPS portal cookies are Secure without trusting forwarded headers',async()=>{
  const secret=db.prepare('SELECT totp_secret FROM users WHERE id=1').get().totp_secret;
  db.prepare('UPDATE users SET last_otp=-1 WHERE id=1').run();
  const login=await api('/api/web/login',{body:{email,password,otp:sec.totp(secret,Math.floor(Date.now()/30000))},headers:{Origin:`https://portal.example.test:${base.split(':').pop()}`}});
  assert.equal(login.status,200);
  assert.match(login.cookie,/; Secure(?:;|$)/);
});

test('security headers preserve strict framing policy',async()=>{
  const raw=await fetch(base+'/api/health');
  assert.equal(raw.headers.get('x-frame-options'),'DENY');
  assert.equal(raw.headers.get('referrer-policy'),'no-referrer');
});

test('malformed native credentials return 400 instead of an internal error',async()=>{
  assert.equal((await api('/api/login',{body:{email,password:{bad:true}}})).status,400);
});

test('invalid pull cursors and limits fail closed',async()=>{
  for(const query of ['limit=-1','limit=0','limit=abc','since=-1','since=abc','since=1e3']) {
    assert.equal((await api('/api/sync/pull?'+query,{headers:auth()})).status,400,query);
  }
});

test('revoked websocket refuses messages immediately before periodic check',async()=>{
  const wsToken=sec.issueSession(db,1,'client');
  const ws=new (require('ws'))(`${base.replace('http','ws')}/ws?token=${wsToken}`);
  await new Promise((resolve,reject)=>{ws.once('open',resolve);ws.once('error',reject);});
  const messages=[];
  ws.on('message',msg=>messages.push(JSON.parse(msg)));
  db.prepare('UPDATE sessions SET revoked=1 WHERE token=?').run(wsToken);
  const close=new Promise(resolve=>ws.once('close',resolve));
  ws.send(JSON.stringify({type:'ssh-open',data:{}}));
  await close;
  assert.deepEqual(messages,[]);
});

test('sync batch rolls back completely on a database write failure',async()=>{
  db.exec("CREATE TRIGGER reject_sync BEFORE INSERT ON sync_items WHEN NEW.key='fail-write' BEGIN SELECT RAISE(ABORT,'test failure'); END");
  try {
    const result=await api('/api/sync/push',{body:{items:[{category:'test',key:'rollback-first',value:'YQ=='},{category:'test',key:'fail-write',value:'Yg=='}]},headers:auth()});
    assert.equal(result.status,500);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sync_items WHERE key='rollback-first'").get().n,0);
  } finally { db.exec('DROP TRIGGER reject_sync'); }
});

test('forged forwarded IP cannot bypass login rate limiting',async()=>{
  let last;
  for(let i=0;i<121;i++) last=await api('/api/login',{body:{email:'missing@example.test',password},headers:{'X-Forwarded-For':`198.51.100.${i}`}});
  assert.equal(last.status,429);
});

