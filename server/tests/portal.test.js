const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const sec = require('../account-security');

let child, dir, base;
const password = 'Test-only-password-123!';
const email = 'alice@example.test';

async function api(url, opts = {}) {
  const response = await fetch(base + url, {
    method: opts.method || (opts.body ? 'POST' : 'GET'),
    headers: { ...(opts.body ? { 'Content-Type': 'application/json', ...(url.startsWith('/api/web/') ? {Origin:base}: {}) } : {}), ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data, cookie: response.headers.get('set-cookie') };
}

test.before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'portal-test-'));
  const port = String(21000 + Math.floor(Math.random() * 2000));
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      DATA_DIR: dir,
      PORT: port,
      PUBLIC_URL: `http://127.0.0.1:${port}`,
      NATIVE_ORIGINS: 'tauri://localhost,http://tauri.localhost',
      WEB_ORIGIN: `http://127.0.0.1:${port}`,
      SESSION_TTL_SEC: '3600'
    }
  });
  let output = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(output)), 10000);
    child.stdout.on('data', (b) => {
      output += b;
      const m = output.match(/listening on 0.0.0.0:(\d+)/);
      if (m) {
        base = `http://127.0.0.1:${m[1]}`;
        clearTimeout(timer);
        resolve();
      }
    });
    child.stderr.on('data', (b) => { output += b; });
    child.on('exit', (c) => reject(new Error(`exit ${c}: ${output}`)));
  });
});

test.after(() => {
  child?.kill();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

let enrollment;
let webCookie;
let nativeToken;
function freshOtp() {
  const db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  db.prepare('UPDATE users SET last_otp=-1 WHERE email=?').run(email);
  db.close();
  return sec.totp(enrollment.secret, Math.floor(Date.now()/30000));
}

test('native register endpoint removed', async () => {
  const res = await api('/api/register', { body: { email, password } });
  assert.equal(res.status, 404);
});

test('web registration returns challenge only and cannot confirm with invalid otp', async () => {
  const res = await api('/api/web/register', { body: { email, password } });
  assert.equal(res.status, 200);
  assert.equal(res.data.token, undefined);
  assert.equal(res.cookie, null);
  assert.match(res.data.secret, /^[A-Z2-7]{32}$/);
  assert.match(res.data.otpauthUrl, /^otpauth:\/\/totp\//);
  assert.ok(res.data.challenge);
  enrollment = res.data;

  const bad = await api('/api/web/enroll/confirm', { body: { challenge: enrollment.challenge, otp: '000000' } });
  assert.equal(bad.status, 401);

  const db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  assert.equal(db.prepare('SELECT count(*) AS n FROM users').get().n, 0);
  db.close();
});

test('confirm with valid OTP creates account, native login still password-only', async () => {
  const counter = Math.floor(Date.now() / 30000);
  const otp = sec.totp(enrollment.secret, counter);
  const done = await api('/api/web/enroll/confirm', { body: { challenge: enrollment.challenge, otp } });
  assert.equal(done.status, 200);

  const login = await api('/api/login', { body: { email, password } });
  assert.equal(login.status, 200);
  assert.ok(login.data.token);
  assert.equal(login.data.email, email);
  assert.ok(login.data.salt);
  nativeToken = login.data.token;
});

test('web login requires password + otp and sets secure cookie session', async () => {
  const noOtp = await api('/api/web/login', { body: { email, password } });
  assert.equal(noOtp.status, 401);

  const otp = freshOtp();
  const ok = await api('/api/web/login', { body: { email, password, otp }, headers: { Origin: base } });
  assert.equal(ok.status, 200);
  assert.ok(ok.cookie && /HttpOnly/i.test(ok.cookie) && /SameSite=Strict/i.test(ok.cookie));
  assert.equal(ok.data.token, undefined);
  webCookie = ok.cookie.split(';')[0];
});

test('web session cannot access client sync APIs or websocket', async () => {
  const sync = await api('/api/sync/pull?since=0', { headers: { Cookie: webCookie } });
  assert.equal(sync.status, 401);

  const wsToken = (() => {
    const db = new DatabaseSync(path.join(dir, 'tiassh.db'));
    const row = db.prepare("SELECT token FROM sessions WHERE scope='web' ORDER BY rowid DESC LIMIT 1").get();
    db.close();
    return row?.token;
  })();
  assert.ok(wsToken);
  const ws = new (require('ws'))(`${base.replace('http', 'ws')}/ws?token=${encodeURIComponent(wsToken)}`);
  const closed = await new Promise((resolve) => ws.on('close', () => resolve(true)));
  assert.equal(closed, true);
});

test('native login rejects browser origins while tauri origin still works', async () => {
  const evil = await api('/api/login', {
    body: { email, password },
    headers: { Origin: base }
  });
  assert.equal(evil.status, 403);

  const native = await api('/api/login', {
    body: { email, password },
    headers: { Origin: 'tauri://localhost' }
  });
  assert.equal(native.status, 200);
  assert.ok(native.data.token);
});

test('native token still works for /api/me and includes authRevision', async () => {
  const me = await api('/api/me', { headers: { Authorization: `Bearer ${nativeToken}` } });
  assert.equal(me.status, 200);
  assert.equal(me.data.email, email);
  assert.ok(me.data.salt);
  assert.equal(typeof me.data.authRevision, 'number');
});

test('replayed OTP is rejected and hostile portal origins rejected', async () => {
  const otp = sec.totp(enrollment.secret, Math.floor(Date.now()/30000));
  assert.equal((await api('/api/web/login', { body:{email,password,otp} })).status,401);
  assert.equal((await api('/api/web/login', { body:{email,password,otp}, headers:{Origin:'https://evil.test'} })).status,403);
  assert.equal((await api('/api/web/profile', {body:{currentPassword:password,otp,displayName:'changed'},headers:{Cookie:webCookie}})).status,401);
});

test('websocket closes when session is revoked in DB', async () => {
  const ws = new (require('ws'))(`${base.replace('http', 'ws')}/ws?token=${encodeURIComponent(nativeToken)}`);
  await new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  const db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  db.prepare('UPDATE sessions SET revoked=1 WHERE token=?').run(nativeToken);
  db.close();
  const closed = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 3000);
    ws.once('close', () => { clearTimeout(timer); resolve(true); });
  });
  assert.equal(closed, true);
});

test('legacy account web login returns enrollment challenge not session', async () => {
  const db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  const legacyEmail = 'legacy@example.test';
  const legacyHash = require('bcryptjs').hashSync(password, 10);
  db.prepare('INSERT INTO users(email, pass_hash, salt) VALUES(?,?,?)').run(legacyEmail, legacyHash, 'legacy-salt');
  db.close();

  const res = await api('/api/web/login', { body: { email: legacyEmail, password }, headers: { Origin: base } });
  assert.equal(res.status, 202);
  assert.equal(res.cookie, null);
  assert.equal(res.data.requiresTotpEnrollment, true);
  assert.ok(res.data.challenge);
  assert.ok(res.data.secret);
});

test('portal serves only account assets; old terminal vendors are not served', async () => {
  const home = await api('/');
  assert.equal(home.status, 200);
  assert.match(home.data, /Kelola akun/);
  assert.doesNotMatch(home.data, /xterm|privateKey|new WebSocket\(.*\/ws\?/);
  for (const asset of ['/vendor/xterm.js','/vendor/aesjs.js','/web/vendor/xterm.js','/portal/vendor/xterm.js']) {
    assert.equal((await api(asset)).status,404);
  }
});

test('profile can be read with cookie and modified only with current password and fresh OTP', async()=>{
  const me=await api('/api/web/me',{headers:{Cookie:webCookie}});
  assert.equal(me.status,200);assert.equal(me.data.email,email);
  const bad=await api('/api/web/profile',{body:{currentPassword:'wrong',otp:freshOtp(),displayName:'<img src=x>'},headers:{Cookie:webCookie}});
  assert.equal(bad.status,401);
  const good=await api('/api/web/profile',{body:{currentPassword:password,otp:freshOtp(),displayName:'<img src=x>'},headers:{Cookie:webCookie}});
  assert.equal(good.status,200);
  assert.equal((await api('/api/web/me',{headers:{Cookie:webCookie}})).data.displayName,'<img src=x>');
});

test('TOTP rotation does not change active secret until confirmed and stale challenges fail', async()=>{
  const start=await api('/api/web/totp/reset',{body:{currentPassword:password,otp:freshOtp()},headers:{Cookie:webCookie}});
  assert.equal(start.status,200);assert.ok(start.data.challenge);
  const db=new DatabaseSync(path.join(dir,'tiassh.db'));
  assert.equal(db.prepare('SELECT totp_secret FROM users WHERE email=?').get(email).totp_secret,enrollment.secret);
  db.prepare('UPDATE users SET auth_revision=auth_revision+1 WHERE email=?').run(email);
  db.close();
  const done=await api('/api/web/enroll/confirm',{body:{challenge:start.data.challenge,otp:sec.totp(start.data.secret,Math.floor(Date.now()/30000))}});
  assert.equal(done.status,401);
  const login=await api('/api/web/login',{body:{email,password,otp:freshOtp()}});webCookie=login.cookie.split(';')[0];
});

test('stolen web cookie cannot authorize account changes or expose credentials', async () => {
  const me=await api('/api/web/me',{headers:{Cookie:webCookie}});
  assert.equal(me.status,200);
  assert.deepEqual(Object.keys(me.data).sort(),['authRevision','displayName','email','totpEnabled']);
  const otp=freshOtp();
  for(const route of ['/api/web/profile','/api/web/password','/api/web/totp/reset']) {
    assert.equal((await api(route,{body:{otp,newPassword:'Attacker-password-123!'},headers:{Cookie:webCookie}})).status,401);
    assert.equal((await api(route,{body:{otp,currentPassword:password},headers:{Cookie:webCookie,Origin:'null'}})).status,403);
    assert.equal((await api(route,{body:{otp,currentPassword:password},headers:{Cookie:webCookie,Origin:''}})).status,403);
  }
  const db=new DatabaseSync(path.join(dir,'tiassh.db'));
  const stolen=webCookie.split('=')[1];
  assert.equal((await api('/api/sync/snapshot',{headers:{Authorization:`Bearer ${stolen}`}})).status,401);
  assert.equal((await api('/api/sync/push',{body:{items:[]},headers:{Cookie:webCookie,Authorization:`Bearer ${nativeToken}`}})).status,401);
  const stale=db.prepare('SELECT challenge_hash FROM enrollments WHERE user_id IS NOT NULL').all();
  assert.ok(stale.length>0);
  db.close();
});

test('confirmed registration challenge cannot be replayed',async()=>{
  assert.equal((await api('/api/web/enroll/confirm',{body:{challenge:enrollment.challenge,otp:freshOtp()}})).status,401);
});

test('changing web password keeps same salt', async () => {
  const old = await api('/api/login', { body: { email, password } });
  const oldSalt = old.data.salt;
  const otp = freshOtp();
  const change = await api('/api/web/password', {
    body: { currentPassword: password, newPassword: 'New-test-password-123!', otp },
    headers: { Cookie: webCookie, Origin: base }
  });
  assert.equal(change.status, 200);

  const after = await api('/api/login', { body: { email, password: 'New-test-password-123!' } });
  assert.equal(after.status, 200);
  assert.equal(after.data.salt, oldSalt);
}
);