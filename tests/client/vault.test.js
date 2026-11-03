const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
// Independent historical writer: reversed HMAC construction, fixed test IV only.
function legacyCipher(obj, pass = 'vault-pass', salt = 'legacy-salt') {
  const S = Buffer.from(salt), P = Buffer.from(pass), blocks = [];
  const hmac = msg => crypto.createHmac('sha256', S).update(msg).digest();
  for (let b = 1; b <= 2; b++) {
    const idx = Buffer.alloc(4); idx.writeUInt32BE(b);
    let u = hmac(Buffer.concat([P, idx])), t = Buffer.from(u);
    for (let i = 1; i < 100000; i++) { u = hmac(u); for (let j = 0; j < 32; j++) t[j] ^= u[j]; }
    blocks.push(t);
  }
  const k = Buffer.concat(blocks), iv = Buffer.alloc(16, 7);
  const cipher = crypto.createCipheriv('aes-256-cbc', k.subarray(0, 32), iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj)), cipher.final()]);
  const data = Buffer.concat([iv, ct]);
  return Buffer.concat([data, crypto.createHmac('sha256', k.subarray(32)).update(data).digest()]).toString('base64');
}

function makeClient({ fetchImpl } = {}) {
  const elements = new Map();
  const storage = new Map();
  const fetchCalls = [];
  let timerId = 1;
  const timers = new Map();

  function makeElement() {
    const classes = new Set();
    return {
      value: '',
      textContent: '',
      innerHTML: '',
      style: {},
      dataset: {},
      classList: {
        add(c) { classes.add(c); },
        remove(c) { classes.delete(c); },
        toggle(c, force) {
          if (force === true) { classes.add(c); return true; }
          if (force === false) { classes.delete(c); return false; }
          if (classes.has(c)) { classes.delete(c); return false; }
          classes.add(c); return true;
        },
        contains(c) { return classes.has(c); }
      },
      addEventListener() {},
      appendChild() {},
      remove() {},
      click() {},
      querySelector() { return makeElement(); },
      querySelectorAll() { return []; },
      focus() {}
    };
  }

  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, makeElement());
      return elements.get(id);
    },
    createElement: makeElement,
    querySelector() { return makeElement(); },
    querySelectorAll() { return []; },
    body: makeElement()
  };

  const location = { protocol: 'https:', host: 'localhost', origin: 'https://localhost', reload() {} };
  class WebSocket { constructor(url) { this.url = url; this.readyState = 0; this.sent = []; } send(s) { this.sent.push(JSON.parse(s)); } close() { this.readyState = 3; } }

  const cryptoObj = {
    subtle: crypto.webcrypto.subtle,
    getRandomValues(arr) {
      return crypto.webcrypto.getRandomValues(arr);
    }
  };

  const ctx = vm.createContext({
    document,
    location,
    window: { location, addEventListener() {} },
    navigator: { userAgent: 'Android' },
    localStorage: {
      getItem(k) { return storage.get(k) || null; },
      setItem(k, v) { storage.set(k, String(v)); },
      removeItem(k) { storage.delete(k); }
    },
    WebSocket,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Blob,
    URL,
    crypto: cryptoObj,
    atob,
    btoa,
    console,
    setTimeout(fn, ms) { const id = timerId++; timers.set(id, { fn, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (url, opts = {}) => {
      fetchCalls.push({ url, opts });
      if (fetchImpl) return fetchImpl(url, opts, fetchCalls);
      return { ok: true, json: async () => ({ items: [], serverTime: 1, email: 'u@e', salt: Buffer.from('salt').toString('base64') }) };
    },
    prompt() { return null; }
  });

  for (const file of ['vendor/sha256.js', 'vendor/aesjs.js', 'app.js']) {
    vm.runInContext(fs.readFileSync(path.join(root, 'web', file), 'utf8'), ctx, { filename: file });
  }

  return {
    ctx,
    storage,
    elements,
    fetchCalls,
    timers,
    run(code) { return vm.runInContext(code, ctx); },
    tick(ms) {
      for (const [id, t] of [...timers.entries()]) {
        if (t.ms <= ms) {
          timers.delete(id);
          t.fn();
        }
      }
    }
  };
}

test('offline lease detects clock rollback across restarts and rejects malformed/overlong leases', () => {
  const c = makeClient();
  const now = Date.now();
  c.ctx.now = now;
  c.run('state.issuedAt=now-1000; state.expiresAt=now+100000; state.leaseSeenAt=now; saveSession()');
  const stored = JSON.parse(c.storage.get('tiassh_session'));
  assert.equal(stored.leaseSeenAt, now);
  c.ctx.stored = stored;
  assert.equal(c.run('leaseValid(stored, now-1)'), false);
  assert.equal(c.run('leaseValid({issuedAt:now-36*3600000,expiresAt:now+3600000},now)'), false);
  assert.equal(c.run('leaseValid({issuedAt:String(now-1000),expiresAt:now+100000},now)'), false);
  assert.equal(c.run('leaseValid({issuedAt:now+1,expiresAt:now+100000},now)'), false);
});

test('cache helpers isolate server/account and store only ciphertext fields', () => {
  const c = makeClient();
  c.run("state.email='u@e'; state.salt='c2FsdA=='; saveSnapshotCache([{category:'host',key:'h',value:'cipher',password:'secret',host:'plaintext'}],12)");
  const cache = JSON.parse(c.storage.get('tiassh_snapshot_cache'));
  assert.equal(JSON.stringify(cache).includes('secret'), false);
  assert.equal(JSON.stringify(cache).includes('plaintext'), false);
  assert.equal(c.run('loadSnapshotCache().items[0].value'), 'cipher');
  c.run("state.email='other'");
  assert.equal(c.run('loadSnapshotCache()'), null);
  c.storage.set('tiassh_snapshot_cache', '{');
  assert.equal(c.run('loadSnapshotCache()'), null);
});

test('lease timer logs out and clears decrypted state without a restart', () => {
  const c = makeClient();
  c.run("state.token='t'; state.key={}; state.issuedAt=Date.now()-1000; state.expiresAt=Date.now()+100; state.hosts.set('h',{password:'secret'}); scheduleLeaseExpiry()");
  c.tick(100);
  assert.equal(c.run('state.token'), null);
  assert.equal(c.run('state.key'), null);
  assert.equal(c.run('state.hosts.size'), 0);
  assert.equal(c.run("$('authLoginFields').classList.contains('hidden')"), false);
});

test('server authentication rejection cannot fall back to offline cache', async () => {
  const c = makeClient({fetchImpl: async () => ({ok:false,status:401,json:async()=>({error:'unauthorized'})})});
  c.run("state.token='t'; state.email='u@e'; state.salt='c2FsdA=='; state.issuedAt=Date.now()-1000; state.expiresAt=Date.now()+100000; saveSession(); saveSnapshotCache([],1)");
  assert.equal(await c.run('tryAutoLogin()'), false);
  assert.equal(c.run('state.token'), null);
  assert.equal(c.storage.has('tiassh_snapshot_cache'), false);
});

test('recovery rejects an already expired server lease instead of enabling writes', async () => {
  const now = Date.now();
  const c = makeClient({fetchImpl: async () => ({ok:true,json:async()=>({email:'u@e',salt:'c2FsdA==',issuedAt:now-1000,expiresAt:now-1})})});
  c.run("state.token='t'; state.email='u@e'; state.salt='c2FsdA=='; state.issuedAt=Date.now()-1000; state.expiresAt=Date.now()+100000; setOfflineMode(true)");
  assert.equal(await c.run('recoverOnlineIfPossible()'), false);
  assert.equal(c.run('state.token'), null);
});

test('host save and delete handlers remain inert if offline begins with modal open', async () => {
  const c = makeClient();
  c.run("state.hosts.set('h',{id:'h',name:'n',host:'x',user:'root'}); hostModal(state.hosts.get('h')); setOfflineMode(true)");
  await c.run("$('f_save').onclick()");
  c.run("$('f_del').onclick()");
  assert.equal(c.run("state.hosts.get('h').host"), 'x');
  assert.equal(c.fetchCalls.length, 0);
  assert.equal(c.run("$('offlineBanner').classList.contains('hidden')"), false);
  assert.match(fs.readFileSync(path.join(root,'web/index.html'),'utf8'), /id="offlineBanner"/);
});

test('auto-login rejects clock rollback using persisted lease watermark before network', async () => {
  const c = makeClient();
  const now = Date.now();
  c.storage.set('tiassh_session', JSON.stringify({token:'t',email:'u@e',salt:'c2FsdA==',issuedAt:now-1000,expiresAt:now+100000,leaseSeenAt:now+5000}));
  assert.equal(await c.run('tryAutoLogin()'), false);
  assert.equal(c.fetchCalls.length, 0);
});

test('expiry clears decrypted host and modal DOM as well as memory', () => {
  const c = makeClient();
  c.run("$('hostList').innerHTML='secret'; $('modal').innerHTML='password'; logoutSession()");
  assert.equal(c.run("$('hostList').innerHTML"), '');
  assert.equal(c.run("$('modal').innerHTML"), '');
});

test('PBKDF2 SHA256 agrees with Node standard vectors', () => {
  const c = makeClient();
  const vectors = [
    ['password', 'salt', 1, 32],
    ['password', 'salt', 2, 64],
    ['päss🔒', 'sält', 37, 48]
  ];
  for (const [p, s, iter, len] of vectors) {
    c.ctx.p = p;
    c.ctx.s = Array.from(Buffer.from(s, 'utf8'));
    c.ctx.iter = iter;
    c.ctx.len = len;
    const actual = Buffer.from(c.run('_pbkdf2(p, s, iter, len)')).toString('hex');
    const expected = crypto.pbkdf2Sync(p, s, iter, len, 'sha256').toString('hex');
    assert.equal(actual, expected);
  }
});

test('login never sends vault passphrase and session stores no plaintext password', async () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient({
    fetchImpl: async (url, opts) => {
      if (url.endsWith('/api/login')) {
        const now = Date.now();
        return { ok: true, json: async () => ({ token: 'tok', email: 'u@e', salt, issuedAt: now, expiresAt: now + 3600_000 }) };
      }
      if (url.endsWith('/api/sync/snapshot')) {
        return { ok: true, json: async () => ({ items: [], serverTime: 1 }) };
      }
      return { ok: true, json: async () => ({ email: 'u@e', salt, authRevision: 1 }) };
    }
  });
  c.run("$('authServer').value='https://srv'; $('authEmail').value='u@e'; $('authPass').value='account-pass'; $('authVaultPass').value='vault-pass';");

  await c.run('doLogin()');

  const login = c.fetchCalls.find(x => String(x.url).endsWith('/api/login'));
  const body = JSON.parse(login.opts.body);
  assert.equal(body.password, 'account-pass');
  assert.equal('vaultPassphrase' in body, false);
  assert.equal('vault' in body, false);

  const sess = JSON.parse(c.storage.get('tiassh_session'));
  assert.equal('pass' in sess, false);
  assert.equal('password' in sess, false);
});

test('auto-login requires explicit vault unlock on restart', async () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient({
    fetchImpl: async (url) => {
      if (url.endsWith('/api/me')) { const now = Date.now(); return { ok: true, json: async () => ({ email: 'u@e', salt, authRevision: 5, issuedAt: now - 1000, expiresAt: now + 3600_000 }) }; }
      return { ok: true, json: async () => ({ items: [], serverTime: 1 }) };
    }
  });
  c.storage.set('tiassh_session', JSON.stringify({ token: 'tok', email: 'u@e', salt, server: 'https://srv' }));
  const ok = await c.run('tryAutoLogin()');
  assert.equal(ok, true);
  assert.equal(c.run('state.key === null'), true);
  assert.equal(c.run('state.unlockRequired'), true);
});

test('offline auto-login uses cached encrypted snapshot under active lease and enters read-only', async () => {
  const now = Date.now();
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient({
    fetchImpl: async (url) => {
      if (url.endsWith('/api/me')) throw new Error('network down');
      if (url.endsWith('/api/sync/snapshot')) throw new Error('network down');
      return { ok: true, json: async () => ({ ok: true }) };
    }
  });
  c.run(`
    state.key = deriveKey('vault-pass', '${salt}');
    globalThis.cachedCipher = encValue({ id:'h1', name:'srv', host:'10.0.0.1', user:'root', auth:'password', password:'pw' });
    state.key = null;
  `);
  c.storage.set('tiassh_snapshot_cache', JSON.stringify({
    v: 1, server: 'https://srv', email: 'u@e', salt,
    serverTime: 99,
    cachedAt: now,
    items: [{ category: 'host', key: 'h1', value: c.run('globalThis.cachedCipher') }]
  }));
  c.storage.set('tiassh_session', JSON.stringify({
    token: 'tok', email: 'u@e', salt, server: 'https://srv', issuedAt: now - 1_000, expiresAt: now + (3 * 60 * 60 * 1000)
  }));

  const ok = await c.run('tryAutoLogin()');
  assert.equal(ok, true);
  await c.run("unlockVault('vault-pass')");
  assert.equal(c.run('state.readOnly'), true);
  assert.equal(c.run('state.offlineMode'), true);
  assert.equal(c.run("state.hosts.get('h1').host"), '10.0.0.1');
});

test('offline auto-login refuses expired lease and clears session', async () => {
  const now = Date.now();
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient({
    fetchImpl: async () => { throw new Error('offline'); }
  });
  c.storage.set('tiassh_session', JSON.stringify({
    token: 'tok', email: 'u@e', salt, server: 'https://srv', issuedAt: now - (40 * 60 * 60 * 1000), expiresAt: now - 1_000
  }));

  const ok = await c.run('tryAutoLogin()');
  assert.equal(ok, false);
  assert.equal(c.storage.get('tiassh_session') || null, null);
});

test('session stores authoritative lease fields from login and me with expires_at fallback', async () => {
  const now = Date.now();
  const salt = Buffer.from('legacy-salt').toString('base64');
  let loginCalls = 0;
  const c = makeClient({
    fetchImpl: async (url) => {
      if (url.endsWith('/api/login')) {
        loginCalls++;
        return { ok: true, json: async () => ({ token: 'tok', email: 'u@e', salt, issuedAt: now, expires_at: now + 3600_000 }) };
      }
      if (url.endsWith('/api/me')) return { ok: true, json: async () => ({ email: 'u@e', salt, issuedAt: now, expiresAt: now + 7200_000 }) };
      if (url.endsWith('/api/sync/snapshot')) return { ok: true, json: async () => ({ items: [], serverTime: 1 }) };
      return { ok: true, json: async () => ({ ok: true }) };
    }
  });

  c.run("$('authServer').value='https://srv'; $('authEmail').value='u@e'; $('authPass').value='account-pass'; $('authVaultPass').value='vault-pass';");
  await c.run('doLogin()');
  const afterLogin = JSON.parse(c.storage.get('tiassh_session'));
  assert.equal(afterLogin.issuedAt, now);
  assert.equal(afterLogin.expiresAt, now + 3600_000);

  await c.run('tryAutoLogin()');
  const afterMe = JSON.parse(c.storage.get('tiassh_session'));
  assert.equal(afterMe.issuedAt, now);
  assert.equal(afterMe.expiresAt, now + 7200_000);
  assert.equal(loginCalls, 1);
});

test('read-only mode blocks host write actions', async () => {
  const c = makeClient();
  c.run("state.readOnly = true; state.hosts.set('h1',{id:'h1',host:'x'});");
  await c.run("pushItem('h1', {id:'h1',host:'y'})");
  await c.run("pushItem('h1', null)");
  assert.equal(c.fetchCalls.filter(x => String(x.url).endsWith('/api/sync/push')).length, 0);
});

test('online recovery exits read-only mode and pulls latest snapshot delta', async () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient({
    fetchImpl: async (url) => {
      if (url.endsWith('/api/me')) {
        const now = Date.now();
        return { ok: true, json: async () => ({ email: 'u@e', salt, issuedAt: now - 1000, expiresAt: now + 100000 }) };
      }
      if (url.includes('/api/sync/pull?since=')) {
        return {
          ok: true,
          json: async () => ({
            items: [{ category: 'host', key: 'h2', value: c.run("encValue({id:'h2',host:'2.2.2.2',user:'root',auth:'password',password:'pw'})") }],
            serverTime: 42
          })
        };
      }
      return { ok: true, json: async () => ({ ok: true }) };
    }
  });
  c.run(`
    state.salt = '${salt}'; state.email = 'u@e';
    state.key = deriveKey('vault-pass', state.salt);
    state.readOnly = true;
    state.offlineMode = true;
    state.lastSync = 0;
  `);
  await c.run('recoverOnlineIfPossible()');
  assert.equal(c.run('state.readOnly'), false);
  assert.equal(c.run('state.offlineMode'), false);
  assert.equal(c.run("state.hosts.get('h2').host"), '2.2.2.2');
});

test('legacy ciphertext decrypts and full legacy snapshot migrates to v2 envelope', async () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  const host = { id: 'h1', host: '1.2.3.4', user: 'root', auth: 'password', password: 'pw' };
  let pushed = null;
  const c = makeClient({
    fetchImpl: async (url, opts) => {
      if (url.endsWith('/api/sync/snapshot')) return { ok: true, json: async () => ({ items: [{ category: 'host', key: 'h1', value: legacyCipher(host) }], serverTime: 10 }) };
      if (url.endsWith('/api/sync/push')) { pushed = JSON.parse(opts.body); return { ok: true, json: async () => ({ ok: true }) }; }
      return { ok: true, json: async () => ({ ok: true }) };
    }
  });

  c.ctx.__host = host;
  c.run(`
    state.salt = '${salt}';
    state.key = deriveKey('vault-pass', state.salt);
    state.legacyKey = deriveLegacyKey('vault-pass', state.salt);
  `);

  await c.run('pullSnapshot()');

  assert.equal(c.run("state.hosts.get('h1').host"), '1.2.3.4');
  assert.ok(pushed);
  assert.equal(pushed.items.length, 1);
  assert.equal(JSON.parse(Buffer.from(pushed.items[0].value, 'base64')).v, 2); c.ctx.migrated = pushed.items[0].value;
  assert.equal(c.run('decValue(migrated).password'), 'pw');
  assert.equal(c.run("JSON.stringify(state.key.encKey)"), JSON.stringify(Array.from(crypto.pbkdf2Sync('vault-pass', 'legacy-salt', 100000, 64, 'sha256').subarray(0,32))));
  c.run('state.legacyKey=null');
  assert.equal(c.run('decValue(migrated).host'), '1.2.3.4');
});

test('migration aborts on undecryptable item and does not overwrite server vault', async () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  let pushed = false;
  const c = makeClient({
    fetchImpl: async (url, opts) => {
      if (url.endsWith('/api/sync/snapshot')) {
        return {
          ok: true,
          json: async () => ({
            items: [
              { category: 'host', key: 'good', value: legacyCipher({id:'good',host:'1.1.1.1',user:'root',auth:'password',password:'x'}) },
              { category: 'host', key: 'bad', value: 'this-is-not-decryptable' }
            ],
            serverTime: 22
          })
        };
      }
      if (url.endsWith('/api/sync/push')) { pushed = true; return { ok: true, json: async () => ({ ok: true }) }; }
      return { ok: true, json: async () => ({ ok: true }) };
    }
  });

  c.run(`
    state.salt = '${salt}';
    state.key = deriveKey('vault-pass', state.salt);
    state.legacyKey = deriveLegacyKey('vault-pass', state.salt);
  `);

  await assert.rejects(() => c.run('pullSnapshot()'), /vault item decrypt failed/);
  assert.equal(pushed, false);
});

test('mixed legacy/v2 snapshot refuses migration and preserves local snapshot', async () => {
  let writes = 0;
  const c = makeClient({fetchImpl: async (url) => {
    if (url.endsWith('/api/sync/push')) writes++;
    return {ok:true,json:async()=>({items:[{category:'host',key:'old',value:legacyCipher({id:'old'})},{category:'host',key:'new',value:c.run('encValue({id:"new"})')}],serverTime:12})};
  }});
  c.run("state.key=deriveKey('vault-pass',btoa('legacy-salt'));state.legacyKey=deriveLegacyKey('vault-pass',btoa('legacy-salt'));state.hosts.set('existing',{id:'existing'});state.lastSync=7;");
  await assert.rejects(()=>c.run('pullSnapshot()'), /mixed/i);
  assert.equal(writes,0);assert.equal(c.run("state.hosts.has('existing') && state.hosts.size===1 && state.lastSync===7"),true);
});

test('v2 envelope authenticates version field and rejects tampering', () => {
  const salt = Buffer.from('legacy-salt').toString('base64');
  const c = makeClient();
  c.run(`state.key = deriveKey('vault-pass', '${salt}'); state.legacyKey = deriveLegacyKey('vault-pass', '${salt}');`);
  const enc = c.run('encValue({id:"h",host:"x"})');
  const parsed = JSON.parse(Buffer.from(enc, 'base64').toString('utf8'));
  parsed.v = 1;
  c.ctx.tampered = Buffer.from(JSON.stringify(parsed), 'utf8').toString('base64');
  assert.throws(() => c.run('decValue(globalThis.tampered)'), /decryption failed|bad envelope|auth/i);
});