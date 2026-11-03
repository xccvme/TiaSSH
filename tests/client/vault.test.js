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
        return { ok: true, json: async () => ({ token: 'tok', email: 'u@e', salt }) };
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
      if (url.endsWith('/api/me')) return { ok: true, json: async () => ({ email: 'u@e', salt, authRevision: 5 }) };
      return { ok: true, json: async () => ({ items: [], serverTime: 1 }) };
    }
  });
  c.storage.set('tiassh_session', JSON.stringify({ token: 'tok', email: 'u@e', salt, server: 'https://srv' }));
  const ok = await c.run('tryAutoLogin()');
  assert.equal(ok, true);
  assert.equal(c.run('state.key === null'), true);
  assert.equal(c.run('state.unlockRequired'), true);
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