const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');

const root = path.resolve(__dirname, '..');

async function boot(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tiassh-portal-'));
  const port = 26000 + Math.floor(Math.random() * 3000);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: root,
    env: {
      ...process.env,
      DATA_DIR: dir,
      MASTER_KEY: 'test-only-master-key',
      PORT: String(port),
      PUBLIC_URL: `http://127.0.0.1:${port}`,
      WEB_ORIGIN: `http://127.0.0.1:${port}`,
      ...env,
    },
  });
  let out = '';
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('boot timeout\n' + out)), 15000);
    child.stdout.on('data', d => { out += d; if (/listening on/i.test(out)) { clearTimeout(t); resolve(); } });
    child.stderr.on('data', d => { out += d; if (/GAGAL|Error|EADDR/i.test(d)) { clearTimeout(t); reject(new Error('server failed to boot\n' + out)); } });
    child.on('exit', code => { if (code) { clearTimeout(t); reject(new Error('server exited ' + code + '\n' + out)); } });
  });
  return { port, dir, child, stop: () => new Promise(r => { child.on('exit', () => r()); child.kill('SIGTERM'); }) };
}
async function req(port, method, p, { headers = {}, body } = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, text, json };
}

test('portal closed (WEB_PORTAL_ENABLED=0): web surface 404, native endpoints alive & fail-closed', async (t) => {
  const s = await boot({ WEB_PORTAL_ENABLED: '0' });
  t.after(async () => { await s.stop(); });

  // Seluruh permukaan web hilang (404, bukan 200/500).
  assert.equal((await req(s.port, 'GET', '/')).status, 404, 'home must 404');
  assert.equal((await req(s.port, 'GET', '/web/portal.js')).status, 404, 'web asset must 404');
  assert.equal((await req(s.port, 'POST', '/api/web/register', { headers: { Origin: `http://127.0.0.1:${s.port}` }, body: { email: 'a@b.co', password: 'aVeryLongPassword1' } })).status, 404, 'web register must 404');
  assert.equal((await req(s.port, 'POST', '/api/web/login', { headers: { Origin: `http://127.0.0.1:${s.port}` }, body: { email: 'a@b.co', password: 'aVeryLongPassword1' } })).status, 404, 'web login must 404');

  // Endpoint native tetap hidup & aman (bukan 404).
  assert.equal((await req(s.port, 'GET', '/api/health')).json.ok, true, 'health must be up');
  const cfg = await req(s.port, 'GET', '/api/config');
  assert.equal(cfg.json.portalEnabled, false, 'config must report portal closed');

  const nativeBad = await req(s.port, 'POST', '/api/login', { body: { email: 'x@y.co', password: 'nope' } });
  assert.ok([400, 401, 404].includes(nativeBad.status), 'native login reachable (got ' + nativeBad.status + ')');
  assert.notEqual(nativeBad.json?.error, 'portal web ditutup', 'native login must not be blocked by portal guard');

  const syncNoTok = await req(s.port, 'GET', '/api/sync/snapshot');
  assert.equal(syncNoTok.status, 401, 'sync must fail-closed without token');
});

test('portal open by default: web surface served and web register reachable', async (t) => {
  const s = await boot({});
  t.after(async () => { await s.stop(); });

  const home = await req(s.port, 'GET', '/');
  assert.ok([200, 503].includes(home.status), 'home should serve portal or "portal belum terpasang" (got ' + home.status + ')');
  assert.equal((await req(s.port, 'GET', '/api/config')).json.portalEnabled, true, 'config must report portal open');

  const reg = await req(s.port, 'POST', '/api/web/register', { headers: { Origin: `http://127.0.0.1:${s.port}` }, body: { email: 'open@test.co', password: 'aVeryLongPassword1' } });
  assert.ok([200, 201, 409].includes(reg.status), 'web register reachable (got ' + reg.status + ')');
});
