/* TiaSSH Sync Server - free, self-hosted
 * Sync account + SSH data between desktop/web/android devices.
 * Zero external paid services. SQLite + bcrypt + JWT + WS + SSH proxy.
 *
 * SYARAT: Node.js v22.13+ (disarankan 24 LTS) — memakai node:sqlite bawaan.
 */
// --- versi guard (error jelas kalau Node terlalu lama) ---
(function () {
  const v = process.versions.node.split('.').map(Number);
  const ok = v[0] > 22 || (v[0] === 22 && v[1] >= 13);
  if (!ok) {
    console.error('\n[tiassh] GAGAL JALAN: Node.js terlanjur lama (v' + process.versions.node + ').\n' +
      '[tiassh] Dibutuhkan Node.js v22.13+ (disarankan 24 LTS).\n\n' +
      '[tiassh] Perbaiki di VPS (Debian/Ubuntu):\n' +
      '  curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -\n' +
      '  sudo apt-get install -y nodejs\n' +
      '  node -v    # pastikan v24.x\n\n');
    process.exit(1);
  }
})();
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
let DatabaseSync = null;
try { ({ DatabaseSync } = require('node:sqlite')); } catch (e) {}
if (!DatabaseSync) {
  console.error('\n[tiassh] GAGAL: modul bawaan node:sqlite tidak tersedia.\n' +
    '[tiassh] Pastikan Node.js >= 22.13 (tanpa flag) — disarankan 24 LTS.\n' +
    '  curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash - && sudo apt-get install -y nodejs\n\n');
  process.exit(1);
}
const express = require('express');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const { Client } = require('ssh2');

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const MASTER_KEY = process.env.MASTER_KEY || (() => {
  const f = path.join(DATA_DIR, 'master.key');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim();
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const k = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(f, k, { mode: 0o600 });
  return k;
})();
const PUBLIC_URL = process.env.PUBLIC_URL || `http://127.0.0.1:${PORT}`;
const WEB_ORIGIN = process.env.WEB_ORIGIN || PUBLIC_URL;
// Electron file:// serializes Origin as "null"; Capacitor uses localhost.
// This browser-origin policy is not cryptographic proof of native identity:
// opaque/sandboxed browser pages can also use "null", and non-browser clients
// can forge or omit Origin. Credentials and scoped sessions remain required.
const NATIVE_ORIGINS = new Set(String(process.env.NATIVE_ORIGINS || 'tauri://localhost,http://tauri.localhost,null,https://localhost,http://localhost').split(',').map(v => v.trim()).filter(Boolean));
const SESSION_TTL_SEC = Math.max(300, parseInt(process.env.SESSION_TTL_SEC || '3600', 10));
const CLIENT_SESSION_TTL_SEC = Math.min(129600, Math.max(1, parseInt(process.env.CLIENT_SESSION_TTL_SEC || '129600', 10)));
const security = require('./account-security');

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'tiassh.db'));
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sync_items(
  user_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  key TEXT NOT NULL,
  value_enc BLOB,
  rev INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id, category, key),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sync_rev ON sync_items(user_id, updated_at);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

// ---------- crypto (client-side key management) ----------
// Zero-knowledge design: the CLIENT encrypts each item with a key derived
// from the user's login password (PBKDF2) BEFORE sending. The server only
// stores opaque blobs. Even with full DB access, data is unreadable
// without the user's password.

// ---------- app ----------
security.migrate(db);
function makeClientSession(userId) {
  const token = security.issueSession(db, userId, 'client', CLIENT_SESSION_TTL_SEC);
  if (!token) return null;
  return security.lookupSession(db, token, 'client');
}
function verifyToken(token) { return security.lookupSession(db, token, 'client')?.id || null; }
function auth(req, res, next) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const uid = verifyToken(token);
  if (!uid) return res.status(401).json({ error: 'unauthorized' });
  req.uid = uid;
  next();
}
function authForSync(req, res, next) {
  if (req.headers.cookie && /tiassh_web=/.test(req.headers.cookie)) return res.status(401).json({ error: 'web session tidak boleh akses sync' });
  if (req.headers.origin && !NATIVE_ORIGINS.has(req.headers.origin)) return res.status(403).json({ error: 'native origin required' });
  return auth(req, res, next);
}

// ---------- app ----------
const app = express();
app.use(express.json({ limit: '8mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  const origin = req.headers.origin;
  if (origin && NATIVE_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use((req, res, next) => {
  const ip = req.socket.remoteAddress || 'ip';
  const key = `${ip}:${req.path}`;
  const now = Date.now();
  if (!global.__rl) global.__rl = new Map();
  const row = global.__rl.get(key) || { count: 0, reset: now + 60000 };
  if (now > row.reset) { row.count = 0; row.reset = now + 60000; }
  row.count += 1;
  global.__rl.set(key, row);
  if (row.count > 120) return res.status(429).json({ error: 'too many requests' });
  next();
});
const PORTAL_DIR = path.join(__dirname, 'web', 'portal');
app.use('/web', express.static(PORTAL_DIR));
app.get('/', (req, res) => {
  const portalIndex = path.join(PORTAL_DIR, 'index.html');
  if (fs.existsSync(portalIndex)) return res.sendFile(portalIndex);
  res.status(503).json({ error: 'portal belum terpasang' });
});
app.get('/api/health', (req, res) => res.json({ ok: true, name: 'tiassh-sync', version: '1.0.0' }));

security.installWebRoutes(app, db, { webOrigin: new URL(WEB_ORIGIN).origin, sessionTtlSec: SESSION_TTL_SEC });
app.post('/api/register', (req, res) => res.status(404).json({ error: 'Pendaftaran hanya melalui portal web' }));

// login
app.post('/api/login', (req, res) => {
  if (req.headers.origin && !NATIVE_ORIGINS.has(req.headers.origin)) return res.status(403).json({ error: 'native origin required' });
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || !email || !password || Buffer.byteLength(password) > 72) return res.status(400).json({ error: 'email + password required' });
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(email).toLowerCase());
  if (!u || !bcrypt.compareSync(password, u.pass_hash)) return res.status(401).json({ error: 'invalid credentials' });
  const session = makeClientSession(u.id);
  if (!session) return res.status(500).json({ error: 'session issue failed' });
  res.json({ token: session.token, email: u.email, salt: u.salt, issuedAt: session.issuedAt, expiresAt: session.expiresAt, expires_at: session.expiresAt });
});

app.get('/api/me', auth, (req, res) => {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const session = security.lookupSession(db, token, 'client');
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  const u = db.prepare('SELECT email, salt, auth_revision FROM users WHERE id=?').get(req.uid);
  res.json({ email: u.email, salt: u.salt, authRevision: u.auth_revision, issuedAt: session.issuedAt, expiresAt: session.expiresAt, expires_at: session.expiresAt });
});

app.post('/api/device', auth, (req, res) => {
  const name = String((req.body || {}).name || 'unknown').slice(0, 80);
  db.prepare('INSERT INTO devices(user_id, name) VALUES(?,?)').run(req.uid, name);
  res.json({ ok: true });
});

// ---------- sync (encrypted at rest) ----------
// Push items: [{category, key, value(base64 ciphertext | null=delete), rev?}]
app.post('/api/sync/push', authForSync, (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  if (items.length > 500) return res.status(400).json({ error: 'too many items' });
  const stmt = db.prepare(`INSERT INTO sync_items(user_id, category, key, value_enc, rev, updated_at, deleted)
    VALUES(?,?,?,?,?,?,?)
    ON CONFLICT(user_id, category, key) DO UPDATE SET
      value_enc=excluded.value_enc, rev=sync_items.rev+1, updated_at=excluded.updated_at, deleted=excluded.deleted`);
  const maxRow = db.prepare('SELECT COALESCE(MAX(updated_at),0) AS ts FROM sync_items WHERE user_id=?').get(req.uid).ts;
  let logicalNow = Math.max(Date.now(), maxRow);
  let accepted = 0;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const it of items) {
      const cat = String(it.category || '').slice(0, 40);
      const k = String(it.key || '').slice(0, 200);
      if (!cat || !k) continue;
      const deleted = it.value === null ? 1 : 0;
      const valueEnc = deleted ? null : Buffer.from(String(it.value || ''), 'base64');
      logicalNow += 1;
      stmt.run(req.uid, cat, k, valueEnc, 1, logicalNow, deleted);
      accepted += 1;
    }
    db.exec('COMMIT');
  } catch {
    db.exec('ROLLBACK');
    return res.status(500).json({ error: 'sync push failed' });
  }
  broadcast(req.uid, 'sync');
  res.json({ ok: true, accepted, serverTime: logicalNow });
});

// Pull items after a timestamp (cursor)
app.get('/api/sync/pull', authForSync, (req, res) => {
  const rawSince = req.query.since === undefined ? '0' : req.query.since;
  const rawLimit = req.query.limit === undefined ? '500' : req.query.limit;
  if (typeof rawSince !== 'string' || typeof rawLimit !== 'string' ||
      !/^\d+$/.test(rawSince) || !/^\d+$/.test(rawLimit) ||
      !Number.isSafeInteger(Number(rawSince)) || !Number.isSafeInteger(Number(rawLimit)) || Number(rawLimit) < 1) {
    return res.status(400).json({ error: 'invalid cursor or limit' });
  }
  const since = Number(rawSince);
  const limit = Math.min(Number(rawLimit), 1000);
  let rows = db.prepare(`SELECT category, key, value_enc, rev, updated_at, deleted FROM sync_items
    WHERE user_id=? AND updated_at>? ORDER BY updated_at ASC, category ASC, key ASC LIMIT ?`).all(req.uid, since, limit);
  // Legacy writes share timestamps. Never split a timestamp group: numeric
  // cursors cannot represent an offset within it. New writes have unique ticks.
  if (rows.length === limit) {
    rows = db.prepare(`SELECT category,key,value_enc,rev,updated_at,deleted FROM sync_items
      WHERE user_id=? AND updated_at>? AND updated_at<=?
      ORDER BY updated_at,category,key`).all(req.uid, since, rows[rows.length - 1].updated_at);
  }
  // server returns opaque ciphertext; client decrypts with user's key
  const out = rows.map(r => ({
    category: r.category, key: r.key, rev: r.rev, ts: r.updated_at,
    value: r.value_enc ? Buffer.from(r.value_enc).toString('base64') : null
  }));
  const maxRow = db.prepare('SELECT COALESCE(MAX(updated_at),0) AS ts FROM sync_items WHERE user_id=?').get(req.uid);
  const serverTime = rows.length ? rows[rows.length - 1].updated_at : maxRow.ts;
  res.json({ items: out, serverTime });
});

// Full snapshot (first login on a device)
app.get('/api/sync/snapshot', authForSync, (req, res) => {
  const rows = db.prepare(`SELECT category, key, value_enc, rev, updated_at FROM sync_items
    WHERE user_id=? AND deleted=0`).all(req.uid);
  const items = rows.map(r => ({
    category: r.category, key: r.key, rev: r.rev, ts: r.updated_at,
    value: r.value_enc ? Buffer.from(r.value_enc).toString('base64') : null
  }));
  const watermark = db.prepare('SELECT COALESCE(MAX(updated_at),0) AS ts FROM sync_items WHERE user_id=?').get(req.uid).ts;
  res.json({ items, serverTime: watermark });
});

// ---------- WebSocket (real-time sync + SSH/SFTP proxy for native clients) ----------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
const userSockets = new Map(); // uid -> Set<ws>

function broadcast(uid, type, data) {
  const set = userSockets.get(uid);
  if (!set) return;
  const msg = JSON.stringify({ type, data });
  for (const ws of set) if (ws.readyState === 1) ws.send(msg);
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const token = url.searchParams.get('token');
  const uid = verifyToken(token);
  if (!uid || (req.headers.origin && !NATIVE_ORIGINS.has(req.headers.origin))) { ws.close(1008, 'unauthorized'); return; }
  const checkSession = () => {
    if (!verifyToken(token)) { ws.close(1008, 'session revoked or expired'); return false; }
    return true;
  };
  const sessionTimer = setInterval(checkSession, 500);
  sessionTimer.unref();
  ws.once('close', () => clearInterval(sessionTimer));
  if (!userSockets.has(uid)) userSockets.set(uid, new Set());
  userSockets.get(uid).add(ws);
  const sshConns = new Map(); // tag -> client
  ws.on('message', (buf) => {
    if (!checkSession()) return;
    let msg; try { msg = JSON.parse(buf.toString()); } catch { return; }
    if (msg.type === 'ssh-open') openSshProxy(ws, uid, msg.data, sshConns);
    else if (msg.type === 'sftp-open') openSftpProxy(ws, uid, msg.data, sshConns);
    else if (msg.type === 'ssh-input' || msg.type === 'ssh-resize') {
      const c = sshConns.get(msg.data?._tag);
      if (!c) return;
      const payload = Buffer.from(msg.data?.data || '', 'base64');
      if (msg.type === 'ssh-input') c.write(payload);
      else c.resize(msg.data?.cols || 80, msg.data?.rows || 24);
    }
    else if (msg.type === 'sftp-op') {
      const c = sshConns.get(msg.data?._tag);
      if (!c || !c.sftp) return;
      handleSftpOp(c.sftp, msg.data, (type, data) => sendTagged(ws, msg.data._tag, type, data));
    }
    else if (msg.type === 'ssh-close' || msg.type === 'sftp-close') {
      const c = sshConns.get(msg.data?._tag);
      if (c) { try { c.client.end(); } catch {} sshConns.delete(msg.data?._tag); }
    }
  });
  ws.on('error', (e) => { try { ws.terminate(); } catch {} });
  ws.on('close', () => {
    userSockets.get(uid)?.delete(ws);
    for (const c of sshConns.values()) { try { c.client.end(); } catch {} }
    sshConns.clear();
  });
});

function sendTagged(ws, tag, type, data) {
  if (ws.readyState === 1) ws.send(JSON.stringify({ type, data: { _tag: tag, ...data } }));
}

// Shared SSH connect (password or keypair w/ optional passphrase)
function buildSshConn(cfg) {
  const { host, port, username, password, privateKey, keyPass } = cfg || {};
  const conn = { host, port: port || 22, username, readyTimeout: 15000, keepaliveInterval: 10000 };
  if (password) conn.password = password;
  else if (privateKey) {
    conn.privateKey = privateKey;
    if (keyPass) conn.passphrase = keyPass;
  }
  return conn;
}

// SSH proxy: web client -> this server -> target host
function openSshProxy(ws, uid, cfg, sshConns) {
  const tag = String(cfg?._tag || Date.now());
  const { host, username, cols, rows } = cfg || {};
  if (!host || !username) { sendTagged(ws, tag, 'ssh-error', { error: 'host+username required' }); return; }
  const conn = buildSshConn(cfg);

  let closed = false;
  const send = (type, data) => { if (!closed && ws.readyState === 1) ws.send(JSON.stringify({ type, data: { _tag: tag, ...data } })); };
  const client = new Client();
  let stream = null;
  const pending = []; // buffer input/resize until shell stream ready
  const flush = () => { if (stream) { for (const p of pending.splice(0)) p(); } };
  const W = Math.max(2, cols || 80), H = Math.max(2, rows || 24);
  const teardown = (reason) => {
    if (closed) return;
    closed = true;
    sshConns.delete(tag);
    try { client.end(); } catch {}
    // notify this tag only — never close the whole WS (other tabs may be active)
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'ssh-terminated', data: { _tag: tag, reason: reason || 'closed' } }));
  };
  client.on('ready', () => {
    client.shell({ pty: { cols: W, rows: H, term: 'xterm-256color', modes: {} } }, (err, s) => {
      if (err) { send('ssh-error', { error: String(err) }); teardown('shell: ' + err.message); return; }
      stream = s;
      s.on('data', d => send('ssh-data', { data: d.toString('base64') }));
      s.stderr?.on('data', d => send('ssh-data', { data: d.toString('base64') }));
      s.on('close', () => teardown('shell closed'));
      send('ssh-ready', {});
      flush();
    });
  });
  client.on('error', (e) => send('ssh-error', { error: String(e.message || e) }));
  client.on('close', () => teardown('connection closed'));
  ws.on('close', () => teardown('ws closed'));
  sshConns.set(tag, {
    client,
    write: (buf) => stream ? stream.write(buf) : pending.push(() => stream && stream.write(buf)),
    resize: (c, r) => stream && stream.setWindow ? stream.setWindow(c, r, 0, 0) : pending.push(() => stream && stream.setWindow && stream.setWindow(c, r, 0, 0))
  });
  try { client.connect(conn); }
  catch (e) { send('ssh-error', { error: String(e.message || e) }); teardown('connect: ' + (e.message || e)); }
}

// SFTP proxy: client issues ops (list/read/write/mkdir/rmdir/unlink/mkdirs/rename/stat)
function openSftpProxy(ws, uid, cfg, sshConns) {
  const tag = String(cfg?._tag || Date.now());
  const { host, username } = cfg || {};
  if (!host || !username) { sendTagged(ws, tag, 'sftp-error', { error: 'host+username required' }); return; }
  const conn = buildSshConn(cfg);
  const client = new Client();
  let sftp = null;
  client.on('ready', () => {
    client.sftp((err, s) => {
      if (err) { sendTagged(ws, tag, 'sftp-error', { error: String(err.message || err) }); return; }
      sftp = s;
      sshConns.set(tag, { client, sftp });
      sendTagged(ws, tag, 'sftp-ready', { cwd: '' });
    });
  });
  client.on('error', (e) => { sendTagged(ws, tag, 'sftp-error', { error: String(e.message || e) }); sshConns.delete(tag); });
  client.on('close', () => { sshConns.delete(tag); sendTagged(ws, tag, 'sftp-terminated', { reason: 'connection closed' }); });
  ws.on('close', () => { sshConns.delete(tag); try { client.end(); } catch {} });
  sshConns.set(tag, { client, get sftp() { return sftp; } });
  try { client.connect(conn); }
  catch (e) { sendTagged(ws, tag, 'sftp-error', { error: String(e.message || e) }); sshConns.delete(tag); }
}

function handleSftpOp(sftp, d, reply) {
  try {
    const op = d.op, path = String(d.path || '/');
    if (op === 'list') {
      sftp.readdir(d.path || '/', (err, entries) => {
        if (err) return reply('sftp-error', { error: String(err.message || err) });
        reply('sftp-list', {
          path: d.path || '/',
          files: entries.map(e => ({
            name: e.filename,
            size: e.attrs && e.attrs.size ? e.attrs.size : 0,
            time: e.attrs && e.attrs.mtime ? e.attrs.mtime * 1000 : 0,
            isDir: e.attrs ? (e.attrs.mode & 0o170000) === 0o040000 : (e.longname || '').startsWith('d')
          }))
        });
      });
    }
    else if (op === 'stat') {
      sftp.lstat(path, (err, stats) => {
        if (err) return reply('sftp-error', { error: String(err.message || err) });
        reply('sftp-stat', { path, size: stats.size, mtime: (stats.mtime || 0) * 1000, isDir: stats.isDirectory() });
      });
    }
    else if (op === 'mkdir') {
      sftp.mkdir(path, d.mode ? parseInt(d.mode, 8) : 0o755, (err) => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path }));
    }
    else if (op === 'rmdir') {
      sftp.rmdir(path, (err) => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path }));
    }
    else if (op === 'unlink') {
      sftp.unlink(path, (err) => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path }));
    }
    else if (op === 'rename') {
      sftp.rename(path, String(d.to || ''), (err) => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path, to: d.to }));
    }
    else if (op === 'read') {
      let done = false;
      const rreply = (type, data) => { if (!done) { done = true; reply(type, data); } };
      sftp.createReadStream(path, { start: d.start || 0, end: (d.end || (d.start || 0) + 1048576) - 1 })
        .on('data', chunk => reply('sftp-data', { path, data: chunk.toString('base64') }))
        .on('end', () => rreply('sftp-end', { path }))
        .on('error', e => rreply('sftp-error', { error: String(e.message || e) }));
    }
    else if (op === 'write') {
      const buf = Buffer.from(d.data || '', 'base64');
      let done = false;
      const wreply = (type, data) => { if (!done) { done = true; reply(type, data); } };
      sftp.createWriteStream(path, { start: d.start || 0, flags: d.append ? 'a' : 'w' })
        .on('close', () => wreply('sftp-ok', { path, bytes: buf.length }))
        .on('error', e => wreply('sftp-error', { error: String(e.message || e) }))
        .end(buf);
    }
    else reply('sftp-error', { error: 'unknown op: ' + op });
  } catch (e) {
    reply('sftp-error', { error: String(e.message || e) });
  }
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[tiassh] sync server listening on 0.0.0.0:${PORT}`);
  console.log(`[tiassh] web app: ${PUBLIC_URL}`);
  console.log(`[tiassh] data dir: ${DATA_DIR}`);
});

process.on('uncaughtException', (e) => { console.error('[tiassh] UNCAUGHT:', e.stack || e.message); });
process.on('unhandledRejection', (e) => { console.error('[tiassh] UNHANDLED REJECTION:', e); });
