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

const email = 'session@example.test';
const password = 'Session-test-password-123!';
let child, dir, base, db, port;

async function api(url, { body, token, headers = {}, method } = {}) {
  const response = await fetch(base + url, {
    method: method || (body ? 'POST' : 'GET'),
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data, headers: response.headers };
}

async function nativeLogin() {
  const response = await api('/api/login', {
    body: { email, password },
    headers: { Origin: 'http://localhost' },
  });
  assert.equal(response.status, 200);
  return response.data;
}

test.before(async () => {
  dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'client-session-test-'));
  port = 25000 + Math.floor(Math.random() * 4000);
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      DATA_DIR: dir,
      MASTER_KEY: 'test-only-master-key',
      PORT: String(port),
      PUBLIC_URL: `http://127.0.0.1:${port}`,
      WEB_ORIGIN: `http://127.0.0.1:${port}`,
      SESSION_TTL_SEC: '3600',
      CLIENT_SESSION_TTL_SEC: '',
    },
  });

  let output = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(output)), 10000);
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.includes('listening on 0.0.0.0')) {
        base = `http://127.0.0.1:${port}`;
        clearTimeout(timer);
        resolve();
      }
    });
    child.stderr.on('data', chunk => { output += chunk; });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`exit ${code}: ${output}`)); });
  });

  db = new DatabaseSync(path.join(dir, 'tiassh.db'));
  db.prepare('INSERT INTO users(email,pass_hash,salt,totp_secret,last_otp,auth_revision) VALUES(?,?,?,?,?,?)')
    .run(email, bcrypt.hashSync(password, 4), 'fixed-salt', sec.base32(Buffer.alloc(20, 3)), -1, 1);
});

test.after(async () => {
  db?.close();
  if (child && child.exitCode === null) {
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill();
    await exited;
  }
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('HTTP native login issues a DB-authoritative fixed 36-hour session', async () => {
  const before = Date.now();
  const session = await nativeLogin();
  assert.ok(Number.isSafeInteger(session.issuedAt));
  assert.ok(Number.isSafeInteger(session.expiresAt));
  assert.equal(session.expires_at, session.expiresAt);
  assert.ok(session.issuedAt >= before && session.issuedAt <= Date.now());
  assert.equal(session.expiresAt - session.issuedAt, 129600000);

  const row = db.prepare('SELECT token, scope, issued_at, expires_at FROM sessions WHERE token=?').get(session.token);
  assert.equal(row.scope, 'client');
  assert.equal(row.issued_at, session.issuedAt);
  assert.equal(row.expires_at, session.expiresAt);
});

test('/api/me returns same authoritative expiry and does not slide-renew', async () => {
  const session = await nativeLogin();
  const firstRow = db.prepare('SELECT issued_at, expires_at FROM sessions WHERE token=?').get(session.token);

  const me1 = await api('/api/me', { token: session.token });
  assert.equal(me1.status, 200);
  assert.equal(me1.data.issuedAt, firstRow.issued_at);
  assert.equal(me1.data.expiresAt, firstRow.expires_at);
  assert.equal(me1.data.expires_at, firstRow.expires_at);

  await new Promise(resolve => setTimeout(resolve, 20));
  const me2 = await api('/api/me', { token: session.token });
  assert.equal(me2.status, 200);

  const secondRow = db.prepare('SELECT issued_at, expires_at FROM sessions WHERE token=?').get(session.token);
  assert.equal(secondRow.issued_at, firstRow.issued_at);
  assert.equal(secondRow.expires_at, firstRow.expires_at);
});

test('expired native session is forbidden over HTTP and WS closes with policy violation', async () => {
  const session = await nativeLogin();
  db.prepare('UPDATE sessions SET expires_at=? WHERE token=?').run(Date.now() - 1, session.token);

  const me = await api('/api/me', { token: session.token });
  assert.equal(me.status, 401);

  const ws = new WebSocket(`${base.replace('http', 'ws')}/ws?token=${encodeURIComponent(session.token)}`);
  const closeCode = await new Promise((resolve) => {
    ws.once('close', (code) => resolve(code));
    ws.once('error', () => resolve(1006));
  });
  assert.equal(closeCode, 1008);
});

test('revoked native session is forbidden over HTTP', async () => {
  const session = await nativeLogin();
  db.prepare('UPDATE sessions SET revoked=1 WHERE token=?').run(session.token);
  const me = await api('/api/me', { token: session.token });
  assert.equal(me.status, 401);
});
