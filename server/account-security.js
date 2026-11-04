'use strict';
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function decode(secret) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const raw of String(secret || '')) {
    const char = raw.toUpperCase();
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error('invalid base32');
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }
  return Buffer.from(bytes);
}

function totp(secret, counter, digits = 6) {
  const input = Buffer.alloc(8);
  input.writeBigUInt64BE(BigInt(counter));
  const hash = crypto.createHmac('sha1', decode(secret)).update(input).digest();
  const offset = hash[19] & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits)).padStart(digits, '0');
}

function digest(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

function migrate(db) {
  const add = (table, name, type) => {
    if (!db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
    }
  };

  transaction(db, () => {
    add('users', 'totp_secret', 'TEXT');
    add('users', 'last_otp', 'INTEGER NOT NULL DEFAULT -1');
    add('users', 'auth_revision', 'INTEGER NOT NULL DEFAULT 1');
    add('users', 'display_name', "TEXT NOT NULL DEFAULT ''");

    add('sessions', 'scope', "TEXT NOT NULL DEFAULT 'client'");
    add('sessions', 'issued_at', 'INTEGER NOT NULL DEFAULT 0');
    add('sessions', 'expires_at', 'INTEGER NOT NULL DEFAULT 0');
    add('sessions', 'revoked', 'INTEGER NOT NULL DEFAULT 0');
    add('sessions', 'auth_revision', 'INTEGER NOT NULL DEFAULT 1');

    db.exec(`
      CREATE TABLE IF NOT EXISTS enrollments(
        challenge_hash TEXT PRIMARY KEY,
        user_id INTEGER,
        email TEXT NOT NULL,
        pass_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        secret TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        last_otp INTEGER NOT NULL DEFAULT -1,
        kind TEXT NOT NULL DEFAULT 'register',
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
      CREATE TABLE IF NOT EXISTS recovery_keys(
        id INTEGER PRIMARY KEY CHECK (id=1),
        key_hash TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_uid_scope ON sessions(user_id, scope, revoked, expires_at);
    `);

    add('enrollments', 'auth_revision', 'INTEGER NOT NULL DEFAULT 1');
    // Legacy unlimited bearer sessions are deliberately revoked on migration.
    db.prepare('UPDATE sessions SET revoked=1 WHERE expires_at=0').run();
  });
}

function issueSession(db, userId, scope, ttlSec = 7 * 24 * 3600) {
  const token = crypto.randomBytes(32).toString('base64url');
  const user = db.prepare('SELECT auth_revision FROM users WHERE id=?').get(userId);
  if (!user) return null;
  const now = Date.now();
  db.prepare('INSERT INTO sessions(token,user_id,scope,issued_at,expires_at,revoked,auth_revision,created_at) VALUES(?,?,?,?,?,?,?,datetime(\'now\'))')
    .run(token, userId, scope, now, now + ttlSec * 1000, 0, user.auth_revision);
  return token;
}

function lookupSession(db, token, scope) {
  if (!token || typeof token !== 'string') return null;
  const row = db.prepare(`
    SELECT s.token,s.user_id,s.scope,s.issued_at,s.expires_at,s.revoked,s.auth_revision AS session_auth_revision,
           u.email,u.salt,u.auth_revision,u.totp_secret,u.last_otp,u.pass_hash,u.display_name
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?
  `).get(token);
  if (!row) return null;
  if (scope && row.scope !== scope) return null;
  if (row.revoked) return null;
  if (row.expires_at <= Date.now()) return null;
  if (row.session_auth_revision !== row.auth_revision) return null;
  return {
    token: row.token,
    id: row.user_id,
    scope: row.scope,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    email: row.email,
    salt: row.salt,
    authRevision: row.auth_revision,
    totpSecret: row.totp_secret,
    lastOtp: row.last_otp,
    passHash: row.pass_hash,
    displayName: row.display_name,
  };
}

function otpCounter(secret, otp, last = -1, now = Date.now()) {
  if (typeof otp !== 'string' || !/^\d{6}$/.test(otp) || !secret) return null;
  const current = Math.floor(now / 30000);
  for (const ctr of [current, current - 1, current + 1]) {
    if (ctr <= last) continue;
    if (crypto.timingSafeEqual(Buffer.from(otp), Buffer.from(totp(secret, ctr)))) return ctr;
  }
  return null;
}


function revokeAllSessions(db, userId, scope = null) {
  if (scope) db.prepare('UPDATE sessions SET revoked=1 WHERE user_id=? AND scope=?').run(userId, scope);
  else db.prepare('UPDATE sessions SET revoked=1 WHERE user_id=?').run(userId);
}

function newEnrollment(db, { userId = null, email, passHash, salt, kind }) {
  const challenge = crypto.randomBytes(32).toString('base64url');
  const secret = base32(crypto.randomBytes(20));
  const challengeHash = digest(challenge);
  const expiresAt = Date.now() + 10 * 60 * 1000;
  const authRevision = userId ? (db.prepare('SELECT auth_revision FROM users WHERE id=?').get(userId)?.auth_revision || 1) : 1;
  db.prepare('DELETE FROM enrollments WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO enrollments(challenge_hash,user_id,email,pass_hash,salt,secret,expires_at,kind,last_otp,auth_revision) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(challengeHash, userId, email, passHash, salt, secret, expiresAt, kind, -1, authRevision);
  return {
    challenge,
    secret,
    expiresIn: 600,
    otpauthUrl: `otpauth://totp/${encodeURIComponent(`TiaSSH:${email}`)}?secret=${secret}&issuer=TiaSSH&algorithm=SHA1&digits=6&period=30`,
  };
}

function consumeEnrollment(db, challenge, otp) {
  const row = db.prepare('SELECT * FROM enrollments WHERE challenge_hash=? AND expires_at>?').get(digest(challenge || ''), Date.now());
  if (!row) return { ok: false };
  if (row.user_id) {
    const current = db.prepare('SELECT auth_revision FROM users WHERE id=?').get(row.user_id);
    if (!current || current.auth_revision !== row.auth_revision) return { ok: false };
  }
  const counter = otpCounter(row.secret, otp, row.last_otp);
  if (counter === null) return { ok: false };
  db.prepare('UPDATE enrollments SET last_otp=? WHERE challenge_hash=?').run(counter, row.challenge_hash);
  return { ok: true, row, counter };
}

function setAuthRevision(db, userId) {
  db.prepare('UPDATE users SET auth_revision=auth_revision+1 WHERE id=?').run(userId);
}

function verifyPassword(user, password) {
  return !!user && typeof password === 'string' && bcrypt.compareSync(password, user.passHash || user.pass_hash);
}

function installWebRoutes(app, db, opts = {}) {
  const webOrigin = opts.webOrigin;
  const sessionTtlSec = opts.sessionTtlSec || 3600;

  const emailOK = (email) => typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const passwordOK = (password) => typeof password === 'string' && password.length >= 12 && Buffer.byteLength(password) <= 72;

  function requireWebOrigin(req, res, next) {
    if (!webOrigin) return next();
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    const origin = req.headers.origin;
    if (origin !== webOrigin) return res.status(403).json({ error: 'origin ditolak' });
    next();
  }

  function parseCookie(req, name) {
    const raw = req.headers.cookie || '';
    const found = raw.split(';').map((v) => v.trim()).find((part) => part.startsWith(`${name}=`));
    return found ? found.slice(name.length + 1) : null;
  }

  function webAuth(req, res, next) {
    const token = parseCookie(req, 'tiassh_web');
    const session = lookupSession(db, token, 'web');
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    req.webSession = session;
    next();
  }

  function requirePasswordAndOtp(req, res) {
    const { currentPassword, otp } = req.body || {};
    if (!verifyPassword(req.webSession, currentPassword)) {
      res.status(401).json({ error: 'sandi salah' });
      return null;
    }
    const counter = otpCounter(req.webSession.totpSecret, otp, req.webSession.lastOtp);
    if (counter === null) {
      res.status(401).json({ error: 'OTP tidak valid atau sudah dipakai' });
      return null;
    }
    return counter;
  }

  app.post('/api/web/register', requireWebOrigin, (req, res) => {
    const { email, password } = req.body || {};
    const normalized = String(email || '').toLowerCase();
    if (!emailOK(normalized) || !passwordOK(password)) {
      return res.status(400).json({ error: 'email valid dan sandi 12-72 byte wajib' });
    }
    if (db.prepare('SELECT id FROM users WHERE email=?').get(normalized)) {
      return res.status(409).json({ error: 'email sudah terdaftar' });
    }
    const passHash = bcrypt.hashSync(password, 12);
    const salt = crypto.randomBytes(16).toString('base64url');
    return res.json(newEnrollment(db, { email: normalized, passHash, salt, kind: 'register' }));
  });

  app.post('/api/web/enroll/confirm', requireWebOrigin, (req, res) => {
    const { challenge, otp } = req.body || {};
    const consumed = consumeEnrollment(db, challenge, otp);
    if (!consumed.ok) return res.status(401).json({ error: 'tantangan/otp tidak valid' });

    const { row, counter } = consumed;
    try {
      transaction(db, () => {
        if (row.kind === 'register') {
          db.prepare('INSERT INTO users(email,pass_hash,salt,totp_secret,last_otp,auth_revision) VALUES(?,?,?,?,?,1)')
            .run(row.email, row.pass_hash, row.salt, row.secret, counter);
        } else {
          db.prepare('UPDATE users SET totp_secret=?, last_otp=?, auth_revision=auth_revision+1 WHERE id=?')
            .run(row.secret, counter, row.user_id);
          revokeAllSessions(db, row.user_id);
        }
        db.prepare('DELETE FROM enrollments WHERE challenge_hash=?').run(row.challenge_hash);
      });
    } catch {
      return res.status(409).json({ error: 'gagal menyimpan enrollment' });
    }
    return res.json({ ok: true });
  });

  app.post('/api/web/login', requireWebOrigin, (req, res) => {
    const { email, password, otp } = req.body || {};
    const normalized = String(email || '').toLowerCase();
    const user = db.prepare('SELECT id,email,pass_hash,salt,totp_secret,last_otp,auth_revision,display_name FROM users WHERE email=?').get(normalized);
    if (!user || !bcrypt.compareSync(String(password || ''), user.pass_hash)) {
      return res.status(401).json({ error: 'kredensial salah' });
    }

    if (!user.totp_secret) {
      const enroll = newEnrollment(db, {
        userId: user.id,
        email: user.email,
        passHash: user.pass_hash,
        salt: user.salt,
        kind: 'legacy-enroll',
      });
      return res.status(202).json({ requiresTotpEnrollment: true, ...enroll });
    }

    const counter = otpCounter(user.totp_secret, otp, user.last_otp);
    if (counter === null) return res.status(401).json({ error: 'otp wajib dan harus fresh' });

    const token = transaction(db, () => {
      db.prepare('UPDATE users SET last_otp=? WHERE id=?').run(counter, user.id);
      return issueSession(db, user.id, 'web', sessionTtlSec);
    });

    const isSecure = webOrigin ? new URL(webOrigin).protocol === 'https:' : !!req.socket.encrypted;
    res.setHeader('Set-Cookie', `tiassh_web=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionTtlSec}${isSecure ? '; Secure' : ''}`);
    return res.json({ ok: true, email: user.email, authRevision: user.auth_revision, displayName: user.display_name || '' });
  });

  app.get('/api/web/me', webAuth, (req,res) => res.json({ email:req.webSession.email, displayName:req.webSession.displayName, authRevision:req.webSession.authRevision, totpEnabled:true }));

  app.post('/api/web/profile', requireWebOrigin, webAuth, (req, res) => {
    const counter = requirePasswordAndOtp(req, res);
    if (counter === null) return;
    const displayName = String(req.body?.displayName || '').trim().slice(0, 80);
    transaction(db, () => {
      db.prepare('UPDATE users SET display_name=?, last_otp=? WHERE id=?').run(displayName, counter, req.webSession.id);
    });
    return res.json({ ok: true, displayName });
  });

  app.post('/api/web/password', requireWebOrigin, webAuth, (req, res) => {
    const counter = requirePasswordAndOtp(req, res);
    if (counter === null) return;
    const { newPassword } = req.body || {};
    if (!passwordOK(newPassword)) return res.status(400).json({ error: 'sandi baru 12-72 byte wajib' });

    transaction(db, () => {
      const user = db.prepare('SELECT salt FROM users WHERE id=?').get(req.webSession.id);
      db.prepare('UPDATE users SET pass_hash=?, last_otp=?, auth_revision=auth_revision+1 WHERE id=?')
        .run(bcrypt.hashSync(newPassword, 12), counter, req.webSession.id);
      // Salt remains unchanged by design.
      void user;
      revokeAllSessions(db, req.webSession.id);
    });
    return res.json({ ok: true });
  });

  app.post('/api/web/totp/reset', requireWebOrigin, webAuth, (req, res) => {
    const counter = requirePasswordAndOtp(req, res);
    if (counter === null) return;
    db.prepare('UPDATE users SET last_otp=? WHERE id=?').run(counter, req.webSession.id);
    const enroll = newEnrollment(db, {
      userId: req.webSession.id,
      email: req.webSession.email,
      passHash: req.webSession.passHash,
      salt: req.webSession.salt,
      kind: 'legacy-enroll',
    });
    return res.json({ ok: true, ...enroll });
  });

  app.post('/api/web/logout', requireWebOrigin, webAuth, (req, res) => {
    db.prepare('UPDATE sessions SET revoked=1 WHERE token=?').run(req.webSession.token);
    res.setHeader('Set-Cookie', 'tiassh_web=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return res.json({ ok: true });
  });

  return { webAuth, requireWebOrigin };
}

function initializeRecoveryKey(db, key) {
  if (typeof key !== 'string' || key.length < 32) throw new Error('invalid recovery key');
  db.prepare('INSERT INTO recovery_keys(id,key_hash) VALUES(1,?)').run(digest('recovery:'+key));
}
function adminResetByEmail(db, { recoveryKey, email, newPassword }) {
  const verifier=db.prepare('SELECT key_hash FROM recovery_keys WHERE id=1').get();
  const hash=digest('recovery:'+String(recoveryKey||''));
  if (!verifier || !crypto.timingSafeEqual(Buffer.from(verifier.key_hash),Buffer.from(hash))) throw new Error('Recovery key ditolak');
  if (typeof newPassword!=='string' || newPassword.length<12 || Buffer.byteLength(newPassword)>72) throw new Error('Sandi harus 12–72 byte');
  const user=db.prepare('SELECT id FROM users WHERE email=?').get(String(email).toLowerCase());
  if (!user) throw new Error('Akun tidak ditemukan');
  const hashPassword=bcrypt.hashSync(newPassword,12);
  transaction(db,()=>{
    db.prepare('UPDATE users SET pass_hash=?,totp_secret=NULL,last_otp=-1,auth_revision=auth_revision+1 WHERE id=?').run(hashPassword,user.id);
    revokeAllSessions(db,user.id);
    db.prepare('DELETE FROM enrollments WHERE user_id=?').run(user.id);
  });
  return {ok:true};
}
module.exports = {
  initializeRecoveryKey,
  adminResetByEmail,
  base32,
  totp,
  digest,
  migrate,
  transaction,
  otpCounter,

  issueSession,
  lookupSession,
  revokeAllSessions,
  setAuthRevision,
  verifyPassword,
  installWebRoutes,
};