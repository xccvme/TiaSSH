'use strict';

const CHANNELS = Object.freeze(['ssh-open', 'ssh-input', 'ssh-resize', 'ssh-close', 'sftp-open', 'sftp-op', 'sftp-close']);

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function createTransport({ createClient, send, pinStorePath }) {
  const sessions = new Map();
  // In-memory storage is for injected test transports only; main supplies userData.
  let memoryPins = {};

  function verifyHost(d, session, key) {
    try {
      const fingerprint = 'SHA256:' + crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
      const scope = JSON.stringify([d.server || '', d.accountId || '', d.host.toLowerCase(), d.port || 22]);
      let pins = memoryPins;
      if (pinStorePath && fs.existsSync(pinStorePath)) {
        pins = JSON.parse(fs.readFileSync(pinStorePath, 'utf8'));
        if (!pins || typeof pins !== 'object' || Array.isArray(pins) || Object.values(pins).some(v => typeof v !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(v))) throw new Error('invalid pin store');
      }
      if (Object.hasOwn(pins, scope) && pins[scope] !== fingerprint) {
        throw new Error(`SSH host key changed for ${d.host}:${d.port || 22}; expected ${pins[scope]}, received ${fingerprint}. Connection rejected before authentication. Verify the server key independently before removing its saved pin.`);
      }
      if (!Object.hasOwn(pins, scope)) {
        pins[scope] = fingerprint;
        if (pinStorePath) {
          fs.mkdirSync(path.dirname(pinStorePath), { recursive: true, mode: 0o700 });
          const temp = pinStorePath + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
          try {
            fs.writeFileSync(temp, JSON.stringify(pins), { mode: 0o600, flag: 'wx' });
            fs.renameSync(temp, pinStorePath);
          } finally { try { fs.unlinkSync(temp); } catch {} }
        } else memoryPins = pins;
      }
      return true;
    } catch (err) {
      session.verificationError = `Host key verification failed: ${err.message}`;
      return false;
    }
  }

  const clamp = (n, fallback) => Number.isInteger(n) ? Math.max(2, Math.min(1000, n)) : fallback;

  function sendTagged(type, tag, data = {}) {
    send({ type, data: { _tag: tag, ...data } });
  }

  function buildConnConfig(d, session) {
    const config = {
      host: d.host,
      port: d.port || 22,
      username: d.username,
      readyTimeout: 15000,
      keepaliveInterval: 10000,
      hostVerifier: key => verifyHost(d, session, key)
    };
    if (d.password) config.password = d.password;
    else if (d.privateKey) {
      config.privateKey = d.privateKey;
      if (d.keyPass) config.passphrase = d.keyPass;
    }
    return config;
  }

  function closeSession(tag, reason, expected) {
    const session = sessions.get(tag);
    if (!session || session.closed || (expected && session !== expected)) return;
    session.closed = true;
    session.pending.length = 0;
    sessions.delete(tag);
    try { session.client.end(); } catch {}
    sendTagged(`${session.kind}-terminated`, tag, { reason: reason || 'closed' });
  }

  function requireTag(message) {
    if (!message || !message.data || typeof message.data._tag !== 'string' || !message.data._tag || message.data._tag.length > 256) {
      throw new Error('invalid routing tag');
    }
    return message.data._tag;
  }

  function ensureOpenPayload(d) {
    if (typeof d.host !== 'string' || !d.host || typeof d.username !== 'string' || !d.username) {
      throw new Error('host+username required');
    }
    if (d.port !== undefined && (!Number.isInteger(d.port) || d.port < 1 || d.port > 65535)) {
      throw new Error('invalid SSH port');
    }
  }

  function handleSftpOp(sftp, d, reply) {
    const op = d.op;
    const remotePath = String(d.path || '/');
    if (op === 'list') {
      sftp.readdir(d.path || '/', (err, entries) => {
        if (err) return reply('sftp-error', { error: String(err.message || err) });
        reply('sftp-list', {
          path: d.path || '/',
          files: (entries || []).map(e => ({
            name: e.filename,
            size: e.attrs && e.attrs.size ? e.attrs.size : 0,
            time: e.attrs && e.attrs.mtime ? e.attrs.mtime * 1000 : 0,
            isDir: e.attrs ? (e.attrs.mode & 0o170000) === 0o040000 : (e.longname || '').startsWith('d')
          }))
        });
      });
      return;
    }
    if (op === 'stat') {
      sftp.lstat(remotePath, (err, stats) => {
        if (err) return reply('sftp-error', { error: String(err.message || err) });
        reply('sftp-stat', { path: remotePath, size: stats.size, mtime: (stats.mtime || 0) * 1000, isDir: stats.isDirectory() });
      });
      return;
    }
    if (op === 'mkdir') {
      sftp.mkdir(remotePath, d.mode ? parseInt(d.mode, 8) : 0o755, err => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path: remotePath }));
      return;
    }
    if (op === 'rmdir') {
      sftp.rmdir(remotePath, err => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path: remotePath }));
      return;
    }
    if (op === 'unlink') {
      sftp.unlink(remotePath, err => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path: remotePath }));
      return;
    }
    if (op === 'rename') {
      sftp.rename(remotePath, String(d.to || ''), err => reply(err ? 'sftp-error' : 'sftp-ok', err ? { error: String(err.message || err) } : { path: remotePath, to: d.to }));
      return;
    }
    if (op === 'read') {
      let done = false;
      const once = (type, data) => { if (!done) { done = true; reply(type, data); } };
      const options = {};
      if (Number.isInteger(d.start) && d.start >= 0) options.start = d.start;
      if (Number.isInteger(d.end) && d.end > (d.start || 0)) options.end = d.end - 1;
      sftp.createReadStream(remotePath, options)
        .on('data', chunk => reply('sftp-data', { path: remotePath, data: chunk.toString('base64') }))
        .on('end', () => once('sftp-end', { path: remotePath }))
        .on('error', e => once('sftp-error', { error: String(e.message || e) }));
      return;
    }
    if (op === 'write') {
      const buf = Buffer.from(d.data || '', 'base64');
      let done = false;
      const once = (type, data) => { if (!done) { done = true; reply(type, data); } };
      const options = { flags: d.append ? 'a' : 'w' };
      if (!d.append && Number.isInteger(d.start) && d.start >= 0) options.start = d.start;
      sftp.createWriteStream(remotePath, options)
        .on('close', () => once('sftp-ok', { path: remotePath, bytes: buf.length }))
        .on('error', e => once('sftp-error', { error: String(e.message || e) }))
        .end(buf);
      return;
    }
    reply('sftp-error', { error: 'unknown op: ' + op });
  }

  function handle(message) {
    if (!message || !CHANNELS.includes(message.type)) throw new Error('unsupported transport message');
    const tag = requireTag(message);
    const d = message.data;
    try {

    if (message.type === 'ssh-open') {
      ensureOpenPayload(d);
      closeSession(tag, 'reopened');
      const client = createClient();
      const session = { kind: 'ssh', tag, client, stream: null, pending: [], closed: false };
      sessions.set(tag, session);

      const fail = err => {
        if (sessions.get(tag) !== session || session.closed) return;
        sendTagged('ssh-error', tag, { error: session.verificationError || String(err.message || err) });
      };
      client.on('error', err => fail(err));
      client.on('close', () => closeSession(tag, 'connection closed', session));
      client.on('ready', () => {
        if (session.closed) return;
        client.shell({ pty: { cols: clamp(d.cols, 80), rows: clamp(d.rows, 24), term: 'xterm-256color', modes: {} } }, (err, stream) => {
          if (session.closed) { try { stream && stream.end(); } catch {} return; }
          if (err) { fail(err); closeSession(tag, 'shell error', session); return; }
          session.stream = stream;
          const emitIfCurrent = (type, payload) => {
            if (sessions.get(tag) !== session || session.closed) return;
            sendTagged(type, tag, payload);
          };
          stream.on('data', chunk => emitIfCurrent('ssh-data', { data: chunk.toString('base64') }));
          stream.stderr?.on('data', chunk => emitIfCurrent('ssh-data', { data: chunk.toString('base64') }));
          stream.on('error', err => { fail(err); closeSession(tag, 'shell error', session); });
          stream.on('close', () => closeSession(tag, 'shell closed', session));
          emitIfCurrent('ssh-ready', {});
          for (const fn of session.pending.splice(0)) fn();
        });
      });

      try { client.connect(buildConnConfig(d, session)); }
      catch (err) { fail(err); closeSession(tag, 'connect error', session); }
      return;
    }

    if (message.type === 'sftp-open') {
      ensureOpenPayload(d);
      closeSession(tag, 'reopened');
      const client = createClient();
      const session = { kind: 'sftp', tag, client, sftp: null, pending: [], closed: false };
      sessions.set(tag, session);

      const fail = err => {
        if (sessions.get(tag) !== session || session.closed) return;
        sendTagged('sftp-error', tag, { error: session.verificationError || String(err.message || err) });
      };
      client.on('error', err => fail(err));
      client.on('close', () => closeSession(tag, 'connection closed', session));
      client.on('ready', () => {
        if (session.closed) return;
        client.sftp((err, sftp) => {
          if (session.closed) { try { sftp && sftp.end && sftp.end(); } catch {} return; }
          if (err) { fail(err); closeSession(tag, 'sftp error', session); return; }
          session.sftp = sftp;
          sendTagged('sftp-ready', tag, { cwd: '' });
          for (const fn of session.pending.splice(0)) fn();
        });
      });

      try { client.connect(buildConnConfig(d, session)); }
      catch (err) { fail(err); closeSession(tag, 'connect error', session); }
      return;
    }

    if (message.type === 'ssh-close' || message.type === 'sftp-close') {
      closeSession(tag, 'closed');
      return;
    }

    const session = sessions.get(tag);
    if (!session || session.closed) return;

    if (message.type === 'ssh-input' || message.type === 'ssh-resize') {
      if (session.kind !== 'ssh') return;
      const run = message.type === 'ssh-input'
        ? () => session.stream && session.stream.write(Buffer.from(d.data || '', 'base64'))
        : () => session.stream && session.stream.setWindow(clamp(d.rows, 24), clamp(d.cols, 80), 0, 0);
      if (session.stream) run();
      else if (session.pending.length < 256) session.pending.push(run);
      else sendTagged('ssh-error', tag, { error: 'SSH pending input limit exceeded' });
      return;
    }

    if (message.type === 'sftp-op') {
      if (session.kind !== 'sftp') return;
      const run = () => {
        const reply = (type, data) => {
          if (sessions.get(tag) !== session || session.closed) return;
          sendTagged(type, tag, data);
        };
        try { handleSftpOp(session.sftp, d, reply); }
        catch (err) { reply('sftp-error', { error: String(err.message || err) }); }
      };
      if (session.sftp) run();
      else if (session.pending.length < 64) session.pending.push(run);
      else sendTagged('sftp-error', tag, { error: 'SFTP pending operation limit exceeded' });
    }
    } catch (err) {
      sendTagged(message.type.startsWith('sftp-') ? 'sftp-error' : 'ssh-error', tag, { error: String(err.message || err) });
    }
  }

  function dispose() {
    for (const tag of [...sessions.keys()]) closeSession(tag, 'renderer closed');
  }

  return { handle, dispose };
}

module.exports = { CHANNELS, createTransport };
