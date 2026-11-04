const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createTransport } = require('../transport');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

test('TOFU SHA256 pins persist and reject changed keys before authentication', t => {
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'desktop-pins-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const pinStorePath = path.join(dir, 'pins.json');
  const open = (accountId = '') => {
    const clients = [], messages = [];
    const transport = createTransport({ pinStorePath, createClient() { const c = new FakeClient(); clients.push(c); return c; }, send(m) { messages.push(m); } });
    transport.handle({ type: 'ssh-open', data: { _tag: 'x', host: 'localhost', username: 'u', password: 'secret', accountId, server: 'https://sync.example' } });
    t.after(() => transport.dispose());
    return { client: clients[0], messages };
  };
  const first = open();
  assert.equal(typeof first.client.config.hostVerifier, 'function');
  assert.equal(first.client.config.hostVerifier(Buffer.from('key-one')), true);
  assert.ok(fs.readFileSync(pinStorePath, 'utf8').includes('SHA256:' + crypto.createHash('sha256').update('key-one').digest('base64').replace(/=+$/, '')));
  const second = open();
  assert.equal(second.client.config.hostVerifier(Buffer.from('key-one')), true);
  assert.equal(second.client.config.hostVerifier(Buffer.from('key-two')), false);
  second.client.emit('error', new Error('Host denied (verification failed)'));
  assert.match(second.messages.at(-1).data.error, /host key changed.*SHA256:/i);
  assert.equal(open('another-account').client.config.hostVerifier(Buffer.from('key-two')), true);
  fs.writeFileSync(pinStorePath, 'invalid json');
  assert.equal(open().client.config.hostVerifier(Buffer.from('key-one')), false);
});

class FakeClient extends EventEmitter {
  connect(config) { this.config = config; }
  end() { this.ended = true; this.emit('close'); }
  shell(options, cb) { this.pty = options.pty; this.shellCallback = cb; }
  sftp(cb) { this.sftpCallback = cb; }
}

function setup() {
  const clients = [];
  const messages = [];
  const transport = createTransport({
    createClient() { const c = new FakeClient(); clients.push(c); return c; },
    send(m) { messages.push(m); }
  });
  return { transport, clients, messages };
}

test('SSH shell bridge preserves tags, buffers input, and applies resize rows/cols order', () => {
  const { transport, clients, messages } = setup();
  transport.handle({ type: 'ssh-open', data: { _tag: 'tab1', host: 'host', username: 'user', privateKey: 'key', keyPass: 'phrase', cols: 90, rows: 30 } });
  const client = clients[0];
  assert.equal(client.config.passphrase, 'phrase');
  assert.equal(client.config.privateKey, 'key');

  transport.handle({ type: 'ssh-input', data: { _tag: 'tab1', data: 'YQ==' } });
  transport.handle({ type: 'ssh-resize', data: { _tag: 'tab1', cols: 100, rows: 40 } });

  client.emit('ready');
  const stream = new EventEmitter();
  stream.stderr = new EventEmitter();
  const writes = [];
  const resizeArgs = [];
  stream.write = d => writes.push(Buffer.isBuffer(d) ? d.toString() : String(d));
  stream.setWindow = (...args) => resizeArgs.push(args);
  client.shellCallback(null, stream);

  assert.equal(client.pty.term, 'xterm-256color');
  assert.deepEqual(writes, ['a']);
  assert.deepEqual(resizeArgs, [[40, 100, 0, 0]]);

  stream.emit('data', Buffer.from('out'));
  stream.stderr.emit('data', Buffer.from('err'));
  assert.deepEqual(messages.map(m => m.type), ['ssh-ready', 'ssh-data', 'ssh-data']);
  assert.ok(messages.every(m => m.data._tag === 'tab1'));

  transport.handle({ type: 'ssh-close', data: { _tag: 'tab1' } });
  assert.equal(client.ended, true);
  assert.equal(messages.at(-1).type, 'ssh-terminated');
});

test('SFTP bridge queues ops until ready and forwards events with the same tag', () => {
  const { transport, clients, messages } = setup();
  transport.handle({ type: 'sftp-open', data: { _tag: 'sf:t1', host: 'host', username: 'user', password: 'pw' } });
  transport.handle({ type: 'sftp-op', data: { _tag: 'sf:t1', op: 'list', path: '/' } });

  const client = clients[0];
  const sftp = {
    readdir(path, cb) {
      assert.equal(path, '/');
      cb(null, [{ filename: 'file.txt', attrs: { size: 3, mtime: 2, mode: 0o100644 } }]);
    }
  };

  client.emit('ready');
  client.sftpCallback(null, sftp);

  const types = messages.map(m => m.type);
  assert.deepEqual(types, ['sftp-ready', 'sftp-list']);
  assert.ok(messages.every(m => m.data._tag === 'sf:t1'));
  assert.equal(messages[1].data.files[0].name, 'file.txt');

  transport.handle({ type: 'sftp-close', data: { _tag: 'sf:t1' } });
  assert.equal(client.ended, true);
  assert.equal(messages.at(-1).type, 'sftp-terminated');
});

test('validation rejects malformed tags and missing open payload', () => {
  const { transport, messages } = setup();
  assert.throws(() => transport.handle({ type: 'ssh-open', data: { _tag: '', host: 'x', username: 'u' } }), /invalid routing tag/);
  transport.handle({ type: 'ssh-open', data: { _tag: 'bad', host: '', username: 'u' } });
  assert.equal(messages[0].type, 'ssh-error');
  assert.equal(messages[0].data._tag, 'bad');
  assert.match(messages[0].data.error, /host\+username required/);
});

test('reopening a tag does not let stale close terminate replacement session', () => {
  const { transport, clients, messages } = setup();
  transport.handle({ type: 'ssh-open', data: { _tag: 'tab1', host: 'host', username: 'user', password: 'pw' } });
  const first = clients[0];
  transport.handle({ type: 'ssh-open', data: { _tag: 'tab1', host: 'host', username: 'user', password: 'pw' } });
  const second = clients[1];
  first.emit('close');
  assert.equal(messages.filter(m => m.type === 'ssh-terminated').length, 1);
  messages.length = 0;
  second.emit('ready');
  const stream = new EventEmitter();
  stream.stderr = new EventEmitter();
  stream.write = () => {};
  stream.setWindow = () => {};
  second.shellCallback(null, stream);
  assert.equal(messages[0].type, 'ssh-ready');
});

test('stale shell data and errors never leak into a replacement tag', () => {
  const { transport, clients, messages } = setup();
  const open = () => transport.handle({ type: 'ssh-open', data: { _tag: 'x', host: 'host', username: 'u' } });
  open();
  clients[0].emit('ready');
  const stream = new EventEmitter(); stream.stderr = new EventEmitter();
  clients[0].shellCallback(null, stream);
  open();
  const before = messages.length;
  clients[0].emit('error', new Error('stale client'));
  stream.emit('error', new Error('stale shell'));
  stream.emit('data', Buffer.from('old'));
  stream.stderr.emit('data', Buffer.from('old stderr'));
  stream.emit('close');
  assert.equal(messages.length, before);
  assert.equal(clients[1].ended, undefined);
  transport.dispose();
});

test('stale SFTP completion and errors never leak into a replacement tag', () => {
  const { transport, clients, messages } = setup();
  const open = () => transport.handle({ type: 'sftp-open', data: { _tag: 'sf:x', host: 'host', username: 'u' } });
  let callback;
  open(); clients[0].emit('ready');
  clients[0].sftpCallback(null, { readdir(_path, cb) { callback = cb; } });
  transport.handle({ type: 'sftp-op', data: { _tag: 'sf:x', op: 'list' } });
  open();
  const before = messages.length;
  callback(null, []);
  clients[0].emit('error', new Error('stale SFTP'));
  clients[0].emit('close');
  assert.equal(messages.length, before);
  assert.equal(clients[1].ended, undefined);
  transport.dispose();
});

test('sftp read does not cap to 1MB and write append avoids truncation flags', () => {
  const { transport, clients, messages } = setup();
  transport.handle({ type: 'sftp-open', data: { _tag: 'sf:t2', host: 'host', username: 'user', password: 'pw' } });
  const client = clients[0];
  let readOpts;
  let writeOpts;
  const sftp = {
    createReadStream(_path, opts) {
      readOpts = opts;
      const emitter = new EventEmitter();
      process.nextTick(() => {
        emitter.emit('data', Buffer.from('abc'));
        emitter.emit('end');
      });
      return emitter;
    },
    createWriteStream(_path, opts) {
      writeOpts = opts;
      const emitter = new EventEmitter();
      emitter.end = () => { emitter.emit('close'); emitter.emit('close'); };
      return emitter;
    }
  };
  client.emit('ready');
  client.sftpCallback(null, sftp);
  transport.handle({ type: 'sftp-op', data: { _tag: 'sf:t2', op: 'read', path: '/big.bin' } });
  transport.handle({ type: 'sftp-op', data: { _tag: 'sf:t2', op: 'write', path: '/big.bin', start: 524288, append: true, data: Buffer.from('x').toString('base64') } });
  assert.deepEqual(readOpts, {});
  assert.deepEqual(writeOpts, { flags: 'a' });
  const okCount = messages.filter(m => m.type === 'sftp-ok').length;
  assert.equal(okCount, 1);
});

test('real ssh2 direct shell+sftp fixture keeps exact binary over >1MB chunks', async t => {
  const { Server, Client, utils: { sftp: sftpUtils } } = require('ssh2');
  const { OPEN_MODE, STATUS_CODE } = sftpUtils;
  const hostKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
  const server = new Server({ hostKeys: [hostKey] });
  const fixtures = new Map([['/seed.bin', Buffer.alloc(1024 * 1024 + 321, 0x61)]]);
  const serverReady = new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());

  server.on('connection', client => {
    client.on('authentication', ctx => (ctx.method === 'password' && ctx.username === 'u' && ctx.password === 'pw') ? ctx.accept() : ctx.reject());
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', accept => accept());
        session.on('window-change', accept => accept && accept());
        session.on('shell', (accept) => {
          const stream = accept();
          stream.write('ready>');
          stream.on('data', chunk => { if (String(chunk).includes('ping')) stream.write('pong\n'); });
        });
        session.on('sftp', accept => {
          const sftp = accept();
          const handles = new Map();
          let handleId = 1;
          sftp.on('OPEN', (reqid, filename, flags) => {
            const file = String(filename);
            const handle = Buffer.alloc(4);
            handle.writeUInt32BE(handleId++, 0);
            const writable = !!(flags & (OPEN_MODE.WRITE | OPEN_MODE.APPEND));
            if (writable && (!fixtures.has(file) || (flags & OPEN_MODE.TRUNC))) fixtures.set(file, Buffer.alloc(0));
            if (!fixtures.has(file)) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE);
            handles.set(handle.toString('hex'), { file, flags });
            sftp.handle(reqid, handle);
          });
          sftp.on('READ', (reqid, handle, offset, length) => {
            const h = handles.get(handle.toString('hex')); if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE);
            const src = fixtures.get(h.file);
            if (offset >= src.length) return sftp.status(reqid, STATUS_CODE.EOF);
            sftp.data(reqid, src.subarray(offset, offset + length));
          });
          sftp.on('WRITE', (reqid, handle, offset, data) => {
            const h = handles.get(handle.toString('hex')); if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE);
            const key = h.file;
            let current = fixtures.get(key) || Buffer.alloc(0);
            if (h.flags & OPEN_MODE.APPEND) offset = current.length;
            const needed = offset + data.length;
            if (current.length < needed) {
              const grown = Buffer.alloc(needed);
              current.copy(grown);
              current = grown;
            }
            Buffer.from(data).copy(current, offset);
            fixtures.set(key, current);
            sftp.status(reqid, STATUS_CODE.OK);
          });
          sftp.on('FSTAT', (reqid, handle) => {
            const h = handles.get(handle.toString('hex'));
            if (!h) return sftp.status(reqid, STATUS_CODE.FAILURE);
            sftp.attrs(reqid, { size: fixtures.get(h.file).length, mode: 0o100644, atime: 1, mtime: 1 });
          });
          sftp.on('CLOSE', (reqid, handle) => { handles.delete(handle.toString('hex')); sftp.status(reqid, STATUS_CODE.OK); });
          sftp.on('OPENDIR', (_reqid, _path) => sftp.status(_reqid, STATUS_CODE.PERMISSION_DENIED));
          sftp.on('REALPATH', (reqid, pathName) => sftp.name(reqid, [{ filename: String(pathName || '/'), longname: '/', attrs: {} }]));
          sftp.on('STAT', (reqid, file) => {
            const buf = fixtures.get(String(file));
            if (!buf) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE);
            sftp.attrs(reqid, { size: buf.length, mode: 0o100644, atime: Math.floor(Date.now() / 1000), mtime: Math.floor(Date.now() / 1000) });
          });
          sftp.on('LSTAT', (reqid, file) => {
            const buf = fixtures.get(String(file));
            if (!buf) return sftp.status(reqid, STATUS_CODE.NO_SUCH_FILE);
            sftp.attrs(reqid, { size: buf.length, mode: 0o100644, atime: Math.floor(Date.now() / 1000), mtime: Math.floor(Date.now() / 1000) });
          });
        });
      });
    });
  });

  await serverReady;
  const port = server.address().port;
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'desktop-real-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const pinStorePath = path.join(dir, 'pins.json');
  const events = [];
  const transport = createTransport({ pinStorePath, createClient: () => new Client(), send: m => events.push(m) });
  t.after(() => transport.dispose());

  transport.handle({ type: 'ssh-open', data: { _tag: 'ssh1', host: '127.0.0.1', port, username: 'u', password: 'pw', accountId: 'acct', server: 'sync' } });
  for (let i = 0; i < 100 && !events.find(e => e.type === 'ssh-ready'); i++) await new Promise(r => setTimeout(r, 15));
  assert.ok(events.find(e => e.type === 'ssh-ready'));
  transport.handle({ type: 'ssh-input', data: { _tag: 'ssh1', data: Buffer.from('ping\n').toString('base64') } });
  for (let i = 0; i < 100 && !events.find(e => e.type === 'ssh-data' && Buffer.from(e.data.data, 'base64').toString().includes('pong')); i++) await new Promise(r => setTimeout(r, 15));
  assert.ok(events.find(e => e.type === 'ssh-data' && Buffer.from(e.data.data, 'base64').toString().includes('pong')));

  transport.handle({ type: 'sftp-open', data: { _tag: 'sf:1', host: '127.0.0.1', port, username: 'u', password: 'pw', accountId: 'acct', server: 'sync' } });
  for (let i = 0; i < 100 && !events.find(e => e.type === 'sftp-ready'); i++) await new Promise(r => setTimeout(r, 15));
  assert.ok(events.find(e => e.type === 'sftp-ready'));

  const upload = crypto.randomBytes(1024 * 1024 + 333);
  const chunk = 512 * 1024;
  let start = 0;
  let chunks = 0;
  while (start < upload.length) {
    const piece = upload.subarray(start, start + chunk);
    const before = events.filter(e => e.type === 'sftp-ok').length;
    transport.handle({ type: 'sftp-op', data: { _tag: 'sf:1', op: 'write', path: '/upload.bin', start, append: start > 0, data: piece.toString('base64') } });
    for (let i = 0; i < 1000 && events.filter(e => e.type === 'sftp-ok').length <= before && !events.find(e => e.type === 'sftp-error'); i++) await new Promise(r => setTimeout(r, 15));
    const err = events.find(e => e.type === 'sftp-error');
    assert.equal(err ? err.data.error : null, null);
    assert.equal(events.filter(e => e.type === 'sftp-ok').length, before + 1);
    start += piece.length;
    chunks++;
  }
  assert.equal(events.filter(e => e.type === 'sftp-ok').length >= chunks, true);

  const beforeRead = events.filter(e => e.type === 'sftp-data' || e.type === 'sftp-end').length;
  transport.handle({ type: 'sftp-op', data: { _tag: 'sf:1', op: 'read', path: '/upload.bin' } });
  for (let i = 0; i < 1000 && events.filter(e => e.type === 'sftp-end').length < 1; i++) await new Promise(r => setTimeout(r, 15));
  const readEvents = events.slice().filter(e => e.type === 'sftp-data' || e.type === 'sftp-end');
  assert.ok(readEvents.length > beforeRead);
  const readBuf = Buffer.concat(events.filter(e => e.type === 'sftp-data').map(e => Buffer.from(e.data.data, 'base64')));
  assert.equal(readBuf.length, upload.length);
  assert.equal(crypto.createHash('sha256').update(readBuf).digest('hex'), crypto.createHash('sha256').update(upload).digest('hex'));

  const storedPins = JSON.parse(fs.readFileSync(pinStorePath, 'utf8'));
  const pinKeys = Object.keys(storedPins);
  assert.ok(pinKeys.some(k => k.includes('127.0.0.1')));
  assert.ok(Object.values(storedPins).every(v => /^SHA256:[A-Za-z0-9+/]{43}$/.test(v)));
} );
