"use strict";
/* ============================================================
   TiaSSH 2.0 — client logic
   - Zero-knowledge sync: items encrypted client-side (AES-256-GCM)
     with key derived from user password via PBKDF2(server salt).
     Server stores only ciphertext.
   - SSH + SFTP proxy over WebSocket
   ============================================================ */

const $ = id => document.getElementById(id);

// ---------- server base (configurable) ----------
function apiBase(){
  const s = (localStorage.getItem('tiassh_server') || '').replace(/\/+$/,'');
  return s || ((window.location.origin && location.protocol.startsWith('http')) ? window.location.origin.replace(/\/+$/,'') : '');
}
function wsBase(){
  const s = (localStorage.getItem('tiassh_server') || '').replace(/\/+$/,'');
  if (s) return s.replace(/^http/,'ws');
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
}

// ---------- state ----------
const state = {
  token: null, email: null, salt: null, key: null,   // crypto key (CryptoKey)
  hosts: new Map(), lastSync: 0, ws: null, tabs: new Map(),
  activeTab: 'welcome'
};

// ---------- crypto (zero-knowledge, pure JS — works over http, byte-identical across devices) ----------
// Scheme: PBKDF2-SHA256(password, serverSalt, 100000) -> 64 bytes = encKey(32) | macKey(32)
//         item = iv(16) | AES-256-CBC(pkcs7(json)) | HMAC-SHA256(iv|ct, macKey)  [encrypt-then-MAC]
function _utf8Bytes(s){ return Array.from(new TextEncoder().encode(s)); }
function _hmacArr(key, msg){ return sha256.hmac.array(key, msg); }
function _pbkdf2(password, salt, iterations, keyLen){
  const P = _utf8Bytes(password), S = salt, out = [];
  const blocks = Math.ceil(keyLen / 32);
  for (let b = 1; b <= blocks; b++){
    const idx = [(b>>24)&255, (b>>16)&255, (b>>8)&255, b&255];
    let U = _hmacArr(S, P.concat(idx)), T = U.slice();
    for (let i = 1; i < iterations; i++){ U = _hmacArr(S, U); for (let j = 0; j < 32; j++) T[j] ^= U[j]; }
    out.push.apply(out, T);
  }
  return out.slice(0, keyLen);
}
function _pkcs7pad(d){ const n = 16 - (d.length % 16); return d.concat(new Array(n).fill(n)); }
function _pkcs7unpad(d){ const n = d[d.length-1]; if (n < 1 || n > 16) throw new Error('bad padding'); return d.slice(0, d.length - n); }

// returns { encKey:number[32], macKey:number[32] }
function deriveKey(password, saltB64){
  const salt = b64toBytes(saltB64);
  const k = _pbkdf2(password, salt, 100000, 64);
  return { encKey: k.slice(0, 32), macKey: k.slice(32, 64) };
}
function b64toBytes(b64){
  const b = atob(String(b64).replace(/-/g,'+').replace(/_/g,'/'));
  const out = new Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}
function bytesToB64(arr){
  const u = arr instanceof Uint8Array ? arr : new Uint8Array(arr);
  let s = '';
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
// state.key = { encKey, macKey }
function encValue(obj){
  const pt = _pkcs7pad(_utf8Bytes(JSON.stringify(obj)));
  const iv = new Array(16);
  for (let i = 0; i < 16; i++) iv[i] = Math.floor(Math.random() * 256);
  const c = Array.from(new aesjs.ModeOfOperation.cbc(state.key.encKey, iv).encrypt(pt));
  const mac = _hmacArr(state.key.macKey, iv.concat(c));
  return bytesToB64(iv.concat(c, mac));
}
function decValue(b64){
  const all = b64toBytes(b64);
  const iv = all.slice(0, 16);
  const c = all.slice(16, all.length - 32);
  const mac = all.slice(all.length - 32);
  const expect = _hmacArr(state.key.macKey, iv.concat(c));
  if (JSON.stringify(expect) !== JSON.stringify(mac)) throw new Error('decryption failed (wrong password or corrupted data)');
  const p = Array.from(new aesjs.ModeOfOperation.cbc(state.key.encKey, iv).decrypt(c));
  return JSON.parse(new TextDecoder().decode(new Uint8Array(_pkcs7unpad(p))));
}

// ---------- session persistence ----------
function saveSession(){
  localStorage.setItem('tiassh_session', JSON.stringify({
    token: state.token, email: state.email, salt: state.salt,
    server: localStorage.getItem('tiassh_server') || '',
    pass: $('authPass') ? $('authPass').value : (state._pass || '')
  }));
}
function loadSession(){
  try {
    const s = JSON.parse(localStorage.getItem('tiassh_session') || 'null');
    if (s && s.token) return s;
  } catch(e){}
  return null;
}
function clearSession(){ localStorage.removeItem('tiassh_session'); }

// ---------- toast ----------
function toast(msg, kind){
  const t = document.createElement('div');
  t.className = 'toast' + (kind ? ' ' + kind : '');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

// ---------- api ----------
async function api(path, opts={}){
  const res = await fetch(apiBase()+path, { ...opts, headers: { 'Content-Type':'application/json', ...(state.token ? { Authorization: 'Bearer ' + state.token } : {}), ...(opts.headers || {}) } });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(j.error || ('HTTP ' + res.status));
  return j;
}

// ---------- AUTH ----------
$('authLoginBtn').onclick = () => doLogin('login');
$('authRegBtn').onclick = () => doLogin('register');
$('authPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin('login'); });

async function doLogin(mode){
  $('authErr').textContent = '';
  try {
    const srv = $('authServer').value.trim().replace(/\/+$/,'');
    localStorage.setItem('tiassh_server', srv);
    const email = $('authEmail').value.trim(), pass = $('authPass').value;
    if (!email || !pass) throw new Error('isi email & password');
    const j = await api('/api/' + mode, { method: 'POST', body: JSON.stringify({ email, password: pass }) });
    state.token = j.token; state.email = j.email; state.salt = j.salt; state._pass = pass;
    state.key = await deriveKey(pass, j.salt);
    saveSession();
    enterApp();
  } catch(e) { $('authErr').textContent = e.message; }
}

async function tryAutoLogin(){
  const s = loadSession();
  if (!s) return false;
  try {
    localStorage.setItem('tiassh_server', s.server || '');
    state.token = s.token; state.email = s.email; state.salt = s.salt; state._pass = s.pass;
    // verify token still valid + fetch fresh salt
    const me = await api('/api/me');
    state.email = me.email; state.salt = me.salt;
    state.key = await deriveKey(s.pass, me.salt);
    enterApp();
    return true;
  } catch(e) { clearSession(); return false; }
}

$('logoutBtn').onclick = () => { clearSession(); location.reload(); };

// ---------- APP ----------
function enterApp(){
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('userLine').textContent = state.email;
  $('avatarEl').textContent = (state.email[0] || '?').toUpperCase();
  api('/api/device', { method: 'POST', body: JSON.stringify({ name: /Mobi|Android/i.test(navigator.userAgent) ? 'android' : 'desktop' }) }).catch(() => {});
  openWs();
  pullSnapshot().catch(e => toast('gagal ambil data: ' + e.message, 'err'));
  window.addEventListener('resize', resizeAll);
}

// ---------- SYNC (zero-knowledge) ----------
function openWs(){
  const ws = new WebSocket(`${wsBase()}/ws?token=${state.token}`);
  ws.onmessage = onWsMessage;
  ws.onclose = () => { setSync(false); setTimeout(openWs, 3000); };
  ws.onopen = () => setSync(true);
  state.ws = ws;
}
function setSync(on){
  $('syncDot').className = 'dot' + (on ? ' on' : '');
  $('syncText').textContent = on ? 'sync aktif' : 'reconnect…';
  $('userStatus').textContent = on ? 'terhubung · terenkripsi' : 'tersinkron terakhir tersimpan';
}
function wsSend(obj){ if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify(obj)); }

async function pullSnapshot(){
  const j = await api('/api/sync/snapshot');
  for (const it of j.items) {
    if (it.category !== 'host') continue;
    try { const v = await decValue(it.value); state.hosts.set(it.key, v); }
    catch(e){ /* unreadable item (wrong password) — skip */ }
  }
  state.lastSync = j.serverTime;
  renderHosts();
}
async function pullLatest(){
  try {
    const j = await api('/api/sync/pull?since=' + state.lastSync);
    for (const it of j.items) {
      if (it.category !== 'host') continue;
      if (it.value === null) state.hosts.delete(it.key);
      else { try { state.hosts.set(it.key, await decValue(it.value)); } catch(e) {} }
    }
    state.lastSync = j.serverTime;
    renderHosts();
  } catch(e) {}
}
async function pushItem(key, value){
  try {
    const enc = value === null ? null : await encValue(value);
    await api('/api/sync/push', { method: 'POST', body: JSON.stringify({ items: [{ category: 'host', key, value: enc, rev: 1 }] }) });
  } catch(e) { toast('gagal simpan: ' + e.message, 'err'); }
}

// ---------- WS message router ----------
function onWsMessage(ev){
  let m; try { m = JSON.parse(ev.data); } catch(e){ return; }
  if (m.type === 'sync') { state.lastSync = 0; pullLatest(); return; }
  const tag = m.data && m.data._tag ? String(m.data._tag) : null;
  const rec = tag ? state.tabs.get(tag) : null;
  if (!rec) { const a = [...state.tabs.values()]; if (a.length === 1) return routeMsg(a[0], m); return; }
  routeMsg(rec, m);
}
function routeMsg(rec, m){
  const t = m.type;
  if (t === 'ssh-ready') {
    rec.term.write('\x1b[32mConnected.\x1b[0m\r\n');
    setConnText(`${rec.host.user}@${rec.host.host}:${rec.host.port || 22} — connected`);
    setTabBadge(rec, 'on');
  }
  else if (t === 'ssh-data' && m.data.data) rec.term.write(fromB64(m.data.data));
  else if (t === 'ssh-error') {
    rec.term.write('\r\n\x1b[31mERROR: ' + esc(m.data.error || 'unknown') + '\x1b[0m\r\n');
    setConnText('connection error');
    setTabBadge(rec, 'err');
  }
  else if (t === 'sftp-ready') { if (rec.sftp) rec.sftp.opened = true; }
  else if (t === 'sftp-list') { if (rec.sftp) renderSftpList(rec, m.data); }
  else if (t === 'sftp-error') { if (rec.sftp) { toast('SFTP: ' + (m.data.error || 'error'), 'err'); } }
  else if (t === 'sftp-data' && rec._dl) {
    rec._dl.buf.push(m.data.data);
  }
  else if (t === 'sftp-end' && rec._dl) { finishDownload(rec); }
  else if (t === 'sftp-ok' && rec._up) {
    if (rec._up.totalChunks && rec._up.received >= rec._up.totalChunks) finishUpload(rec);
    else rec._up.received++;
  }
}
function setTabBadge(rec, cls){
  const el = rec.tabEl && rec.tabEl.querySelector('.badge-conn');
  if (el) el.className = 'badge-conn ' + cls;
}
function fromB64(b){
  const bin = atob(b);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

// ---------- HOSTS ----------
function renderHosts(){
  const list = $('hostList');
  const q = ($('hostSearch').value || '').toLowerCase();
  list.innerHTML = '';
  const arr = [...state.hosts.values()]
    .filter(h => !q || (h.name || '').toLowerCase().includes(q) || (h.host || '').toLowerCase().includes(q))
    .sort((a,b) => (a.name || '').localeCompare(b.name || ''));
  arr.forEach(h => {
    const d = document.createElement('div');
    d.className = 'host-item' + (state.activeTab === h.id ? ' active' : '');
    const authIco = h.auth === 'key' ? '🔑' : '🔒';
    d.innerHTML = `<div class="h-name"><span class="h-ico">🖥️</span>${esc(h.name || h.host)}</div>
      <div class="h-meta">${authIco} ${esc(h.user)}@${esc(h.host)}:${h.port || 22}</div>`;
    d.onclick = () => openTab(h);
    d.oncontextmenu = e => { e.preventDefault(); hostModal(h); };
    list.appendChild(d);
  });
  if (!arr.length) list.innerHTML = '<div class="empty-list">Belum ada host.<br>Klik <b>"+ Host"</b> untuk menambah.</div>';
}
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
$('hostSearch').addEventListener('input', renderHosts);
$('addHostBtn').onclick = () => hostModal(null);

function hostModal(existing){
  const h = existing || { id: 'h' + Date.now() + Math.random().toString(36).slice(2,6), name:'', host:'', port:22, user:'root', auth:'password', password:'', privateKey:'', keyPass:'' };
  const m = $('modal');
  m.innerHTML = `
    <h2>${existing ? 'Edit Host' : 'Host Baru'}</h2>
    <div class="m-sub">${existing ? 'Perubahan langsung ter-sync ke semua perangkat' : 'Kredensial dienkripsi sebelum dikirim ke server'}</div>
    <label>Nama</label>
    <input id="f_name" value="${esc(h.name)}" placeholder="VPS produksi">
    <div class="row">
      <div><label>Host (IP / domain)</label><input id="f_host" value="${esc(h.host)}" placeholder="203.0.113.10"></div>
      <div style="max-width:96px"><label>Port</label><input id="f_port" value="${h.port || 22}" inputmode="numeric"></div>
    </div>
    <label>Username</label>
    <input id="f_user" value="${esc(h.user)}" placeholder="root">
    <label>Metode Autentikasi</label>
    <div class="auth-seg">
      <button id="seg_pw" class="${h.auth !== 'key' ? 'on' : ''}">Password</button>
      <button id="seg_key" class="${h.auth === 'key' ? 'on' : ''}">SSH Key / Keypair</button>
    </div>
    <div id="pwBox" class="${h.auth === 'key' ? 'hidden' : ''}">
      <label>Password</label>
      <input id="f_pass" type="password" value="${esc(h.password || '')}">
    </div>
    <div id="keyBox" class="${h.auth === 'key' ? '' : 'hidden'}">
      <label>Private Key (PEM — OpenSSH/RSA/Ed25519)</label>
      <textarea id="f_key" class="mono" rows="6" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----">${esc(h.privateKey || '')}</textarea>
      <label>Passphrase (opsional, jika key proteksi)</label>
      <input id="f_keypass" type="password" value="${esc(h.keyPass || '')}">
    </div>
    <div class="actions">
      ${existing ? '<button class="btn danger left" id="f_del">Hapus</button>' : ''}
      <button class="btn ghost" id="f_cancel">Batal</button>
      <button class="btn" id="f_save">Simpan & Sync</button>
    </div>`;
  $('modalBg').classList.remove('hidden');
  const setSeg = which => {
    $('seg_pw').className = which === 'password' ? 'on' : '';
    $('seg_key').className = which === 'key' ? 'on' : '';
    $('pwBox').classList.toggle('hidden', which !== 'password');
    $('keyBox').classList.toggle('hidden', which !== 'key');
  };
  $('seg_pw').onclick = () => setSeg('password');
  $('seg_key').onclick = () => setSeg('key');
  $('f_cancel').onclick = closeModal;
  if (existing) $('f_del').onclick = () => {
    state.hosts.delete(h.id);
    pushItem(h.id, null);
    renderHosts(); closeModal();
    toast('host dihapus & sync', 'ok');
  };
  $('f_save').onclick = async () => {
    const auth = $('seg_key').classList.contains('on') ? 'key' : 'password';
    const nh = {
      id: h.id,
      name: $('f_name').value.trim() || $('f_host').value.trim(),
      host: $('f_host').value.trim(),
      port: parseInt($('f_port').value, 10) || 22,
      user: $('f_user').value.trim(),
      auth
    };
    if (auth === 'password') nh.password = $('f_pass').value;
    else { nh.privateKey = $('f_key').value.trim(); nh.keyPass = $('f_keypass').value; }
    if (!nh.host || !nh.user) { toast('host & username wajib diisi', 'err'); return; }
    state.hosts.set(nh.id, nh);
    await pushItem(nh.id, nh);
    renderHosts(); closeModal();
    toast('tersimpan & tersinkron', 'ok');
  };
}
function closeModal(){ $('modalBg').classList.add('hidden'); }

// ---------- TABS ----------
function openTab(host){
  if (state.tabs.has(host.id)) { activateTab(host.id); return; }
  const term = new Terminal({
    fontFamily: 'Cascadia Code, Consolas, monospace', fontSize: 13,
    cursorBlink: true, theme: { background: '#0a0c10', foreground: '#e8ecf4' }
  });
  const fit = new FitAddon.FitAddon(); term.loadAddon(fit);

  const termDiv = document.createElement('div');
  termDiv.className = 'xterm'; termDiv.style.display = 'none';
  $('termWrap').appendChild(termDiv); term.open(termDiv); fit.fit();

  const sftpDiv = document.createElement('div');
  sftpDiv.className = 'sftp-wrap'; sftpDiv.style.display = 'none';
  $('termWrap').appendChild(sftpDiv);

  const rec = { id: host.id, host, term, fit, termDiv, sftpDiv, view: 'term', sftp: { opened: false, cwd: '' }, connState: 'off' };
  state.tabs.set(host.id, rec);

  const tabEl = document.createElement('div');
  tabEl.className = 'tab'; tabEl.dataset.tab = host.id;
  tabEl.innerHTML = `<span class="t-ico">🖥️</span><span class="t-name">${esc(host.name || host.host)}</span><span class="badge-conn off"></span><span class="t-x">✕</span>`;
  tabEl.onclick = () => activateTab(host.id);
  tabEl.querySelector('.t-x').onclick = e => { e.stopPropagation(); closeTab(host.id); };
  $('tabsBar').appendChild(tabEl);
  rec.tabEl = tabEl;

  // view switch buttons
  const vs = document.createElement('div');
  vs.className = 'view-switch';
  vs.innerHTML = `<button data-v="term" class="on">▤ Terminal</button><button data-v="sftp">📁 Files</button>`;
  sftpDiv.parentNode.insertBefore(vs, sftpDiv.nextSibling);
  rec.viewSwitch = vs;
  vs.querySelectorAll('button').forEach(b => b.onclick = () => setView(rec, b.dataset.v));

  activateTab(host.id);
  connectSsh(rec);

  term.onData(d => wsSend({ type: 'ssh-input', data: { data: b64EncStr(d), _tag: rec.id } }));
  term.onResize(({ cols, rows }) => wsSend({ type: 'ssh-resize', data: { cols, rows, _tag: rec.id } }));
  setTimeout(() => { fit.fit(); wsSend({ type: 'ssh-resize', data: { cols: term.cols, rows: term.rows, _tag: rec.id } }); }, 80);
}

function b64EncStr(s){ return btoa(unescape(encodeURIComponent(s))); }

function connectSsh(rec){
  const h = rec.host;
  const conn = { host: h.host, port: h.port || 22, username: h.user, _tag: rec.id, cols: rec.term.cols, rows: rec.term.rows };
  if (h.auth === 'key') { conn.privateKey = h.privateKey; if (h.keyPass) conn.keyPass = h.keyPass; }
  else conn.password = h.password;
  rec.term.write(`\x1b[36m→ ${h.user}@${h.host}:${h.port || 22} (${h.auth === 'key' ? 'key' : 'password'})\x1b[0m\r\n`);
  wsSend({ type: 'ssh-open', data: conn });
  setConnText(`connecting ${h.user}@${h.host}…`);
  setTabBadge(rec, 'off');
  // open sftp channel lazily when user switches to Files
  rec._sftpOpened = false;
}

function ensureSftp(rec){
  if (rec._sftpOpened) return;
  rec._sftpOpened = true;
  const h = rec.host;
  const conn = { host: h.host, port: h.port || 22, username: h.user, _tag: rec.id };
  if (h.auth === 'key') { conn.privateKey = h.privateKey; if (h.keyPass) conn.keyPass = h.keyPass; }
  else conn.password = h.password;
  rec.sftp.cwd = '';
  renderSftpShell(rec);
  wsSend({ type: 'sftp-open', data: conn });
  // give it a moment then list home
  setTimeout(() => sftpList(rec, ''), 1200);
}

function setView(rec, v){
  rec.view = v;
  rec.viewSwitch.querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.v === v));
  if (v === 'term') {
    rec.termDiv.style.display = '';
    rec.sftpDiv.style.display = 'none';
    rec.viewSwitch.style.display = 'none';
    rec.fit.fit(); rec.term.focus();
  } else {
    rec.termDiv.style.display = 'none';
    rec.sftpDiv.style.display = '';
    rec.viewSwitch.style.display = '';
    ensureSftp(rec);
  }
}

function activateTab(id){
  document.querySelectorAll('#tabsBar .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === String(id)));
  state.activeTab = id;
  const show = id !== 'welcome';
  $('welcome').style.display = show ? 'none' : '';
  state.tabs.forEach((r, rid) => {
    const vis = String(rid) === String(id);
    if (r.view === 'term') r.termDiv.style.display = vis ? '' : 'none';
    else { r.sftpDiv.style.display = vis ? '' : 'none'; r.viewSwitch.style.display = vis ? '' : 'none'; }
  });
  const r = state.tabs.get(id);
  if (r && r.view === 'term') { r.fit.fit(); r.term.focus(); }
  renderHosts();
}
function closeTab(id){
  const r = state.tabs.get(id); if (!r) return;
  wsSend({ type: 'ssh-close', data: { _tag: id } });
  wsSend({ type: 'sftp-close', data: { _tag: id } });
  r.term.dispose(); r.termDiv.remove(); r.sftpDiv.remove(); r.viewSwitch.remove();
  state.tabs.delete(id);
  const tabEl = document.querySelector(`.tab[data-tab="${id}"]`); if (tabEl) tabEl.remove();
  if (state.tabs.size === 0) { $('welcome').style.display = ''; state.activeTab = 'welcome'; }
  else activateTab(state.tabs.keys().next().value);
  renderHosts();
}
function setConnText(t){ $('connText').textContent = t; }
function resizeAll(){ state.tabs.forEach(r => { try { if (r.view === 'term') r.fit.fit(); } catch(e){} }); }

$('menuBtn').onclick = () => $('sidebar').classList.toggle('open');
document.querySelector('.tab[data-tab="welcome"]').addEventListener('click', () => {
  state.activeTab = 'welcome';
  $('welcome').style.display = '';
  state.tabs.forEach(r => { r.termDiv.style.display = 'none'; r.sftpDiv.style.display = 'none'; if (r.viewSwitch) r.viewSwitch.style.display = 'none'; });
  document.querySelectorAll('#tabsBar .tab').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab[data-tab="welcome"]').classList.add('active');
  renderHosts();
});

// ---------- SFTP ----------
function renderSftpShell(rec){
  rec.sftpDiv.innerHTML = `
    <div class="sftp-top">
      <button class="btn ghost small" id="sf_up">⬆</button>
      <button class="btn ghost small" id="sf_refresh">⟳</button>
      <div class="sftp-path" id="sf_path"></div>
      <button class="btn ghost small" id="sf_newdir">+ Folder</button>
      <button class="btn small" id="sf_upload">⬆ Upload</button>
      <input type="file" id="sf_file" multiple style="display:none">
    </div>
    <div class="sftp-body">
      <div class="sftp-table">
        <div class="sftp-head"><div>Nama</div><div class="f-size">Ukuran</div><div class="f-time">Dimodifikasi</div></div>
        <div class="sftp-table-body"><div class="sftp-loading">Menghubungkan ke SFTP…</div></div>
      </div>
      <div class="sftp-foot" id="sf_foot">SFTP siap</div>
    </div>`;
  rec.$sf = {
    up: rec.sftpDiv.querySelector('#sf_up'),
    refresh: rec.sftpDiv.querySelector('#sf_refresh'),
    path: rec.sftpDiv.querySelector('#sf_path'),
    newdir: rec.sftpDiv.querySelector('#sf_newdir'),
    upload: rec.sftpDiv.querySelector('#sf_upload'),
    file: rec.sftpDiv.querySelector('#sf_file'),
    body: rec.sftpDiv.querySelector('.sftp-table-body'),
    foot: rec.sftpDiv.querySelector('#sf_foot')
  };
  rec.$sf.up.onclick = () => {
    const p = rec.sftp.cwd || '/';
    const parent = p === '/' ? '/' : p.replace(/[^/]+$/, '').replace(/\/$/, '') || '/';
    sftpList(rec, parent);
  };
  rec.$sf.refresh.onclick = () => sftpList(rec, rec.sftp.cwd || '');
  rec.$sf.newdir.onclick = () => {
    const name = prompt('Nama folder baru:');
    if (!name) return;
    const dir = joinPath(rec.sftp.cwd, name);
    sftpOp(rec, { op: 'mkdir', path: dir, mode: '755' }).then(ok => { if (ok) { toast('folder dibuat', 'ok'); sftpList(rec, rec.sftp.cwd || ''); } });
  };
  rec.$sf.upload.onclick = () => rec.$sf.file.click();
  rec.$sf.file.onchange = async () => {
    for (const f of rec.$sf.file.files) {
      await sftpUpload(rec, f);
    }
    rec.$sf.file.value = '';
    sftpList(rec, rec.sftp.cwd || '');
  };
}
function joinPath(dir, name){
  if (!name) return dir || '/';
  if (dir && dir.endsWith('/')) return dir + name;
  if (!dir) return '/' + name;
  return dir + '/' + name;
}
function sftpList(rec, dir){
  rec.sftp.cwd = dir;
  renderSftpCrumbs(rec);
  rec.$sf.body.innerHTML = '<div class="sftp-loading">Memuat…</div>';
  wsSend({ type: 'sftp-op', data: { _tag: rec.id, op: 'list', path: dir || '/' } });
}
function renderSftpCrumbs(rec){
  const dir = rec.sftp.cwd || '/';
  const parts = dir.split('/').filter(Boolean);
  let html = `<span class="crumb" data-p="/">/</span>`;
  let acc = '';
  parts.forEach(p => {
    acc += '/' + p;
    html += `<span class="sep">/</span><span class="crumb" data-p="${esc(acc)}">${esc(p)}</span>`;
  });
  rec.$sf.path.innerHTML = html;
  rec.$sf.path.querySelectorAll('.crumb').forEach(c => c.onclick = () => sftpList(rec, c.dataset.p));
}
function renderSftpList(rec, data){
  const files = (data.files || []).sort((a,b) => (b.isDir - a.isDir) || a.name.localeCompare(b.name));
  rec.$sf.foot.textContent = `${files.length} item · ${data.path}`;
  if (!files.length) { rec.$sf.body.innerHTML = '<div class="sftp-loading">Folder kosong</div>'; return; }
  rec.$sf.body.innerHTML = files.map(f => `
    <div class="sftp-row" data-name="${esc(f.name)}" data-dir="${f.isDir ? 1 : 0}">
      <div class="f-name"><span class="f-ico">${f.isDir ? '📁' : '📄'}</span>${esc(f.name)}</div>
      <div class="f-size">${f.isDir ? '—' : fmtSize(f.size)}</div>
      <div class="f-time">${f.time ? new Date(f.time).toLocaleString('id-ID') : '—'}</div>
    </div>`).join('');
  rec.$sf.body.querySelectorAll('.sftp-row').forEach(row => {
    row.onclick = e => {
      const name = row.dataset.name;
      const full = joinPath(rec.sftp.cwd, name);
      if (row.dataset.dir === '1') sftpList(rec, full);
      else sftpDownload(rec, full, name);
    };
    row.oncontextmenu = e => {
      e.preventDefault();
      sftpFileMenu(rec, row.dataset.name, row.dataset.dir === '1', e);
    };
  });
}
function fmtSize(n){
  if (!n && n !== 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}
function sftpOp(rec, data){
  return new Promise(resolve => {
    const prev = rec._sftpPending;
    const timer = setTimeout(() => resolve(false), 15000);
    rec._sftpPending = result => { clearTimeout(timer); resolve(result); };
    prev && prev(false);
    wsSend({ type: 'sftp-op', data: { ...data, _tag: rec.id } });
  });
}
function sftpFileMenu(rec, name, isDir, e){
  const full = joinPath(rec.sftp.cwd, name);
  const m = $('modal');
  m.innerHTML = `
    <h2>${esc(name)}</h2>
    <div class="m-sub">${full}</div>
    <div class="actions" style="flex-wrap:wrap;justify-content:flex-start">
      ${!isDir ? '<button class="btn" id="m_dl">⬇ Unduh</button>' : ''}
      <button class="btn ghost" id="m_ren">✎ Ganti Nama</button>
      <button class="btn danger" id="m_del">🗑 Hapus</button>
      <button class="btn ghost" id="m_close">Tutup</button>
    </div>`;
  $('modalBg').classList.remove('hidden');
  $('m_close').onclick = closeModal;
  if (!isDir) $('m_dl').onclick = () => { closeModal(); sftpDownload(rec, full, name); };
  $('m_ren').onclick = () => {
    const nn = prompt('Nama baru:', name);
    if (!nn || nn === name) return closeModal();
    const to = joinPath(rec.sftp.cwd, nn);
    sftpOp(rec, { op: 'rename', path: full, to }).then(ok => { if (ok) sftpList(rec, rec.sftp.cwd || ''); });
    closeModal();
  };
  $('m_del').onclick = async () => {
    closeModal();
    const ok = await sftpOp(rec, { op: isDir ? 'rmdir' : 'unlink', path: full });
    if (ok) { toast('terhapus', 'ok'); sftpList(rec, rec.sftp.cwd || ''); }
  };
}
function sftpDownload(rec, path, name){
  if (rec._dl) { toast('download sedang berjalan', 'err'); return; }
  rec._dl = { path, name, buf: [] };
  rec.$sf.foot.textContent = 'Mengunduh ' + name + '…';
  wsSend({ type: 'sftp-op', data: { _tag: rec.id, op: 'read', path } });
}
function finishDownload(rec){
  const dl = rec._dl; rec._dl = null;
  try {
    // concat base64 chunks
    const bin = atob(dl.buf.join(''));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = dl.name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    toast('terunduh: ' + dl.name, 'ok');
  } catch(e){ toast('gagal unduh: ' + e.message, 'err'); }
  rec.$sf.foot.textContent = 'SFTP siap';
}
async function sftpUpload(rec, file){
  const dest = joinPath(rec.sftp.cwd, file.name);
  const chunks = [];
  const CHUNK = 512 * 1024;
  let offset = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, offset + CHUNK);
    const b64 = await blobToB64(slice);
    chunks.push({ start: offset, data: b64, append: offset > 0 });
    offset += CHUNK;
  }
  if (!chunks.length) chunks.push({ start: 0, data: '', append: false });
  rec._up = { name: file.name, received: 0, totalChunks: chunks.length };
  rec.$sf.foot.textContent = `Mengunggah ${file.name} (0/${chunks.length})…`;
  for (const c of chunks) {
    wsSend({ type: 'sftp-op', data: { _tag: rec.id, op: 'write', path: dest, ...c } });
  }
}
function finishUpload(rec){
  const up = rec._up; rec._up = null;
  rec.$sf.foot.textContent = 'SFTP siap';
  toast('terunggah: ' + up.name, 'ok');
}
function blobToB64(blob){
  return new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(String(fr.result).split(',')[1]);
    fr.onerror = rej;
    fr.readAsDataURL(blob);
  });
}

// ---------- SFTP message handling hook ----------
// (routeMsg already handles sftp-* types above; wire _sftpPending for ops)
const _origRoute = routeMsg;
routeMsg = function(rec, m){
  const t = m.type;
  if ((t === 'sftp-ok' || t === 'sftp-error' || t === 'sftp-list' || t === 'sftp-end') && rec._sftpPending) {
    const ok = t === 'sftp-ok';
    if (t === 'sftp-error' && !rec._up) { /* let normal handler toast */ }
    const p = rec._sftpPending; rec._sftpPending = null;
    if (t !== 'sftp-list' && t !== 'sftp-end') p(ok);
  }
  _origRoute(rec, m);
};

// ---------- boot ----------
(async function boot(){
  const ok = await tryAutoLogin();
  if (!ok) $('auth').classList.remove('hidden');
})();
