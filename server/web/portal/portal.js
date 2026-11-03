const $ = (id) => document.getElementById(id);
let challenge = null;
let resetChallenge = null;
let resetSecret = null;

function setStatus(id, msg, ok = false) {
  const e = $(id);
  e.textContent = msg || '';
  e.className = `status ${msg ? (ok ? 'ok' : 'bad') : ''}`;
}

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body || {}),
  });
  const text = await r.text();
  let data = {};
  try { data = JSON.parse(text); } catch { data = { error: text }; }
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function getCreds(withOtp = true) {
  return {
    email: $('email').value.trim(),
    password: $('password').value,
    otp: withOtp ? $('otp').value.trim() : undefined,
  };
}

async function register() {
  try {
    const data = await post('/api/web/register', {
      email: $('email').value.trim(),
      password: $('password').value,
    });
    challenge = data.challenge;
    $('otpWrap').classList.remove('hidden');
    $('btnConfirm').classList.remove('hidden');
    $('enrollBox').classList.remove('hidden');
    $('enrollBox').textContent = `Secret: ${data.secret}\n${data.otpauthUrl}`;
    setStatus('authStatus', 'Pendaftaran dibuat. Masukkan OTP dari Google Authenticator.', true);
  } catch (e) {
    setStatus('authStatus', e.message);
  }
}

async function confirmRegistration() {
  try {
    await post('/api/web/enroll/confirm', { challenge, otp: $('otp').value.trim() });
    setStatus('authStatus', 'Pendaftaran selesai. Silakan login web.', true);
  } catch (e) {
    setStatus('authStatus', e.message);
  }
}

async function login() {
  try {
    const data = await post('/api/web/login', getCreds(true));
    if (data.requiresTotpEnrollment) {
      challenge = data.challenge;
      $('otpWrap').classList.remove('hidden');
      $('btnConfirm').classList.remove('hidden');
      $('enrollBox').classList.remove('hidden');
      $('enrollBox').textContent = `Akun lama wajib aktivasi TOTP.\nSecret: ${data.secret}\n${data.otpauthUrl}`;
      setStatus('authStatus', 'Aktifkan TOTP dulu lalu konfirmasi OTP.', false);
      return;
    }
    $('authCard').classList.add('hidden');
    $('accountCard').classList.remove('hidden');
    $('accountEmail').textContent = `${data.email} • auth rev ${data.authRevision}`;
    $('displayName').value = data.displayName || '';
    setStatus('authStatus', '', true);
  } catch (e) {
    setStatus('authStatus', e.message);
  }
}

function accountPayload() {
  return {
    currentPassword: $('currentPassword').value,
    otp: $('freshOtp').value.trim(),
  };
}

async function saveProfile() {
  try {
    await post('/api/web/profile', {
      ...accountPayload(),
      displayName: $('displayName').value,
    });
    setStatus('acctStatus', 'Profil tersimpan.', true);
  } catch (e) {
    setStatus('acctStatus', e.message);
  }
}

async function changePassword() {
  try {
    await post('/api/web/password', {
      ...accountPayload(),
      newPassword: $('newPassword').value,
    });
    setStatus('acctStatus', 'Sandi berhasil diganti. Login ulang.', true);
  } catch (e) {
    setStatus('acctStatus', e.message);
  }
}

async function startTotpReset() {
  try {
    const data = await post('/api/web/totp/reset', accountPayload());
    resetChallenge = data.challenge;
    resetSecret = data.secret;
    $('totpResetBox').classList.remove('hidden');
    $('confirmResetWrap').classList.remove('hidden');
    $('totpResetBox').textContent = `Secret baru: ${data.secret}\n${data.otpauthUrl}`;
    setStatus('acctStatus', 'Masukkan OTP dari secret baru lalu konfirmasi reset.', true);
  } catch (e) {
    setStatus('acctStatus', e.message);
  }
}

async function confirmTotpReset() {
  try {
    await post('/api/web/enroll/confirm', {
      challenge: resetChallenge,
      otp: $('resetOtp').value.trim(),
    });
    setStatus('acctStatus', 'TOTP baru aktif.', true);
    $('resetOtp').value = '';
    $('confirmResetWrap').classList.add('hidden');
  } catch (e) {
    setStatus('acctStatus', e.message);
  }
}

async function logout() {
  try {
    await post('/api/web/logout', {});
    window.location.reload();
  } catch (e) {
    setStatus('acctStatus', e.message);
  }
}

$('btnRegister').addEventListener('click', register);
$('btnConfirm').addEventListener('click', confirmRegistration);
$('btnLogin').addEventListener('click', login);
$('btnSaveProfile').addEventListener('click', saveProfile);
$('btnChangePassword').addEventListener('click', changePassword);
$('btnResetTotp').addEventListener('click', startTotpReset);
$('btnConfirmReset').addEventListener('click', confirmTotpReset);
$('btnLogout').addEventListener('click', logout);

(async function restoreSession() {
  try {
    const r = await fetch('/api/web/me', { credentials: 'include' });
    if (!r.ok) return;
    const me = await r.json();
    $('authCard').classList.add('hidden');
    $('accountCard').classList.remove('hidden');
    $('accountEmail').textContent = `${me.email} • auth rev ${me.authRevision}`;
    $('displayName').value = me.displayName || '';
    if (resetSecret) $('totpResetBox').textContent = `Secret baru: ${resetSecret}`;
  } catch {
    // no session
  }
})();
