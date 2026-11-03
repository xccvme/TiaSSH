# Peta proyek TiaSSH

## Arsitektur yang ada di sumber

```text
Browser ── HTTPS ── portal akun + /api/web/*
                      │ cookie scope web
                      ▼
               server/account-security.js ── SQLite

Electron / Capacitor ── HTTPS login native ── /api/login
       │ bearer scope client                        │
       ├─ passphrase lokal → PBKDF2 → AES/HMAC vault ─┤ /api/sync/*
       │                           ciphertext       │ SQLite sync_items
       └─ WebSocket /ws ── server SSH/SFTP proxy ────┴─ ssh2 → target SSH
                               ↑
                       kredensial SSH tersedia
                       dalam plaintext saat koneksi

Terminal operator (TTY) → admin-recovery.js → verifier recovery/reset akun
```

Browser bukan klien terminal/vault. `web/` di root proyek adalah sumber **UI native**, sedangkan `server/web/portal/` adalah sumber portal akun yang disajikan server. Nama folder `web` tidak berarti semua file disajikan ke browser publik.

## File dan tanggung jawab

| Komponen / path | Fungsi |
|---|---|
| `server/server.js` | Bootstrap runtime, direktori data/master.key, SQLite tabel dasar, Express auth native, API sync, HTTP health, WebSocket, proxy SSH/SFTP, serving portal. |
| `server/account-security.js` | Migrasi auth; base32/RFC6238 TOTP; enrollment challenge; validasi OTP dan counter replay; cookie sesi scope web vs bearer scope client; revisi auth/revokasi; profil/sandi/TOTP; verifier recovery dan reset by email. |
| `server/admin-recovery.js` | CLI `init` / `reset-email`, wajib stdin/stdout TTY; init satu kali menampilkan key acak langsung operator dan hanya menyimpan hash; reset tidak memodifikasi ciphertext. Memerlukan DB dengan tabel dasar server. |
| `server/install-server.sh` | Validasi root/Node 24/config; lock; tar staging; npm; stop service; salinan data+WAL; backup aplikasi/unit; cutover; restart; health; recovery init TTY atau fail non-TTY; rollback best-effort. |
| `server/web/portal/index.html` | Struktur halaman account-only dan form enrollment/login/profile/password/TOTP. |
| `server/web/portal/portal.js` | Fetch `/api/web/*` memakai cookie, enrollment TOTP, rendering aman via textContent; tidak menyimpan bearer/host/private key di browser storage. |
| `server/web/portal/portal.css` | Style portal terpisah sesuai CSP tanpa inline script/style. |
| `web/index.html` | UI native login/unlock vault, host/keypair, terminal tabs, file manager. |
| `web/app.js` | Login/sesi lokal; `deriveKey`, `deriveLegacyKey`, `encValue`/`decValue`; unlock/migrasi vault; snapshot/pull/push; `openWs`, pesan sinkronisasi, reconnect/backoff; `connectSsh`, `ensureSftp`, operasi file/upload/download. |
| `web/vendor/*` | aes-js, js-sha256, xterm dan fit addon lokal; lisensi upstream tetap berlaku. |
| `desktop/main.js` | Electron single-instance, BrowserWindow dengan contextIsolation/sandbox dan tanpa nodeIntegration; load `desktop/web/index.html`, membuka URL luar di browser sistem. |
| `desktop/package.json` | Dependensi Electron/electron-builder; NSIS Windows x64 dan AppImage Linux; build output `desktop/dist/`. |
| `desktop/web/` | Salinan UI native untuk packaging; harus disinkronkan dari root `web/` sebelum build. |
| `android/capacitor.config.json`, `android/package.json` | Konfigurasi Capacitor, webDir `../web`, npm scripts sync/build. |
| `android/android/app/src/main/AndroidManifest.xml` | Permission/konfigurasi activity Android; bukan logika auth server. |
| `android/android/` | Project Gradle, Android Gradle Plugin 8.2.1, wrapper Gradle 8.2.1, SDK compile/target 34; sumber generated Capacitor dan aset. |
| `android/android/app/src/main/assets/public/` | Output hasil `cap sync android`, bukan sumber primer UI. |
| `server/data/` saat runtime | `tiassh.db`, SQLite WAL/SHM, `master.key`, auth/sync runtime. Bukan isi distribusi. |
| `server/tests/*.test.js` | Suite API/OTP/sesi/recovery/portal/UI/security dan regresi sync. |
| `tests/client/*.test.js` | Suite kriptografi vault (termasuk legacy/v2) dan reliability klien. |
| `tests/installer/test_installer.py` | Unit/integration transaksi filesystem nyata di sandbox dengan OS/npm/Node/systemd/network mock. |
| `LICENSE`, `THIRD_PARTY_NOTICES.md`, `licenses/` | WTFPL untuk kode milik proyek; inventaris/notices dan teks lisensi pihak ketiga. |
| `README.md`, `PANDUAN_SETUP_SERVER.md` | Penggunaan/build dan deployment/migrasi/backup/pemulihan operasional. |

## Alur autentikasi dan akun

1. Registrasi hanya `/api/web/register`: menghasilkan secret/otpauth URL dan challenge sementara, **bukan sesi**. `/api/web/enroll/confirm` mengesahkan OTP sebelum akun aktif.
2. Login portal `/api/web/login` meminta email, sandi, dan OTP. Akun legacy tanpa TOTP menerima challenge enrollment dahulu. Cookie HttpOnly/SameSite Strict (Secure untuk origin HTTPS), bukan native bearer.
3. `/api/web/me` memberi informasi akun; `/api/web/profile`, `/api/web/password`, `/api/web/totp/reset` mensyaratkan sesi web, origin valid, sandi saat ini, dan kode baru. Rotasi secret TOTP harus dikonfirmasi; secret lama tetap aktif sampai itu.
4. TOTP SHA1 enam digit periode 30 detik, toleransi ±1 counter; counter terakhir dicatat sehingga kode yang sudah dikonsumsi tidak dapat dipakai ulang.
5. `/api/register` native tidak tersedia. `/api/login` native memakai email/sandi, tidak meminta OTP. Request browser origin tidak boleh dipakai untuk mencetak token password-only native. Origin allowlist adalah pembatasan browser, **bukan bukti bahwa semua client HTTP adalah aplikasi asli**.
6. Sesi dicatat dengan scope, expiry, revoked, dan auth revision. Web tidak boleh memakai sync/WS. Perubahan auth/recovery mencabut sesi yang relevan; socket mengecek status sesi. Sesi native dan keys vault disimpan/dipegang di perangkat, bukan cookie portal.

## Alur vault dan sinkronisasi

1. Login native memperoleh salt akun dan token. Passphrase vault lokal default sandi login asli saat vault dibuat; dapat berbeda dari sandi login baru.
2. PBKDF2-HMAC-SHA256 100.000 iterasi menghasilkan 64 byte → AES key 32 + HMAC key 32. Envelope v2 memakai IV acak, AES-256-CBC, HMAC-SHA256 dan verifikasi sebelum decrypt. Jalur legacy derivation/envelope dibaca untuk migrasi; jangan menulis ulang data ketika unlock gagal.
3. Host/keypair diserialisasi dan dienkripsi sebelum `pushItem` → `/api/sync/push`. SQLite menyimpan `value_enc`, bukan kredensial host plaintext sebagai item sync.
4. Login/unlock menarik `/api/sync/snapshot`; pembaruan berikutnya `/api/sync/pull?since=...`. Revisi/cursor/tombstone mencegah kehilangan update/delete; WS memberi notifikasi agar klien menyegarkan data.
5. Passphrase/account salt tidak berubah hanya karena sandi akun di web berubah. Reset administrator juga tidak rekey/decrypt vault. Pemulihan akun tidak berarti pemulihan passphrase.

## Alur SSH/SFTP dan reconnect

- Native membuka `/ws` dengan bearer client dan mengirim pesan `ssh-open` / `sftp-open`. Proxy membuat koneksi upstream memakai `ssh2`, lalu merutekan stdin/stdout/resize atau operasi SFTP berdasarkan tag/channel.
- Kredensial SSH/private key yang diperlukan untuk upstream dikirim lewat TLS dan **tersedia kepada proxy**. Vault ciphertext-at-rest tidak menyembunyikannya dari server aktif.
- Klien menampilkan status sync/reconnect dan retry; diagnosis membutuhkan jaringan, TLS, forwarding Upgrade WS, serta revokasi sesi. Setelah Android background/resume, verifikasi koneksi/perangkat nyata; suite unit bukan bukti reconnect sempurna pada semua OS.
- Logging/pengujian tidak boleh merekam kredensial, bearer, atau key recovery. Jangan memakai origin header sebagai autentikasi proxy.

## Deployment, persistence, rollback

Installer membuat `$APP_DIR/.deploy.*`, menyalin source tanpa runtime, menginstall dependensi sebelum downtime, lalu menghentikan service dan menyalin seluruh data. Backup `old-app/` tetap utuh ketika release baru menulis schema/data. Kegagalan install/stop/copy/move/restart/health/init memulihkan release/data/unit sejauh filesystem dan service tersedia. Non-TTY tanpa recovery verifier harus gagal dengan instruksi operator; tidak ada key dev nyata yang dibuat oleh test.

Batas: bukan transaksi filesystem power-loss-proof, bukan backup eksternal, bukan pengelola firewall/Node, tidak mendeteksi proses manual yang menulis DB, tidak otomatis memindahkan DATA_DIR eksternal. Rollback kegagalan layanan harus diperiksa operator. Retensi `.deploy.*` memerlukan pembersihan manual dan permission data yang aman.

## Build dan pengujian

- Runtime installer/QA: Node 24+. Runtime sumber minimal Node 22.13 karena `node:sqlite`.
- Server: `(cd server && npm ci && npm test)`.
- Client: `node --test tests/client/*.test.js`.
- Installer: `python3 -m unittest discover -s tests/installer -p 'test_*.py' -v`; `bash -n server/install-server.sh`.
- Desktop: salin `web/.` → `desktop/web/`, `(cd desktop && npm ci && npm run build:win)`. Linux→Windows membutuhkan toolchain Wine yang sesuai; build Linux tersendiri memakai script `build:linux`.
- Android: JDK17/SDK34, `(cd android && npm ci && npx cap sync android && cd android && ./gradlew assembleDebug)`; APK debug bukan signed production release.
- QA terpisah: native boot/login/unlock, dua perangkat sync, SSH/SFTP, Android jaringan/background/resume/reconnect, HTTPS/origin, OTP replay, sandi baru + vault lama, sandbox restore.

Dokumen ini menggambarkan sumber dan workflow, **bukan sertifikat audit keamanan atau klaim semua build/native QA lulus**. Catat hasil aktual per release; jangan menyalin angka test lama sebagai bukti release baru.
