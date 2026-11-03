# TiaSSH

Klien SSH/SFTP self-hosted untuk Windows (Electron) dan Android (Capacitor), dengan sinkronisasi vault terenkripsi. **Browser hanya portal akun**: daftar, login, profil, perubahan sandi, dan pengelolaan TOTP. Browser tidak menyediakan terminal, SFTP, atau daftar host.

Kode milik proyek dirilis di bawah [WTFPL v2](LICENSE). Dependensi, vendor, Electron/Chromium, dan Gradle tetap memakai lisensi asalnya; lihat [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Mulai menggunakan

1. Deploy server mengikuti [PANDUAN_SETUP_SERVER.md](PANDUAN_SETUP_SERVER.md), menggunakan Node.js 24+ dan HTTPS.
2. Operator menginisialisasi recovery key sekali di terminal interaktif server dan menyimpannya offline. Jangan mengirim key ke chat atau merekam output terminal.
3. Buka URL server di browser. Daftarkan email dan sandi, simpan secret TOTP dalam aplikasi authenticator, lalu konfirmasi kode enam digit.
4. Install aplikasi Windows/Android dari hasil build atau paket distribusi yang tersedia. Masukkan URL server HTTPS dan login dengan email serta sandi akun yang sama.
5. Buka vault dengan **passphrase vault**. Field kosong saat login pertama memakai sandi login sebagai default. Untuk vault lama, default yang benar adalah **sandi login asli yang dipakai ketika vault dibuat**, bukan sandi baru setelah perubahan lewat web.
6. Tambahkan host/keypair di aplikasi native. Host terenkripsi tersinkron; koneksi terminal dan SFTP dilakukan melalui server proxy.

Email adalah identitas akun lokal, bukan Google OAuth. Pendaftaran hanya lewat web; aplikasi native hanya login. Login native tidak meminta OTP, sementara login web serta perubahan profil/sandi/TOTP memerlukan TOTP. Akun lama tanpa TOTP diminta melakukan enrollment saat masuk portal.

## Sandi akun, vault, dan pemulihan

- **Sandi akun** mengautentikasi login. Hash bcrypt disimpan di server.
- **Passphrase vault** menurunkan kunci lokal PBKDF2-HMAC-SHA256 (100.000 iterasi, 64 byte), dipisah menjadi kunci AES-256-CBC dan HMAC-SHA256. Envelope v2 memakai autentikasi sebelum dekripsi. Pembacaan/migrasi vault legacy didukung; simpan backup sebelum migrasi.
- Mengubah sandi akun di web **tidak mengubah passphrase vault atau salt vault**. Gunakan sandi akun baru untuk login dan passphrase lama untuk membuka data.
- Reset administrator hanya memulihkan akses akun, mencabut sesi, dan menghapus enrollment TOTP. **Reset sandi tidak bisa mendekripsi vault**. Tanpa passphrase lama, recovery key administrator tidak menyelamatkan data SSH terenkripsi.
- TOTP berbasis waktu, periode **30 detik**, enam digit. Counter yang sudah dipakai ditolak (replay); tunggu kode berikutnya sebelum tindakan lain. Sinkronkan jam server/HP; toleransi implementasi satu periode sekitar waktu server bukan izin memakai ulang kode.

## Batas keamanan

Vault tersimpan sebagai ciphertext, tetapi ini bukan jaminan “server diretas tetap aman”. **Saat membuka SSH/SFTP, server proxy menerima kredensial SSH dalam bentuk yang dapat dipakai** untuk koneksi upstream. Operator server, malware perangkat, atau penyerang yang menguasai proxy aktif dapat membacanya. Login juga mengirim sandi akun melalui TLS; default sandi vault yang sama dengan sandi login memperlemah pemisahan rahasia terhadap operator server. Pilih passphrase vault independen untuk vault baru.

Gunakan HTTPS, sandi kuat, backup terenkripsi, perangkat terpercaya, dan batasi akses server. Secret TOTP dan data autentikasi perlu dilindungi bersama DB. `master.key` bukan passphrase vault. Sesi web menggunakan cookie HttpOnly/SameSite, sesi native menggunakan bearer dengan scope berbeda; cookie web tidak memberi akses API vault/WS. Jangan mencatat bearer, sandi, key SSH, TOTP secret, atau recovery key ke log.

## Struktur sumber

- `server/`: Express API, SQLite bawaan Node, portal akun, WebSocket SSH/SFTP, CLI recovery, installer.
- `web/`: sumber UI **native**, kriptografi vault, sinkronisasi, terminal/SFTP, vendor lokal.
- `desktop/`: Electron dan salinan `desktop/web/` untuk packaging.
- `android/`: konfigurasi Capacitor, project Android Gradle, aset hasil `cap sync`.
- `tests/client/`: pengujian vault dan reliability klien.
- `tests/installer/`: transaksi deploy dengan filesystem sungguhan di sandbox dan OS/service mock.
- [docs/PROJECT_MAP.md](docs/PROJECT_MAP.md): peta komponen, alur data, build/test, batas keamanan.

## Build dari sumber

Server memerlukan Node minimal 22.13 karena `node:sqlite`; **installer sengaja meminta Node 24+**. Gunakan Node 24 untuk workflow yang konsisten.

```bash
cd server
npm ci
npm test
# Pengembangan saja, menggunakan DATA_DIR terpisah:
PORT=8080 PUBLIC_URL=http://127.0.0.1:8080 DATA_DIR=/path/ke/data-dev node server.js
```

Build Windows (pada Windows, atau lingkungan Linux dengan Wine yang sesuai):

```bash
# Dari root proyek: refresh UI native sebelum build.
cp -a web/. desktop/web/
cd desktop
npm ci
npm run build:win
# Output: desktop/dist/ (nama installer mengikuti versi package.json)
```

Build Android memerlukan JDK 17, Android SDK platform/build-tools 34, dan SDK path yang benar:

```bash
cd android
npm ci
npx cap sync android
cd android
./gradlew assembleDebug
# Output: android/android/app/build/outputs/apk/debug/app-debug.apk
```

APK debug untuk uji, bukan rilis yang ditandatangani untuk distribusi produksi. `assembleRelease` membutuhkan kebijakan signing sendiri; jangan commit keystore/password. Jangan menyunting aset generated sebagai sumber utama.

## Pengujian dan diagnosis

Dari root proyek:

```bash
python3 -m unittest discover -s tests/installer -p 'test_*.py' -v
node --test tests/client/*.test.js
(cd server && npm test)
bash -n server/install-server.sh
```

Harness installer menjalankan copy/move/tar sungguhan, tetapi memalsukan Node/npm/systemctl/network dalam direktori sementara. Itu bukan verifikasi deployment systemd asli. Pengujian native emulator/perangkat dan QA paket distribusi harus dilakukan terpisah; tidak ada klaim semua platform sudah bebas masalah.

Jika reconnect gagal, cek URL HTTPS, jaringan/DNS, forwarding WebSocket `/ws`, sertifikat TLS, dan status sesi setelah sandi diubah. Tunggu retry yang ditampilkan aplikasi; logout/login jika sesi dicabut. Jangan memakai `127.0.0.1` sebagai alamat VPS di HP. Lihat panduan server untuk backup, rollback, pemulihan, dan diagnosis deployment.
