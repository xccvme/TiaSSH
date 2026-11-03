# Lisensi dan notices pihak ketiga

`LICENSE` utama (WTFPL v2) berlaku hanya pada kode/dokumentasi milik TiaSSH. **Tidak mengubah lisensi library, vendor, Gradle wrapper, Electron/Chromium, Capacitor, Android SDK, atau komponen generated pihak ketiga.** Pertahankan copyright/header/notices upstream ketika menyalin atau mendistribusikan sumber/binary.

## Vendor native yang dibundel

| File | Proyek / asal | Lisensi |
|---|---|---|
| `web/vendor/aesjs.js` | aes-js, Richard Moore; header copyright 2015–2018 | MIT; `licenses/aes-js-LICENSE.txt` |
| `web/vendor/sha256.js` | js-sha256 1.0.0, Chen Yi-Cyuan; header copyright 2014–2026 | MIT; `licenses/js-sha256-LICENSE.txt` |
| `web/vendor/xterm.js`, `xterm.css`, `xterm-addon-fit.js` | xterm.js dan fit addon; xterm authors, Christopher Jeffrey, asal desain Fabrice Bellard sebagaimana header CSS | MIT; `licenses/xterm-LICENSE.txt`; pertahankan header CSS asli |

Salinan vendor di `desktop/web/` dan aset Android tetap memakai lisensi yang sama, bukan WTFPL. Tidak semua bundle minified menyertakan teks lisensi penuh; sertakan folder `licenses/` dan dokumen notices saat distribusi. Versi vendor xterm/aes-js tidak ditetapkan ulang dari tebakan nama file; header/release sumber menentukan versi.

## Dependensi npm utama

| Komponen | Paket | Lisensi upstream |
|---|---|---|
| Server HTTP | express | MIT |
| WebSocket | ws | MIT |
| SSH/SFTP | ssh2 | MIT-style teks LICENSE Brian White (package.json terpasang tidak memiliki field `license`) |
| Hash sandi | bcryptjs | Metadata npm menyebut MIT; teks LICENSE bundle juga memuat syarat BSD-style. **Teks upstream disertakan apa adanya**, jangan menggantinya dengan WTFPL. |
| Desktop runtime | electron | MIT untuk Electron; Chromium dan komponen runtime memakai banyak lisensi lain |
| Desktop packaging | electron-builder | MIT; dependensi/build tools punya lisensi sendiri |
| Android wrapper | @capacitor/core, @capacitor/android, @capacitor/cli | MIT, Drifty Co. |

Teks lisensi utama yang tersedia dari paket terpasang disalin ke `licenses/npm-*-LICENSE.txt`. Ini daftar dependensi langsung, **bukan klaim inventaris lengkap semua transitive dependency atau binary**. Lockfiles menunjukkan pohon/versi yang terpasang; pertahankan LICENSE/NOTICE masing-masing paket ketika mendistribusikan node_modules. Komponen opsional seperti cpu-features/bcrypt-pbkdf/tweetnacl juga tetap berlisensi asal. Penanda private package tidak berarti menghapus kewajiban lisensi.

## Electron/Chromium dan binary

Jangan menghapus `LICENSE.electron.txt` dan `LICENSES.chromium.html` dari output Electron (`desktop/dist/win-unpacked/` ketika tersedia). Distribusi Chromium/Node/V8/FFmpeg dan komponen runtime lainnya mengikuti lisensi tersendiri. Bundle binary memerlukan notices dari binary/toolchain **yang benar-benar dibangun**, bukan hanya tabel di atas. Pertahankan notices Android/Capacitor/Cordova yang dibundel dan periksa hasil packaging release.

## Gradle dan Android toolchain

`android/android/gradlew`, `gradlew.bat`, serta Gradle wrapper adalah pihak ketiga; header lisensinya **Apache License 2.0**, bukan WTFPL. Teks: `licenses/Apache-2.0.txt`. Wrapper distribution saat ini menunjuk Gradle 8.2.1; distribusinya memiliki LICENSE/NOTICE sendiri. Android Gradle Plugin, AndroidX, Cordova, JDK, dan Android SDK mengikuti lisensi masing-masing. Jangan mengganti header generated Gradle/Capacitor dengan header lisensi proyek.

## Referensi lisensi

- WTFPL resmi v2: http://www.wtfpl.net/txt/copying/
- aes-js: https://github.com/ricmoo/aes-js
- js-sha256: https://github.com/emn178/js-sha256
- xterm.js: https://github.com/xtermjs/xterm.js
- Apache 2.0: https://www.apache.org/licenses/LICENSE-2.0.txt

Periksa kembali notices bila dependensi berubah. Dokumen ini panduan distribusi, bukan nasihat hukum atau klaim semua kewajiban binary sudah diaudit.
