# Panduan setup dan migrasi server TiaSSH

## Quick start Ubuntu 22.04 (otomatis, direkomendasikan)

> Jalankan di **Ubuntu Server 22.04 LTS**, VM/VPS dengan systemd, sebagai user dengan akses `sudo`. Pilih **satu** jalur: cepat atau manual. Ganti seluruh `ssh.example.com` dengan domain Anda, arahkan DNS A/AAAA ke VPS, dan gunakan port SSH administrasi yang benar. Installer tidak memasang Node atau mengubah firewall otomatis.

### A) Update OS + kernel dulu

Backup/snapshot VPS dan jadwalkan downtime sebelum upgrade; `reboot` memutus sesi SSH. `full-upgrade` memperbarui kernel mengikuti metapackage yang sudah terpasang. Jangan memakai `do-release-upgrade`: contoh ini tetap Ubuntu 22.04. Untuk VM Ubuntu standar yang **belum memiliki** metapackage kernel, gunakan `sudo apt-get install linux-generic` sebelum reboot. VPS dengan kernel khusus/cloud (`linux-virtual`, `linux-aws`, dll.) harus mengikuti image/provider; container/OpenVZ tidak bisa memperbarui kernel host dari dalam container. Jangan menghapus kernel lama sebelum kernel baru berhasil boot.

```bash
sudo apt-get update
sudo apt-get -y full-upgrade
sudo reboot
```

Setelah login lagi:

```bash
uname -r
lsb_release -a
```

### B) Install dependensi dasar

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git rsync nano unzip tar xz-utils util-linux nginx sqlite3
```

### C) Install Node.js 24 + npm

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x -o "$HOME/nodesource_setup_24.sh"
less "$HOME/nodesource_setup_24.sh"
# Setelah memeriksa dan mempercayai script NodeSource:
sudo -E bash "$HOME/nodesource_setup_24.sh"
sudo apt-get install -y nodejs build-essential
node -v
npm -v
```

### D) Download source dan deploy cepat

NodeSource memasang **npm bersama paket nodejs**; jangan memasang paket `npm` Ubuntu terpisah atau memakai Node lama bawaan Ubuntu. Uji SQLite: `node -e "require('node:sqlite'); console.log('SQLite OK')"`.

Download dari GitHub (perintah di bawah untuk folder baru; jika sudah ada, jangan menimpa data lama):

```bash
git clone https://github.com/xccvme/TiaSSH.git "$HOME/tiassh"
cd "$HOME/tiassh/server"
sudo env APP_DIR=/opt/tiassh PORT=8080 \
  PUBLIC_URL=https://ssh.example.com \
  WEB_ORIGIN=https://ssh.example.com \
  bash install-server.sh
```

Installer sudah membuat daemon, enable boot dan restart. Recovery key ditampilkan **sekali** di terminal interaktif; simpan offline/password manager. Jangan menjalankan installer dengan `tee`, redirect, CI log, atau rekaman layar. Init yang gagal/non-TTY menyebabkan rollback, bukan key dicetak ke log.

### E) Aktivasi daemon + cek service

```bash
sudo systemctl daemon-reload
sudo systemctl enable tiassh
sudo systemctl restart tiassh
sudo systemctl status tiassh --no-pager
curl -fsS http://127.0.0.1:8080/api/health
```

### F) Reverse proxy HTTPS (Nginx)

Buka TCP 80/443 pada firewall provider/security group. Jika memakai UFW, **izinkan port SSH administrasi sebelum enable** agar tidak terkunci. Contoh ini mengasumsikan SSH port 22; sesuaikan jika bukan 22. Jangan menjalankan UFW di container atau host yang firewall-nya dikelola sistem lain tanpa review.

```bash
sudo apt-get install -y ufw
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 8080/tcp
sudo ufw enable
sudo ufw status verbose
```

Server Node mendengarkan semua interface; jangan buka 8080 ke publik. Nginx tetap memakai upstream loopback. Periksa aturan UFW lama dan firewall provider, jangan menganggap `deny` membatalkan semua aturan `allow` yang sudah ada.

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo nano /etc/nginx/sites-available/tiassh
```

Isi config contoh:

```nginx
server {
    listen 80;
    server_name ssh.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
}
```

Aktifkan site + SSL:

```bash
sudo ln -s /etc/nginx/sites-available/tiassh /etc/nginx/sites-enabled/tiassh
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d ssh.example.com
sudo certbot renew --dry-run
curl -fsS https://ssh.example.com/api/health
```

---

## Install manual Ubuntu 22.04 (tanpa installer otomatis)

Pakai mode ini jika Anda ingin menyusun service secara manual step-by-step.

### 1) Update OS + install paket

Ikuti langkah **A** di atas termasuk reboot dan pemeriksaan kernel, lalu jalankan:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git rsync nano unzip tar xz-utils util-linux nginx sqlite3
curl -fsSL https://deb.nodesource.com/setup_24.x -o "$HOME/nodesource_setup_24.sh"
less "$HOME/nodesource_setup_24.sh"
# Setelah memeriksa dan mempercayai script NodeSource:
sudo -E bash "$HOME/nodesource_setup_24.sh"
sudo apt-get install -y nodejs build-essential
node -v
npm -v
```

### 2) Download source dan siapkan akun service

Hanya untuk instalasi **baru**; untuk update/migrasi gunakan bagian migrasi/installer transaksional di bawah. Jangan rsync source ke aplikasi produksi yang masih berjalan.

```bash
git clone https://github.com/xccvme/TiaSSH.git "$HOME/tiassh"
sudo useradd --system --user-group --home-dir /opt/tiassh --shell /usr/sbin/nologin tiassh
sudo install -d -m 0755 /opt/tiassh/server
```

Jika akun `tiassh` sudah ada, lewati `useradd`; periksa `id tiassh`. Jangan menjalankan instalasi baru di direktori yang berisi data lama.

### 3) Upload/copy source server

```bash
sudo rsync -av \
  --exclude node_modules --exclude data --exclude .git --exclude .env \
  "$HOME/tiassh/server/" /opt/tiassh/server/
sudo chown -R tiassh:tiassh /opt/tiassh/server
```

### 4) Install dependency produksi

```bash
cd /opt/tiassh/server
sudo -u tiassh npm ci --omit=dev --no-audit --no-fund
sudo -u tiassh mkdir -p data
sudo chmod 700 data
```

### 5) Uji Node foreground + inisialisasi recovery

Jalankan server pertama kali untuk membuat schema SQLite. Buka sesi SSH kedua untuk health check, lalu hentikan proses foreground dengan **Ctrl+C** sebelum membuat daemon. Jangan menjalankan dua penulis DB bersamaan.

```bash
cd /opt/tiassh/server
sudo -u tiassh env NODE_ENV=production PORT=8080 \
  PUBLIC_URL=https://ssh.example.com WEB_ORIGIN=https://ssh.example.com \
  DATA_DIR=/opt/tiassh/server/data /usr/bin/node server.js
```

Di sesi SSH kedua:

```bash
curl -fsS http://127.0.0.1:8080/api/health
```

Setelah Ctrl+C, jalankan init di terminal pribadi (tanpa redirect/tee):

```bash
cd /opt/tiassh/server
sudo -u tiassh env DATA_DIR=/opt/tiassh/server/data /usr/bin/node admin-recovery.js init
```

Simpan recovery key offline; key tidak bisa ditampilkan ulang. DB hanya menyimpan verifier hash.

### 6) Buat service systemd manual

```bash
sudo tee /etc/systemd/system/tiassh.service >/dev/null <<'EOF'
[Unit]
Description=TiaSSH account and sync server
After=network.target

[Service]
Type=simple
User=tiassh
Group=tiassh
WorkingDirectory=/opt/tiassh/server
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production
Environment=PORT=8080
Environment=DATA_DIR=/opt/tiassh/server/data
Environment=PUBLIC_URL=https://ssh.example.com
Environment=WEB_ORIGIN=https://ssh.example.com

[Install]
WantedBy=multi-user.target
EOF
```

### 7) Enable + jalankan daemon

```bash
sudo systemctl daemon-reload
sudo systemctl enable tiassh
sudo systemctl restart tiassh
sudo systemctl status tiassh --no-pager
```

### 8) Cek health + log

```bash
curl -fsS http://127.0.0.1:8080/api/health
sudo journalctl -u tiassh -n 100 --no-pager
```

### 9) Aktifkan HTTPS dan firewall

Ikuti langkah **F** di atas (Nginx + Certbot), lalu lakukan checklist akun/native di bagian verifikasi. Service manual menggunakan akun `tiassh`; untuk CLI recovery dan backup, jalankan sebagai user service yang benar. Jika nanti beralih ke installer otomatis, review unit/drop-in dan ownership karena unit installer standar berjalan sebagai root.

---

## 1. Persiapan

- Linux dengan systemd (contoh Debian/Ubuntu), akses root/sudo, Node.js **24+**, npm, curl, tar, dan util-linux (`flock`). Installer tidak mengunduh script NodeSource/menjalankannya sebagai root dan tidak mengubah firewall otomatis.
- Server memakai `node:sqlite` (minimum runtime sumber 22.13; installer meminta 24+).
- Domain HTTPS yang menunjuk ke VPS, port 80/443 untuk reverse proxy, konektivitas outbound ke port SSH target. Server bukan daemon SSH: native → HTTP/WebSocket TiaSSH → SSH target.
- Ruang disk untuk salinan sumber, dependensi baru, dan **salinan seluruh data lama**. Backup berisi akun, secret TOTP, sesi, ciphertext, dan `master.key`; lindungi sebagai data rahasia.
- Satu service dan satu proses yang menulis DB. Jangan menjalankan proses manual bersamaan dengan service; installer hanya menghentikan service yang dikonfigurasi, bukan semua proses Node.

Cek prasyarat:

```bash
node --version
npm --version
command -v curl tar flock
systemctl --version
```

Pasang Node 24 melalui package manager/repositori resmi yang telah Anda verifikasi. Jika Node tidak ada atau terlalu lama, installer berhenti sebelum deploy; tidak ada upgrade OS/Node tersembunyi.

## 2. Deploy pertama, interaktif

Upload **folder `server/` lengkap**, termasuk portal, `account-security.js`, `admin-recovery.js`, package-lock, dan installer. Jangan upload data pengguna atau node_modules dari mesin pengembangan.

```bash
sudo env APP_DIR=/opt/tiassh PORT=8080 \
  PUBLIC_URL=https://ssh.example.com \
  WEB_ORIGIN=https://ssh.example.com \
  bash /root/tiassh/server/install-server.sh
```

Ganti domain/path contoh dengan milik Anda. Jalankan dari terminal interaktif tanpa `tee`, redirection, CI log, screen recording, atau transcript terminal. Setelah health check, jika recovery key belum ada, installer memanggil `node admin-recovery.js init` dengan stdin/stdout langsung ke operator. **Key acak ditampilkan sekali saja; simpan offline/password manager.** DB hanya menyimpan verifier hash recovery. Jangan kirim key ke developer/chat, jangan commit key, jangan mencoba CLI ini pada data produksi untuk pengujian.

Installer:

1. Validasi root, Node, URL/path/port dan lock deployment.
2. Snapshot sumber ke staging, mengecualikan `data`, `node_modules`, `.env`, `.git`. Aman walaupun installer dijalankan dari `/opt/tiassh/server` sendiri.
3. Install dependensi **di staging** (`npm ci --omit=dev` jika package-lock tersedia). Kegagalan ini tidak menyentuh aplikasi lama.
4. Hentikan service aktif. Jika stop gagal, berhenti tanpa menyalin DB yang masih berjalan.
5. Salin seluruh direktori data lama **termasuk `tiassh.db-wal`, `tiassh.db-shm`, `master.key`**. Aplikasi lama dipindahkan ke backup transaksi, bukan dihapus.
6. Aktifkan release baru, tulis systemd unit, daemon-reload, enable, dan **restart eksplisit**; `enable --now` saja tidak cukup untuk update service yang sudah aktif.
7. Periksa service aktif dan respons `/api/health` (`ok: true`, `name: tiassh-sync`), lalu periksa verifier recovery. Kegagalan melakukan rollback berkas/data/unit dan mencoba restart service lama jika sebelumnya aktif.

Direktori transaksi `/opt/tiassh/.deploy.XXXXXXXX/` dipertahankan untuk backup/diagnosis, dengan permission privat. Setelah sukses `old-app/` adalah snapshot sebelum update. Setelah kegagalan pasca-cutover, `failed-app/` berisi release gagal dan datanya. Review lalu hapus backup lama secara manual sesuai retensi; **jangan menghapus data aktif**. Rollback best-effort tidak menjamin keberhasilan saat disk rusak/penuh, permission salah, listrik padam, atau stop/restart gagal lagi. Periksa pesan error dan service sendiri.

### Deployment noninteraktif

Jika key recovery belum ada, deployment **gagal dengan instruksi init manual**, bukan membuat key lalu mencatatnya ke log. Release gagal tetap disimpan di `TX/failed-app` dan release lama dipulihkan.

Untuk **deploy pertama** yang gagal karena non-TTY, ikuti path transaksi nyata yang dicetak installer, dari terminal pribadi:

```bash
# Ganti TX dengan path .deploy.* yang dicetak; JANGAN ambil wildcard acak.
TX=/opt/tiassh/.deploy.GANTI_DENGAN_PATH_ASLI
cd "$TX/failed-app"
sudo env DATA_DIR="$TX/failed-app/data" node admin-recovery.js init
# Simpan key sekali, offline; jangan redirect stdout.
sudo mkdir -p /opt/tiassh/server
sudo cp -a "$TX/failed-app/data" /opt/tiassh/server/data
# Jalankan kembali installer dari source upload dengan URL yang sama.
```

Untuk **update akun lama** dengan key belum diinisialisasi, cara aman yang disarankan adalah ulangi installer secara interaktif. Jangan menimpa DB aktif dengan `failed-app/data`: salinan tersebut mungkin tertinggal setelah service lama hidup kembali. Init di DB lama hanya jika schema account-security sudah tersedia dan service dihentikan/backup dibuat. CLI `init` bukan bootstrap DB kosong: ia memerlukan tabel dasar yang disiapkan server.

## 3. Konfigurasi

| Variabel installer | Default / arti |
|---|---|
| `APP_DIR` | `/opt/tiassh`; aplikasi di `$APP_DIR/server`, data di `$APP_DIR/server/data` |
| `SYSTEMD_DIR` | `/etc/systemd/system`; override untuk harness/test |
| `SERVICE_NAME` | `tiassh`; nama systemd unit |
| `PORT` | `8080`, angka 1–65535 |
| `PUBLIC_URL` | URL publik; jika kosong menggunakan IP pertama `hostname -I` (atau loopback jika tidak tersedia) + port. Fallback **tidak menjamin IP publik/reachable**; tetapkan domain sendiri. |
| `WEB_ORIGIN` | Default `PUBLIC_URL`; origin portal `scheme://host[:port]`, tanpa path/query/fragment. Harus sama dengan origin yang dibuka browser. |
| `HEALTH_RETRIES` | `15`; jumlah pemeriksaan |
| `HEALTH_DELAY_SEC` | `1`; jeda pemeriksaan |

APP_DIR/path systemd harus absolute, tanpa spasi/karakter kontrol; target/data symlink tidak didukung. Installer tidak membaca `.env` dan selalu mengganti unit miliknya. Jika deployment lama memakai `DATA_DIR` eksternal, **backup dan migrasikan secara sadar sebelum menjalankan installer** atau pertahankan konfigurasi lewat systemd drop-in dan verifikasi path data; installer standar hanya memelihara `$APP_DIR/server/data`. Jangan mengasumsikan data di path lain akan otomatis disalin.

Untuk service manual, variabel tambahan di server meliputi `DATA_DIR`, `NATIVE_ORIGINS`, `SESSION_TTL_SEC`; jangan mengubah allowlist origin tanpa memahami pembatasan browser/native. Lihat sumber untuk nilai persis. Service default berjalan sebagai root karena installer root/systemd; untuk hardening buat akun khusus dan drop-in `User=`, berikan akses data yang benar, lalu uji. Installer tidak mengklaim sandbox service lengkap.

Mengubah konfigurasi unit/drop-in memerlukan:

```bash
sudo systemctl daemon-reload
sudo systemctl restart tiassh
```

Pastikan drop-in lama tidak menimpa URL/port baru. Jangan memakai URL loopback VPS di HP.

## 4. HTTPS reverse proxy (Nginx)

1. Arahkan DNS domain ke IP VPS. Buka TCP 80/443 di firewall cloud dan host; jangan membuka port 8080 ke publik jika hanya proxy lokal yang memerlukannya.
2. Pasang Nginx/Certbot:

```bash
sudo apt-get update
sudo apt-get install nginx certbot python3-certbot-nginx
sudo nano /etc/nginx/sites-available/tiassh
```

Isi config (ganti domain):

```nginx
server {
    listen 80;
    server_name ssh.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/tiassh /etc/nginx/sites-enabled/tiassh
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d ssh.example.com
sudo certbot renew --dry-run
curl -fsS https://ssh.example.com/api/health
```

Jika symlink sudah ada jangan membuatnya ulang. Konfigurasi di atas meneruskan `/ws` melalui blok `/`; tidak boleh membuang header Upgrade. Konfigurasi `PUBLIC_URL` dan `WEB_ORIGIN` harus **HTTPS publik**, walau upstream ke Node HTTP lokal, agar cookie portal Secure dan pemeriksaan origin cocok. Header forwarded bukan bukti identitas klien yang boleh dipercaya sembarang; jangan mengubah trust proxy sembarangan.

HTTP hanya untuk pengembangan/LAN terkendali; sandi, token, dan kredensial proxy dapat disadap melalui HTTP. Jangan menyatakan Android selalu mengizinkan cleartext: gunakan HTTPS dan sertifikat terpercaya. Browser/native harus memakai domain yang sama dengan sertifikat, bukan IP yang tidak tercakup.

## 5. Migrasi tanpa membuang data

**Jangan** menjalankan installer lama yang menghapus folder server sebelum menyalin source, menghapus tabel users, mengubah salt akun, atau membuat akun ulang untuk “memperbaiki” login.

1. Catat service, URL, port, DATA_DIR, drop-in, versi Node, dan passphrase vault pengguna. Hentikan penulisan/proses manual lain.
2. Backup data konsisten ketika service berhenti:

```bash
sudo systemctl stop tiassh
sudo tar -C /opt/tiassh/server -czf /root/tiassh-data-backup.tar.gz data
sudo systemctl start tiassh
```

Simpan arsip di penyimpanan terenkripsi/akses terbatas; jangan tar DB hidup tanpa mekanisme SQLite backup. Salin seluruh data dan WAL/SHM, bukan DB saja. Simpan recovery key terpisah, bukan dalam source/zip/log.

3. Upload source baru tanpa data/node_modules. Jalankan installer baru interaktif dengan APP_DIR/URL/port yang sama. Same-source deploy didukung, tetapi upload terpisah memudahkan rollback/source review.
4. Migrasi schema dilakukan server. Akun, ciphertext, dan salt dipertahankan. Sesi legacy dapat dicabut; login ulang. Akun lama akan diminta enrollment TOTP lewat web.
5. Native membuka vault menggunakan passphrase lama (default sandi login **asli** ketika vault dibuat). Mengubah sandi web bukan rekey vault. Klien mendukung envelope legacy dan v2; uji data nyata dengan backup sebelum memakai seluruh perangkat. Jangan menjalankan klien versi lama dan baru bersamaan selama migrasi vault.
6. Periksa data dan login di dua perangkat, SSH/SFTP, serta reconnect sesudah network/background. Health check tidak membuktikan semua ini.

## 6. Recovery administrator

Recovery key hanya untuk operator. CLI menolak stdin/stdout non-TTY.

```bash
sudo systemctl stop tiassh
cd /opt/tiassh/server
sudo env DATA_DIR=/opt/tiassh/server/data node admin-recovery.js reset-email
sudo systemctl start tiassh
```

Prompt meminta recovery key, email akun, dan sandi baru (12–72 byte). Reset mempertahankan ciphertext dan salt; semua sesi dicabut dan TOTP dihapus. Pengguna login portal dengan sandi baru untuk enrollment TOTP ulang, lalu native login dengan sandi baru **dan passphrase vault lama**. Tanpa passphrase vault lama, data tetap tidak bisa dibuka. Jangan menghapus user/ciphertext sebagai langkah reset. Key yang hilang tidak dapat ditampilkan kembali oleh CLI; lindungi backup offline sejak init.

## 7. Verifikasi dan troubleshooting

```bash
sudo systemctl status tiassh
sudo journalctl -u tiassh -n 50 --no-pager
curl -fsS http://127.0.0.1:8080/api/health
curl -fsS https://ssh.example.com/api/health
```

- Node hilang/lama: pasang Node 24, pastikan executable systemd sama dengan yang diuji.
- Health gagal: periksa log startup, port bentrok, permission data, dependensi; installer nonzero dan mencoba rollback. Cek old-app/failed-app, jangan hapus backup.
- Rollback restart gagal: data lama masih backup; hentikan proses lain, pulihkan old-app/unit dengan path transaksi tepat dan restart manual. Jangan lanjut update sebelum penyebab diketahui.
- Browser ditolak origin/cookie: WEB_ORIGIN harus sama dengan URL browser, PUBLIC_URL HTTPS benar, bukan URL upstream localhost.
- OTP ditolak: kode sudah dipakai, tunggu 30 detik berikutnya; periksa sinkronisasi waktu/NTP HP/server. Jangan disable TOTP sebagai shortcut.
- Login berhasil tetapi vault gagal: sandi login baru bukan passphrase lama. Jangan reset salt atau memaksa menulis ciphertext kosong.
- Android reconnect: cek TLS, jaringan/DNS, proxy Upgrade `/ws`, sesi setelah reset/sandi berubah; uji background/resume nyata. Bukan klaim perbaikan tervalidasi hanya dari health.

Checklist operator sebelum menyatakan siap: HTTPS valid; recovery key tersimpan offline; health lokal/publik aktif; daftar/enrollment web; replay OTP ditolak; perubahan profil/sandi membutuhkan sandi saat ini + kode baru; native login dan passphrase lama; sync dua perangkat; SSH/SFTP; background/reconnect; backup dan restore sandbox. Hasil test otomatis bukan jaminan tidak ada masalah produksi.
