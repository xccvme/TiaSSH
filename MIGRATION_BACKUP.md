# Migrasi dan Backup Data TiaSSH

## Overview

TiaSSH menyimpan semua data di `/opt/tiassh/server/data/`:
- `tiassh.db` — SQLite database (akun, vault ciphertext, TOTP secrets terenkripsi, sync items)
- `tiassh.db-wal`, `tiassh.db-shm` — SQLite write-ahead log (harus ikut di-backup)
- `master.key` — 64 byte kunci enkripsi TOTP (tanpa ini TOTP tidak bisa dibaca)

**Penting:** Vault user tetap tersimpan sebagai ciphertext (butuh passphrase user untuk buka). TOTP secrets butuh `master.key`.

---

## Backup Manual (Aman untuk Migrasi)

### Script Otomatis Terenkripsi

```bash
cd /opt/tiassh/server
sudo bash backup.sh
```

Output:
- Backup terenkripsi AES-256-CBC: `/root/tiassh-backups/tiassh-backup-YYYYMMDD_HHMMSS.tar.gz.enc`
- Password file: `/root/tiassh-backups/tiassh-backup-YYYYMMDD_HHMMSS.password.txt`

**WAJIB:**
1. Stop service otomatis ditawarkan (konsistensi data)
2. Simpan password file **di luar server** (local, USB terenkripsi, password manager)
3. Hapus password file dari server setelah aman: `rm /root/tiassh-backups/*.password.txt`

### Backup Manual Tanpa Script

```bash
sudo systemctl stop tiassh
sudo tar -C /opt/tiassh/server -czf /root/tiassh-data-$(date +%Y%m%d).tar.gz data
sudo systemctl start tiassh
```

⚠️ **Jangan backup saat service aktif** — SQLite WAL bisa tidak konsisten.

---

## Restore ke Server Baru (Migrasi)

### Prasyarat
1. Server baru sudah install TiaSSH (`install-server.sh` sudah dijalankan, tapi **jangan buat akun dulu**)
2. Backup file + password tersedia

### Langkah Restore

```bash
# 1. Copy backup file ke server baru
scp tiassh-backup-20261104_101530.tar.gz.enc root@server-baru:/root/

# 2. Copy script restore (atau download dari repo)
scp restore.sh root@server-baru:/root/

# 3. Di server baru, jalankan restore
sudo bash /root/restore.sh /root/tiassh-backup-20261104_101530.tar.gz.enc 'PASSWORD_DARI_FILE'
```

Script otomatis:
- Stop service
- Backup data lama (jika ada) ke `data.before-restore.TIMESTAMP`
- Decrypt dan extract
- Validasi `tiassh.db` + `master.key`
- Set permission
- Start service
- Health check

### Verifikasi Setelah Restore

```bash
# Cek service
sudo systemctl status tiassh

# Cek health
curl http://127.0.0.1:8080/health

# Cek log
sudo journalctl -u tiassh -n 50

# Test login web
https://your-domain.com/portal/

# Test native client login
# (gunakan sandi akun + passphrase vault yang sama)
```

---

## Restore ke Server yang Sama (Disaster Recovery)

Sama seperti migrasi, tapi data lama otomatis di-backup ke `data.before-restore.TIMESTAMP` sebelum restore.

```bash
sudo bash restore.sh /root/tiassh-backup-20261104_101530.tar.gz.enc 'PASSWORD'
```

Jika restore gagal, data lama masih ada di `data.before-restore.*` dan bisa dikembalikan manual:

```bash
sudo systemctl stop tiassh
sudo rm -rf /opt/tiassh/server/data
sudo mv /opt/tiassh/server/data.before-restore.XXXXXXXX /opt/tiassh/server/data
sudo systemctl start tiassh
```

---

## Update Server yang Sama (Bukan Migrasi)

Installer `install-server.sh` **sudah otomatis backup** saat update:
- Data di-copy ke `/opt/tiassh/.deploy.XXXXXXXX/old-data/`
- Jika deployment gagal, rollback otomatis
- Tidak perlu backup manual kecuali untuk disaster recovery

---

## Backup Berkala (Cron)

Tambahkan ke crontab root:

```bash
sudo crontab -e
```

Tambah baris (backup setiap hari jam 3 pagi):

```
0 3 * * * /opt/tiassh/server/backup.sh >> /var/log/tiassh-backup.log 2>&1
```

⚠️ **Pastikan password file di-download otomatis** atau simpan ke sistem backup terpusat (bukan di server yang sama).

---

## Keamanan Backup

1. **Enkripsi:** Backup terenkripsi AES-256-CBC, password 32 byte random
2. **Permission:** File backup chmod 600 (hanya root yang bisa baca)
3. **Offline storage:** Password **harus** disimpan di luar server
4. **Rotation:** Hapus backup lama manual sesuai retensi (misal: 30 hari terakhir)

```bash
# Hapus backup lebih dari 30 hari
find /root/tiassh-backups -name "tiassh-backup-*.tar.gz.enc" -mtime +30 -delete
```

---

## Troubleshooting

### Restore gagal "password salah"
- Pastikan password dari file `.password.txt` di-copy **persis** (tanpa spasi/newline ekstra)
- Jangan edit password file dengan editor yang tambah newline

### Service gagal start setelah restore
```bash
sudo journalctl -u tiassh -n 100
```

Kemungkinan:
- Permission salah → `sudo chmod 700 /opt/tiassh/server/data && sudo chmod 600 /opt/tiassh/server/data/*`
- Port bentrok → cek `PORT=8080` di environment atau unit systemd
- DB corrupt → restore dari backup lebih lama

### TOTP tidak bekerja setelah restore
- `master.key` tidak ikut ter-restore → pastikan backup include `master.key`
- `master.key` dari server lain → TOTP tidak bisa didekripsi (beda key)

### Vault user tidak bisa dibuka
- Passphrase user salah → vault ciphertext butuh passphrase asli saat vault pertama dibuat
- Perubahan sandi web **tidak** rekey vault → passphrase vault tetap yang lama

---

## Checklist Migrasi Server

- [ ] Backup di server lama: `sudo bash backup.sh`
- [ ] Download password file ke local: `scp root@old:/root/tiassh-backups/*.password.txt ~/`
- [ ] Download backup file ke local: `scp root@old:/root/tiassh-backups/*.tar.gz.enc ~/`
- [ ] Hapus password dari server lama: `sudo rm /root/tiassh-backups/*.password.txt`
- [ ] Setup server baru: install OS, Node 24, Nginx, SSL
- [ ] Install TiaSSH di server baru: `sudo bash install-server.sh` (jangan init recovery key dulu)
- [ ] Upload backup ke server baru: `scp backup.tar.gz.enc restore.sh root@new:/root/`
- [ ] Restore: `sudo bash /root/restore.sh /root/backup.tar.gz.enc 'PASSWORD'`
- [ ] Verifikasi health: `curl http://127.0.0.1:8080/health`
- [ ] Test login web + native client
- [ ] Update DNS A record ke IP baru
- [ ] Test dari client (offline cache otomatis re-sync)
- [ ] Matikan server lama setelah 36 jam (lease native client expired)

---

## FAQ

**Q: Apakah backup include vault user?**  
A: Ya, tapi sebagai **ciphertext**. User tetap butuh passphrase untuk buka vault. Backup tidak simpan passphrase.

**Q: Apakah bisa restore ke server dengan versi TiaSSH berbeda?**  
A: Ya, selama schema DB kompatibel. Update minor (1.0.x → 1.0.y) aman. Update major test dulu di staging.

**Q: Apakah bisa backup saat service aktif?**  
A: **Tidak disarankan** — SQLite WAL bisa tidak konsisten. Script `backup.sh` tawarkan stop service otomatis.

**Q: Apakah password backup bisa diganti?**  
A: Tidak, password random saat backup. Untuk ganti, decrypt + re-encrypt manual dengan openssl.

**Q: Apakah restore menghapus data lama?**  
A: Tidak, data lama otomatis di-backup ke `data.before-restore.TIMESTAMP` sebelum restore.
