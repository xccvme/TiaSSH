#!/usr/bin/env bash
# Backup transaksional TiaSSH data untuk migrasi/disaster recovery.
set -Eeuo pipefail
umask 077

SERVICE_NAME="${SERVICE_NAME:-tiassh}"
APP_DIR="${APP_DIR:-/opt/tiassh}"
BACKUP_DIR="${BACKUP_DIR:-/root/tiassh-backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/tiassh-backup-$TIMESTAMP.tar.gz.enc"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$(id -u)" == "0" ]] || fail "jalankan sebagai root (sudo)."
[[ -d "$APP_DIR/server/data" ]] || fail "direktori data tidak ditemukan: $APP_DIR/server/data"

command -v openssl >/dev/null 2>&1 || fail "openssl tidak ditemukan. Install: apt install openssl"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

echo "=== TiaSSH Backup Transaksional ==="
echo "Service: $SERVICE_NAME"
echo "Data: $APP_DIR/server/data"
echo "Output: $BACKUP_FILE"
echo ""

# Cek service status
SERVICE_ACTIVE=0
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  SERVICE_ACTIVE=1
  echo "⚠ Service $SERVICE_NAME sedang berjalan."
  read -p "Stop service untuk backup konsisten? (y/n): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping $SERVICE_NAME..."
    systemctl stop "$SERVICE_NAME" || fail "gagal stop service"
    sleep 2
  else
    echo "⚠ Backup dilakukan saat service aktif (risiko: data tidak konsisten)."
    echo "   Tunggu 3 detik untuk cancel (Ctrl+C)..."
    sleep 3
  fi
fi

# Validasi file kritis
[[ -f "$APP_DIR/server/data/tiassh.db" ]] || fail "tiassh.db tidak ditemukan"
[[ -f "$APP_DIR/server/data/master.key" ]] || fail "master.key tidak ditemukan (TOTP tidak bisa dibaca tanpa ini)"

# Generate password backup
BACKUP_PASSWORD="$(openssl rand -base64 32)"
BACKUP_PASSWORD_FILE="$BACKUP_DIR/tiassh-backup-$TIMESTAMP.password.txt"

echo "Membuat backup terenkripsi..."
tar -C "$APP_DIR/server" -czf - data | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$BACKUP_PASSWORD" \
  -out "$BACKUP_FILE" || fail "backup gagal"

# Simpan password
cat > "$BACKUP_PASSWORD_FILE" <<EOF
TiaSSH Backup Password
======================
File: $(basename "$BACKUP_FILE")
Tanggal: $(date '+%Y-%m-%d %H:%M:%S %Z')

Password (simpan offline, jangan di server):
$BACKUP_PASSWORD

Restore command:
sudo bash restore.sh "$BACKUP_FILE" "$BACKUP_PASSWORD"

PENTING:
- Simpan file ini DI LUAR SERVER (local, USB terenkripsi, vault)
- Tanpa password ini, backup TIDAK BISA di-restore
- master.key di dalam backup = TOTP secrets bisa dibaca
- Hapus file password dari server setelah aman tersimpan offline
EOF

chmod 600 "$BACKUP_PASSWORD_FILE"
chmod 600 "$BACKUP_FILE"

# Restart service jika perlu
if [[ $SERVICE_ACTIVE -eq 1 ]] && ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "Restarting $SERVICE_NAME..."
  systemctl start "$SERVICE_NAME" || fail "gagal restart service"
  sleep 2
fi

BACKUP_SIZE="$(du -h "$BACKUP_FILE" | cut -f1)"

echo ""
echo "✓ Backup berhasil!"
echo ""
echo "File backup (terenkripsi):"
echo "  $BACKUP_FILE ($BACKUP_SIZE)"
echo ""
echo "Password backup:"
echo "  $BACKUP_PASSWORD_FILE"
echo ""
echo "⚠ SEGERA simpan password file ke lokasi AMAN di luar server:"
echo "  scp root@server:$BACKUP_PASSWORD_FILE ~/backup-passwords/"
echo "  rm $BACKUP_PASSWORD_FILE"
echo ""
echo "Untuk restore di server baru:"
echo "  1. Install TiaSSH server kosong (jangan buat akun dulu)"
echo "  2. Stop service: sudo systemctl stop $SERVICE_NAME"
echo "  3. Copy backup file ke server baru"
echo "  4. Jalankan: sudo bash restore.sh <backup-file> <password>"
echo ""
