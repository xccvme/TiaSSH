#!/usr/bin/env bash
# Restore TiaSSH data dari backup terenkripsi.
set -Eeuo pipefail
umask 077

SERVICE_NAME="${SERVICE_NAME:-tiassh}"
APP_DIR="${APP_DIR:-/opt/tiassh}"
RESTORE_TEMP="/tmp/tiassh-restore-$$"

fail() {
  echo "ERROR: $*" >&2
  [[ -d "$RESTORE_TEMP" ]] && rm -rf "$RESTORE_TEMP"
  exit 1
}

cleanup() {
  [[ -d "$RESTORE_TEMP" ]] && rm -rf "$RESTORE_TEMP"
}
trap cleanup EXIT

[[ "$(id -u)" == "0" ]] || fail "jalankan sebagai root (sudo)."

if [[ $# -lt 2 ]]; then
  echo "Usage: sudo bash restore.sh <backup-file.tar.gz.enc> <password>"
  echo ""
  echo "Contoh:"
  echo "  sudo bash restore.sh /root/tiassh-backup-20261104_101530.tar.gz.enc 'password123'"
  echo ""
  echo "PENTING:"
  echo "  - Server TiaSSH harus sudah terinstall (installer sudah dijalankan)"
  echo "  - Service akan di-stop otomatis saat restore"
  echo "  - Data lama akan di-backup ke $APP_DIR/server/data.before-restore"
  exit 1
fi

BACKUP_FILE="$1"
BACKUP_PASSWORD="$2"

[[ -f "$BACKUP_FILE" ]] || fail "file backup tidak ditemukan: $BACKUP_FILE"
[[ -d "$APP_DIR/server" ]] || fail "TiaSSH belum terinstall di $APP_DIR (jalankan install-server.sh dulu)"

command -v openssl >/dev/null 2>&1 || fail "openssl tidak ditemukan. Install: apt install openssl"

echo "=== TiaSSH Restore ==="
echo "Backup: $(basename "$BACKUP_FILE")"
echo "Target: $APP_DIR/server/data"
echo ""

# Stop service
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  echo "Stopping $SERVICE_NAME..."
  systemctl stop "$SERVICE_NAME" || fail "gagal stop service"
  sleep 2
fi

# Backup data lama jika ada
if [[ -d "$APP_DIR/server/data" ]]; then
  BACKUP_OLD="$APP_DIR/server/data.before-restore.$(date +%Y%m%d_%H%M%S)"
  echo "⚠ Data lama ditemukan. Backup ke: $(basename "$BACKUP_OLD")"
  mv "$APP_DIR/server/data" "$BACKUP_OLD" || fail "gagal backup data lama"
fi

# Decrypt dan extract
echo "Decrypting dan extracting backup..."
mkdir -p "$RESTORE_TEMP"

openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:"$BACKUP_PASSWORD" \
  -in "$BACKUP_FILE" 2>/dev/null | tar -xzf - -C "$RESTORE_TEMP" || fail "decrypt gagal (password salah atau file corrupt)"

# Validasi hasil extract
[[ -d "$RESTORE_TEMP/data" ]] || fail "struktur backup tidak valid (data/ tidak ditemukan)"
[[ -f "$RESTORE_TEMP/data/tiassh.db" ]] || fail "tiassh.db tidak ada dalam backup"
[[ -f "$RESTORE_TEMP/data/master.key" ]] || fail "master.key tidak ada dalam backup"

# Pindahkan ke lokasi final
mv "$RESTORE_TEMP/data" "$APP_DIR/server/data" || fail "gagal restore data"
chmod 700 "$APP_DIR/server/data"
chmod 600 "$APP_DIR/server/data"/*

# Set ownership jika service punya user khusus
if id "tiassh" >/dev/null 2>&1; then
  chown -R tiassh:tiassh "$APP_DIR/server/data"
fi

# Start service
echo "Starting $SERVICE_NAME..."
systemctl start "$SERVICE_NAME" || fail "gagal start service"

# Health check
echo "Waiting for health check..."
sleep 3

PORT="${PORT:-8080}"
HEALTH_OK=0
for i in {1..15}; do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

echo ""
if [[ $HEALTH_OK -eq 1 ]]; then
  echo "✓ Restore berhasil! Service aktif dan health OK."
else
  echo "⚠ Service started tapi health check gagal. Cek log:"
  echo "  sudo journalctl -u $SERVICE_NAME -n 50"
fi

echo ""
echo "Data restored dari: $(basename "$BACKUP_FILE")"
echo "Lokasi: $APP_DIR/server/data"
echo ""
echo "Akun, vault, TOTP, dan sync items sekarang tersedia."
echo ""
