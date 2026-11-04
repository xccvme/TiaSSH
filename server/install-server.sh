#!/usr/bin/env bash
# Installer/deploy transaksional TiaSSH server.
set -Eeuo pipefail
umask 077

SERVICE_NAME="${SERVICE_NAME:-tiassh}"
APP_DIR="${APP_DIR:-/opt/tiassh}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
PORT="${PORT:-8080}"
HEALTH_RETRIES="${HEALTH_RETRIES:-15}"
HEALTH_DELAY_SEC="${HEALTH_DELAY_SEC:-1}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SRC="$SCRIPT_DIR"
[[ -d "$SCRIPT_DIR/server" ]] && SRC="$SCRIPT_DIR/server"
ACTIVE="$APP_DIR/server"
UNIT="$SYSTEMD_DIR/${SERVICE_NAME}.service"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$(id -u)" == "0" ]] || fail "jalankan sebagai root (sudo)."

[[ "$APP_DIR" == /* ]] || fail "APP_DIR harus absolute path."
[[ "$APP_DIR" != "/" ]] || fail "APP_DIR tidak boleh '/'."
[[ "$APP_DIR" =~ ^[A-Za-z0-9/_\.-]+$ ]] || fail "APP_DIR mengandung karakter tidak aman."
[[ "$SYSTEMD_DIR" =~ ^/[A-Za-z0-9/_\.-]+$ ]] || fail "SYSTEMD_DIR tidak aman."
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_-]+$ ]] || fail "SERVICE_NAME tidak aman."
[[ "$APP_DIR" != *'/../'* && "$APP_DIR" != */.. ]] || fail "APP_DIR tidak boleh mengandung traversal."
[[ ! -L "$ACTIVE" && ! -L "$ACTIVE/data" ]] || fail "Target/data symlink tidak didukung: gunakan direktori nyata."
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "PORT harus angka."
(( PORT >= 1 && PORT <= 65535 )) || fail "PORT di luar rentang 1..65535."

contains_newline() {
  [[ "$1" == *$'\n'* || "$1" == *$'\r'* ]]
}

command -v node >/dev/null 2>&1 || fail "Node.js tidak ditemukan. Install Node.js 24.x dulu lalu jalankan ulang."

NODE_VERSION="$(node --version 2>/dev/null || true)"
[[ "$NODE_VERSION" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || fail "tidak bisa membaca versi Node.js ($NODE_VERSION)."
NODE_MAJOR="${BASH_REMATCH[1]}"
(( NODE_MAJOR >= 24 )) || fail "Node.js minimal v24.x. Terdeteksi: $NODE_VERSION"

[[ -f "$SRC/server.js" && -f "$SRC/package.json" ]] || fail "sumber deploy tidak valid: $SRC"

if [[ -z "${PUBLIC_URL:-}" ]]; then
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$SERVER_IP" ]] && SERVER_IP="127.0.0.1"
  PUBLIC_URL="http://${SERVER_IP}:${PORT}"
fi

if [[ -z "${WEB_ORIGIN:-}" ]]; then
  WEB_ORIGIN="$PUBLIC_URL"
fi

# Portal web (registrasi/management akun) bisa ditutup operator:
# WEB_PORTAL_ENABLED=1 (default, buka) atau 0 (tutup -> surface web 404,
# endpoint native tetap hidup & tervalidasi).
WEB_PORTAL_ENABLED="${WEB_PORTAL_ENABLED:-1}"

contains_newline "$PUBLIC_URL" && fail "PUBLIC_URL mengandung newline tidak aman."
contains_newline "$WEB_ORIGIN" && fail "WEB_ORIGIN mengandung newline tidak aman."
[[ "$HEALTH_RETRIES" =~ ^[1-9][0-9]*$ ]] || fail "HEALTH_RETRIES harus positif."
[[ "$HEALTH_DELAY_SEC" =~ ^[0-9]+$ ]] || fail "HEALTH_DELAY_SEC harus angka."
[[ "$PUBLIC_URL" =~ ^https?://[^[:space:]\"\\]+$ ]] || fail "PUBLIC_URL harus http/https tanpa karakter kontrol."
[[ "$WEB_ORIGIN" =~ ^https?://[^[:space:]\"\\]+$ ]] || fail "WEB_ORIGIN harus http/https tanpa karakter kontrol."
[[ "$WEB_PORTAL_ENABLED" =~ ^[01]$ ]] || fail "WEB_PORTAL_ENABLED harus 0 (tutup) atau 1 (buka)."

node -e '
const [pub, web] = process.argv.slice(1);
const p = new URL(pub);
const w = new URL(web);
const ok = ["http:","https:"].includes(p.protocol) && ["http:","https:"].includes(w.protocol);
process.exit(ok && !p.username && !p.password && !w.username && !w.password && w.pathname === "/" && !w.search && !w.hash ? 0 : 1);
' "$PUBLIC_URL" "$WEB_ORIGIN" >/dev/null 2>&1 || fail "PUBLIC_URL/WEB_ORIGIN tidak valid (harus http/https)."

mkdir -p -- "$APP_DIR" "$SYSTEMD_DIR"
command -v flock >/dev/null || fail "Install util-linux (flock) terlebih dahulu."
exec 9>"$APP_DIR/.deploy.lock"
flock -n 9 || fail "Deployment lain masih berjalan."
TX="$(mktemp -d "$APP_DIR/.deploy.XXXXXXXX")"
STAGE="$TX/stage"
mkdir -- "$STAGE"

was_active=0
had_app=0
had_unit=0
switched=0
moved_old=0
stopped=0
success=0

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if (( ! success )); then
    set +e
    if (( switched )); then
      systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
      [[ -d "$ACTIVE" ]] && mv -- "$ACTIVE" "$TX/failed-app" 2>/dev/null || true
      if (( had_app )); then
        mv -- "$TX/old-app" "$ACTIVE" 2>/dev/null || true
      fi
      if (( had_unit )); then
        cp -a -- "$TX/old-unit" "$UNIT" 2>/dev/null || true
      else
        rm -f -- "$UNIT"
      fi
      systemctl daemon-reload >/dev/null 2>&1 || true
    elif (( moved_old )); then
      mv -- "$TX/old-app" "$ACTIVE" || echo "ROLLBACK GAGAL: pulihkan manual dari $TX/old-app" >&2
    fi
    if (( was_active )) && (( stopped )); then
      systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    echo "ERROR: deployment gagal, rollback dijalankan. Folder diagnostik: $TX" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Snapshot sumber dilakukan sebelum menyentuh target supaya aman ketika SRC==ACTIVE.
tar -C "$SRC" \
  --exclude=data \
  --exclude=node_modules \
  --exclude=.env \
  --exclude=.git \
  -cf "$TX/source.tar" .
tar -C "$STAGE" -xf "$TX/source.tar"
rm -f -- "$TX/source.tar"

cd -- "$STAGE"
if [[ -f package-lock.json ]]; then
  npm ci --omit=dev --no-audit --no-fund
else
  npm install --omit=dev --no-audit --no-fund
fi

if systemctl is-active --quiet "$SERVICE_NAME"; then
  was_active=1
fi

if [[ -d "$ACTIVE" ]]; then
  had_app=1
fi
if [[ -f "$UNIT" ]]; then
  had_unit=1
  cp -a -- "$UNIT" "$TX/old-unit"
fi

if (( was_active )); then
  systemctl stop "$SERVICE_NAME"
  stopped=1
fi

# Pertahankan semua data runtime termasuk SQLite WAL/SHM/master.key.
if [[ -d "$ACTIVE/data" ]]; then
  cp -a -- "$ACTIVE/data" "$STAGE/data"
else
  mkdir -p -- "$STAGE/data"
fi

if (( had_app )); then
  mv -- "$ACTIVE" "$TX/old-app"
  moved_old=1
fi
mv -- "$STAGE" "$ACTIVE"
switched=1

cat > "$UNIT" <<EOF
[Unit]
Description=TiaSSH account and sync server
After=network.target

[Service]
Type=simple
WorkingDirectory=$ACTIVE
ExecStart=$(command -v node) server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production
Environment=PORT=$PORT
Environment=PUBLIC_URL=$PUBLIC_URL
Environment=WEB_ORIGIN=$WEB_ORIGIN
Environment=WEB_PORTAL_ENABLED=$WEB_PORTAL_ENABLED

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

health_ok=0
for ((i=1; i<=HEALTH_RETRIES; i++)); do
  health_json="$(curl -fsS "http://127.0.0.1:${PORT}/api/health" 2>/dev/null || true)"
  if systemctl is-active --quiet "$SERVICE_NAME" && node -e 'const o=JSON.parse(process.argv[1]); process.exit(o && o.ok===true && o.name==="tiassh-sync" ? 0 : 1)' "$health_json" >/dev/null 2>&1; then
    health_ok=1
    break
  fi
  sleep "$HEALTH_DELAY_SEC"
done

if (( ! health_ok )); then
  echo "ERROR: health check gagal pada /api/health" >&2
  exit 1
fi

has_recovery_key() {
  node -e '
const dbPath = process.argv[1];
const fs = require("node:fs");
if (!fs.existsSync(dbPath)) process.exit(1);
const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync(dbPath, { readOnly: true });
try {
  const table = db.prepare("SELECT name FROM sqlite_master WHERE type=? AND name=?").get("table", "recovery_keys");
  if (!table) process.exit(1);
  const row = db.prepare("SELECT 1 AS ok FROM recovery_keys WHERE id=1").get();
  process.exit(row ? 0 : 1);
} finally { db.close(); }
' "$ACTIVE/data/tiassh.db" >/dev/null 2>&1
}

if ! has_recovery_key; then
  if [[ -t 0 && -t 1 ]]; then
    echo "Recovery key belum ada. Menjalankan init interaktif..."
    (cd "$ACTIVE" && DATA_DIR="$ACTIVE/data" node admin-recovery.js init)
    if ! has_recovery_key; then
      echo "ERROR: init recovery key tidak menghasilkan key valid." >&2
      exit 1
    fi
  else
    echo "ERROR: recovery key belum diinisialisasi." >&2
    echo "Setelah rollback, jalankan interaktif (jangan redirect/tee/log terminal):" >&2
    echo "cd $TX/failed-app && DATA_DIR=$TX/failed-app/data node admin-recovery.js init" >&2
    if (( ! had_app )); then
      echo "Lalu seed data untuk deploy ulang: mkdir -p $ACTIVE && cp -a $TX/failed-app/data $ACTIVE/data" >&2
    else
      echo "Salin DB yang sudah di-init dari failed-app/data ke data lama hanya saat service dihentikan dan setelah backup; atau inisialisasi DB lama jika schema sudah tersedia." >&2
    fi
    exit 1
  fi
fi

success=1
echo "Deploy sukses: ${PUBLIC_URL}"
