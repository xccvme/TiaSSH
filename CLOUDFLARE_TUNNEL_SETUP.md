# Setup TiaSSH dengan Cloudflare Tunnel

## Arsitektur

```
Client (Desktop/Android/Web)
    ↓ HTTPS
https://tia-ssh.meiyu.my.id
    ↓
Cloudflare Tunnel (cloudflared)
    ↓ HTTP (tunnel lokal)
http://10.10.10.107:8080
    ↓
TiaSSH Server
```

## Install TiaSSH Server

```bash
# Clone repo
git clone https://github.com/xccvme/TiaSSH.git "$HOME/tiassh"
cd "$HOME/tiassh/server"

# Install dengan PUBLIC_URL = domain cloudflare
sudo env APP_DIR=/opt/tiassh \
  PORT=8080 \
  PUBLIC_URL=https://tia-ssh.meiyu.my.id \
  WEB_ORIGIN=https://tia-ssh.meiyu.my.id \
  bash install-server.sh
```

**Penting:**
- `PUBLIC_URL` = domain public (https://tia-ssh.meiyu.my.id) bukan IP lokal
- `PORT=8080` = port lokal yang di-listen server
- Server listen di `0.0.0.0:8080` (semua interface)

## Setup Cloudflare Tunnel

### 1. Install cloudflared

```bash
# Download
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Atau via package manager
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb
```

### 2. Login Cloudflare

```bash
cloudflared tunnel login
```

Browser akan terbuka, pilih domain `meiyu.my.id`.

### 3. Buat Tunnel

```bash
cloudflared tunnel create tiassh-tunnel
```

Output: Tunnel ID dan credentials file location.

### 4. Konfigurasi Tunnel

Buat `/root/.cloudflared/config.yml`:

```yaml
tunnel: <TUNNEL_ID_DARI_STEP3>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: tia-ssh.meiyu.my.id
    service: http://10.10.10.107:8080
    originRequest:
      noTLSVerify: false
      connectTimeout: 30s
      # WebSocket support penting untuk /ws
      http2Origin: false
  - service: http_status:404
```

**Penting:**
- `service: http://10.10.10.107:8080` = URL lokal server TiaSSH
- `http2Origin: false` = force HTTP/1.1 untuk WebSocket compatibility

### 5. Route DNS

```bash
cloudflared tunnel route dns tiassh-tunnel tia-ssh.meiyu.my.id
```

Ini otomatis tambah CNAME record di Cloudflare DNS: `tia-ssh.meiyu.my.id` → `<tunnel-id>.cfargotunnel.com`

### 6. Run Tunnel sebagai Service

```bash
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
sudo systemctl status cloudflared
```

## Verifikasi

### 1. Cek Server TiaSSH

```bash
# Health check lokal
curl http://10.10.10.107:8080/health

# Cek service
sudo systemctl status tiassh
```

### 2. Cek Tunnel

```bash
# Status tunnel
sudo systemctl status cloudflared

# Log tunnel
sudo journalctl -u cloudflared -f
```

### 3. Test Public Access

```bash
# Health check via domain public
curl https://tia-ssh.meiyu.my.id/health

# Portal web
# Buka browser: https://tia-ssh.meiyu.my.id/portal/
```

### 4. Test WebSocket (Penting!)

```bash
# Install wscat jika belum ada
npm install -g wscat

# Test WebSocket upgrade
wscat -c "wss://tia-ssh.meiyu.my.id/ws" -H "Authorization: Bearer test-token"
```

Harus dapat response atau close (bukan HTTP error), berarti WebSocket works.

## Native Client Configuration

Desktop dan Android:
- **Server URL:** `https://tia-ssh.meiyu.my.id` (tanpa port)
- Login normal, tunnel otomatis handle routing

## Troubleshooting

### WebSocket gagal koneksi

**Symptom:** Native client connect gagal, log `WebSocket error`

**Fix:** Pastikan Cloudflare Tunnel config punya `http2Origin: false`:

```yaml
ingress:
  - hostname: tia-ssh.meiyu.my.id
    service: http://10.10.10.107:8080
    originRequest:
      http2Origin: false  # Ini penting!
```

Restart tunnel:
```bash
sudo systemctl restart cloudflared
```

### CORS error di web portal

**Symptom:** Browser console `CORS policy blocked`

**Fix:** Cek `WEB_ORIGIN` di systemd unit:

```bash
sudo systemctl cat tiassh | grep WEB_ORIGIN
# Harus: Environment=WEB_ORIGIN=https://tia-ssh.meiyu.my.id
```

Jika salah, edit:
```bash
sudo systemctl edit tiassh --full
# Ubah WEB_ORIGIN
sudo systemctl daemon-reload
sudo systemctl restart tiassh
```

### Cookie tidak tersimpan

**Symptom:** Login web berhasil tapi logout otomatis

**Cause:** Cookie `Secure` flag butuh HTTPS di PUBLIC_URL

**Fix:** Pastikan PUBLIC_URL `https://` (bukan `http://`):
```bash
sudo systemctl cat tiassh | grep PUBLIC_URL
# Harus: Environment=PUBLIC_URL=https://tia-ssh.meiyu.my.id
```

### Health check timeout

**Symptom:** `curl https://tia-ssh.meiyu.my.id/health` timeout

**Check:**
1. Server TiaSSH running: `sudo systemctl status tiassh`
2. Tunnel running: `sudo systemctl status cloudflared`
3. Port 8080 listen: `sudo ss -tlnp | grep 8080`
4. Cloudflare DNS propagasi: `nslookup tia-ssh.meiyu.my.id`

### Server tidak bisa diakses dari luar jaringan

**Cause:** Firewall lokal block port (tapi seharusnya OK karena tunnel outbound-only)

**Cloudflare Tunnel = outbound-only**, tidak perlu buka port inbound di firewall. Tunnel buat koneksi keluar ke Cloudflare edge.

Jika masih issue:
```bash
# Cek tunnel log
sudo journalctl -u cloudflared -n 100

# Cek koneksi ke Cloudflare
cloudflared tunnel info tiassh-tunnel
```

## Keamanan

**Advantages Cloudflare Tunnel:**
1. **No port forwarding** — tidak perlu buka port 8080 ke internet
2. **DDoS protection** — Cloudflare edge handle attack
3. **Auto SSL/TLS** — Cloudflare manage certificate
4. **Hide origin IP** — IP server 10.10.10.107 tidak exposed

**Server Side:**
- Server tetap bind `0.0.0.0:8080` tapi hanya tunnel local yang akses
- Cloudflare edge terminate TLS, tunnel ke server HTTP (aman kalau server private network)
- Jika mau extra security, bisa firewall restrict port 8080 hanya dari localhost:
  
```bash
# Optional: restrict port 8080 ke localhost saja
sudo ufw allow from 127.0.0.1 to any port 8080
sudo ufw allow from 10.10.10.0/24 to any port 8080  # Jika butuh akses LAN
```

Tapi **tidak perlu** karena tunnel outbound connection, bukan inbound port.

## Monitoring

### Cloudflare Dashboard

Login https://dash.cloudflare.com → Traffic → Cloudflare Tunnel

Monitor:
- Tunnel status (healthy/down)
- Request rate
- Bandwidth usage
- Response time

### Server Logs

```bash
# TiaSSH logs
sudo journalctl -u tiassh -f

# Cloudflare tunnel logs
sudo journalctl -u cloudflared -f

# Health check cron
watch -n 5 'curl -sf https://tia-ssh.meiyu.my.id/health && echo OK || echo FAIL'
```

## Backup Konfigurasi

```bash
# Backup tunnel credentials (PENTING!)
sudo cp -r /root/.cloudflared /root/cloudflared-backup

# Simpan offline:
sudo tar czf cloudflared-config.tar.gz /root/.cloudflared
# Download ke local: scp root@server:~/cloudflared-config.tar.gz ~/
```

**Tanpa credentials ini, tunnel tidak bisa direstore!**

## Update DNS (Pindah Domain)

Jika ganti domain dari `tia-ssh.meiyu.my.id` ke domain lain:

```bash
# 1. Route DNS baru
cloudflared tunnel route dns tiassh-tunnel new-domain.com

# 2. Update config.yml
sudo nano /root/.cloudflared/config.yml
# Ubah hostname: new-domain.com

# 3. Update TiaSSH environment
sudo systemctl edit tiassh --full
# Ubah PUBLIC_URL dan WEB_ORIGIN
sudo systemctl daemon-reload
sudo systemctl restart tiassh

# 4. Restart tunnel
sudo systemctl restart cloudflared
```

## Checklist Setup

- [ ] TiaSSH installed dengan PUBLIC_URL=https://tia-ssh.meiyu.my.id
- [ ] cloudflared installed
- [ ] Tunnel created dan credentials tersimpan
- [ ] config.yml dibuat dengan `http2Origin: false`
- [ ] DNS route configured (`tia-ssh.meiyu.my.id` CNAME)
- [ ] Tunnel service running: `sudo systemctl status cloudflared`
- [ ] Server service running: `sudo systemctl status tiassh`
- [ ] Health check OK: `curl https://tia-ssh.meiyu.my.id/health`
- [ ] Portal web accessible: https://tia-ssh.meiyu.my.id/portal/
- [ ] WebSocket test OK (wscat atau native client connect)
- [ ] Backup credentials: `/root/.cloudflared/*.json`
