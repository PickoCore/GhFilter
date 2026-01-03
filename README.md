# GhFilter
GhFilter adalah plugin Velocity yang berfungsi sebagai lapisan pertahanan tambahan untuk server Minecraft public, fokus pada mitigasi connection flood, bot spam, dan trafik tidak valid sebelum mencapai backend server.

# GhFilter 🔥  
Advanced Connection & Bot Flood Protection for Velocity

**GhFilter** adalah plugin **Velocity Proxy** yang dirancang untuk melindungi server Minecraft public dari **connection flood**, **bot spam**, dan **trafik tidak valid (null / garbage packets)** dengan memblokir serangan **seawal mungkin di tahap PreLogin**.

Plugin ini dibuat sebagai **application-layer defense (L7)** dan ditujukan untuk melengkapi (bukan menggantikan) proteksi jaringan dari provider.

---

## ✨ Fitur Utama
- 🛡️ **Per-IP connection rate limiting** (sliding window)
- 🚦 **Limit koneksi aktif per IP (concurrent connections)**
- ⏳ **Temporary ban otomatis** untuk IP abusif
- 🧠 **Deteksi trafik tidak valid / null-byte–like** berbasis *incomplete handshake*
- 📊 **Metrics real-time** (attempts, blocked, bans, handshake status)
- 🚨 **Discord webhook alert** (embed merah) saat terdeteksi pola serangan
- ⚡ **Fail-fast blocking** (sebelum login, limbo, atau backend)
- 🧹 **Auto cleanup state** (memory-safe untuk server jangka panjang)
- 🪶 **Lightweight & dependency-free**

---

## 🎯 Cocok Digunakan Untuk
- Server **Minecraft public**
- Setup dengan **Velocity + LimboAuth**
- Server yang sering jadi target:
  - bot Termux
  - script Python connection spam
  - invalid / malformed traffic
- Infrastruktur dengan backend **tidak diekspos publik**

---

## ❌ Bukan Untuk
- Botnet besar (ribuan IP berbeda)
- Serangan L3/L4 skala ISP
- Pengganti firewall, anti-DDoS provider, atau TCP shield

> GhFilter bekerja di **lapisan aplikasi**, bukan jaringan.

---

## 🧠 Cara Kerja Singkat
1. Semua koneksi masuk dicek di **Velocity (PreLoginEvent)**
2. GhFilter mencatat:
   - jumlah percobaan koneksi per IP
   - jumlah koneksi aktif per IP
   - koneksi yang **tidak pernah menyelesaikan handshake**
3. Jika IP melanggar batas:
   - koneksi langsung ditolak
   - IP dikenakan **temporary ban**
4. Trafik berbahaya **tidak pernah mencapai Limbo atau backend**

> Bot receh berhenti di pintu depan 🚪

---

## 📦 Instalasi
1. Build plugin:
   ```bash
   mvn package
Ambil file:
Copy code

target/ghfilter-1.1.0.jar
Masukkan ke folder plugin Velocity:
Copy code

velocity/plugins/
Restart Velocity
⚙️ Konfigurasi
File: plugins/ghfilter/config.yml
Copy code
Yml
# rate limiting
window_ms: 5000
max_attempts_per_window: 4

# concurrent limit
max_concurrent: 2

# temporary ban
ban_seconds: 60

# kick message
kick_message: "terlalu banyak koneksi, coba lagi nanti."

# invalid / null-like traffic detection
handshake_timeout_ms: 800
max_incomplete_per_window: 3

# metrics logging
metrics_log_interval_seconds: 10

# attack alert
attack_block_threshold: 25
attack_alert_cooldown_seconds: 60

# discord webhook
discord_webhook_url: ""
discord_username: "GhFilter"
discord_embed_title: "⚠️ attack detected"
discord_embed_color_red: 16711680
📊 Metrics & Logs
GhFilter akan mencetak log berkala seperti:
Copy code

[GhFilter metrics] attempts=120 blocked=87 tempbans=5 handshake_ok=10 handshake_incomplete=110
Metrics ini membantu:
mendeteksi serangan lebih awal
memverifikasi proteksi bekerja
analisis pola trafik

🚨 Discord Webhook Alert
Jika jumlah koneksi yang diblokir melewati threshold:
GhFilter akan mengirim Discord embed merah
Ada cooldown agar tidak spam
Contoh isi alert:
blocked connections
total attempts
incomplete handshakes
timestamp

🔐 Best Practice (WAJIB)
✅ Hanya port Velocity yang publik
❌ Jangan expose backend (Paper / LeafMC)
✅ Gunakan bersama:
Sonar AntiBot
LimboAuth
LibreLogin
Firewall / provider DDoS protection

🧪 Contoh Serangan yang Bisa Ditahan
Script Python:
banyak thread
connect → kirim byte kecil → disconnect
satu / sedikit IP
Bot yang tidak menyelesaikan handshake Minecraft

⚠️ Batasan Teknis
Efektif untuk connection flood & bot spam
Tidak cukup sendirian untuk distributed botnet
Harus dikombinasikan dengan proteksi jaringan

🛠️ Rencana Pengembangan
CIDR whitelist
Ban escalation (bertingkat)
Command admin (/ghfilter stats, /ghfilter reload)
Mode strict otomatis saat 
