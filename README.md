# Python script to generate a README.md file for liveOpsec

readme_content = """
# 🛡️ liveOpsec

liveOpsec is a real-time, terminal-based OPSEC monitoring tool for red teamers, security professionals, and privacy-focused users. It detects system compromise, suspicious activity, and misconfigurations — all while ensuring your VPN is live and active before displaying results.

## 🚀 Features

- 🔐 VPN Detection & Auto-Connect (with ProtonVPN CLI support)
- 🛡️ Firewall Status Monitoring
- 🕵️‍♂️ Suspicious Process Detection (e.g., tcpdump, keyloggers, reverse shells)
- 📹 Microphone & Webcam Usage Alerts
- 📡 Network Interface Enumeration
- 🌍 Public IP + GeoIP + DNS Leak Tests
- 📛 SetUID/SetGID Privilege Escalation File Scanning
- 🧟 Temp Directory Execution Detection (`/tmp`, `/dev/shm`, `/run`)
- 🧾 Sudo Usage Log Monitoring
- 📜 Recent System Logs + SSH Login Monitoring
- 🚀 Persistence Mechanism Detection (cron jobs & autostart entries)
- 👥 Live User Session and Login History
- ✨ **GUI Dashboard with Color-Coded Alerts (via yad)**

## 📦 Requirements

Ensure the following tools are available:

```
yad curl ip hostname awk grep sed systemctl ss ps lsof dig host whois find pipx
```

ProtonVPN CLI is also used (via `pipx`).

## 🛠️ Installation

Use the provided setup script:

```bash
chmod +x install-opsecmonitor.sh
./install-opsecmonitor.sh
```

This will:

- Install all required tools
- Install ProtonVPN CLI using `pipx`
- Ensure `~/.local/bin` is added to your path
- Prompt you to initialize ProtonVPN via `sudo protonvpn init`

## 🧪 Testing the Monitor

Use the simulator script to trigger fake OPSEC violations:

```bash
chmod +x trip_opsec.sh
./trip_opsec.sh
```

This simulates:

- Suspicious processes
- SetUID binary
- Cron + autostart persistence
- Webcam/mic usage
- Sudo activity
- Temp execution

The script auto-cleans after 30 seconds.

To clean manually:

```bash
chmod +x clear_opsec_traps.sh
./clear_opsec_traps.sh
```

## 🖥️ Running liveOpsec

```bash
chmod +x liveopsec.sh
./liveopsec.sh
```

The live dashboard updates every 10 seconds. Any compromise will trigger a visual `ALERT` in red.

## ⚠️ Disclaimer

liveOpsec is for educational, red team, and internal defense purposes only. Do not deploy or simulate threats on systems you don’t own or manage.

## 👤 Author

Crafted by [@bsec](https://github.com/bsec)  
Because real hackers monitor themselves. 🕵️‍♂️💻
"""
