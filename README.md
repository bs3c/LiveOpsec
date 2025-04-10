# 🛡️ LiveOpsec

**LiveOpsec** is a real-time OPSEC monitoring tool with a sleek terminal GUI, designed for red teamers, security professionals, and privacy-focused users. It detects system compromise, misconfigurations, VPN/firewall status, and suspicious processes with one goal: **self-monitoring for hackers**.

---

## 🚀 Features

- 🔐 **VPN Detection** (with support for ProtonVPN and tun/wg detection)
- 🧱 **Firewall Status Monitoring**
- 🕵️‍♂️ **Suspicious Process Detection** (keyloggers, tcpdump, reverse shells, etc.)
- 📹 **Microphone & Webcam Activity Detection**
- 🌐 **Network Interface and Public IP Checks**
- 📡 **DNS Leak & GeoIP Detection**
- 📛 **Privilege Escalation File Scanning** (SetUID/GID binaries)
- 🧟 **Temp Execution Detection** (`/tmp`, `/dev/shm`, `/run`)
- 🧾 **Sudo Log + System Log Parsing**
- 🔁 **Persistence Mechanism Detection**
- 🧑‍💻 **Live User Sessions & SSH Login History**
- ✨ **Tkinter GUI Dashboard** with color-coded output

---

## 📦 Requirements

Install the following dependencies:

```bash
sudo apt update && sudo apt install -y curl iputils-ping net-tools nmap lsof ss yad whois dnsutils ufw
pip install protonvpn-cli
```

---

## 🛠️ Installation

Use the included installer:

```bash
chmod +x install.sh
./install.sh
```

This script:
- Installs all required tools
- Installs ProtonVPN CLI
- Adds `~/.local/bin` to your path

---

## 💻 Running LiveOpsec

```bash
sudo python3 liveOpsec.py
```

**Note**: The dashboard auto-updates every 15 seconds.

---

## ⚠️ Disclaimer

This tool is for internal defense, red teamers, and educational use only. Do not run on systems you don't own or manage.

---

## 👤 Author

Crafted by **@bsec**  
“Because real hackers monitor themselves.” 🕵️‍♂️💻
