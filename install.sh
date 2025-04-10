#!/bin/bash

echo "[+] Removing broken PPA if it exists..."
sudo add-apt-repository --remove ppa:micahflee/ppa -y 2>/dev/null

echo "[+] Updating package list..."
sudo apt update

echo "[+] Installing system dependencies..."
sudo apt install -y iproute2 curl ufw lsof net-tools procps grep gawk sed coreutils python3-tk python3-pip

echo "[+] Ensuring ~/.local/bin is in PATH..."
if ! echo $PATH | grep -q "$HOME/.local/bin"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
fi

# Add global executable link
echo "[+] Linking liveOpsec.py to /usr/local/bin/liveopsec..."
sudo ln -sf /opt/LiveOpsec/liveOpsec.py /usr/local/bin/liveopsec
sudo chmod +x /opt/liveopsec/liveOpsec.py

echo ""
echo "👻 Ghosint - Live OPSEC Monitor is ready!"
echo "✅ You can now run the monitor globally with:"
echo "  liveopsec"
