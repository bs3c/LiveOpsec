bsec@bsec:~/tools/LiveOpsec$ cat install.sh 
#!/bin/bash

echo "[+] Removing broken PPA if it exists..."
sudo add-apt-repository --remove ppa:micahflee/ppa -y 2>/dev/null

echo "[+] Updating package list..."
sudo apt update

echo "[+] Installing system dependencies..."
sudo apt install -y iproute2 curl ufw lsof net-tools procps grep gawk sed coreutils python3-tk python3-pip

echo "[+] Checking for pipx..."
if ! command -v pipx &> /dev/null; then
    echo "[+] Installing pipx..."
    python3 -m pip install --user pipx --break-system-packages
    python3 -m pipx ensurepath
else
    echo "[✓] pipx is already installed."
fi

echo "[+] Checking for ProtonVPN CLI..."
if ! pipx list | grep -q protonvpn-cli; then
    echo "[+] Installing ProtonVPN CLI via pipx..."
    pipx install protonvpn-cli
else
    echo "[✓] ProtonVPN CLI is already installed."
fi

echo "[+] Ensuring ~/.local/bin is in PATH..."
if ! echo $PATH | grep -q "$HOME/.local/bin"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
fi

echo ""
echo "👻 Ghosint - Live OPSEC Monitor dependencies are installed!"
echo "Run this to initialize ProtonVPN:"
echo "  sudo protonvpn init"
echo ""
echo "✅ You can now run the monitor with:"
echo "  sudo python3 liveOpsec.py"

