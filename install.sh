!/bin/bash

set -e

echo "[*] Installing OPSEC Monitor dependencies..."

# Core dependencies
REQUIRED_TOOLS=(yad curl ip hostname awk grep sed systemctl ss ps lsof dig host whois find)

echo "[*] Checking/installing required tools..."
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        echo "  [+] Installing: $tool"
        sudo apt install -y "$tool"
    else
        echo "  [✓] $tool is already installed"
    fi
done

# Install pipx if missing
if ! command -v pipx &>/dev/null; then
    echo "[*] pipx not found — installing..."
    sudo apt install -y pipx python3-venv
    python3 -m pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "[✓] pipx is already installed"
fi

# Ensure ~/.local/bin is in PATH for current shell
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> ~/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
    echo "[*] Added ~/.local/bin to PATH (reload your shell after this)"
fi

# Install ProtonVPN CLI using pipx
if ! command -v protonvpn &>/dev/null; then
    echo "[*] Installing ProtonVPN CLI via pipx..."
    pipx install protonvpn-cli
else
    echo "[✓] ProtonVPN CLI is already installed"
fi

# Symlink ProtonVPN for root access
if [[ ! -e "/usr/local/bin/protonvpn" ]]; then
    echo "[*] Linking ProtonVPN CLI so sudo can access it..."
    sudo ln -s "$HOME/.local/bin/protonvpn" /usr/local/bin/protonvpn
else
    echo "[✓] ProtonVPN CLI is already linked for sudo"
fi

echo ""
echo "[✓] All dependencies installed!"
echo ""
echo "👉 Next step: Run 'sudo protonvpn init' to configure your account"
echo "   If you're using Secure Core, set it up during this step."
echo ""
echo "🚀 You're now ready to use opsecmonitor!"
