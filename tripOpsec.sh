#!/bin/bash

echo "[*] Triggering OPSEC red flags..."

# 1. Simulate suspicious processes
sleep 300 &  # background sleeper
(sleep 5; echo "GET / HTTP/1.1") | nc 127.0.0.1 80 &
tcpdump -i lo -w /dev/null &
bash -c 'while :; do :; done' &
keylogger_process() { while :; do echo "keystroke"; sleep 2; done; }; keylogger_process &

# 2. Fake persistence
mkdir -p ~/.config/autostart
echo "[Desktop Entry]
Type=Application
Exec=nc -lvnp 4444
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=FakeBackdoor" > ~/.config/autostart/fake.desktop

echo "@reboot nc -lvnp 9999" | sudo tee -a /etc/crontab > /dev/null

# 3. Fake SetUID binary
echo -e '#!/bin/bash\necho "I am root!"' | sudo tee /usr/local/bin/fakeroot > /dev/null
sudo chmod +x /usr/local/bin/fakeroot
sudo chmod u+s /usr/local/bin/fakeroot

# 4. Fake media usage
touch /tmp/fakevid && lsof /tmp/fakevid 2>/dev/null &
touch /dev/video0 2>/dev/null
touch /dev/snd/fakeaudio 2>/dev/null

# 5. Fake sudo log
sudo -k
sudo echo "Triggered sudo event" > /dev/null

# 6. Execute from /tmp
echo -e '#!/bin/bash\necho "Running from /tmp!"' > /tmp/tmp_exec.sh
chmod +x /tmp/tmp_exec.sh
/tmp/tmp_exec.sh &

echo "[✓] All traps set. Your OPSEC monitor should now be screaming. 🚨"
echo "[*] Cleaning up in 30 seconds..."
sleep 30

# Clean up
echo "[*] Cleaning up test artifacts..."
sudo sed -i '/nc -lvnp 9999/d' /etc/crontab
rm -f ~/.config/autostart/fake.desktop
sudo rm -f /usr/local/bin/fakeroot
rm -f /tmp/tmp_exec.sh /tmp/fakevid /dev/snd/fakeaudio /dev/video0

# Kill backgrounded fake procs
pkill -f "tcpdump -i lo"
pkill -f keylogger_process
pkill -f "/tmp/tmp_exec.sh"
pkill -f "while :; do :; done"
pkill -f "sleep 300"
pkill -f "nc -lvnp"

echo "[✓] System cleaned. You're back to stealth mode. 🕵️"
