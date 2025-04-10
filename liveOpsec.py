#!/usr/bin/env python3

import subprocess
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import time
import signal
import sys

# Ghost theme colors
BG_COLOR = '#000000'
TEXT_COLOR = '#FFFFFF'
ALERT_COLOR = '#FF5555'
HIGHLIGHT_COLOR = '#AAAAAA'

class OpsecMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title('👻 Ghosint - Live OPSEC Monitor')
        self.root.configure(bg=BG_COLOR)
        self.root.geometry('900x700')

        self.output = ScrolledText(root, font=('Courier New', 11), bg=BG_COLOR, fg=TEXT_COLOR)
        self.output.pack(expand=True, fill='both')

        self.refresh_interval = 15
        self.running = True

        signal.signal(signal.SIGINT, self.signal_handler)

        threading.Thread(target=self.run_checks, daemon=True).start()

    def signal_handler(self, sig, frame):
        self.running = False
        self.root.quit()
        sys.exit(0)

    def run_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
            decoded_result = result.decode().strip()
            return decoded_result if decoded_result else 'No issues detected'
        except subprocess.CalledProcessError:
            return 'Command failed or not available'

    def run_checks(self):
        commands = [
            ('Hostname', 'hostname'),
            ('Default Interface', "ip route | grep default | awk '{print $5}' | head -n 1"),
            ('MAC Address', "ip link | grep ether | awk '{print $2}' | head -n 1"),
            ('DNS Servers', "grep 'nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd ', '"),
            ('VPN Status', "ip -br addr | grep -E 'tun[0-9]+|wg[0-9]+|proton' || echo 'No VPN interface detected'"),
            ('Tor Status', "ps -eo comm,args | grep -E '^tor\\s' | grep -v grep || echo 'Tor is not running'"),
            ('ProxyChains Usage', "ps -ef | grep proxychains | grep -v grep || echo 'No proxychains usage detected'"),
            ('Firewall Status', "sudo ufw status | grep -i active"),
            ('Loaded Kernel Modules', "lsmod | grep -Ei 'hide|rootkit|stealth' || echo 'No suspicious kernel modules found'"),
            ('Media Devices', "lsof /dev/video0 /dev/snd/* 2>/dev/null || echo 'No active media devices'"),
            ('Persistence Checks', "ls /etc/cron* ~/.config/autostart 2>/dev/null"),
            ('Active Browser Sessions', "ps -eo comm | grep -E '^firefox$|^chrome$|^chromium$|^brave$|^tor-browser$' | sort | uniq -c || echo 'No active browsers'"),
            ('Suspicious Processes', "ps -eo comm | grep -Ei 'keylog|tcpdump|wireshark|netcat|nmap|socat|nc|strace|xinput|xev|ffmpeg|obs|peek' | sort -u || echo 'No suspicious processes'"),
            ('Recent SSH Logins', "last -ai | grep -vE '127.0.0.1|::1' | head -n 5"),
            ('Listening Ports', "ss -tunlp || echo 'No listening ports found'"),
            ('Active Connections', "ss -tunap | tail -n 10"),
            ('DNS Leak Check', "curl -s https://dnsleaktest.com/api/v1/dns | grep -Po '(?<=\"ip\":\")[^\"]+' | uniq"),
            ('GeoIP Information', "curl -s https://ipinfo.io/json"),
            ('Public IP Info', "curl -s https://api.ipify.org"),
            ('Hidden Files', "find / -type f -name '.*' 2>/dev/null | head -n 10"),
            ('Recent System Logs', "journalctl --since today | tail -n 10"),
            ('SetUID Binaries', r"find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 10"),
            ('Temp Exec Processes', "ps aux | grep -E '/tmp|/dev/shm|/run' | grep -v grep"),
            ('User Activity', "who -a"),
            ('Sudo Audit Logs', "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -n 10")
        ]

        while self.running:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            separator = f"\n{'='*40}\n[+] Updated: {timestamp}\n{'='*40}\n\n"
            self.output.insert(tk.END, separator, 'highlight')

            for title, cmd in commands:
                result = self.run_command(cmd)
                color = ALERT_COLOR if ('failed' in result.lower() or 'command failed' in result.lower() or 'not available' in result.lower() or 'no issues detected' not in result.lower()) and title in ['Loaded Kernel Modules', 'Media Devices', 'Suspicious Processes', 'Proxy Status', 'DNS Leak Check'] else TEXT_COLOR
                self.output.insert(tk.END, f"{title}:\n", 'highlight')
                self.output.insert(tk.END, f"{result}\n\n", ('status', color))

            self.output.tag_config('highlight', foreground=HIGHLIGHT_COLOR)
            self.output.tag_config('status', foreground=TEXT_COLOR)
            #self.output.see(tk.END)
            
            self.root.update()

            for _ in range(self.refresh_interval):
                if not self.running:
                    break
                time.sleep(10)

if __name__ == "__main__":
    root = tk.Tk()
    app = OpsecMonitor(root)

try:
    root.mainloop()
except KeyboardInterrupt:
    print("\n[!] Caught interrupt. Exiting cleanly...")
    root.quit()
    sys.exit(0)

