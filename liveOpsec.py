import subprocess
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import time

# Ghost theme colors
BG_COLOR = '#000000'
TEXT_COLOR = '#FFFFFF'
ALERT_COLOR = '#FF5555'
OK_COLOR = '#55FF55'
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

        threading.Thread(target=self.run_checks, daemon=True).start()

    def run_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
            return result.decode().strip()
        except subprocess.CalledProcessError:
            return 'Command failed or not available'

    def run_checks(self):
        commands = [
            ('Hostname', 'hostname'),
            ('Default Interface', "ip route | grep default | awk '{print $5}' | head -n 1"),
            ('MAC Address', "ip link | grep ether | awk '{print $2}' | head -n 1"),
            ('DNS Servers', "grep 'nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd ', '"),
            ('VPN Status', "ip -br link | awk '{print $1}' | grep -E '^(tun|wg)' | head -n 1"),
            ('Firewall Status', "sudo ufw status | grep -i active"),
            ('Loaded Kernel Modules', "lsmod | grep -Ei 'hide|rootkit|stealth'"),
            ('Media Devices', "lsof /dev/video0 /dev/snd/* 2>/dev/null"),
            ('Persistence Checks', "ls /etc/cron* ~/.config/autostart 2>/dev/null"),
            ('Active Browser Sessions', "ps -eo pid,comm,args | grep -E 'firefox|chrome|chromium|brave|tor-browser' | grep -v grep"),
            ('Suspicious Processes', "ps aux | grep -Ei 'keylog|tcpdump|wireshark|netcat|nmap|socat|nc|strace|xinput|xev|ffmpeg|obs|peek' | grep -v grep"),
            ('Recent SSH Logins', "last -ai | grep -vE '127.0.0.1|::1' | head -n 5"),
            ('Proxy Status', "pgrep -a proxychains4"),
            ('Listening Ports', "ss -tunlp | tail -n 10"),
            ('Active Connections', "ss -tunap | tail -n 10"),
            ('DNS Leak Check', "curl -s https://dnsleaktest.com | grep -i 'your ip'"),
            ('GeoIP Information', "curl -s https://ipinfo.io/json"),
            ('Public IP Info', "curl -s https://api.ipify.org"),
            ('Hidden Files', "find / -type f -name '.*' 2>/dev/null | head -n 10"),
            ('Recent System Logs', "journalctl --since today | tail -n 10"),
            ('SetUID Binaries', "find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 10"),
            ('Temp Exec Processes', "ps aux | grep -E '/tmp|/dev/shm|/run' | grep -v grep"),
            ('User Activity', "who -a"),
            ('Sudo Audit Logs', "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -n 10")
        ]

        while True:
            self.output.delete('1.0', tk.END)
            for title, cmd in commands:
                result = self.run_command(cmd)
                color = ALERT_COLOR if not result or 'failed' in result.lower() else OK_COLOR
                self.output.insert(tk.END, f"{title}:\n", 'highlight')
                self.output.insert(tk.END, f"{result}\n\n", ('status', color))

            self.output.tag_config('highlight', foreground=HIGHLIGHT_COLOR)
            self.output.tag_config('status', foreground=TEXT_COLOR)
            self.output.tag_configure(OK_COLOR, foreground=OK_COLOR)
            self.output.tag_configure(ALERT_COLOR, foreground=ALERT_COLOR)

            self.root.update()
            time.sleep(self.refresh_interval)

if __name__ == "__main__":
    root = tk.Tk()
    app = OpsecMonitor(root)
    root.mainloop()
