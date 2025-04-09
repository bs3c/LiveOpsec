#!/bin/bash

ALERT=false

check_dependencies() {
    for tool in yad curl ip hostname awk grep sed systemctl ss ps lsof dig host whois find; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "$tool is required but not installed. Exiting."
            exit 1
        }
    done
}

start_vpn_if_needed() {
    VPN_CMD=$(command -v protonvpn || command -v protonvpn-cli)

    if [[ -z "$VPN_CMD" ]]; then
        echo "[!] ProtonVPN CLI not found. Please run the install script."
        ALERT=true
        return
    fi

    vpn_status=$($VPN_CMD status 2>/dev/null | grep -i 'Status' | awk '{print tolower($2)}')

    if [[ "$vpn_status" != "connected" ]]; then
        echo "[*] VPN is not connected. Attempting to connect to the fastest server..."
        sudo "$VPN_CMD" c --fastest --sc
        sleep 5
        vpn_status=$($VPN_CMD status 2>/dev/null | grep -i 'Status' | awk '{print tolower($2)}')
        if [[ "$vpn_status" == "connected" ]]; then
            echo "[+] ProtonVPN connected successfully."
        else
            ALERT=true
            echo "[!] Failed to connect to ProtonVPN."
        fi
    else
        echo "✅ ProtonVPN already connected."
    fi
}

get_interface_info() {
    interfaces_output=""
    interfaces=$(ip -br link | awk '{print $1}')

    for iface in $interfaces; do
        ipv4=$(ip -4 addr show "$iface" | awk '/inet / {print $2}')
        ipv6=$(ip -6 addr show "$iface" | awk '/inet6 / {print $2}')
        [[ -z "$ipv4" && -z "$ipv6" ]] && continue
        interfaces_output+="Interface: $iface\n"
        [[ -n "$ipv4" ]] && interfaces_output+="  \u25B8 IPv4: $ipv4\n"
        [[ -n "$ipv6" ]] && interfaces_output+="  \u25B8 IPv6: $ipv6\n"
        interfaces_output+="\n"
    done
    echo -e "$interfaces_output"
}

check_vpn_status() {
    vpn_iface=$(ip -br link | awk '{print $1}' | grep -E '^tun|^wg' | head -n 1)
    if [[ -n "$vpn_iface" ]]; then
        vpn_ip=$(ip -4 addr show "$vpn_iface" | awk '/inet / {print $2}')
        echo "✅ VPN active on $vpn_iface ($vpn_ip)"
    else
        ALERT=true
        echo "❌ No VPN interface detected"
    fi
}

check_firewall_status() {
    if command -v ufw >/dev/null; then
        ufw_status=$(sudo ufw status | grep -i active)
        [[ -n "$ufw_status" ]] && echo "✅ UFW is active" || {
            ALERT=true
            echo "❌ UFW is inactive"
        }
    else
        iptables_count=$(sudo iptables -L | wc -l)
        [[ $iptables_count -gt 8 ]] && echo "✅ iptables rules are active" || {
            ALERT=true
            echo "❌ No active iptables rules"
        }
    fi
}

check_loaded_modules() {
    suspicious_modules=$(lsmod | grep -Ei 'hide|rootkit|stealth')
    [[ -n "$suspicious_modules" ]] && {
        ALERT=true
        echo "$suspicious_modules"
    } || echo "✅ No suspicious kernel modules detected"
}

check_media_devices() {
    cam=$(lsof /dev/video0 2>/dev/null)
    mic=$(lsof /dev/snd/* 2>/dev/null)

    [[ -n "$cam" ]] && {
        ALERT=true
        echo "⚠️ Webcam may be in use:\n$cam\n"
    } || echo "✅ Webcam not in use"

    [[ -n "$mic" ]] && {
        ALERT=true
        echo "⚠️ Microphone may be in use:\n$mic\n"
    } || echo "✅ Microphone not in use"
}

check_persistence() {
    crons=$(ls /etc/cron* 2>/dev/null)
    autostarts=$(ls ~/.config/autostart 2>/dev/null)
    [[ -n "$crons" ]] && echo "🕒 Cron jobs detected:\n$crons\n"
    [[ -n "$autostarts" ]] && echo "🚀 Autostart entries:\n$autostarts\n"
}

check_browser_sessions() {
    ps -eo pid,comm,etime,args | grep -E 'firefox|chrome|chromium|brave|tor-browser' | grep -v grep
}

check_suspicious_procs() {
    procs=$(ps aux | grep -Ei "keylog|tcpdump|wireshark|netcat|nmap|socat|nc|strace|xinput|xev|ffmpeg|obs|peek" | grep -v grep)
    [[ -n "$procs" ]] && {
        ALERT=true
        echo "$procs"
    }
}

check_recent_ssh() {
    if command -v last >/dev/null; then
        last -ai | grep -vE "127.0.0.1|::1" | head -n 5
    else
        echo "[!] 'last' command not found. Skipping SSH login check."
    fi
}

check_listening_ports() {
    ss -tunlp
}

check_connections() {
    ss -tunap
}

check_dns_leak() {
    curl -s https://dnsleaktest.com | grep -i "your ip" || echo "[!] DNS leak check failed or blocked"
}

check_geoip() {
    geo=$(curl -s --max-time 10 https://ipinfo.io/json)
    if [[ -z "$geo" || "$geo" =~ "limit" || "$geo" =~ "error" ]]; then
        echo "[!] GeoIP lookup failed or blocked"
    else
        echo "$geo" | grep -E '"ip"|"city"|"region"|"country"' | sed 's/[",]//g'
    fi
}

check_public_ip_info() {
    ip=$(curl -s --max-time 10 https://api.ipify.org)
    if [[ -z "$ip" ]]; then
        echo -e "IP: Unavailable"
        echo -e "Reverse DNS: N/A"
        echo -e "WHOIS: N/A"
        return
    fi

    echo -e "IP: $ip\n"
    rdns=$(host "$ip" 2>/dev/null || echo "Not found")
    whois_output=$(whois "$ip" 2>/dev/null | head -n 10)
    echo -e "Reverse DNS: $rdns"
    echo -e "WHOIS:\n$whois_output"
}

check_hidden_files() {
    find / -type f -name ".*" 2>/dev/null | head -n 10
}

check_syslogs() {
    journalctl --since today | tail -n 10
}

check_setuid_binaries() {
    echo "📛 SetUID/SetGID Binaries (potential privilege escalation):"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | head -n 10
}

check_temp_exec_procs() {
    echo "🧟 Processes running from /tmp, /dev/shm, or /run:"
    ps aux | grep -E '/tmp|/dev/shm|/run' | grep -v grep
}

check_user_activity() {
    echo "👥 Active Sessions:"
    who -a | grep -v "localhost"
    echo -e "\n🕵️ Last Logged Users:"
    lastlog | grep -v "Never"
}

check_sudo_audit_logs() {
    echo "🪪 Recent sudo activity (auth.log):"
    grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -n 10
}

generate_opsec_report() {
    hostname=$(hostname)
    default_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    mac=$(ip link | grep ether | awk '{print $2}' | head -n 1)
    dns=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}' | paste -sd ", ")
    interfaces=$(get_interface_info)
    vpn_status=$(check_vpn_status)
    firewall_status=$(check_firewall_status)
    kernel_modules=$(check_loaded_modules)
    media_devices=$(check_media_devices)
    persistence=$(check_persistence)
    browsers=$(check_browser_sessions)
    suspicious=$(check_suspicious_procs)
    recent_ssh=$(check_recent_ssh)
    listening_ports=$(check_listening_ports | tail -n 10)
    conns=$(check_connections | tail -n 10)
    dns_leak=$(check_dns_leak)
    geoip=$(check_geoip)
    public_info=$(check_public_ip_info)
    hidden_files=$(check_hidden_files)
    logs=$(check_syslogs)
    setuid_bins=$(check_setuid_binaries)
    tmp_exec=$(check_temp_exec_procs)
    user_activity=$(check_user_activity)
    sudo_logs=$(check_sudo_audit_logs)

    output=""
    [[ "$ALERT" == true ]] && output+="<span foreground='red' weight='bold' size='large'>🚨 ALERT: OPSEC BREACH DETECTED!</span>\n\n"

    output+="<b>🔒 Ghosint - Live OPSEC Monitor</b>\n\n"

    output+="<b>💼 System Identity</b>\n"
    output+="Hostname: $hostname\n"
    output+="Interface: $default_iface\n"
    output+="MAC Address: $mac\n"
    output+="DNS Servers: $dns\n\n"

    output+="<b>🕵️ VPN Status</b>\n$vpn_status\n"
    output+="<i>Explanation:</i> Ensures your real IP is hidden behind a VPN tunnel.\n\n"

    output+="<b>⛑️ Firewall Status</b>\n$firewall_status\n"
    output+="<i>Explanation:</i> Confirms whether system defenses are active.\n\n"

    output+="<b>🧬 Kernel Modules Check</b>\n$kernel_modules\n"
    output+="<i>Explanation:</i> Detects rootkits or stealthy modules.\n\n"

    output+="<b>📹 Media Devices</b>\n$media_devices\n"
    output+="<i>Explanation:</i> Flags if webcam or mic are in use.\n\n"

    output+="<b>🔐 Persistence Checks</b>\n$persistence\n"
    output+="<i>Explanation:</i> Autostarts or cron jobs may be used by malware.\n\n"

    output+="<b>📡 Network Interfaces</b>\n$interfaces\n"
    output+="<i>Explanation:</i> Lists all network interfaces and IPs.\n\n"

    [[ -n "$browsers" ]] && {
        output+="<b>🌐 Active Browser Sessions</b>\n$browsers\n"
        output+="<i>Explanation:</i> Useful to confirm Tor/secure browser usage.\n\n"
    }

    [[ -n "$suspicious" ]] && {
        output+="<span foreground='red'><b>⚠️ Suspicious Processes</b></span>\n$suspicious\n"
        output+="<i>Explanation:</i> Looks for tools commonly used for surveillance or attacks.\n\n"
    }

    [[ -n "$recent_ssh" ]] && {
        output+="<b>⚠️ Recent External SSH Logins</b>\n$recent_ssh\n"
        output+="<i>Explanation:</i> Helps detect unauthorized remote access.\n\n"
    }

    output+="<b>⚙️ Listening Ports</b>\n$listening_ports\n"
    output+="<i>Explanation:</i> Shows which services are exposed to the network.\n\n"

    output+="<b>🚁 Active Connections</b>\n$conns\n"
    output+="<i>Explanation:</i> Helps spot suspicious outbound activity.\n\n"

    output+="<b>🔍 DNS Leak Check</b>\n$dns_leak\n"
    output+="<i>Explanation:</i> Confirms if DNS requests are leaking real location/IP.\n\n"

    output+="<b>🌍 GeoIP Info</b>\n$geoip\n"
    output+="<i>Explanation:</i> IP’s geographic location should match VPN expectations.\n\n"

    output+="<b>🌐 Public IP Info</b>\n$public_info\n"
    output+="<i>Explanation:</i> Reverse DNS & WHOIS give insight into IP reputation.\n\n"

    output+="<b>🔎 Hidden Files (dotfiles)</b>\n$hidden_files\n"
    output+="<i>Explanation:</i> Might indicate hidden malware configs.\n\n"

    output+="<b>📜 Recent System Logs</b>\n$logs\n"
    output+="<i>Explanation:</i> Helps spot strange behavior or errors.\n\n"

    output+="<b>📛 SetUID/SetGID Binaries</b>\n$setuid_bins\n"
    output+="<i>Explanation:</i> Privileged binaries could be exploited.\n\n"

    output+="<b>🧟 Suspicious Temp Execution</b>\n$tmp_exec\n"
    output+="<i>Explanation:</i> Malware often runs from /tmp or /dev/shm.\n\n"

    output+="<b>👥 User Sessions & Activity</b>\n$user_activity\n"
    output+="<i>Explanation:</i> Checks current and past logins.\n\n"

    output+="<b>🪪 Sudo Audit Logs</b>\n$sudo_logs\n"
    output+="<i>Explanation:</i> Shows recent privileged command usage.\n\n"

    # Summary
    passed_checks=$(grep -c "✅" <<< "$output")
    alerts=$(grep -c "⚠️\|❌\|📛\|🧟" <<< "$output")

    output+="----------------------\n"
    output+="<b>🧾 Summary:</b>\n"
    output+="✅ Passed Checks: <span foreground='green'>$passed_checks</span>\n"
    output+="🚨 Alerts: <span foreground='red'>$alerts</span>\n"
    output+="----------------------\n"

    echo -e "$output"
}

launch_yad_monitor() {
    export GDK_BACKEND=x11

    (
        while :; do
            ALERT=false
            generate_opsec_report
            sleep 10
        done
    ) | yad --text-info \
        --title="Ghosint - Enhanced OPSEC Monitor" \
        --width=1000 \
        --height=800 \
        --fontname="monospace 10" \
        --center \
        --window-icon=dialog-warning \
        --no-buttons \
        --timeout-indicator=bottom \
        --forever \
        --markup

    echo "[*] Monitor closed. Exiting."
}

main() {
    check_dependencies
    start_vpn_if_needed
    launch_yad_monitor
}

main
