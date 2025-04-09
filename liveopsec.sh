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

get_interface_info() {
    interfaces_output=""
    interfaces=$(ip -br link | awk '{print $1}')

    for iface in $interfaces; do
        ipv4=$(ip -4 addr show "$iface" | awk '/inet / {print $2}')
        ipv6=$(ip -6 addr show "$iface" | awk '/inet6 / {print $2}')
        [[ -z "$ipv4" && -z "$ipv6" ]] && continue
        interfaces_output+="Interface: $iface\n"
        [[ -n "$ipv4" ]] && interfaces_output+="  ▸ IPv4: $ipv4\n"
        [[ -n "$ipv6" ]] && interfaces_output+="  ▸ IPv6: $ipv6\n"
        interfaces_output+="\n"
    done
    echo -e "$interfaces_output"
}

check_tor_status() {
    local status=""
    tor_status=$(systemctl is-active tor 2>/dev/null)

    if [[ "$tor_status" == "active" ]]; then
        status="✔️ Tor service is running"
        tor_check_output=$(curl -s --socks5-hostname 127.0.0.1:9050 --max-time 10 https://check.torproject.org 2>/dev/null)
        if echo "$tor_check_output" | grep -q "Congratulations"; then
            status+=" (✔️ traffic is routed via Tor)"
        else
            ALERT=true
            status+=" (⚠️ traffic NOT using Tor)"
        fi
    else
        ALERT=true
        status="❌ Tor service is NOT running (skipping routing check)"
    fi

    echo "$status"
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
    torsocks dig +short txt o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null || echo "[!] DNS leak check failed"
}

check_geoip() {
    torsocks curl -s https://ipinfo.io/json | grep -E '"ip"|"city"|"region"|"country"' || echo "[!] GeoIP lookup failed or blocked"
}

check_public_ip_info() {
    ip=$(torsocks curl -s https://check.torproject.org/api/ip | grep -oP '(?<="IP": ")[^"]+')
    echo -e "IP: $ip\n"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "Reverse DNS: $(host $ip 2>/dev/null || echo 'Not found')"
        echo -e "WHOIS:\n$(whois $ip 2>/dev/null | head -n 10)"
    else
        echo -e "Reverse DNS: IP not valid or check failed"
    fi
}

check_ip_leak() {
    real_ip=$(curl -s --max-time 5 https://icanhazip.com || echo "Unavailable")
    tor_ip=$(curl -s --socks5-hostname 127.0.0.1:9050 --max-time 10 https://icanhazip.com || echo "Unavailable")
    if [[ "$real_ip" == "$tor_ip" ]]; then
        echo "✅ All good - IP masked"
    else
        ALERT=true
        echo "⚠️ Possible leak - Tor not enforced globally"
    fi
}

check_hidden_files() {
    find / -type f -name ".*" 2>/dev/null | head -n 10
}

check_syslogs() {
    journalctl --since today | tail -n 10
}

generate_opsec_report() {
    hostname=$(hostname)
    default_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    mac=$(ip link | grep ether | awk '{print $2}' | head -n 1)
    dns=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}' | paste -sd ", ")
    interfaces=$(get_interface_info)
    tor_check=$(check_tor_status)
    tor_leak_status=$(check_ip_leak)
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

    output=""
    [[ "$ALERT" == true ]] && output+="<span foreground='red' weight='bold' size='large'>🚨 ALERT: OPSEC BREACH DETECTED!</span>\n\n"

    output+="🔒 Ghosint - Enhanced OPSEC Monitor\n\n"
    output+="💼 Hostname: $hostname\n"
    output+="💐 Default Interface: $default_iface\n"
    output+="🆔 MAC Address: $mac\n"
    output+="🧠 DNS: $dns\n"
    output+="🧅 Tor Status: $tor_check\n"
    output+="🛡️ IP Leak Check: $tor_leak_status\n"
    output+="🕵️ VPN Status: $vpn_status\n"
    output+="⛑️ Firewall Status: $firewall_status\n"
    output+="🧬 Kernel Module Check:\n$kernel_modules\n\n"
    output+="📹 Media Device Status:\n$media_devices\n\n"
    output+="🔐 Persistence Check:\n$persistence\n\n"
    output+="📡 Interfaces:\n$interfaces\n\n"

    [[ -n "$browsers" ]] && output+="🌐 Active Browser Sessions:\n$browsers\n\n"
    [[ -n "$suspicious" ]] && output+="⚠️ Suspicious Processes:\n$suspicious\n\n"
    [[ -n "$recent_ssh" ]] && output+="⚠️ Recent External SSH Logins:\n$recent_ssh\n\n"
    [[ -n "$listening_ports" ]] && output+="⚙️ Listening Ports:\n$listening_ports\n\n"
    [[ -n "$conns" ]] && output+="🚁 Active Connections:\n$conns\n\n"
    [[ -n "$dns_leak" ]] && output+="🔍 DNS Leak Check:\n$dns_leak\n\n"
    [[ -n "$geoip" ]] && output+="🌍 GeoIP Info:\n$geoip\n\n"
    [[ -n "$public_info" ]] && output+="🌐 Public IP Info:\n$public_info\n\n"
    [[ -n "$hidden_files" ]] && output+="🔎 Hidden Files (sample):\n$hidden_files\n\n"
    [[ -n "$logs" ]] && output+="📜 Recent Logs:\n$logs\n\n"

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
    launch_yad_monitor
}

main
