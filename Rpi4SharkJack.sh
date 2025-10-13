#!/bin/bash

LOOT="loot.txt"
INTERFACE="eth0"

# Farebné kódy
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

cprint() { echo -e "$1$2${NC}"; }

> "$LOOT"

# === 1. ČAKANIE NA KÁBEL ===
cprint "$CYAN" "🔌 Waiting for Ethernet cable..."
while ! ethtool "$INTERFACE" 2>/dev/null | grep -q "Link detected: yes"; do
    sleep 1
done
cprint "$GREEN" "✅ Cable connected."

# === 2. ZÍSKAJ IP ===
dhclient -q "$INTERFACE" 2>/dev/null &
sleep 6
pkill -f "dhclient.*$INTERFACE" 2>/dev/null

LOCAL_IP=$(ip -4 addr show "$INTERFACE" | grep -oP 'inet \K[\d.]+')
if [ -z "$LOCAL_IP" ]; then
    cprint "$YELLOW" "⚠️ No DHCP. Using fallback."
    LOCAL_IP="169.254.10.10"
    ip addr add "$LOCAL_IP/16" dev "$INTERFACE" 2>/dev/null || true
fi
SUBNET=$(echo "$LOCAL_IP" | cut -d. -f1-3).0/24
cprint "$GREEN" "🌐 Local IP: $LOCAL_IP"

# === 3. INŠTALÁCIA ===
cprint "$CYAN" "📦 Installing tools..."
for pkg in nmap curl; do
    command -v "$pkg" &>/dev/null || { apt update &>/dev/null && apt install -y "$pkg" &>/dev/null; }
done

# === 4. HOST DISCOVERY S MAC + HOSTNAME (KĽÚČOVÝ KROK) ===
cprint "$BLUE" "📡 Running nmap -sn (IP + MAC + hostname)..."
# Musí bežať ako root, aby videl MAC
NMAP_DISCOVERY=$(sudo nmap -sn --system-dns -n "$SUBNET" 2>/dev/null)

# === 5. PARSOVANIE VŠETKÉHO Z JEDNÉHO VÝSTUPU ===
declare -A IP_MAC HOSTNAME_MAP

current_ip=""; current_mac=""; current_hostname="N/A"

while IFS= read -r line; do
    # Nové zariadenie
    if [[ $line =~ Nmap\ scan\ report\ for\ (.+)\ \(([0-9.]+)\) ]]; then
        hn="${BASH_REMATCH[1]}"; ip="${BASH_REMATCH[2]}"
        current_ip="$ip"
        if [[ ! $hn =~ ^[0-9.]+$ ]]; then
            current_hostname="$hn"
        else
            current_hostname="N/A"
        fi
    elif [[ $line =~ Nmap\ scan\ report\ for\ ([0-9.]+)$ ]]; then
        current_ip="${BASH_REMATCH[1]}"
        current_hostname="N/A"
    fi

    # MAC adresa (len ak je k dispozícii)
    if [[ $line =~ MAC\ Address:\ ([0-9a-fA-F:]{17}) ]]; then
        current_mac="${BASH_REMATCH[1]}"
        # Ulož všetko
        if [ -n "$current_ip" ]; then
            # Preskoč RPi4 samotnú
            if [[ "$current_mac" != "$(cat /sys/class/net/$INTERFACE/address 2>/dev/null)" ]]; then
                IP_MAC["$current_ip"]="$current_mac"
                HOSTNAME_MAP["$current_ip"]="$current_hostname"
            fi
        fi
        current_ip=""; current_mac=""; current_hostname="N/A"
    fi
done <<< "$NMAP_DISCOVERY"

# Ak niektoré zariadenia nemajú MAC (napr. cez router), skúsime fallback
if [ ${#IP_MAC[@]} -eq 0 ]; then
    cprint "$YELLOW" "⚠️ No MAC from nmap. Falling back to ip neigh..."
    while IFS= read -r line; do
        if [[ $line =~ ^([0-9.]+)[[:space:]]+.*lladdr[[:space:]]+([0-9a-fA-F:]{17}) ]]; then
            ip="${BASH_REMATCH[1]}"; mac="${BASH_REMATCH[2]}"
            if [[ "$mac" != "$(cat /sys/class/net/$INTERFACE/address 2>/dev/null)" ]]; then
                IP_MAC["$ip"]="$mac"
                HOSTNAME_MAP["$ip"]="${HOSTNAME_MAP[$ip]:-N/A}"
            fi
        fi
    done < <(ip neigh show dev "$INTERFACE" 2>/dev/null)
fi

# === 6. VENDOR ===
get_vendor() {
    local mac="$1"
    local prefix=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]' | tr -d ':')
    for db in /usr/share/arp-scan/ieee-oui.txt /usr/share/nmap/nmap-mac-prefixes; do
        if [ -f "$db" ]; then
            match=$(grep -i "^$prefix" "$db" | head -1)
            if [ -n "$match" ]; then
                echo "$match" | cut -f2- | xargs
                return
            fi
        fi
    done
    echo "Unknown"
}

# === 7. OS SCAN ===
declare -A OS_MAP
if [ ${#IP_MAC[@]} -gt 0 ]; then
    cprint "$BLUE" "🔍 Scanning OS..."
    nmap_os=$(nmap -T4 -F -O --osscan-guess --max-os-tries=2 -n "$SUBNET" 2>/dev/null)
    current_ip=""
    while IFS= read -r line; do
        if [[ $line =~ Nmap\ scan\ report\ for\ ([0-9.]+) ]]; then
            current_ip="${BASH_REMATCH[1]}"
            OS_MAP["$current_ip"]="Unknown"
        elif [[ -n "$current_ip" ]] && [[ $line == *"Running:"* || $line == *"OS details:"* ]]; then
            OS_MAP["$current_ip"]="${line#*: }"
        fi
    done <<< "$nmap_os"
fi

# === 8. PUBLIC IP + GEO ===
cprint "$BLUE" "🌍 Fetching public IP and location..."
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me)
CITY="N/A"; COUNTRY="N/A"
if [ -n "$PUBLIC_IP" ] && [[ $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    geo=$(curl -s --max-time 5 "https://ipinfo.io/$PUBLIC_IP/json")
    CITY=$(echo "$geo" | grep -oP '"city":\s*"\K[^"]*' || echo "N/A")
    COUNTRY=$(echo "$geo" | grep -oP '"country":\s*"\K[^"]*' || echo "N/A")
fi

# === 9. VÝSTUP DO TERMINÁLU ===
cprint "$GREEN" "\n=== 🌐 NETWORK INVENTORY ==="
printf "${CYAN}%-16s %-18s %-22s %-18s %s${NC}\n" "IP" "MAC" "VENDOR" "HOSTNAME" "OS"
echo "--------------------------------------------------------------------------------"

if [ ${#IP_MAC[@]} -eq 0 ]; then
    cprint "$YELLOW" "⚠️ No devices found."
else
    for ip in $(printf '%s\n' "${!IP_MAC[@]}" | sort -V); do
        mac="${IP_MAC[$ip]}"
        vendor="$(get_vendor "$mac")"
        hn="${HOSTNAME_MAP[$ip]:-N/A}"
        os="${OS_MAP[$ip]:-Unknown}"
        printf "${GREEN}%-16s${NC} ${YELLOW}%-18s${NC} %-22s %-18s %s\n" "$ip" "$mac" "${vendor:0:21}" "${hn:0:17}" "${os:0:20}"
    done
fi

cprint "$BLUE" "\n=== 🌍 CONNECTION INFO ==="
echo "Public IP : $PUBLIC_IP"
echo "Location  : $CITY, $COUNTRY"
echo "Devices   : ${#IP_MAC[@]}"

# === 10. VÝSTUP DO loot.txt ===
{
    echo "=== SHARKJACK LAN RECON REPORT ==="
    echo "Local IP: $LOCAL_IP"
    echo "Public IP: $PUBLIC_IP"
    echo "City: $CITY"
    echo "Country: $COUNTRY"
    echo "Time: $(date)"
    echo ""
    echo "=== NETWORK INVENTORY ==="
    printf "%-16s %-18s %-24s %-20s %s\n" "IP" "MAC" "VENDOR" "HOSTNAME" "OS"
    echo "--------------------------------------------------------------------------------"
    
    if [ ${#IP_MAC[@]} -eq 0 ]; then
        echo "No devices found."
    else
        for ip in $(printf '%s\n' "${!IP_MAC[@]}" | sort -V); do
            mac="${IP_MAC[$ip]}"
            vendor="$(get_vendor "$mac")"
            hn="${HOSTNAME_MAP[$ip]:-N/A}"
            os="${OS_MAP[$ip]:-Unknown}"
            printf "%-16s %-18s %-24s %-20s %s\n" "$ip" "$mac" "${vendor:0:23}" "${hn:0:19}" "${os:0:18}"
        done
    fi
    
    echo ""
    echo "Total devices: ${#IP_MAC[@]}"
} > "$LOOT"

cprint "$GREEN" "\n✅ Recon complete! Full report saved to loot.txt"