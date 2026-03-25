#!/usr/bin/env bash
#===============================================================================
#  install.sh
#  WiFi Security Audit Toolkit — Installer
#
#  Installs all dependencies and configures the system.
#  Supports: Kali Linux, Parrot OS, Ubuntu/Debian, Arch Linux
#===============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TOOL_NAME="WiFi-Astra"
readonly INSTALL_DIR="/opt/wifi-astra"
readonly BIN_LINK="/usr/local/bin/wifi-astra"
readonly CONFIG_FILE="/etc/wifi-astra.conf"

# Colors
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

info()  { echo -e "  ${C_CYAN}[INFO]${C_RESET}  $*"; }
ok()    { echo -e "  ${C_GREEN}[OK]${C_RESET}    $*"; }
warn()  { echo -e "  ${C_YELLOW}[WARN]${C_RESET}  $*"; }
err()   { echo -e "  ${C_RED}[ERR]${C_RESET}   $*"; }

#--- Root check ---
if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root."
    echo "  Usage: sudo ./install.sh"
    exit 1
fi

#--- Banner ---
echo ""
echo -e "${C_CYAN}${C_BOLD}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════════════════════════╗
  ║           WiFi Security Audit Toolkit — Installer            ║
  ╚═══════════════════════════════════════════════════════════════╝
BANNER
echo -e "${C_RESET}"

#--- Detect OS ---
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            kali)   echo "kali" ;;
            parrot) echo "parrot" ;;
            ubuntu) echo "ubuntu" ;;
            debian) echo "debian" ;;
            arch|manjaro) echo "arch" ;;
            *)      echo "$ID" ;;
        esac
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
info "Detected OS: ${OS}"

#--- Package lists ---
# Core (required)
CORE_PACKAGES=(
    "aircrack-ng"
    "nmap"
    "tcpdump"
    "tshark"
    "iw"
    "wireless-tools"
    "net-tools"
    "jq"
    "bc"
    "curl"
    "wget"
    "macchanger"
    "hostapd"
    "dnsmasq"
    "iptables"
    "iproute2"
    "procps"
    "coreutils"
    "dnsutils"
    "golang"
)

# Extended (optional but recommended)
EXTENDED_PACKAGES=(
    "dsniff"
    "ettercap-text-only"
    "yersinia"
    "mdk4"
    "responder"
    "iperf3"
    "speedtest-cli"
    "arping"
    "python3-scapy"
    "hashcat"
    "hcxdumptool"
    "hcxtools"
    "wifite"
    "bettercap"
    "masscan"
    "snmpwalk"
    "nbtscan"
    "reaver"
    "bully"
    "wash"
    "iodine"
    "mitmproxy"
    "sslstrip"
    "python3-dnspython"
)

# Python packages
PYTHON_PACKAGES=(
    "scapy"
)

#--- Install functions ---
# Uses only apt-get install (no apt-get update/upgrade) to avoid full system upgrade.
install_apt() {
    info "Installing core packages... (apt-get install only, no upgrade)"
    info "Updating package lists..."
    apt-get update -qq || warn "apt-get update failed, proceeding anyway..."
    
    local installed=0
    local failed=0

    for pkg in "${CORE_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            ok "${pkg} (already installed)"
        else
            if apt-get install -y -qq "$pkg" &>/dev/null; then
                ok "${pkg}"
                ((installed++))
            else
                warn "Failed to install: ${pkg}"
                ((failed++))
            fi
        fi
    done

    echo ""
    info "Installing extended packages (optional)..."
    for pkg in "${EXTENDED_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            ok "${pkg} (already installed)"
        else
            if apt-get install -y -qq "$pkg" &>/dev/null; then
                ok "${pkg}"
                ((installed++))
            else
                warn "Optional: ${pkg} not available"
            fi
        fi
    done

    echo ""
    info "Core: installed=${installed}, failed=${failed}"
}

install_pacman() {
    info "Skipping package database update to prevent system upgrades..."

    local pacman_packages=(
        "aircrack-ng" "nmap" "tcpdump" "wireshark-cli"
        "iw" "wireless_tools" "net-tools" "jq" "bc" "curl" "wget"
        "macchanger" "hostapd" "dnsmasq" "iptables" "iproute2"
        "bind-tools" "iperf3" "python-scapy" "hashcat"
    )

    for pkg in "${pacman_packages[@]}"; do
        if pacman -Q "$pkg" &>/dev/null; then
            ok "${pkg} (already installed)"
        else
            if pacman -S --noconfirm "$pkg" &>/dev/null; then
                ok "${pkg}"
            else
                warn "Failed: ${pkg}"
            fi
        fi
    done
}

install_python() {
    info "Installing Python packages..."
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if python3 -c "import ${pkg}" &>/dev/null; then
            ok "python3-${pkg} (already installed)"
        else
            if pip3 install "$pkg" &>/dev/null; then
                ok "python3-${pkg}"
            else
                warn "Failed: python3-${pkg}"
            fi
        fi
    done
}

#--- Install based on OS ---
case "$OS" in
    kali|parrot|ubuntu|debian)
        install_apt
        ;;
    arch|manjaro)
        install_pacman
        ;;
    *)
        warn "Unrecognized OS: ${OS}"
        warn "Attempting apt-get based install..."
        install_apt
        ;;
esac

install_python

#--- Install the toolkit ---
echo ""
info "Installing toolkit to ${INSTALL_DIR}..."

mkdir -p "$INSTALL_DIR"
cp -r "${SCRIPT_DIR}/"* "$INSTALL_DIR/" 2>/dev/null || true

# Set permissions
chmod -R 755 "$INSTALL_DIR"
chmod +x "${INSTALL_DIR}/wifi-astra.sh" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/modules/"*.sh 2>/dev/null || true
chmod +x "${INSTALL_DIR}/lib/"*.sh 2>/dev/null || true

# Build Assessment Engine
info "Building Assessment Engine..."
if command -v go &>/dev/null; then
    (
        cd "${INSTALL_DIR}/engine"
        go build -o astra-engine cmd/main.go
    )
    if [[ -f "${INSTALL_DIR}/engine/astra-engine" ]]; then
        chmod +x "${INSTALL_DIR}/engine/astra-engine"
        ln -sf "${INSTALL_DIR}/engine/astra-engine" "${INSTALL_DIR}/astra-engine"
        ok "Assessment Engine built successfully."
    else
        err "Failed to build Assessment Engine binary."
    fi
else
    warn "Go compiler not found. Assessment Engine will not be functional."
fi

# Create symlink
ln -sf "${INSTALL_DIR}/wifi-astra.sh" "$BIN_LINK"
ok "Symlink created: ${BIN_LINK} → ${INSTALL_DIR}/wifi-astra.sh"

# Create evidence directory
mkdir -p "${INSTALL_DIR}/evidence"
chmod 700 "${INSTALL_DIR}/evidence"
ok "Evidence directory: ${INSTALL_DIR}/evidence"

# Create default config
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<'CONFIG'
# WiFi-Astra Configuration
# ==========================================

# Default output directory for session logs, evidence, and reports
OUTPUT_DIR="/var/log/wifi-astra"

# Default interface settings (auto-detect if empty)
WIFI_INTERFACE=""
MONITOR_INTERFACE_NAME="wlan0mon"

# Default scan timeout (seconds)
SCAN_TIMEOUT=60
CONFIG
    ok "Default config: ${CONFIG_FILE}"
fi

#--- Verify installation ---
echo ""
echo -e "${C_CYAN}${C_BOLD}  ═══════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}         Installation Verification       ${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}  ═══════════════════════════════════════${C_RESET}"
echo ""

declare -A TOOL_CHECK=(
    ["aircrack-ng"]="aircrack-ng"
    ["airodump-ng"]="airodump-ng"
    ["aireplay-ng"]="aireplay-ng"
    ["nmap"]="nmap"
    ["tcpdump"]="tcpdump"
    ["tshark"]="tshark"
    ["jq"]="jq"
    ["hostapd"]="hostapd"
    ["dnsmasq"]="dnsmasq"
    ["macchanger"]="macchanger"
    ["curl"]="curl"
    ["iw"]="iw"
    ["astra-engine"]="${INSTALL_DIR}/engine/astra-engine"
)

tool_ok=0
tool_missing=0

for tool_name in "${!TOOL_CHECK[@]}"; do
    tool_cmd="${TOOL_CHECK[$tool_name]}"
    if command -v "$tool_cmd" &>/dev/null; then
        ok "${tool_name}"
        ((tool_ok++))
    else
        warn "${tool_name} — NOT FOUND"
        ((tool_missing++))
    fi
done

echo ""
info "Tools verified: ${tool_ok} OK, ${tool_missing} missing"

# Check wireless interface
echo ""
info "Checking wireless interfaces..."
wifi_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ -n "$wifi_ifaces" ]]; then
    for ifc in $wifi_ifaces; do
        phy=$(iw dev "$ifc" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        monitor_support=""
        monitor_support=$(iw "$phy" info 2>/dev/null | grep -c "monitor" || echo 0)
        if [[ $monitor_support -gt 0 ]]; then
            ok "${ifc} (monitor mode supported) ← ${phy}"
        else
            warn "${ifc} (monitor mode NOT supported) ← ${phy}"
        fi
    done
else
    warn "No wireless interfaces detected"
fi

#--- Final summary ---
echo ""
echo -e "${C_GREEN}${C_BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║               Installation Complete!                          ║"
echo "  ╠═══════════════════════════════════════════════════════════════╣"
echo "  ║                                                               ║"
echo "  ║  Run the toolkit:                                             ║"
echo "  ║    sudo wifi-astra                                            ║"
echo "  ║                                                               ║"
echo "  ║  Configuration: /etc/wifi-astra.conf                          ║"
echo "  ║  Evidence Base: /var/log/wifi-astra/                          ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo -e "${C_RESET}"
echo ""

exit 0