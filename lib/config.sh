#!/usr/bin/env bash
#===============================================================================
#  lib/config.sh — Global Configuration & Variables
#===============================================================================

#--- Version ---
export TOOLKIT_VERSION="1.0"

#--- Global Tool Paths ---
declare -gA TOOL_PATHS
TOOL_PATHS=(
    ["airmon-ng"]=""
    ["airodump-ng"]=""
    ["aireplay-ng"]=""
    ["hcxdumptool"]=""
    ["hcxpcapngtool"]=""
    ["nmap"]=""
    ["masscan"]=""
    ["tcpdump"]=""
    ["tshark"]=""
    ["nbtscan"]=""
    ["onesixtyone"]=""
    ["snmpwalk"]=""
    ["searchsploit"]=""
    ["nuclei"]=""
    ["msfconsole"]=""
    ["iodine"]=""
    ["ptunnel-ng"]=""
    ["chisel"]=""
    ["yersinia"]=""
    ["fping"]=""
    ["arping"]=""
    ["ping"]=""
    ["timeout"]=""
    ["avahi-browse"]=""
    ["dig"]=""
    ["nslookup"]=""
    ["ip"]=""
    ["jq"]=""
    ["curl"]=""
    ["wget"]=""
    ["mdk4"]=""
    ["wash"]=""
    ["reaver"]=""
    ["bully"]=""
    ["hostapd"]=""
    ["dnsmasq"]=""
    ["macchanger"]=""
    ["aircrack-ng"]=""
    ["packetforge-ng"]=""
    ["airsnitch"]=""
    ["eaphammer"]=""
    ["hostapd-mana"]=""
    ["iw"]=""
    ["wkhtmltopdf"]=""
    ["astra-engine"]="/home/kali/Documents/Antigravity/WiFi_PT/engine/astra-engine"
)

#--- Command Execution Safety ---
run_tool() {
    local tool_name="$1"
    shift
    # Use run_fg with --quiet for internal library tool calls to avoid UI clutter
    if declare -f run_fg &>/dev/null; then
        run_fg --quiet "$tool_name" "$@"
    else
        # Fallback if process_manager.sh isn't loaded yet
        local path="${TOOL_PATHS[$tool_name]:-}"
        if [[ -n "$path" && -x "$path" ]]; then
            "$path" "$@"
        else
            log_error "Required tool '$tool_name' not found or not executable."
            return 127
        fi
    fi
}

#--- Configuration Loading ---
# Load from /etc if available, otherwise use defaults
if [[ -f "/etc/wifi-astra.conf" ]]; then
    source "/etc/wifi-astra.conf"
fi

#--- Directory Structure ---
# Detect real user's home directory even if running as root via sudo
REAL_USER_HOME="${HOME}"
if [[ -n "${SUDO_USER:-}" ]]; then
    REAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
fi

export SESSION_BASE_DIR="${SCRIPT_DIR}/sessions"
export LIB_DIR="${SCRIPT_DIR}/lib"
export MOD_DIR="${SCRIPT_DIR}/modules"
export EVIDENCE_BASE="${SESSION_BASE_DIR}"
export WORDLIST_DIR="${SCRIPT_DIR}/wordlists"
export ROCKYOU_PATH="/usr/share/wordlists/rockyou.txt"

#--- Create directories if missing ---
mkdir -p "$EVIDENCE_BASE" "$WORDLIST_DIR"
chmod 700 "$EVIDENCE_BASE" 2>/dev/null || true
if [[ -n "${SUDO_USER:-}" ]]; then
    # Ensure the parent .wifi-astra is also owned by the user
    chown "$SUDO_USER:$SUDO_USER" "${REAL_USER_HOME}/.wifi-astra" 2>/dev/null || true
    chown -R "$SUDO_USER:$SUDO_USER" "$EVIDENCE_BASE" 2>/dev/null || true
fi

#--- Session Variables (set during init) ---
export SESSION_ID=""
export SESSION_DIR=""
export SESSION_STATE_FILE=""
export SESSION_LOG_DIR=""
export SESSION_EVIDENCE_DIR=""
export SESSION_REPORT_DIR=""
export SESSION_RESULTS_DIR=""

declare -ga SESSION_VARS=(
    "SESSION_NAME" "WIFI_INTERFACE" "MONITOR_INTERFACE" "GUEST_SSID" 
    "GUEST_BSSID" "GUEST_CHANNEL" "INTERNAL_SSID" "INTERNAL_BSSID" 
    "GATEWAY_IP" "MY_IP" "MY_MAC" "DNS_SERVER" "VPS_IP" 
    "VPS_DOMAIN" "VPS_CONFIGURED" "CAPTIVE_PORTAL" "C2_SCOPE" 
    "PREFLIGHT_DONE"
)

#--- Color Codes ---
export C_RESET=$'\033[0m'
export C_RED=$'\033[1;31m'
export C_GREEN=$'\033[1;32m'
export C_YELLOW=$'\033[1;33m'
export C_BLUE=$'\033[1;34m'
export C_MAGENTA=$'\033[1;35m'
export C_CYAN=$'\033[1;36m'
export C_WHITE=$'\033[1;37m'
export C_GRAY=$'\033[0;37m'
export C_BOLD=$'\033[1m'
export C_DIM=$'\033[2m'
export C_BLINK=$'\033[5m'
export C_BG_RED=$'\033[41m'
export C_BG_GREEN=$'\033[42m'
export C_BG_YELLOW=$'\033[43m'

#--- Status Icons (text only for alignment, colors added in menu.sh) ---
export ICON_DONE="[✓]"
export ICON_PENDING="[ ]"
export ICON_FAIL="[x]"
export ICON_WARN="[!]"
export ICON_INFO="[i]"
export ICON_RUNNING="[>]"
export ICON_CRITICAL="*"
export ICON_LOCK="[L]"
export ICON_KEY="[K]"

#--- Hardware Capabilities (set during hardware query) ---
export HW_CAN_INJECT="no"
export HW_CAN_MONITOR="no"
export HW_24GHZ_SUPPORT="no"
export HW_5GHZ_SUPPORT="no"
export HW_6GHZ_SUPPORT="no"
export ICON_SKIP="[S]"

#--- Category Labels ---
declare -gA CATEGORY_LABELS
CATEGORY_LABELS=(
    ["A"]="A — PASSIVE WIRELESS RECON"
    ["B"]="B — NETWORK & SERVICE RECON"
    ["C"]="C — SEGMENTATION & FILTERING"
    ["D"]="D — ENCRYPTION & AUTH ATTACKS"
    ["E"]="E — PROTOCOL VULNERABILITY"
    ["F"]="F — ROGUE AP & CLIENT ATTACKS"
    ["G"]="G — MITM & NETWORK ATTACKS"
    ["H"]="H — DEFENSE VALIDATION"
)

#--- Category Display Order ---
declare -ga CATEGORY_ORDER=("A" "B" "C" "D" "E" "F" "G" "H")

# NOTE: TC_ORDER, TC_REGISTRY, TC_REQUIREMENTS, etc. are now 
# dynamically populated by lib/discovery.sh at startup.

#--- TC Status Tracking (in-memory, persisted to session file) ---
declare -gA TC_STATUS
# Possible values: "not_run" "running" "done" "failed" "aborted"

#--- TC Result Data (in-memory cache) ---
declare -gA TC_RESULTS_FILE
# Maps TC-ID to its results JSON file path

#--- Global Runtime State ---
export CURRENT_TC=""            # Currently running TC-ID
export CURRENT_TC_PID=""        # PID of current background process (if any)
export TC_ABORT_REQUESTED=0     # Flag: Ctrl+\ was pressed
export SCRIPT_EXIT_REQUESTED=0  # Flag: Ctrl+C was pressed

#--- Network Configuration (populated during tests) ---
export WIFI_INTERFACE=""        # e.g., wlan0
export MONITOR_INTERFACE=""     # e.g., wlan0mon
export GUEST_SSID=""            # Target network SSID (GUEST prefix kept for variable consistency)
export GUEST_BSSID=""           # Target network BSSID
export GUEST_CHANNEL=""         # Target channel
export GATEWAY_IP=""            # Default gateway on target network
export MY_IP=""                 # Our IP on target network
export MY_MAC=""                # Our MAC address
export DNS_SERVER=""            # DNS server on target network
export INTERNAL_SSID=""         # Reference internal/corporate SSID for segregation tests
export INTERNAL_BSSID=""        # Reference internal/corporate BSSID

#--- Assessment preferences (preflight wizard) ---
export C2_SCOPE=""              # Optional scan scope hint for C2 (e.g. 192.168.1.0/24)
export PREFLIGHT_DONE=0         # 1 when wizard has been completed for this session

#--- VPS Configuration (for egress tests) ---
export VPS_IP=""
export VPS_DOMAIN=""
export VPS_SSH_KEY=""
export VPS_CONFIGURED=0

#--- Captive Portal Configuration ---
export CAPTIVE_PORTAL=""            # "yes", "no", or "" (unknown)

#--- Timing Defaults ---
export AIRODUMP_SCAN_TIME=60         # Seconds for initial WiFi scan
export CDP_CAPTURE_TIME=120          # Seconds for CDP/LLDP capture
export MDNS_CAPTURE_TIME=60          # Seconds for mDNS capture
export MASSCAN_RATE=1000             # Packets per second for masscan
export NMAP_TIMING="-T3"            # Nmap timing template
export PMKID_CAPTURE_TIME=120       # Seconds for PMKID capture attempt
