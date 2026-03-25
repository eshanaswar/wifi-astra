#!/usr/bin/env bash
#===============================================================================
#  verify_hardware_state.sh — Post-Audit Hardware Health Check
#
#  Verifies that wireless interfaces are properly restored to managed mode
#  and that no rogue monitor interfaces or tool processes remain.
#===============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# Source core config for colors/paths
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/logger.sh"

check_interface_state() {
    local iface="$1"
    echo -n "[CHECK] Interface ${iface} state ... "
    
    if ! iw dev "$iface" info &>/dev/null; then
        echo -e "${C_RED}MISSING${C_RESET}"
        return 1
    fi
    
    local type=$(iw dev "$iface" info | awk '/type/{print $2}')
    if [[ "$type" == "managed" ]]; then
        echo -e "${C_GREEN}MANAGED (OK)${C_RESET}"
    else
        echo -e "${C_YELLOW}${type^^} (NOT RESTORED)${C_RESET}"
        return 1
    fi
    return 0
}

check_rogue_monitor() {
    echo -n "[CHECK] Rogue monitor interfaces ... "
    local rogue=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E "mon|wlan[0-9]+mon")
    if [[ -z "$rogue" ]]; then
        echo -e "${C_GREEN}NONE (OK)${C_RESET}"
    else
        echo -e "${C_RED}FOUND: ${rogue}${C_RESET}"
        return 1
    fi
    return 0
}

check_lingering_processes() {
    echo -n "[CHECK] Lingering attack processes ... "
    local tools=("airodump-ng" "aireplay-ng" "aircrack-ng" "tcpdump" "tshark" "hostapd" "dnsmasq")
    local found=()
    
    for tool in "${tools[@]}"; do
        if pgrep -x "$tool" >/dev/null; then
            found+=("$tool")
        fi
    done
    
    if [[ ${#found[@]} -eq 0 ]]; then
        echo -e "${C_GREEN}NONE (OK)${C_RESET}"
    else
        echo -e "${C_RED}FOUND: ${found[*]}${C_RESET}"
        return 1
    fi
    return 0
}

#--- Main ---
echo "============================================================"
echo "  WiFi-Astra Hardware Health & Cleanup Verification"
echo "============================================================"

FAILED=0

# Check primary interface if known
if [[ -n "${WIFI_INTERFACE:-}" ]]; then
    check_interface_state "$WIFI_INTERFACE" || FAILED=1
fi

check_rogue_monitor || FAILED=1
check_lingering_processes || FAILED=1

echo "------------------------------------------------------------"
if [[ $FAILED -eq 0 ]]; then
    echo -e "${C_GREEN}${C_BOLD}VERDICT: Hardware state is CLEAN. Cleanup successful.${C_RESET}"
else
    echo -e "${C_RED}${C_BOLD}VERDICT: Hardware state is DIRTY. Cleanup FAILED.${C_RESET}"
    echo -e "Run 'airmon-ng check kill' and restart NetworkManager manually."
fi
echo "============================================================"

exit $FAILED
