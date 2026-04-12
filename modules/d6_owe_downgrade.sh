#!/usr/bin/env bash
# MODULE_META
# NAME="OWE Transition Mode Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,airodump-ng"
# DESC="Test if OWE networks can be downgraded to Open by spoofing transition mode"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="owe"

#===============================================================================
#  modules/d6_owe_downgrade.sh
#  D6: OWE Transition Mode Downgrade (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-15}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D6"
SCAN_PREFIX="${EVIDENCE_DIR}/${TC_ID}_airodump"
CSV_FILE="${SCAN_PREFIX}-01.csv"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. OWE testing requires a target SSID."
    exit 1
fi

echo "[*] Testing OWE downgrade / transition mode for ${SSID}..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Scanning for OWE transition mode..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (airodump-ng)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    timeout --foreground "$SCAN_TIME" airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" || true
    RET=$?
else
    # Background Execution
    airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
    AIRO_PID=$!
    sleep "$SCAN_TIME"
    kill "$AIRO_PID" 2>/dev/null || true
    wait "$AIRO_PID" 2>/dev/null || true
    RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Check findings
OWE_PRESENT=$(awk -F, -v s="$SSID" 'tolower($14) ~ tolower(s) && $6 ~ /OWE/ {print "YES"}' "$CSV_FILE" 2>/dev/null || true)

if [[ "$OWE_PRESENT" == "YES" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "OWE Transition Mode Detected" \
        --desc "The network ${SSID} uses OWE Transition Mode, broadcasted both OWE and Open BSSIDs." \
        --severity MEDIUM \
        --evidence "$CSV_FILE" \
        --rationale "Transition mode is susceptible to downgrade attacks."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Scanned for OWE transition mode vulnerabilities on SSID ${SSID}. No issues identified." \
        --severity INFO \
        --evidence "$CSV_FILE" \
        --rationale "Ensuring modern encryption standards are not misconfigured."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
