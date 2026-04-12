#!/usr/bin/env bash
# MODULE_META
# NAME="Kr00k Vulnerability Test"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="tshark"
# DESC="Test if AP/client are vulnerable to Kr00k (CVE-2019-15126) decryption"
# REQS="monitor_iface,target_bssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e5_kr00k_test.sh
#  E5: Kr00k Test (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Identify if the target AP or client uses Broadcom or Cypress WiFi chipsets.
#  2. Send deauthentication frames to trigger a disassociation.
#  3. Capture the data frames sent immediately following disassociation.
#  4. Test if these frames are encrypted with an all-zero TK (Temporal Key), 
#     allowing for trivial decryption.
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
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e5"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E5"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting Kr00k (CVE-2019-15126) vulnerability test against ${BSSID}..."

RES_FILE="${EVIDENCE_PREFIX}_results.txt"
KROOK_LOG="${EVIDENCE_DIR}/${TC_ID}_krook.log"

# 1. Run Kr00k test scripts if available
KROOK_SCRIPT=$(find /opt/ /usr/share/ "${SCRIPT_DIR:-.}" -name "kr00k-test.py" 2>/dev/null | head -1)

if [[ -n "$KROOK_SCRIPT" ]]; then
    echo "[*] Running Kr00k test script: ${KROOK_SCRIPT} (${SCAN_TIME}s)..."

    # Start dynamic telemetry heartbeat
    (
        HEARTBEAT_ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
            PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / SCAN_TIME) ))
            [[ $PCT -gt 90 ]] && PCT=90
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing attack..."
            sleep 2
            HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
        done
    ) &
    TELEMETRY_PID=$!

    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout --foreground "$SCAN_TIME" python3 "$KROOK_SCRIPT" -i "$INTERFACE" -b "$BSSID" || true
    else
        timeout --foreground "$SCAN_TIME" python3 "$KROOK_SCRIPT" -i "$INTERFACE" -b "$BSSID" > "$KROOK_LOG" 2>&1 &
        TOOL_PID=$!
        wait $TOOL_PID || true
    fi
    
    kill "$TELEMETRY_PID" 2>/dev/null || true

    if grep -qi "vulnerable" "$KROOK_LOG"; then
        cp "$KROOK_LOG" "$RES_FILE"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Kr00k Vulnerability Detected" \
            --severity HIGH \
            --desc "The target is vulnerable to the Kr00k (CVE-2019-15126) decryption flaw." \
            --target "${BSSID}" \
            --evidence "$RES_FILE" \
            --rationale "Kr00k allows an attacker to decrypt sensitive data packets by forcing a disassociation and exploiting a flaw where the device uses an all-zero encryption key for the remaining buffered data."
    fi
else
    echo "[!] Kr00k test script not found. Performing OUI-based passive check..." > "$KROOK_LOG"
    OUI=$(echo "$BSSID" | cut -d: -f1-3)
    VENDOR=$("$ASTRA_BIN" lookup-oui "$BSSID" 2>/dev/null || echo "Unknown")
    echo "BSSID OUI: $OUI ($VENDOR)" >> "$KROOK_LOG"
    
    # Flag known vulnerable vendors
    if echo "$VENDOR" | grep -Ei "Broadcom|Cypress" >/dev/null; then
        echo "[!] WARNING: Target hardware ($VENDOR) is known to use chipsets vulnerable to CVE-2019-15126." >> "$KROOK_LOG"
    fi
fi

# Audit Complete finding if no critical vulnerability was recorded above
if [[ ! -f "$RES_FILE" ]]; then
    echo "[+] Kr00k testing complete (no active vulnerabilities confirmed)."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[E5] Audit Complete" \
        --severity INFO \
        --desc "Completed passive and OUI-based Kr00k vulnerability assessment for ${BSSID}." \
        --target "${BSSID}" \
        --evidence "$KROOK_LOG" \
        --rationale "Passive auditing identifies chipsets known to be vulnerable to Kr00k (Broadcom/Cypress). If active testing was not possible, this remains a configuration/hardware-level risk."
else
    echo "[+] Kr00k testing complete."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
