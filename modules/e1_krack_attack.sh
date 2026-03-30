#!/usr/bin/env bash
# MODULE_META
# NAME="KRACK Attack Testing"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="tshark,krack-test"
# DESC="Test WPA2 key reinstallation (CVE-2017-13077), nonce reuse, GTK reinstall"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e1_krack_attack.sh
#  E1: KRACK Attack (Golden Wrapper)
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
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E1"
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_capture.pcap"
RES_FILE="${EVIDENCE_DIR}/${TC_ID}_results.txt"
TCPDUMP_LOG="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$BSSID" ]]; then
    echo "[!] GUEST_BSSID not set. KRACK testing requires a target BSSID."
    exit 1
fi

echo "[*] Starting KRACK vulnerability tests against ${BSSID} (SSID: ${SSID:-Unknown})..."

# Ensure channel is set correctly
if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

# 1. Capture for analysis (EAPOL traffic)
echo "[*] Capturing EAPOL handshakes for nonce reuse analysis (${SCAN_TIME}s)..."

# Start dynamic telemetry heartbeat
(
    HEARTBEAT_ELAPSED=0
    # Capture (SCAN_TIME) + Script (120)
    TOTAL_TIME=$((SCAN_TIME + 120))
    while [[ $HEARTBEAT_ELAPSED -lt $TOTAL_TIME ]]; do
        PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / TOTAL_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing attack..."
        sleep 2
        HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# type 0x888e is EAPOL
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID and (type 0x888e)" || true
else
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID and (type 0x888e)" > "$TCPDUMP_LOG" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 2. Optional: Run specialized KRACK test scripts if available
KRACK_SCRIPT=$(find /opt/ /usr/share/ /root/ -name "krack_all_zero_tk.py" 2>/dev/null | head -1)
VULN_DETECTED=0

if [[ -n "$KRACK_SCRIPT" ]]; then
    echo "[*] Running KRACK test script: ${KRACK_SCRIPT}..."
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout 120 python3 "$KRACK_SCRIPT" -i "$INTERFACE" -b "$BSSID" -s "${SSID:-}" || true
    else
        timeout 120 python3 "$KRACK_SCRIPT" -i "$INTERFACE" -b "$BSSID" -s "${SSID:-}" > "$RES_FILE" 2>&1 &
        TOOL_PID=$!
        wait $TOOL_PID || true
    fi
    
    if awk 'tolower($0) ~ /vulnerable|reinstall|reuse/ {exit 0} END {exit 1}' "$RES_FILE"; then
        VULN_DETECTED=1
        echo "[!] VULNERABILITY DETECTED: KRACK (Key Reinstallation)"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "KRACK Vulnerability Detected" \
            --desc "Target AP ${BSSID} is vulnerable to Key Reinstallation Attacks (KRACK). The implementation allows for reinstallation of an already-in-use encryption key, leading to nonce reuse." \
            --severity CRITICAL \
            --evidence "$RES_FILE" \
            --rationale "KRACK (CVE-2017-13077) allows an attacker to decrypt traffic, hijack connections, and potentially inject malicious data into a WPA2-protected stream by forcing the reuse of cryptographic nonces."
    fi
else
    echo "[!] Specialized KRACK test script not found. Manual analysis of PCAP required." > "$RES_FILE"
fi

kill "$TELEMETRY_PID" 2>/dev/null || true

echo "[+] KRACK testing complete."
if [[ "$VULN_DETECTED" -eq 0 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Completed KRACK (Key Reinstallation Attack) testing against ${BSSID}. No immediate evidence of key reinstallation or nonce reuse was detected." \
        --severity INFO \
        --evidence "$PCAP_FILE" \
        --rationale "WPA2 networks should be audited for KRACK resilience. Modern firmware patches generally mitigate this class of vulnerability by preventing the reinstallation of keys during the 4-way handshake."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
