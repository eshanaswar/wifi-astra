#!/usr/bin/env bash
# MODULE_META
# NAME="CDP/LLDP Information Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="[LEGACY] CDP/LLDP leak detection — wirelessly rare; most effective on wired segments"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

set -euo pipefail

#  modules/b3_cdp_lldp_leaks.sh
#  B3: CDP/LLDP Leak Analysis

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-120}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B3"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_leaks.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

# Note: CDP and LLDP are Layer 2 protocols forwarded between switches and APs over wired
# uplinks. They are almost never forwarded over-the-air on standard WiFi deployments
# (controller-based or tunneled architectures). Detection is most useful when the test
# machine is connected via Ethernet to a trunk port, or in AP-mode bridge deployments.
# Results on a purely wireless client interface will usually be negative.
echo "[!] LEGACY MODULE: CDP/LLDP frames are rarely forwarded over WiFi. Expect negative results in most wireless environments — this test is most effective on wired trunk connections."
echo "[*] [$TC_ID] Identifying CDP/LLDP leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# Identify & Target
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing CDP/LLDP frames..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:0e" || true
else
    # Run with redirection
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:0e" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait "$TOOL_PID" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing capture..."
FOUND=0
if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    LEAKED_INFO=$(tshark -r "$PCAP_FILE" -T fields \
        -e cdp.device_id -e cdp.port_id -e lldp.tlv.system.name -e lldp.tlv.port.id \
        2>/dev/null | sort -u | grep -v "^$" || true)
    
    if [[ -n "$LEAKED_INFO" ]]; then
        FOUND=1
        echo "[!] CDP/LLDP LEAKS DETECTED!"
        while read -r line; do
            [[ -z "$line" ]] && continue
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type "vulnerability" \
                --name "Infrastructure Info Leak (CDP/LLDP)" \
                --desc "Discovered leaked infrastructure info: $line. This protocol reveals physical switching details." \
                --severity "LOW" \
                --evidence "$PCAP_FILE" \
                --rationale "CDP/LLDP leaks reveal network topology, device models, and VLAN configurations, aiding in reconnaissance."
        done <<< "$LEAKED_INFO"
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No CDP/LLDP leaks detected."
    # Use PCAP_FILE as evidence — LOG_FILE only exists in background mode and will not
    # be present when ASTRA_IN_WINDOW=true (foreground tcpdump writes directly to PCAP).
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No CDP or LLDP packets were detected during the monitoring period." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Properly configured network infrastructure should not leak discovery protocols on wireless client segments."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
