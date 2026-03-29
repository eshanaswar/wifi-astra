#!/usr/bin/env bash
# MODULE_META
# NAME="CDP/LLDP Information Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Capture CDP/LLDP frames leaking infrastructure details"
# REQS="managed_iface"
# PCAP="yes"
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

echo "[*] [$TC_ID] Identifying CDP/LLDP leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# 🛰️ DYNAMIC TELEMETRY HEARTBEAT
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing CDP/LLDP frames..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# Identify & Target
timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:0e" > "$LOG_FILE" 2>&1 || true

kill "$TELEMETRY_PID" 2>/dev/null || true

# Verify
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
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No CDP or LLDP packets were detected during the monitoring period." \
        --severity "INFO" \
        --evidence "$LOG_FILE" \
        --rationale "Properly configured network infrastructure should not leak discovery protocols on wireless client segments."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
