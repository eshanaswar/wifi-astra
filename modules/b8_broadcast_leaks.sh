#!/usr/bin/env bash
# MODULE_META
# NAME="Broadcast & Multicast Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Analyze UDP traffic for SSDP/LLMNR/NetBIOS storms bleeding from corporate"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# DECODE="none"

#  modules/b8_broadcast_leaks.sh
#  B8: Broadcast/Multicast Leaks

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B8"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_broadcast.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying broadcast/multicast leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# Identify & Target
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing broadcast traffic..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "broadcast or multicast" || true
    RET=$?
else
    # Run with redirection
    tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "broadcast or multicast" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    (sleep "$SCAN_TIME"; kill "$TOOL_PID" 2>/dev/null || true) &
    wait "$TOOL_PID" 2>/dev/null || true
    RET=$?
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing traffic patterns..."
FOUND=0
if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    PROTOCOLS=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol 2>/dev/null | sort | uniq -c | sort -nr || true)
    
    if [[ -n "$PROTOCOLS" ]]; then
        FOUND=1
        while read -r count proto; do
            [[ -z "$proto" ]] && continue
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type "vulnerability" \
                --name "Sensitive Broadcast Traffic: $proto" \
                --desc "Detected $count packets of $proto broadcast traffic. This can leak service details." \
                --severity "LOW" \
                --evidence "$PCAP_FILE" \
                --rationale "Excessive broadcast traffic facilitates reconnaissance and spoofing attacks."
        done <<< "$PROTOCOLS"
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No sensitive broadcast traffic detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No significant or sensitive broadcast/multicast leaks were detected." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Restricting broadcast traffic is a key network hardening measure."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
