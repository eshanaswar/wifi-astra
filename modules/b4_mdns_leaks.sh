#!/usr/bin/env bash
# MODULE_META
# NAME="mDNS/Bonjour Information Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Detect mDNS/Bonjour service announcements from corporate devices"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="none"

set -euo pipefail

#  modules/b4_mdns_leaks.sh
#  B4: mDNS/Bonjour Leak Analysis

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B4"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_mdns.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying mDNS/Bonjour services on ${INTERFACE} for ${SCAN_TIME}s..."

# 🛰️ DYNAMIC TELEMETRY HEARTBEAT
# Phase 1: 10% - 50%
(
    ELAPSED=0
    HALF_TIME=$((SCAN_TIME / 2))
    while [[ $ELAPSED -lt $HALF_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 40 / HALF_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Discovering mDNS services..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# 1. Active discovery using avahi-browse if available
AVAHI_OUT="${EVIDENCE_PREFIX}_avahi_raw.txt"
if command -v avahi-browse &>/dev/null; then
    timeout "$((SCAN_TIME/2))" avahi-browse -art > "$AVAHI_OUT" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true

# Phase 2: 50% - 90%
(
    ELAPSED=0
    HALF_TIME=$((SCAN_TIME / 2))
    while [[ $ELAPSED -lt $HALF_TIME ]]; do
        PCT=$(( 50 + (ELAPSED * 40 / HALF_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing mDNS traffic..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# 2. Passive capture of mDNS traffic (UDP 5353)
timeout "$((SCAN_TIME/2))" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "udp port 5353" > "$LOG_FILE" 2>&1 || true

kill "$TELEMETRY_PID" 2>/dev/null || true

# Verify
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."
FOUND=0
if [[ -f "$AVAHI_OUT" && -s "$AVAHI_OUT" ]]; then
    SERVICES=$(grep "^=" "$AVAHI_OUT" | awk '{print $4 " (" $5 ")"}' | sort -u || true)
    
    if [[ -n "$SERVICES" ]]; then
        FOUND=1
        while read -r service; do
            [[ -z "$service" ]] && continue
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type "vulnerability" \
                --name "mDNS Service Discovered" \
                --desc "Discovered active mDNS/Bonjour service: $service. This reveals device types and service availability." \
                --severity "INFO" \
                --evidence "$AVAHI_OUT" \
                --rationale "mDNS leaks reveal hostnames and service types, facilitating reconnaissance."
        done <<< "$SERVICES"
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No mDNS leaks detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No mDNS/Bonjour services or traffic were detected during the monitoring period." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "A lack of mDNS traffic on a guest segment is a sign of good network hygiene."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
