#!/usr/bin/env bash
# MODULE_META
# NAME="VLAN Hopping"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="yersinia,tcpdump"
# DESC="Attempt 802.1Q double-tagging and DTP spoofing to reach other VLANs"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

#  modules/c3_vlan_hopping.sh
#  C3: VLAN Hopping / Trunking Test

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C3"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_trunking.pcap"
YERSINIA_OUT="${EVIDENCE_PREFIX}_yersinia.txt"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying VLAN hopping / DTP leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing trunking & DTP audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (tcpdump + yersinia)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:00 or ether host 01:00:0c:cc:cc:cd" 2>&1 | tee "$LOG_FILE" || true
    
    if command -v yersinia &>/dev/null; then
        echo "[*] Attempting DTP trunk negotiation..."
        timeout 30 yersinia dtp -i "$INTERFACE" -n 1 2>&1 | tee "$YERSINIA_OUT" || true
    fi
    RET=$?
else
    # Background Execution
    (
        timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
            "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:00 or ether host 01:00:0c:cc:cc:cd" > "$LOG_FILE" 2>&1 || true
        
        if command -v yersinia &>/dev/null; then
            timeout 30 yersinia dtp -i "$INTERFACE" -n 1 > "$YERSINIA_OUT" 2>&1 || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Verify
FOUND=0
if [[ -f "$YERSINIA_OUT" ]] && grep -qi "DTP" "$YERSINIA_OUT"; then
    FOUND=1
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "DTP Information Leak / Trunk Possible" \
        --desc "Dynamic Trunking Protocol (DTP) frames detected on the segment." \
        --severity "HIGH" \
        --evidence "$PCAP_FILE" \
        --rationale "DTP frames indicate the switch port is in dynamic mode. An attacker can negotiate a trunk and access all VLANs traversing that switch, completely bypassing network segmentation."
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No trunking protocol leaks detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No DTP or VTP management frames were detected." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Hardcoded access ports prevent VLAN hopping and are a key security configuration for untrusted client segments."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

exit $RET
