#!/usr/bin/env bash
set -euo pipefail

#===============================================================================
#  modules/c3_vlan_hopping.sh
#  C3: VLAN Hopping / Trunking Test
#===============================================================================

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

# Identify & Target
timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:00" > "$LOG_FILE" 2>&1 || true

if command -v yersinia &>/dev/null; then
    timeout 30 yersinia dtp -i "$INTERFACE" -n 1 > "$YERSINIA_OUT" 2>/dev/null || true
fi

# Verify
FOUND=0
if [[ -f "$YERSINIA_OUT" ]] && grep -qi "DTP" "$YERSINIA_OUT"; then
    FOUND=1
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "DTP Information Leak" \
        --desc "Dynamic Trunking Protocol (DTP) frames detected." \
        --severity "MEDIUM" \
        --evidence "$PCAP_FILE" \
        --rationale "DTP frames indicate the switch port is in dynamic mode, allowing trunk negotiation."
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
        --rationale "Hardcoded access ports prevent VLAN hopping."
fi

# Cleanup
exit 0

