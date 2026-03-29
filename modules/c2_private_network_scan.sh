#!/usr/bin/env bash
set -euo pipefail

#===============================================================================
#  modules/c2_private_network_scan.sh
#  C2: Private Network Egress Scan
#===============================================================================

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C2"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
REACHABLE_FILE="${EVIDENCE_PREFIX}_reachable_gateways.txt"
OUTPUT_XML="${EVIDENCE_PREFIX}_nmap_internal.xml"

echo "[*] [$TC_ID] Identifying egress to RFC1918 networks from ${INTERFACE}..."

# Identify & Target
RANGES=("10.0.0.1" "10.1.1.1" "172.16.0.1" "192.168.0.1" "192.168.1.1" "192.168.10.1" "192.168.100.1")
fping -a -t 500 "${RANGES[@]}" 2>/dev/null > "$REACHABLE_FILE" || true

# Verify
REACHABLE=$(cat "$REACHABLE_FILE")
if [[ -n "$REACHABLE" ]]; then
    nmap -Pn -p 22,80,443,445,3389 $REACHABLE -oX "$OUTPUT_XML" >/dev/null 2>&1 || true
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal Network Reachability Detected" \
        --desc "Guest network allows access to RFC1918 addresses: ${REACHABLE}" \
        --severity "HIGH" \
        --evidence "$OUTPUT_XML" \
        --rationale "Failure to segment guest WiFi from internal networks allows pivoting."
else
    echo "[+] No internal gateways reachable."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No common RFC1918 gateways were reachable." \
        --severity "INFO" \
        --evidence "$REACHABLE_FILE" \
        --rationale "Effective segmentation is a critical security control."
fi

# Cleanup
exit 0

