#!/usr/bin/env bash
set -euo pipefail

#===============================================================================
#  modules/c4_radius_reachability.sh
#  C4: RADIUS Server Reachability
#===============================================================================

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C4"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
OUTPUT_XML="${EVIDENCE_PREFIX}_nmap_radius.xml"

echo "[*] [$TC_ID] Identifying reachable RADIUS servers from ${INTERFACE}..."

# Identify & Target
RADIUS_CANDIDATES=("10.0.0.10" "10.1.1.10" "172.16.0.10" "192.168.1.10" "10.0.0.1" "192.168.1.1")
nmap -Pn -sU -p 1812,1813,1645,1646 "${RADIUS_CANDIDATES[@]}" -oX "$OUTPUT_XML" >/dev/null 2>&1 || true

# Verify
OPEN_RADIUS=$(grep "state=\"open\"" "$OUTPUT_XML" || echo "")

if [[ -n "$OPEN_RADIUS" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal RADIUS Reachability" \
        --desc "Internal RADIUS servers are reachable from the guest network." \
        --severity "HIGH" \
        --evidence "$OUTPUT_XML" \
        --rationale "Exposure of authentication infrastructure increases brute-force risks."
else
    echo "[+] No RADIUS servers detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No RADIUS authentication services were reachable." \
        --severity "INFO" \
        --evidence "$OUTPUT_XML" \
        --rationale "Segmented guest networks should not communicate with core auth backbone."
fi

# Cleanup
exit 0

