#!/usr/bin/env bash
# MODULE_META
# NAME="Egress Port Filtering"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Test which outbound ports are allowed through the wireless gateway"
# REQS="managed_iface"
# PCAP="no"
# 
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/c5_egress_filtering.sh
#  C5: Egress Port Filtering (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
EGRESS_TARGET="${EGRESS_TARGET:-1.1.1.1}" 
TC_ID="C5"
OUTPUT_XML="${EVIDENCE_DIR}/${TC_ID}_nmap_egress.xml"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Testing outbound egress filtering from ${INTERFACE} to ${EGRESS_TARGET}..."

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Testing outbound port filtering (nmap)..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (nmap)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    timeout --foreground "$SCAN_TIME" nmap -vv -Pn -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080 "$EGRESS_TARGET" -oX "$OUTPUT_XML" || true
    RET=$?
else
    # Background Execution
    nmap -vv -Pn -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080 "$EGRESS_TARGET" -oX "$OUTPUT_XML" > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Robust parsing of Nmap XML for open ports
OPEN_PORTS=$(awk -F'"' '/<port / {p=$4} /<state / {s=$4; if(s=="open") print p}' "$OUTPUT_XML" | xargs | sed 's/ /, /g')

if [[ -n "$OPEN_PORTS" ]]; then
    echo "[+] ALLOWED OUTBOUND PORTS: $OPEN_PORTS"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Weak Egress Filtering Policy" \
        --desc "The following outbound ports are allowed through the gateway to $EGRESS_TARGET: $OPEN_PORTS. Permissive egress policies allow compromised internal clients to communicate with C2 servers and facilitate data exfiltration." \
        --severity MEDIUM \
        --evidence "$OUTPUT_XML" \
        --rationale "Strict egress filtering (denying all by default and only allowing specific required ports) is a key defense-in-depth measure to prevent C2 communication and unauthorized data transfers."
else
    echo "[!] NO OUTBOUND PORTS DETECTED. Egress may be heavily restricted."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "No common outbound ports (21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080) were reachable on the external target $EGRESS_TARGET from the wireless network." \
        --severity INFO \
        --evidence "$OUTPUT_XML" \
        --rationale "Strict egress filtering is present, reducing the risk of data exfiltration and C2 beaconing from compromised wireless clients."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

exit $RET
