#!/usr/bin/env bash
# MODULE_META
# NAME="AP Management Exposure"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Check if AP management interfaces (Web, SSH, SNMP) are accessible"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/b2_mgmt_exposure.sh
#  B2: AP Management Exposure (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
GATEWAY="${GATEWAY_IP:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/b2"
TC_ID="B2"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$GATEWAY" ]]; then
    # Auto-detect if not set
    GATEWAY=$(ip -4 route show dev "${INTERFACE:-}" | awk '/default/{print $3}' | head -1 || true)
    if [[ -z "$GATEWAY" ]]; then
        echo "[!] Gateway IP not set or detected. Connect to WiFi first."
        exit 1
    fi
fi

echo "[*] Testing Management Exposure on ${GATEWAY}..."

# Scan common management ports on the gateway
echo "[*] Running Nmap scan for common management ports..."
(
    while true; do
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 25 --status "Scanning management ports (nmap)..."
        sleep 5
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    nmap -Pn -p 22,23,80,443,161,8080,8443 "$GATEWAY" -sV -oG "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml"
    RET=$?
else
    nmap -Pn -p 22,23,80,443,161,8080,8443 "$GATEWAY" -sV -oG "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml" > "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."
if [[ -f "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" ]]; then
    # Extract the Ports field and split by comma
    OPEN_PORTS_LIST=$(awk -F'\t' '/Ports:/ {print $2}' "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" | sed 's/Ports: //')
    
    if [[ -n "$OPEN_PORTS_LIST" ]]; then
        # Use awk to process each port entry (delimited by , )
        # Each port entry is port/state/protocol/owner/service/rpcinfo/version
        # We split by ", " first
        echo "$OPEN_PORTS_LIST" | tr ',' '\n' | awk -F'/' '/open/ {print $1,$5,$7}' | while read -r port service version; do
            [[ -z "$port" ]] && continue
            echo "[!] Open port: $port ($service $version)"
            
            $ASTRA_BIN record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "Exposed Management Port: $port" \
                --severity MEDIUM \
                --desc "The gateway ($GATEWAY) has an exposed management port $port ($service $version). This could be used for unauthorized administrative access." \
                --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
                --rationale "Exposed management interfaces on the AP can lead to unauthorized administrative access and device takeover, compromising the entire network infrastructure."
        done
        exit 0
    fi
fi

echo "[+] No management interfaces detected on the AP."
$ASTRA_BIN record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "[B2] Audit Complete" \
    --severity INFO \
    --desc "No common management ports were found open on the gateway ($GATEWAY)." \
    --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
    --rationale "Hiding management interfaces from client segments is a best practice to prevent unauthorized administrative attempts. No risks were found in this interval."

exit 0
