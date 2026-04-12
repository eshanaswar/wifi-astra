#!/usr/bin/env bash
# MODULE_META
# NAME="Client-to-Client Isolation"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap,fping,arping"
# DESC="Test if connected clients on target WiFi can see each other"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# 
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/b1_client_isolation.sh
#  B1: Client-to-Client Isolation Test (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
OUTPUT_CSV="${OUTPUT_CSV:-${EVIDENCE_DIR}/b1_results.csv}"
OUTPUT_XML="${EVIDENCE_DIR}/b1_results.xml"
TC_ID="B1"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

# Get current IP and Subnet
MY_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
if [[ -z "$MY_IP" ]]; then
    echo "[!] No IP address on ${INTERFACE}. Connect to WiFi first."
    exit 1
fi

SUBNET=$(ip -4 route show dev "$INTERFACE" | grep "kernel" | awk '{print $1}' || true)
if [[ -z "$SUBNET" ]]; then
    # Fallback: Try to get subnet from IP and mask (requires ipcalc or manual calculation)
    # For now, let's just warn and exit gracefully to show the error
    echo "[!] Could not determine subnet for ${INTERFACE}. Ensure you are connected to the WiFi."
    exit 1
fi

echo "[*] Testing client isolation on ${INTERFACE} (${MY_IP}) in subnet ${SUBNET}..."

# 1. ARP Scan to find other clients (Produce XML for Go ingest)
echo "[*] Running ARP scan (nmap -vv -sn -PR)..."
(
    # Simple background telemetry for nmap
    while true; do
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 25 --status "Scanning subnet $SUBNET..."
        sleep 5
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -vv -sn -PR "$SUBNET" -oX "$OUTPUT_XML" || true
    RET=$?
else
    nmap -vv -sn -PR "$SUBNET" -oX "$OUTPUT_XML" > "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Parsing results..."
CLIENT_COUNT=$(grep "<address addr=" "$OUTPUT_XML" | grep "addrtype=\"ipv4\"" | grep -v "$MY_IP" | wc -l)
echo "[+] Discovered ${CLIENT_COUNT} other clients on the network."

if [[ $CLIENT_COUNT -gt 0 ]]; then
    echo "[!] CLIENT ISOLATION MAY BE DISABLED."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Client Isolation Disabled" \
        --severity HIGH \
        --desc "Discovered ${CLIENT_COUNT} other clients on the subnet ${SUBNET} via ARP scanning. This indicates client-to-client isolation is likely disabled." \
        --evidence "$OUTPUT_XML" \
        --rationale "Lack of client isolation allows an attacker to pivot and attack other devices directly on the same segment, facilitating lateral movement and internal discovery."
else
    echo "[+] No other clients discovered. Isolation likely enforced."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[B1] Audit Complete" \
        --severity INFO \
        --desc "No other clients were discovered on the subnet ${SUBNET} via ARP scanning. Client-to-client isolation appears to be enforced." \
        --evidence "$OUTPUT_XML" \
        --rationale "Client-to-client isolation is a critical security control for public and guest WiFi networks to prevent peer-to-peer attacks. No risks were found in this interval."
fi


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
