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
# TIMED="yes"
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
OUTPUT_XML="${EVIDENCE_DIR}/b1_results.xml"
TC_ID="B1"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

# Get current IP, Subnet, and Gateway
MY_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
if [[ -z "$MY_IP" ]]; then
    echo "[!] No IP address on ${INTERFACE}. Connect to WiFi first."
    exit 1
fi

SUBNET=$(ip -4 route show dev "$INTERFACE" | awk '/kernel/{print $1}' | head -1 || true)
if [[ -z "$SUBNET" ]]; then
    echo "[!] Could not determine subnet for ${INTERFACE}. Ensure you are connected to the WiFi."
    exit 1
fi

# Exclude the default gateway — it is always reachable via ARP regardless of client isolation
GATEWAY_IP=$(ip -4 route show dev "$INTERFACE" | awk '/default/{print $3}' | head -1 || true)

echo "[*] Testing client isolation on ${INTERFACE} (${MY_IP}) in subnet ${SUBNET}..."

# 1. ARP Scan to find other clients
echo "[*] Running ARP scan (nmap -sn -PR)..."
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Scanning subnet ${SUBNET} for peers (ARP)..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -sn -PR "$SUBNET" -oX "$OUTPUT_XML" || true
else
    timeout "$SCAN_TIME" nmap -sn -PR "$SUBNET" -oX "$OUTPUT_XML" > "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Parsing results..."
CLIENT_COUNT=0
if [[ -f "$OUTPUT_XML" ]]; then
    CLIENT_COUNT=$(grep -c "addrtype=\"ipv4\"" "$OUTPUT_XML" 2>/dev/null || echo 0)
    # Subtract our own IP (always reachable, not a peer)
    if grep -q "\"${MY_IP}\"" "$OUTPUT_XML" 2>/dev/null; then
        CLIENT_COUNT=$(( CLIENT_COUNT - 1 ))
    fi
    # Subtract the gateway IP — the AP always forwards traffic to the gateway regardless
    # of client isolation policy. Finding the gateway via ARP is not a finding.
    if [[ -n "$GATEWAY_IP" ]] && grep -q "\"${GATEWAY_IP}\"" "$OUTPUT_XML" 2>/dev/null; then
        CLIENT_COUNT=$(( CLIENT_COUNT - 1 ))
    fi
    [[ $CLIENT_COUNT -lt 0 ]] && CLIENT_COUNT=0
fi
echo "[+] Discovered ${CLIENT_COUNT} other clients on the network."

if [[ $CLIENT_COUNT -gt 0 ]]; then
    # ARP responses alone are not enough to confirm isolation failure — some APs use proxy-ARP,
    # which makes remote clients appear visible via ARP even when L2 isolation blocks traffic.
    # Confirm with ICMP to verify actual traffic can reach the peer.
    echo "[!] ARP visible peers detected. Confirming with ICMP ping to rule out proxy-ARP..."
    CONFIRMED_REACHABLE=0
    REACHABLE_HOSTS=()
    while read -r peer_ip; do
        [[ -z "$peer_ip" ]] && continue
        [[ "$peer_ip" == "$MY_IP" ]] && continue
        [[ "$peer_ip" == "$GATEWAY_IP" ]] && continue
        if ping -c 2 -W 1 "$peer_ip" >/dev/null 2>&1; then
            echo "[!] ICMP REACHABLE: $peer_ip — client isolation CONFIRMED BROKEN"
            CONFIRMED_REACHABLE=$(( CONFIRMED_REACHABLE + 1 ))
            REACHABLE_HOSTS+=("$peer_ip")
        else
            echo "[+] ICMP failed to $peer_ip — may be proxy-ARP only (isolation may be enforced)"
        fi
    done < <(grep "addrtype=\"ipv4\"" "$OUTPUT_XML" 2>/dev/null | sed 's/.*addr="//;s/".*//')

    if [[ $CONFIRMED_REACHABLE -gt 0 ]]; then
        REACHABLE_LIST="${REACHABLE_HOSTS[*]}"
        echo "[!] CLIENT ISOLATION DISABLED — ${CONFIRMED_REACHABLE} peer(s) directly reachable."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Client Isolation Disabled" \
            --severity HIGH \
            --desc "ICMP confirmed ${CONFIRMED_REACHABLE} peer client(s) directly reachable on ${SUBNET}: ${REACHABLE_LIST}. Both ARP and ICMP succeeded, confirming L2/L3 isolation is not enforced." \
            --evidence "$OUTPUT_XML" \
            --rationale "Lack of client isolation allows an attacker to pivot and attack other devices directly on the same segment, facilitating lateral movement and internal discovery."
    else
        echo "[+] ARP saw peers but ICMP was blocked. Proxy-ARP present but isolation enforced."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[B1] Audit Complete" \
            --severity INFO \
            --desc "ARP discovered ${CLIENT_COUNT} client(s) on ${SUBNET} but ICMP ping to all was blocked — consistent with proxy-ARP with client isolation enforced." \
            --evidence "$OUTPUT_XML" \
            --rationale "Client-to-client isolation is a critical security control for public and guest WiFi networks to prevent peer-to-peer attacks."
    fi
else
    echo "[+] No other clients discovered. Isolation likely enforced."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[B1] Audit Complete" \
        --severity INFO \
        --desc "No other clients were discovered on subnet ${SUBNET} via ARP scanning. Client-to-client isolation appears to be enforced." \
        --evidence "$OUTPUT_XML" \
        --rationale "Client-to-client isolation is a critical security control for public and guest WiFi networks to prevent peer-to-peer attacks."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
