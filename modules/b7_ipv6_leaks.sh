#!/usr/bin/env bash
# MODULE_META
# NAME="IPv6 SLAAC & RA Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Listen for corporate IPv6 router advertisements bleeding into target VLAN"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

#  modules/b7_ipv6_leaks.sh
#  B7: IPv6 Leaks

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B7"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_ipv6.pcap"
STATUS_FILE="${EVIDENCE_PREFIX}_ipv6_status.txt"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying IPv6 leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# Identify & Target
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing ICMPv6 RA frames..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "icmp6 and (ip6[40] == 134)" || true
else
    # Run with redirection
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "icmp6 and (ip6[40] == 134)" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait "$TOOL_PID" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Checking IPv6 configuration..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    ip -6 addr show dev "$INTERFACE" | tee "$STATUS_FILE" || true
else
    ip -6 addr show dev "$INTERFACE" > "$STATUS_FILE" 2>/dev/null || true
fi

# Verify — only flag global unicast IPv6 addresses (not link-local fe80:: or loopback ::1)
FOUND=0
if [[ -f "$STATUS_FILE" ]]; then
    # Exclude fe80:: (link-local) and ::1 (loopback) — these are on every interface by default
    GLOBAL_IPV6=$(grep "inet6" "$STATUS_FILE" | awk '{print $2}' | grep -v "^fe80:" | grep -v "^::1" || true)
    if [[ -n "$GLOBAL_IPV6" ]]; then
        FOUND=1
        IPV6_ADDRS=$(echo "$GLOBAL_IPV6" | xargs)
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "Routable IPv6 Address on Wireless Segment" \
            --desc "Interface ${INTERFACE} has global IPv6 address(es): ${IPV6_ADDRS}. These may bypass IPv4-only firewall rules." \
            --severity "MEDIUM" \
            --evidence "$STATUS_FILE" \
            --rationale "Routable IPv6 addresses on wireless segments can bypass IPv4-only security controls and filtering rules."
    fi
fi

if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    RA_COUNT=$(tshark -r "$PCAP_FILE" -T fields -e frame.number 2>/dev/null | wc -l)
    if [[ $RA_COUNT -gt 0 ]]; then
        FOUND=1
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "IPv6 Router Advertisements Detected" \
            --desc "Detected $RA_COUNT IPv6 Router Advertisements." \
            --severity "MEDIUM" \
            --evidence "$PCAP_FILE" \
            --rationale "Active IPv6 routing often lacks same security rigor as IPv4."
    fi
fi

# Check for DHCPv6 traffic (UDP 546/547) — indicates server-managed IPv6 addressing
DHCPV6_PCAP="${EVIDENCE_PREFIX}_dhcpv6.pcap"
DHCPV6_LOG="${EVIDENCE_DIR}/${TC_ID}_dhcpv6.log"
echo "[*] Checking for DHCPv6 traffic on UDP 546/547..."
timeout 15 tcpdump -i "$INTERFACE" -w "$DHCPV6_PCAP" "udp port 546 or udp port 547" > "$DHCPV6_LOG" 2>&1 &
DHCPV6_PID=$!
wait "$DHCPV6_PID" 2>/dev/null || true

if command -v tshark &>/dev/null && [[ -f "$DHCPV6_PCAP" && -s "$DHCPV6_PCAP" ]]; then
    DHCPV6_COUNT=$(tshark -r "$DHCPV6_PCAP" -T fields -e frame.number 2>/dev/null | wc -l)
    if [[ $DHCPV6_COUNT -gt 0 ]]; then
        FOUND=1
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "DHCPv6 Traffic Detected" \
            --desc "Detected ${DHCPV6_COUNT} DHCPv6 packet(s) on UDP 546/547. A DHCPv6 server is providing IPv6 addresses on this segment." \
            --severity "MEDIUM" \
            --evidence "$DHCPV6_PCAP" \
            --rationale "DHCPv6 traffic confirms server-managed IPv6 addressing on the segment. A rogue DHCPv6 server can supply attacker-controlled DNS (option 23) bypassing IPv4-only controls."
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No IPv6 leaks detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No active IPv6 addresses or Router Advertisements were detected." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Disabling IPv6 on untrusted segments reduces attack surface."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
