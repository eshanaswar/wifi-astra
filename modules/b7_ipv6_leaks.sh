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
# 🛰️ DYNAMIC TELEMETRY HEARTBEAT
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing scan..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# 1. Listen for ICMPv6 RA
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "icmp6 and (ip6[40] == 134)" || true
else
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "icmp6 and (ip6[40] == 134)" > "$LOG_FILE" 2>&1 || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true

# 2. Check current addresses
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Checking IPv6 configuration..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    ip -6 addr show dev "$INTERFACE" | tee "$STATUS_FILE" || true
else
    ip -6 addr show dev "$INTERFACE" > "$STATUS_FILE" 2>/dev/null || true
fi

# Verify
FOUND=0
if grep -q "inet6" "$STATUS_FILE"; then
    FOUND=1
    IPV6_ADDRS=$(grep "inet6" "$STATUS_FILE" | awk '{print $2}' | xargs || true)
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "IPv6 Enabled on Network" \
        --desc "The network has IPv6 enabled with addresses: $IPV6_ADDRS." \
        --severity "MEDIUM" \
        --evidence "$STATUS_FILE" \
        --rationale "IPv6 leaks can bypass IPv4-only security controls."
fi

if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    RA_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
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
exit 0
