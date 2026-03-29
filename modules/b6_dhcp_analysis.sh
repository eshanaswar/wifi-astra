#!/usr/bin/env bash
# MODULE_META
# NAME="DHCP Architecture Analysis"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap,tcpdump"
# DESC="Analyze DHCP configuration and check for rogue DHCP servers"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="none"

set -euo pipefail

#===============================================================================
#  modules/b6_dhcp_analysis.sh
#  B6: DHCP Architecture Analysis
#===============================================================================

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B6"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_dhcp.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"
NMAP_OUT="${EVIDENCE_PREFIX}_nmap_dhcp.txt"

echo "[*] [$TC_ID] Identifying DHCP architecture on ${INTERFACE}..."

# Identify & Target
# Start passive capture
timeout 30 tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "udp port 67 or udp port 68" > "$LOG_FILE" 2>&1 &
TCPDUMP_PID=$!

# Force DHCP renewal to trigger traffic
if command -v dhclient &>/dev/null; then
    dhclient -v -r "$INTERFACE" 2>/dev/null || true
    dhclient -v "$INTERFACE" 2>/dev/null || true
fi

# Active discovery
nmap --script broadcast-dhcp-discover -e "$INTERFACE" > "$NMAP_OUT" 2>/dev/null || true

# Verify
DHCP_SERVERS=$(grep "Server Identifier:" "$NMAP_OUT" | awk '{print $NF}' | sort -u || true)

if [[ -n "$DHCP_SERVERS" ]]; then
    while read -r server; do
        [[ -z "$server" ]] && continue
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "DHCP Server Discovered" \
            --desc "Identified active DHCP server at $server." \
            --severity "INFO" \
            --evidence "$NMAP_OUT" \
            --rationale "DHCP analysis is critical for mapping network topology."
    done <<< "$DHCP_SERVERS"
else
    echo "[+] No DHCP servers detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No DHCP servers were discovered during the scan." \
        --severity "INFO" \
        --evidence "$NMAP_OUT" \
        --rationale "Lack of DHCP activity might indicate a static-only or restricted network segment."
fi

# Cleanup
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
exit 0

