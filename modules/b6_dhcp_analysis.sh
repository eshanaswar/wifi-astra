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
# TIMED="yes"
# DECODE="none"
# PROMPTS="managed_connect"

set -euo pipefail

#  modules/b6_dhcp_analysis.sh
#  B6: DHCP Architecture Analysis

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
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
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing DHCP discovery..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

# Start passive capture in background (always background)
timeout 30 tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "udp port 67 or udp port 68" > "$LOG_FILE" 2>&1 &
TCPDUMP_PID=$!

# Force DHCP renewal to trigger traffic
if command -v dhclient &>/dev/null; then
    dhclient -v -r "$INTERFACE" >/dev/null 2>&1 || true
    dhclient -v "$INTERFACE" >/dev/null 2>&1 || true
fi

# Active discovery
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap --script broadcast-dhcp-discover -e "$INTERFACE" | tee "$NMAP_OUT" || true
else
    timeout "$SCAN_TIME" nmap --script broadcast-dhcp-discover -e "$INTERFACE" > "$NMAP_OUT" 2>&1 || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing DHCP architecture..."
DHCP_SERVERS=$(grep "Server Identifier:" "$NMAP_OUT" 2>/dev/null | awk '{print $NF}' | sort -u || true)

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

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0

