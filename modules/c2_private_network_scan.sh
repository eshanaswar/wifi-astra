#!/usr/bin/env bash
# MODULE_META
# NAME="Private Network Scan"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="yes"
# TOOLS="fping,nmap"
# DESC="Scan RFC1918 ranges for reachable corporate hosts from target WiFi"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# TIMED="yes"
# DECODE="none"
# PROMPTS="managed_connect"

#  modules/c2_private_network_scan.sh
#  C2: Private Network Egress Scan

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

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
NMAP_LOG="${EVIDENCE_PREFIX}_nmap.log"

# Dynamic Intelligence: Determine local subnet and common RFC1918 gateways
LOCAL_GW=$(ip -4 route show dev "$INTERFACE" | awk '/default/{print $3}' | head -1 || true)
LOCAL_NET=$(ip -4 route show dev "$INTERFACE" | grep "kernel" | awk '{print $1}' || true)

echo "[*] [$TC_ID] Identifying egress to RFC1918 networks from ${INTERFACE}..."

# Dynamic Targets: Test local gateway, and common gateways in other RFC1918 ranges
RANGES=("$LOCAL_GW" "10.0.0.1" "10.1.1.1" "172.16.0.1" "192.168.0.1" "192.168.1.1" "192.168.10.1" "192.168.100.1")
# Add the .1 address of the current local network if not already present
if [[ -n "$LOCAL_NET" ]]; then
    NET_PREFIX=$(echo "$LOCAL_NET" | cut -d. -f1-3)
    RANGES+=("${NET_PREFIX}.1")
fi

# Unique sorted list
TARGETS=$(printf "%s\n" "${RANGES[@]}" | sort -u | grep -v "^$")

echo "[*] Testing reachability for gateways: $(echo "$TARGETS" | xargs)"

# 1. Start Telemetry in Background (bounded)
MAX_TEL=$((SCAN_TIME + 60))
(
    ELAPSED=0
    while [[ $ELAPSED -lt $MAX_TEL ]]; do
        PCT=$(( 10 + (ELAPSED * 75 / MAX_TEL) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing RFC1918 egress audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (fping + nmap)
# fping -a outputs only alive hosts to stdout; errors/unreachable go to stderr (discarded).
# Mixing 2>&1 would pollute REACHABLE_FILE with error messages that match IP regex.
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # shellcheck disable=SC2086 # $TARGETS is a newline-separated list; word-splitting is intentional
    fping -a -t 500 $TARGETS 2>/dev/null | tee "$REACHABLE_FILE" || true
    # shellcheck disable=SC2086
    REACHABLE=$(grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "$REACHABLE_FILE" | xargs || true)
    if [[ -n "$REACHABLE" ]]; then
        # shellcheck disable=SC2086
        timeout --foreground "$SCAN_TIME" nmap -Pn -p 22,80,443,445,3389 $REACHABLE -oX "$OUTPUT_XML" 2>&1 | tee "$NMAP_LOG" || true
    fi
else
    (
        # shellcheck disable=SC2086
        fping -a -t 500 $TARGETS 2>/dev/null > "$REACHABLE_FILE" || true
        # shellcheck disable=SC2086
        REACHABLE=$(grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "$REACHABLE_FILE" | xargs || true)
        if [[ -n "$REACHABLE" ]]; then
            # shellcheck disable=SC2086
            timeout "$SCAN_TIME" nmap -Pn -p 22,80,443,445,3389 $REACHABLE -oX "$OUTPUT_XML" > "$NMAP_LOG" 2>&1 || true
        fi
    ) &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Verify — exclude local gateway (always reachable by design, not a segmentation violation)
# Segmentation findings are non-gateway RFC1918 hosts that answer from this segment
VIOLATIONS=$(grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "$REACHABLE_FILE" \
    | grep -v "^${LOCAL_GW}$" || true)
VIOLATION_COUNT=$(echo "$VIOLATIONS" | grep -c "." 2>/dev/null || echo 0)
[[ -z "$VIOLATIONS" ]] && VIOLATION_COUNT=0

FOUND=0
if [[ "$VIOLATION_COUNT" -gt 0 ]]; then
    FOUND=1
    VIOLATION_HOSTS=$(echo "$VIOLATIONS" | xargs)
    echo "[!] RFC1918 segmentation violation — ${VIOLATION_COUNT} host(s) reachable: ${VIOLATION_HOSTS}"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal Network Reachability Detected" \
        --desc "Guest WiFi can reach non-local RFC1918 hosts: ${VIOLATION_HOSTS}. ${VIOLATION_COUNT} host(s) responded across segment boundary." \
        --severity "HIGH" \
        --evidence "$OUTPUT_XML" \
        --rationale "Failure to segment guest WiFi from internal networks allows pivoting and direct attacks on internal assets."
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No cross-segment RFC1918 reachability detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No RFC1918 hosts beyond the local gateway were reachable from the guest segment." \
        --severity "INFO" \
        --evidence "$REACHABLE_FILE" \
        --rationale "Effective segmentation is a critical security control."
fi

# FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
