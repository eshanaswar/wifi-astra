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
# 
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

# 1. Start Telemetry in Background
(
    ELAPSED=0
    while true; do
        PCT=$(( 10 + (ELAPSED % 85) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing RFC1918 egress audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (fping + nmap)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    # shellcheck disable=SC2086 # $TARGETS is a newline-separated list of IP ranges; word-splitting is intentional
    fping -a -t 500 $TARGETS 2>&1 | tee "$REACHABLE_FILE" || true
    REACHABLE=$(cat "$REACHABLE_FILE" | grep -E "[0-9.]+" | xargs || true)
    if [[ -n "$REACHABLE" ]]; then
        # shellcheck disable=SC2086 # $REACHABLE is a space-separated list of live IPs; word-splitting is intentional
        nmap -Pn -p 22,80,443,445,3389 $REACHABLE -oX "$OUTPUT_XML" 2>&1 | tee "$NMAP_LOG" || true
    fi
    RET=$?
else
    # Background Execution
    (
        # shellcheck disable=SC2086 # $TARGETS is a newline-separated list of IP ranges; word-splitting is intentional
        fping -a -t 500 $TARGETS > "$REACHABLE_FILE" 2>&1 || true
        REACHABLE=$(cat "$REACHABLE_FILE" | grep -E "[0-9.]+" | xargs || true)
        if [[ -n "$REACHABLE" ]]; then
            # shellcheck disable=SC2086 # $REACHABLE is a space-separated list of live IPs; word-splitting is intentional
            nmap -Pn -p 22,80,443,445,3389 $REACHABLE -oX "$OUTPUT_XML" > "$NMAP_LOG" 2>&1 || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Verify
REACHABLE_COUNT=$(cat "$REACHABLE_FILE" | grep -E "[0-9.]+" | wc -l || echo 0)
if [[ "$REACHABLE_COUNT" -gt 0 ]]; then
    REACHABLE_HOSTS=$(cat "$REACHABLE_FILE" | grep -E "[0-9.]+" | xargs || true)
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal Network Reachability Detected" \
        --desc "Guest network allows access to RFC1918 addresses: ${REACHABLE_HOSTS}" \
        --severity "HIGH" \
        --evidence "$OUTPUT_XML" \
        --rationale "Failure to segment guest WiFi from internal networks allows pivoting and direct attacks on internal assets."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No common RFC1918 gateways were reachable." \
        --severity "INFO" \
        --evidence "$REACHABLE_FILE" \
        --rationale "Effective segmentation is a critical security control."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

exit $RET
