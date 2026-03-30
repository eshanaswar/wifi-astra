#!/usr/bin/env bash
# MODULE_META
# NAME="Internal DNS Resolution"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="dig,host"
# DESC="Test if target WiFi DNS resolves internal hostnames"
# REQS="managed_iface,dns_server"
# PCAP="no"
# DECODE="none"

#  modules/c1_dns_resolution.sh
#  C1: Internal DNS Resolution

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
DNS_SERVER="${DNS_SERVER:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C1"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

# Dynamic Intelligence: Identify DNS server if not provided
if [[ -z "$DNS_SERVER" ]]; then
    DNS_SERVER=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}' || true)
fi

if [[ -z "$DNS_SERVER" ]]; then
    echo "[!] DNS_SERVER not detected. Falling back to gateway."
    DNS_SERVER=$(ip -4 route show dev "$INTERFACE" | awk '/default/{print $3}' | head -1 || true)
fi

if [[ -z "$DNS_SERVER" ]]; then
    echo "[!] Could not identify target DNS server."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
RESOLUTION_FILE="${EVIDENCE_PREFIX}_resolution.txt"
AXFR_FILE="${EVIDENCE_PREFIX}_axfr.txt"

echo "[*] [$TC_ID] Identifying internal DNS resolution via ${DNS_SERVER}..."

# 🛰️ DYNAMIC TELEMETRY HEARTBEAT
(
    ELAPSED=0
    while true; do
        # Incrementally move from 10% to 60% during discovery
        PCT=$(( 10 + (ELAPSED % 50) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Probing internal hostnames..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# Dynamic Targets: Use the actual domain search suffix if available
SEARCH_DOMAINS=$(grep "^search" /etc/resolv.conf 2>/dev/null | cut -d' ' -f2- || true)
HOSTNAMES=("internal" "dc01" "mail" "vpn" "wifi" "proxy" "intranet" "portal" "git" "jira")

for host in "${HOSTNAMES[@]}"; do
    # Try raw host
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        dig +short "@$DNS_SERVER" "$host" 2>&1 | tee -a "$RESOLUTION_FILE" || true
    else
        dig +short "@$DNS_SERVER" "$host" 2>/dev/null >> "$RESOLUTION_FILE" || true
    fi
    # Try with search suffixes
    for suffix in $SEARCH_DOMAINS; do
        if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
            dig +short "@$DNS_SERVER" "${host}.${suffix}" 2>&1 | tee -a "$RESOLUTION_FILE" || true
        else
            dig +short "@$DNS_SERVER" "${host}.${suffix}" 2>/dev/null >> "$RESOLUTION_FILE" || true
        fi
    done
done

kill "$TELEMETRY_PID" 2>/dev/null || true

# Verify
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 60 --status "Checking resolved hosts..."
FOUND=0
RESOLVED_COUNT=$(grep -v "NOT FOUND" "$RESOLUTION_FILE" 2>/dev/null | grep -E "[0-9.]+" | wc -l || echo 0)

if [[ "$RESOLVED_COUNT" -gt 0 ]]; then
    FOUND=1
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal DNS Info Leak" \
        --desc "Resolved $RESOLVED_COUNT internal hostnames via $DNS_SERVER." \
        --severity "HIGH" \
        --evidence "$RESOLUTION_FILE" \
        --rationale "Access to internal DNS reveals infrastructure details and facilitates pivoting."
fi

# AXFR Attempt (Dynamic)
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 80 --status "Attempting DNS zone transfers..."
(
    ELAPSED=0
    while true; do
        PCT=$(( 80 + (ELAPSED % 15) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Attempting DNS zone transfers..."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

for dom in $SEARCH_DOMAINS; do
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        dig "@$DNS_SERVER" "$dom" AXFR 2>&1 | tee -a "$AXFR_FILE" || true
    else
        dig "@$DNS_SERVER" "$dom" AXFR >> "$AXFR_FILE" 2>/dev/null || true
    fi
done

kill "$TELEMETRY_PID" 2>/dev/null || true

if [[ -s "$AXFR_FILE" ]]; then
    if grep -q "SOA" "$AXFR_FILE"; then
        FOUND=1
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "DNS Zone Transfer (AXFR) Possible" \
            --desc "Successfully performed AXFR from $DNS_SERVER." \
            --severity "CRITICAL" \
            --evidence "$AXFR_FILE" \
            --rationale "AXFR exposes all internal hostnames and IP addresses, providing a complete map of the internal infrastructure."
    fi
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 95 --status "Finalizing DNS audit..."
if [[ $FOUND -eq 0 ]]; then
    echo "[+] No DNS leaks detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No internal hostnames resolved and AXFR attempts failed." \
        --severity "INFO" \
        --evidence "$RESOLUTION_FILE" \
        --rationale "Restricting DNS queries is key for network isolation."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Cleanup
exit 0
