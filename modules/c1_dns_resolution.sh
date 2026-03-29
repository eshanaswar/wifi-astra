#!/usr/bin/env bash
<<<<<<< HEAD
set -euo pipefail
=======
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
>>>>>>> feature/smart-tactical-modernization

#===============================================================================
#  modules/c1_dns_resolution.sh
#  C1: Internal DNS Resolution
#===============================================================================

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

if [[ -z "$DNS_SERVER" ]]; then
    DNS_SERVER=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}' || true)
fi

if [[ -z "$DNS_SERVER" ]]; then
    echo "[!] DNS_SERVER not detected."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
RESOLUTION_FILE="${EVIDENCE_PREFIX}_resolution.txt"
AXFR_FILE="${EVIDENCE_PREFIX}_axfr.txt"

echo "[*] [$TC_ID] Identifying internal DNS resolution via ${DNS_SERVER}..."

# Identify & Target
HOSTNAMES=("internal.corp" "dc01.corp" "mail.corp" "vpn.corp" "wifi.corp" "proxy.corp" "intranet" "portal" "git" "jira")
for host in "${HOSTNAMES[@]}"; do
    dig +short "@$DNS_SERVER" "$host" 2>/dev/null >> "$RESOLUTION_FILE" || true
done

# Verify
FOUND=0
RESOLVED_COUNT=$(grep -v "NOT FOUND" "$RESOLUTION_FILE" 2>/dev/null | wc -l || echo 0)

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
        --rationale "Access to internal DNS reveals infrastructure details."
fi

# AXFR Attempt
domains=("corp" "internal" "local" "guest.corp")
for dom in "${domains[@]}"; do
    dig "@$DNS_SERVER" "$dom" AXFR >> "$AXFR_FILE" 2>/dev/null || true
done

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
            --rationale "AXFR exposes all internal hostnames and IP addresses."
    fi
fi

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

# Cleanup
exit 0

