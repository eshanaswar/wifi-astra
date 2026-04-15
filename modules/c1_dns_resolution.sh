#!/usr/bin/env bash
# MODULE_META
# NAME="Internal DNS Resolution"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="dig,host"
# DESC="Test if target WiFi DNS resolves internal hostnames and allows zone transfer"
# REQS="managed_iface,dns_server"
# PCAP="no"
# DECODE="none"
# PROMPTS="managed_connect"

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

# Dynamic Intelligence: Use DNS assigned by the target WiFi DHCP, not system resolv.conf
# resolv.conf may reflect a VPN or management interface — we specifically want the
# DNS the AP gave us via DHCP so we test what internal resolvers are reachable.
if [[ -z "$DNS_SERVER" ]]; then
    # Try DHCP lease files for the correct interface
    DNS_SERVER=$(grep -h "domain-name-servers" \
        /var/lib/dhcp/dhclient."${INTERFACE}".leases \
        /var/lib/dhclient/dhclient--"${INTERFACE}".lease 2>/dev/null \
        | tail -1 | awk -F'[ ;]' '{print $3}' || true)
fi

if [[ -z "$DNS_SERVER" ]]; then
    # Fall back to resolv.conf but prefer non-loopback entries
    DNS_SERVER=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | grep -v "127\." | head -1 | awk '{print $2}' || true)
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

echo "[*] [$TC_ID] Probing internal DNS via ${DNS_SERVER}..."

# Bounded telemetry (max 120s)
MAX_TEL=120
(
    ELAPSED=0
    while [[ $ELAPSED -lt $MAX_TEL ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / MAX_TEL) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Probing internal hostnames & AXFR..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# Dynamic Targets: Use search suffix from resolv.conf if available
SEARCH_DOMAINS=$(grep "^search" /etc/resolv.conf 2>/dev/null | cut -d' ' -f2- || true)
HOSTNAMES=("internal" "dc01" "dc" "mail" "vpn" "wifi" "proxy" "intranet" "portal" "git" "jira" "ldap" "ad")

# Run dig probes (always write to file regardless of window mode)
for host in "${HOSTNAMES[@]}"; do
    dig +short +time=2 "@$DNS_SERVER" "$host" >> "$RESOLUTION_FILE" 2>/dev/null || true
    for suffix in $SEARCH_DOMAINS; do
        dig +short +time=2 "@$DNS_SERVER" "${host}.${suffix}" >> "$RESOLUTION_FILE" 2>/dev/null || true
    done
done

# Attempt AXFR for each search domain
for dom in $SEARCH_DOMAINS; do
    dig +time=5 "@$DNS_SERVER" "$dom" AXFR >> "$AXFR_FILE" 2>/dev/null || true
done

# Display results if in window
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo "[*] Resolution results:"
    cat "$RESOLUTION_FILE" 2>/dev/null || true
fi

kill $TEL_PID 2>/dev/null || true

# Verify Findings

# Count lines that look like IP addresses (strict pattern)
RESOLVED_COUNT=$(grep -cE "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "$RESOLUTION_FILE" 2>/dev/null || echo 0)

FOUND=0
if [[ "$RESOLVED_COUNT" -gt 0 ]]; then
    FOUND=1
    RESOLVED_IPS=$(grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" "$RESOLUTION_FILE" | sort -u | xargs)
    echo "[!] Resolved ${RESOLVED_COUNT} internal hostname(s) → ${RESOLVED_IPS}"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "Internal DNS Resolution via Wireless DNS" \
        --desc "Resolved ${RESOLVED_COUNT} internal hostname(s) via ${DNS_SERVER}: ${RESOLVED_IPS}. The wireless segment has access to an internal DNS resolver." \
        --severity "HIGH" \
        --evidence "$RESOLUTION_FILE" \
        --rationale "Access to internal DNS reveals infrastructure details and enables targeted pivoting against resolved hosts."
fi

# AXFR: a successful zone transfer has records beyond the SOA (ANSWER section count > 1)
if [[ -s "$AXFR_FILE" ]]; then
    # dig AXFR output shows ";; ANSWER SECTION:" with the record count in the header
    # A refused/failed transfer returns 0 answers. A successful one has many records.
    AXFR_RECORDS=$(grep -cE "^[^;].*IN\s+(A|AAAA|MX|NS|CNAME|PTR|TXT|SRV)" "$AXFR_FILE" 2>/dev/null || echo 0)
    if [[ "$AXFR_RECORDS" -gt 2 ]]; then
        FOUND=1
        echo "[!] CRITICAL: DNS Zone Transfer (AXFR) succeeded — ${AXFR_RECORDS} records exposed!"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "DNS Zone Transfer (AXFR) Allowed" \
            --desc "Successfully transferred ${AXFR_RECORDS} DNS records from ${DNS_SERVER}. The zone transfer reveals all internal hostnames and IP addresses." \
            --severity "CRITICAL" \
            --evidence "$AXFR_FILE" \
            --rationale "AXFR exposes the complete internal DNS zone, providing a full map of infrastructure hostnames and IPs — a pentest goldmine for targeting."
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No internal DNS resolution or AXFR."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "DNS server ${DNS_SERVER}: no internal hostnames resolved, AXFR refused." \
        --severity "INFO" \
        --evidence "$RESOLUTION_FILE" \
        --rationale "Restricting DNS to external-only resolution is a key control for guest/wireless network isolation."
fi

# FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
