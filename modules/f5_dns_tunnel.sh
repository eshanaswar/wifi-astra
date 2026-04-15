#!/usr/bin/env bash
# MODULE_META
# NAME="DNS Tunneling (Iodine)"
# CATEGORY="F"
# DEPS="none"
# CRITICAL="no"
# TOOLS="iodine"
# DESC="Bypass restrictive portals using DNS tunneling via iodine"
# REQS="managed_iface"
# PCAP="no"
# TIMED="yes"
# PROMPTS="tunnel_config"
# DECODE="dns"

#===============================================================================
#  modules/f5_dns_tunnel.sh
#  F5: DNS Tunneling (Golden Wrapper)
#
#  METHODOLOGY (SPEC SECTION 6.2):
#  1. Establish a DNS tunnel client connection to a remote iodine server.
#  2. Use tactical domain and password from Go brain.
#  3. Provide a virtual tunnel interface (dns0) for encapsulated traffic.
#===============================================================================

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F5"

# Tactical Selections from Go Brain
TUNNEL_DOMAIN="${TUNNEL_DOMAIN:-}"
TUNNEL_PASS="${TUNNEL_PASS:-}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

if [[ -z "$TUNNEL_DOMAIN" ]]; then
    echo "[!] Tunnel domain not specified. DNS tunneling requires a target domain."
    exit 0
fi

echo -e "${C_PROMPT}[*]${C_RESET} Attempting DNS tunnel via ${C_VAR}${TUNNEL_DOMAIN}${C_RESET}..."

LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_iodine.log"

# Execution
cleanup() {
    echo -e "${C_PROMPT}[*]${C_RESET} Tearing down DNS Tunneling environment..."
    [[ -n "${IODINE_PID:-}" ]] && kill "$IODINE_PID" 2>/dev/null || true
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Start dynamic telemetry heartbeat
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PERCENT -gt 90 ]] && PERCENT=90
        STATUS="Tunneling via $TUNNEL_DOMAIN... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED += 5))
    done
) &
TEL_PID=$!

TUNNEL_SUCCESS=0

if command -v iodine &>/dev/null; then
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        # FOREGROUND
        timeout "$SCAN_TIME" iodine -f -P "$TUNNEL_PASS" "$TUNNEL_DOMAIN" 2>&1 | tee "$LOG_FILE" || true
    else
        # BACKGROUND
        iodine -f -P "$TUNNEL_PASS" "$TUNNEL_DOMAIN" > "$LOG_FILE" 2>&1 &
        IODINE_PID=$!
        wait "$IODINE_PID" 2>/dev/null || true
    fi

    # Check if the dns0 tunnel interface was created (iodine creates it on success)
    if ip addr show dns0 >/dev/null 2>&1; then
        TUNNEL_SUCCESS=1
    fi

    cleanup
    trap - EXIT

    if [[ $TUNNEL_SUCCESS -eq 1 ]]; then
        echo -e "[!] ${C_BOLD}SUCCESS: DNS TUNNEL ESTABLISHED via dns0!${C_RESET}"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "DNS Tunneling Successful" \
            --severity HIGH \
            --desc "Established iodine DNS tunnel via $TUNNEL_DOMAIN. Virtual interface dns0 is up — traffic can be encapsulated in DNS queries to bypass the captive portal/firewall." \
            --target "$TUNNEL_DOMAIN" \
            --evidence "$LOG_FILE" \
            --rationale "DNS tunneling allows bypassing restrictive captive portals and firewalls by encapsulating IP traffic in DNS queries. Outbound UDP/53 is allowed on almost all networks to enable name resolution."
    else
        echo -e "[+] Tunnel attempt complete — dns0 interface not created (tunnel did not establish)."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[F5] Audit Complete" \
            --severity INFO \
            --desc "DNS tunneling via iodine attempted to $TUNNEL_DOMAIN — tunnel did not establish during the test window." \
            --target "$TUNNEL_DOMAIN" \
            --evidence "$LOG_FILE" \
            --rationale "DNS tunnel failure may indicate DNS egress filtering, rate limiting, or that the iodine server is unreachable. Check iodine log for server response details."
    fi
else
    cleanup
    trap - EXIT
    echo "[!] iodine not found — DNS tunneling test skipped."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F5] Audit Incomplete — iodine Missing" \
        --severity INFO \
        --desc "DNS tunneling test could not run because iodine is not installed." \
        --target "$TUNNEL_DOMAIN" \
        --evidence "$LOG_FILE" \
        --rationale "Install iodine (Kali: apt install iodine) and configure an iodine server on a VPS with an NS record pointing to it."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
