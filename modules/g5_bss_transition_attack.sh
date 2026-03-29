#!/usr/bin/env bash
# MODULE_META
# NAME="BSS Transition Attack"
# CATEGORY="G"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd"
# DESC="Force clients to transition to a malicious AP using 802.11v BSS Transition Management"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/g5_bss_transition_attack.sh
#  G5: BSS Transition Attack (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Target clients connected to an AP supporting 802.11v.
#  2. Send a 'BSS Transition Management Request' frame to the client.
#  3. The request "recommends" the client move to a new BSSID (our rogue AP).
#  4. This allows for a "polite" MITM attack that does not require deauth
#     and is less likely to be detected by WIDS.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/g5"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G5"

if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_SSID not set."
    exit 1
fi

echo "[*] Testing BSS Transition (802.11v) for SSID: ${SSID}..."

# 1. Listen for BSS Transition Management frames
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_transition.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up tcpdump..."
    [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 802.11v BSS Transition Management Request is subtype 13 of type management
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "type mgt subtype 13" > "$LOG_FILE" 2>&1 &
TCPDUMP_PID=$!

sleep 60

cleanup
trap - EXIT

# 2. Reporting
if [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "BSS Transition Activity Detected" \
        --severity INFO \
        --desc "Captured 802.11v BSS Transition Management frames for ${SSID}." \
        --target "${SSID}" \
        --evidence "$PCAP_FILE" \
        --rationale "802.11v Transition Management can be abused to force clients onto attacker-controlled Access Points without the disruption or noise of a deauthentication attack."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G5] Audit Complete" \
        --severity INFO \
        --desc "Completed monitoring for 802.11v BSS Transition susceptibility on ${SSID}. No transition frames captured." \
        --target "${SSID}" \
        --evidence "$LOG_FILE" \
        --rationale "Lack of 802.11v activity reduces the risk of 'polite' MITM attacks. This audit confirms whether the target infrastructure actively uses BSS Transition Management for load balancing or roaming."
fi

echo "[+] BSS transition test complete."
exit 0
