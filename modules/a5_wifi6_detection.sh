#!/usr/bin/env bash
# MODULE_META
# NAME="Wi-Fi 6 Environment Detection"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="tshark,iw"
# DESC="Detect 802.11ax (Wi-Fi 6/6E) capabilities: BSS Coloring, OFDMA, TWT, MU-MIMO"
# REQS="monitor_iface"
# PCAP="no"
# TIMED="yes"
# PROMPTS=""
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a5_wifi6_detection.sh
#  A5: Wi-Fi 6 Environment Detection
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-30}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
TC_ID="A5"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

# Color variables
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
# shellcheck disable=SC2034
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

mkdir -p "${EVIDENCE_DIR}"

if [[ -z "${INTERFACE}" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Wi-Fi 6 beacon scan on ${C_VAR}${INTERFACE}${C_RESET} for ${C_VAR}${SCAN_TIME}s${C_RESET}..."

# Telemetry heartbeat
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "Capturing Wi-Fi 6 beacons... ($(( SCAN_TIME - ELAPSED ))s left)"
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

# 1. Passive beacon capture with tshark - HE (802.11ax) fields
timeout "${SCAN_TIME}" tshark -i "${INTERFACE}" -f "type mgt subtype beacon" \
    -T fields \
    -e wlan.ssid \
    -e wlan.bssid \
    -e wlan.he.operation.bss_color \
    -e wlan.he.mac_cap.ofdma_ra \
    -e wlan.he.mac_cap.twt_req \
    -e wlan.he.mac_cap.dl_mu_mimo \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f \
    2>/dev/null > "${EVIDENCE_DIR}/A5_raw.csv" || true

kill "${TELEMETRY_PID}" 2>/dev/null || true

# 2. Count total beacons (subtract header line)
TOTAL_LINES=0
if [[ -f "${EVIDENCE_DIR}/A5_raw.csv" ]]; then
    TOTAL_LINES=$(( $(wc -l < "${EVIDENCE_DIR}/A5_raw.csv") - 1 ))
    [[ "${TOTAL_LINES}" -lt 0 ]] && TOTAL_LINES=0
fi

# 3. Count Wi-Fi 6 beacons: lines where he.operation.bss_color (col 3) is non-empty
WIFI6_COUNT=0
if [[ -f "${EVIDENCE_DIR}/A5_raw.csv" ]]; then
    WIFI6_COUNT=$(awk -F',' 'NR>1 && $3!="\"\"" && $3!="" {count++} END {print count+0}' "${EVIDENCE_DIR}/A5_raw.csv")
fi

# 4. Check 6GHz adapter support
SUPPORTS_6GHZ=false
if iw phy 2>/dev/null | grep -qE "6[0-9]{3} MHz"; then
    SUPPORTS_6GHZ=true
fi

# 5. Determine wifi6_present
WIFI6_PRESENT=false
[[ "${WIFI6_COUNT}" -gt 0 ]] && WIFI6_PRESENT=true

# 6. Write environment JSON
printf '{
  "tc_id": "%s",
  "interface": "%s",
  "scan_duration_sec": %s,
  "adapter_6ghz_support": %s,
  "beacons_captured": %s,
  "wifi6_beacons": %s,
  "raw_csv": "%s"
}\n' \
    "${TC_ID}" \
    "${INTERFACE}" \
    "${SCAN_TIME}" \
    "${SUPPORTS_6GHZ}" \
    "${TOTAL_LINES}" \
    "${WIFI6_COUNT}" \
    "${EVIDENCE_DIR}/A5_raw.csv" \
    > "${EVIDENCE_DIR}/A5_wifi6_environment.json"

# 7. Write result JSON
printf '{
  "tc_id": "%s",
  "status": "complete",
  "wifi6_present": %s,
  "adapter_6ghz": %s,
  "beacons_captured": %s
}\n' \
    "${TC_ID}" \
    "${WIFI6_PRESENT}" \
    "${SUPPORTS_6GHZ}" \
    "${TOTAL_LINES}" \
    > "${EVIDENCE_DIR}/A5_result.json"

# 8. Summary output
echo -e "${C_BOLD}[A5] Wi-Fi 6 Detection Complete${C_RESET}"
echo -e "${C_PROMPT}  Beacons captured   :${C_RESET} ${C_VAR}${TOTAL_LINES}${C_RESET}"
echo -e "${C_PROMPT}  Wi-Fi 6 beacons    :${C_RESET} ${C_VAR}${WIFI6_COUNT}${C_RESET}"
echo -e "${C_PROMPT}  6GHz adapter       :${C_RESET} ${C_VAR}${SUPPORTS_6GHZ}${C_RESET}"
echo -e "${C_PROMPT}  Evidence           :${C_RESET} ${C_VAR}${EVIDENCE_DIR}/A5_result.json${C_RESET}"

# 9. Record findings
if [[ "${WIFI6_PRESENT}" == "true" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Wi-Fi 6 (802.11ax) Environment Detected" \
        --severity INFO \
        --desc "Detected ${WIFI6_COUNT} Wi-Fi 6 beacon(s) out of ${TOTAL_LINES} total. BSS Coloring, OFDMA, TWT, and MU-MIMO capabilities present. 6GHz adapter support: ${SUPPORTS_6GHZ}." \
        --target "Global" \
        --evidence "${EVIDENCE_DIR}/A5_raw.csv"
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[A5] Audit Complete — No Wi-Fi 6 Detected" \
        --severity INFO \
        --desc "Scanned ${TOTAL_LINES} beacon(s) for 802.11ax HE indicators. No Wi-Fi 6 APs detected in range during ${SCAN_TIME}s window. 6GHz adapter support: ${SUPPORTS_6GHZ}." \
        --target "Global" \
        --evidence "${EVIDENCE_DIR}/A5_result.json"
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
