#!/usr/bin/env bash
# MODULE_META
# NAME="OWE Transition Mode Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,airodump-ng"
# DESC="Test if OWE networks can be downgraded to Open by spoofing transition mode"
# REQS="monitor_iface,managed_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="owe"

#===============================================================================
#  modules/d6_owe_downgrade.sh
#  D6: OWE Transition Mode Downgrade (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
MANAGED_IFACE="${WIFI_INTERFACE:-}"   # managed mode interface used for active association test
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-15}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D6"
SCAN_PREFIX="${EVIDENCE_DIR}/${TC_ID}_airodump"
CSV_FILE="${SCAN_PREFIX}-01.csv"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. OWE testing requires a target SSID."
    exit 1
fi

echo "[*] Testing OWE downgrade / transition mode for ${SSID}..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Scanning for OWE transition mode..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (airodump-ng)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" || true
else
    # Background Execution: use timeout instead of manual sleep/kill so exit code is clean
    timeout "$SCAN_TIME" airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" > /dev/null 2>&1 || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Check findings
OWE_PRESENT=$(awk -F, -v s="$SSID" 'tolower($14) ~ tolower(s) && $6 ~ /OWE/ {print "YES"}' "$CSV_FILE" 2>/dev/null || true)

# OWE Transition Mode Pair Detection
# Check if both an Open and OWE BSSID exist for the same SSID — the hallmark of Transition Mode
OPEN_BSSID=""

if [[ -f "${CSV_FILE}" ]]; then
    OPEN_ROW=$(awk -F',' -v s="${SSID}" 'tolower($14) ~ tolower(s) && ($6 ~ /OPN/ || $6 ~ /Open/) {print $1; exit}' "${CSV_FILE}" 2>/dev/null || true)
    OWE_ROW=$(awk -F',' -v s="${SSID}" 'tolower($14) ~ tolower(s) && $6 ~ /OWE/ {print $1; exit}' "${CSV_FILE}" 2>/dev/null || true)
    OPEN_BSSID="${OPEN_ROW// /}"

    if [[ -n "${OPEN_BSSID}" && -n "${OWE_ROW}" ]]; then
        echo "[D6] OWE Transition Mode pair detected!"
        echo "[D6]   Open BSSID : ${OPEN_BSSID}"
        echo "[D6]   OWE  BSSID : ${OWE_ROW// /}"

        # Active association test: attempt to force-associate to the open BSSID.
        # MUST use the managed-mode interface (WIFI_INTERFACE), NOT the monitor interface.
        # A monitor interface cannot associate — iwconfig on wlan1mon silently fails every time.
        if [[ -n "$MANAGED_IFACE" ]]; then
            echo "[D6] Testing forced association to open BSSID via ${MANAGED_IFACE}..."
            timeout 10 iwconfig "${MANAGED_IFACE}" essid "${SSID}" ap "${OPEN_BSSID}" 2>/dev/null || true
            sleep 3
            ASSOC_LINE=$(iwconfig "${MANAGED_IFACE}" 2>/dev/null | grep -i "access point" || true)
            if echo "${ASSOC_LINE}" | grep -qi "${OPEN_BSSID}"; then
                echo "[D6] FINDING: Associated to open BSSID — OWE protection NOT enforced"
                echo "transition_bypass=true" >> "${EVIDENCE_DIR}/D6_result.txt"
            else
                echo "[D6] Association to open BSSID failed — OWE may be enforced"
                echo "transition_bypass=false" >> "${EVIDENCE_DIR}/D6_result.txt"
            fi
        else
            echo "[D6] WIFI_INTERFACE not set — skipping active association test (passive detection only)"
            echo "transition_bypass=untested" >> "${EVIDENCE_DIR}/D6_result.txt"
        fi
    fi
fi

if [[ "$OWE_PRESENT" == "YES" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "OWE Transition Mode Detected" \
        --desc "The network ${SSID} uses OWE Transition Mode, broadcasted both OWE and Open BSSIDs." \
        --severity MEDIUM \
        --evidence "$CSV_FILE" \
        --rationale "Transition mode is susceptible to downgrade attacks."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Scanned for OWE transition mode vulnerabilities on SSID ${SSID}. No issues identified." \
        --severity INFO \
        --evidence "$CSV_FILE" \
        --rationale "Ensuring modern encryption standards are not misconfigured."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
