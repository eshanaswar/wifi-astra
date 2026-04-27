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
# --- Scope Guardrail ---
# Verify this module was launched by the wifi-astra controller.
# Prevents casual direct invocation against unauthorized targets.
if [[ -n "${ASTRA_SCOPE_TOKEN:-}" && -n "${GUEST_BSSID:-}" ]]; then
    if ! "$ASTRA_BIN" verify-scope \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --bssid "$GUEST_BSSID" \
            --token "$ASTRA_SCOPE_TOKEN"; then
        echo "[!] Scope guardrail failed — aborting." >&2
        exit 1
    fi
fi
# (Token absent = headless or legacy mode; guard is skipped but logged)
if [[ -z "${ASTRA_SCOPE_TOKEN:-}" && "${ASTRA_HEADLESS:-}" != "true" ]]; then
    echo "[!] WARNING: ASTRA_SCOPE_TOKEN not set. Run this module via wifi-astra start." >&2
fi
# --- End Scope Guardrail ---
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
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "OWE downgrade active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5; ELAPSED=$((ELAPSED + 5))
            continue
        fi
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

# Read back active association test result to determine actual bypass outcome
BYPASS_RESULT=$(grep "^transition_bypass=" "${EVIDENCE_DIR}/D6_result.txt" 2>/dev/null | tail -1 | cut -d= -f2 || true)

if [[ "$OWE_PRESENT" == "YES" ]]; then
    if [[ "$BYPASS_RESULT" == "true" ]]; then
        FINDING_SEVERITY="HIGH"
        FINDING_NAME="OWE Transition Mode Bypass Confirmed"
        FINDING_DESC="The network ${SSID} uses OWE Transition Mode and the client successfully associated to the open BSSID (${OPEN_BSSID}), bypassing OWE encryption entirely."
    elif [[ "$BYPASS_RESULT" == "false" ]]; then
        FINDING_SEVERITY="MEDIUM"
        FINDING_NAME="OWE Transition Mode Detected (Bypass Blocked)"
        FINDING_DESC="The network ${SSID} broadcasts both OWE and Open BSSIDs (transition mode). Active association to the open BSSID failed — OWE enforcement appears active for this client."
    else
        # untested or no managed interface available
        FINDING_SEVERITY="MEDIUM"
        FINDING_NAME="OWE Transition Mode Detected"
        FINDING_DESC="The network ${SSID} uses OWE Transition Mode, broadcasting both OWE and Open BSSIDs. Active bypass test was not performed (WIFI_INTERFACE not set)."
    fi
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "$FINDING_NAME" \
        --desc "$FINDING_DESC" \
        --severity "$FINDING_SEVERITY" \
        --evidence "$CSV_FILE" \
        --rationale "OWE Transition Mode allows legacy clients to connect without encryption. If the AP does not enforce OWE for capable clients, an attacker can trivially downgrade to an open association."
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
