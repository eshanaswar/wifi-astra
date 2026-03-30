#!/usr/bin/env bash
# MODULE_META
# NAME="Identify All Wireless Networks"
# CATEGORY="A"
# DEPS="none"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng"
# DESC="Enumerate all SSIDs, BSSIDs, channels, encryption using monitor mode"
# REQS="monitor_iface"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a1_identify_networks.sh
#  A1: Identify All Wireless Networks (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
OUTPUT_CSV="${OUTPUT_CSV:-${EVIDENCE_DIR}/a1_results.csv}"
TC_ID="A1"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

# 0. Intelligence Insight
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

echo -e "${C_PROMPT}[*]${C_RESET} Starting airodump-ng scan on ${C_VAR}${INTERFACE}${C_RESET} for ${C_VAR}${SCAN_TIME}s${C_RESET}..."

CSV_PREFIX="${OUTPUT_CSV%.csv}"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_airodump.log"

# 1. 🛰️ DYNAMIC TELEMETRY HEARTBEAT (Background)
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 95 ]] && PCT=95
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Scanning channels..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. RUN PRIMARY TOOL (Foreground in Window, Background with Wait otherwise)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # In Tactical Window: Run in foreground so ncurses renders correctly
    airodump-ng "$INTERFACE" --write "$CSV_PREFIX" --output-format csv --band abg
    RET=$?
else
    # In Main Feed: Redirect to log to keep terminal clean
    airodump-ng "$INTERFACE" --write "$CSV_PREFIX" --output-format csv --band abg > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. CLEANUP & REPORTING
kill $TEL_PID 2>/dev/null || true

# Rename the file to the exact requested path
if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# Final Signal
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

if [[ -f "$OUTPUT_CSV" && -s "$OUTPUT_CSV" ]]; then
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Network Discovery Complete" \
        --severity INFO \
        --desc "Successfully identified wireless networks using $INTERFACE." \
        --target "Global" \
        --evidence "$OUTPUT_CSV"
else
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[A1] Audit Complete" \
        --severity INFO \
        --desc "Scan completed, but no wireless networks were identified." \
        --target "Global" \
        --evidence "$LOG_FILE"
fi

exit $RET
