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
OUTPUT_PCAP="${OUTPUT_PCAP:-${EVIDENCE_DIR}/a1_results.pcap}"
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

# Tactical options are now passed from the Go brain via Env
echo -e "${C_PROMPT}[*]${C_RESET} Starting airodump-ng scan on ${C_VAR}${INTERFACE}${C_RESET} for ${C_VAR}${SCAN_TIME}s${C_RESET}..."


# airodump-ng appends -01.csv to the prefix. 
# We remove the suffix from the target path to match airodump's behavior
CSV_PREFIX="${OUTPUT_CSV%.csv}"

# Run airodump-ng in background
# Redirect stdout/stderr to a log to prevent terminal pollution unless ASTRA_IN_WINDOW=true
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    airodump-ng "$INTERFACE" \
        --write "$CSV_PREFIX" \
        --output-format csv \
        --band abg &
else
    airodump-ng "$INTERFACE" \
        --write "$CSV_PREFIX" \
        --output-format csv \
        --band abg > "${EVIDENCE_DIR}/${TC_ID}_airodump.log" 2>&1 &
fi
AIRODUMP_PID=$!

# Wait for the specified time with real-time progress updates
ELAPSED=0
while [[ $ELAPSED -lt $SCAN_TIME ]]; do
    PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
    STATUS="Scanning channels... ($(( SCAN_TIME - ELAPSED ))s left)"
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
    
    sleep 2
    ((ELAPSED+=2))
done

# Final progress
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Scan complete. Processing results..."

# Stop airodump-ng
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

# Rename the file to the exact requested path (remove the -01 suffix)
if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# Check if output exists
if [[ -f "$OUTPUT_CSV" && -s "$OUTPUT_CSV" ]]; then
    echo "[+] Scan complete. Results in $OUTPUT_CSV"
    
    # Record finding
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Network Discovery Complete" \
        --severity INFO \
        --desc "Successfully identified wireless networks using $INTERFACE. Results saved to $(basename "$OUTPUT_CSV")" \
        --target "Global" \
        --evidence "$OUTPUT_CSV" \
        --rationale "Provides the baseline network map for all subsequent attacks."

    exit 0
else
    echo "[!] No output CSV found or file is empty."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[A1] Audit Complete" \
        --severity INFO \
        --desc "Scan completed, but no wireless networks were identified in this environment." \
        --target "Global" \
        --evidence "${EVIDENCE_DIR}/${TC_ID}_airodump.log" \
        --rationale "No wireless infrastructure was detected during the scan interval. This may indicate a RF-shielded area or lack of nearby APs."
    exit 0
fi
