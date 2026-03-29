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
C_RESET="${ASTRA_COLOR_RESET:-}"

echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Select Scan Depth:${C_RESET}"
echo "    1) Standard (60s)"
echo "    2) Deep Scan (120s - Recommended for DFS/5GHz)"
read -p "$(echo -e "${C_BOLD}Selection [1/2]: ${C_RESET}")" depth_choice

if [[ "$depth_choice" == "2" ]]; then
    SCAN_TIME=120
    echo -e "${C_PROMPT}[*]${C_RESET} Deep Scan enabled. Setting interval to ${C_VAR}120s${C_RESET}..."
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting airodump-ng scan on ${C_VAR}${INTERFACE}${C_RESET} for ${C_VAR}${SCAN_TIME}s${C_RESET}..."

# airodump-ng appends -01.csv to the prefix. 
# We remove the suffix from the target path to match airodump's behavior
CSV_PREFIX="${OUTPUT_CSV%.csv}"

# Run airodump-ng in background
# Redirect stdout/stderr to a log to prevent terminal pollution
airodump-ng "$INTERFACE" \
    --write "$CSV_PREFIX" \
    --output-format csv \
    --band abg > "${EVIDENCE_DIR}/${TC_ID}_airodump.log" 2>&1 &
AIRODUMP_PID=$!

# Wait for the specified time
sleep "$SCAN_TIME"

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
