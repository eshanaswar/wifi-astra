#!/usr/bin/env bash
# MODULE_META
# NAME="Client Fingerprinting"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng"
# DESC="Enumerate all connected clients and their probe lists"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="no"
# TIMED="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a4_client_fingerprinting.sh
#  A4: Client Fingerprinting (Golden Wrapper)
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
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
OUTPUT_CSV="${OUTPUT_CSV:-${EVIDENCE_DIR}/a4_results.csv}"
TC_ID="A4"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting client fingerprinting on ${C_VAR}${INTERFACE}${C_RESET} (BSSID: ${C_VAR}${BSSID}${C_RESET})..."

CSV_PREFIX="${OUTPUT_CSV%.csv}"

# Start telemetry background
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Mapping clients... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 2
        ((ELAPSED+=2))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout "$SCAN_TIME" airodump-ng "$INTERFACE" \
        --bssid "$BSSID" \
        --channel "${CHANNEL:-0}" \
        --write "$CSV_PREFIX" \
        --output-format csv \
        --band abg || true
    RET=$?
else
    # Run with redirection
    airodump-ng "$INTERFACE" \
        --bssid "$BSSID" \
        --channel "${CHANNEL:-0}" \
        --write "$CSV_PREFIX" \
        --output-format csv \
        --band abg > "${EVIDENCE_DIR}/${TC_ID}_airodump.log" 2>&1 &
    TOOL_PID=$!
    # Wait for SCAN_TIME
    (sleep "$SCAN_TIME"; kill "$TOOL_PID" 2>/dev/null || true) &
    wait "$TOOL_PID" 2>/dev/null || true
    RET=$?
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Processing results..."

# Rename the file
if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 3. Spec-Aligned Parsing (Single Pass)
PARSED_PROBES="${EVIDENCE_DIR}/a4_parsed_probes.txt"

if [[ -f "$OUTPUT_CSV" && -s "$OUTPUT_CSV" ]]; then
    echo -e "${C_PROMPT}[*]${C_RESET} Extracting Client PNLs from CSV..."
    
    awk -F',' '
        /Station/ {found=1; next}
        found {
            mac = $1; gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", mac);
            if (mac !~ /^[0-9A-Fa-f:]{17}$/) next;

            pnl = "";
            for(i=7; i<=NF; i++) {
                p = $i; gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", p);
                if (p != "") {
                    pnl = (pnl == "" ? p : pnl "," p);
                }
            }
            if (pnl != "") {
                print mac "|" pnl;
            } else {
                print mac "|<NONE>";
            }
        }
    ' "$OUTPUT_CSV" > "$PARSED_PROBES"
fi

FOUND_COUNT=0
if [[ -f "$PARSED_PROBES" ]]; then
    while IFS="|" read -r mac pnl; do
        [[ -z "$mac" ]] && continue
        FOUND_COUNT=$((FOUND_COUNT + 1)) # SAFE INCREMENT
        
        if [[ "$pnl" == "<NONE>" ]]; then
            echo -e "[+] Found station: ${C_VAR}$mac${C_RESET} (No PNL leaked)"
            $ASTRA_BIN record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "Client Identified" \
                --severity INFO \
                --desc "Station $mac identified associated with $BSSID." \
                --target "$mac" \
                --evidence "$OUTPUT_CSV"
        else
            echo -e "[!] ${C_BOLD}PNL LEAK DETECTED:${C_RESET} ${C_VAR}$mac${C_RESET} probes for ${C_VAR}[$pnl]${C_RESET}"
            $ASTRA_BIN record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "PNL Leak Detected" \
                --severity HIGH \
                --desc "Station $mac leaked its PNL: $pnl." \
                --target "$mac" \
                --evidence "$OUTPUT_CSV"
        fi
    done < "$PARSED_PROBES"
fi

if [[ $FOUND_COUNT -eq 0 ]]; then
    echo -e "${C_PROMPT}[*]${C_RESET} No active clients discovered for $BSSID."
fi

exit 0
