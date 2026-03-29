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
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a4_client_fingerprinting.sh
#  A4: Client Fingerprinting (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Targeted scan of the specific BSSID to identify associated stations.
#  2. Parse BOTH associated MACs and their Probed ESSIDs (PNLs) from the CSV.
#  3. Record detailed findings for each client to build the PNL database.
#===============================================================================

set -euo pipefail

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

echo "[*] Starting client fingerprinting on ${INTERFACE} (BSSID: ${BSSID}, CH: ${CHANNEL:-auto})..."

CSV_PREFIX="${OUTPUT_CSV%.csv}"

# 1. Start airodump-ng to map clients
airodump-ng "$INTERFACE" \
    --bssid "$BSSID" \
    --channel "${CHANNEL:-0}" \
    --write "$CSV_PREFIX" \
    --output-format csv \
    --band abg > "${EVIDENCE_DIR}/${TC_ID}_airodump.log" 2>&1 &
AIRODUMP_PID=$!

# Wait for completion
sleep "$SCAN_TIME"

# Cleanup
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

# Rename the file
if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 2. Spec-Aligned Parsing (Single Pass)
# Extracts Station MAC (Col 1) and Probed ESSIDs (Col 7+ in Station section)
PARSED_PROBES="${EVIDENCE_DIR}/a4_parsed_probes.txt"

if [[ -f "$OUTPUT_CSV" && -s "$OUTPUT_CSV" ]]; then
    echo "[*] Extracting Client PNLs from CSV..."
    
    awk -F',' '
        /Station/ {found=1; next}
        found {
            mac = $1; gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", mac);
            if (mac !~ /^[0-9A-Fa-f:]{17}$/) next;

            # PNLs start at field 7. Handle multiple comma-separated probes if present.
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
        ((FOUND_COUNT++))
        
        if [[ "$pnl" == "<NONE>" ]]; then
            echo "[+] Found station: $mac (No PNL leaked)"
            $ASTRA_BIN record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "Client Identified" \
                --severity INFO \
                --desc "Station $mac identified associated with $BSSID. No PNL leaked in this window." \
                --target "$mac" \
                --evidence "$OUTPUT_CSV" \
                --rationale "Passive identification of associated stations is the first step in client-side targeting."
        else
            echo "[!] LEAK DETECTED: $mac probes for [$pnl]"
            $ASTRA_BIN record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "PNL Leak Detected" \
                --severity HIGH \
                --desc "Station $mac leaked its Preferred Network List (PNL): $pnl. This data enables targeted Karma attacks." \
                --target "$mac" \
                --evidence "$OUTPUT_CSV" \
                --rationale "Clients broadcasting directed probes for past networks (PNL) are highly vulnerable to Karma attacks. Spoofer APs can reactively claim these SSIDs to force automatic association."
        fi
    done < "$PARSED_PROBES"
fi

if [[ $FOUND_COUNT -eq 0 ]]; then
    echo "[*] No active clients discovered for $BSSID."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --severity INFO \
        --desc "Scan completed. No active clients were identified in this interval." \
        --evidence "${EVIDENCE_DIR}/${TC_ID}_airodump.log" \
        --rationale "Lack of user activity during the scan window reduces the immediate attack surface for client-side exploits."
fi

exit 0
