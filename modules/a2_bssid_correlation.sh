#!/usr/bin/env bash
# MODULE_META
# NAME="BSSID Correlation Analysis"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng"
# DESC="Map BSSIDs to same controller, detect infra overlap"
# REQS="monitor_iface,target_ssid"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a2_bssid_correlation.sh
#  A2: BSSID Correlation Analysis (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
# Analysis module: Ignore its own OUTPUT_CSV and look for A1 discovery data
A1_CSV="${EVIDENCE_DIR}/a1_results.csv"
OUTPUT_FILE="${EVIDENCE_DIR}/a2_results.txt"
TC_ID="A2"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ ! -f "$A1_CSV" ]]; then
    echo "[!] A1 discovery results not found: $A1_CSV"
    echo "[*] Please run Category A1 (Identify Networks) before running correlation."
    exit 1
fi

echo "[*] Analyzing BSSID correlation from A1 scan data..."

# Check if A1_CSV is empty (only header or nothing)
if [[ ! -s "$A1_CSV" || $(wc -l < "$A1_CSV") -le 1 ]]; then
    echo "[!] A1 results file is empty or missing data."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[A2] Audit Complete" \
        --severity INFO \
        --desc "BSSID correlation analysis completed, but no baseline network data was available from A1." \
        --evidence "$A1_CSV" \
        --rationale "Without baseline discovery data, correlation cannot be performed."
    exit 0
fi

# Group by OUI prefix (first 3 octets)
{
    echo "============================================================"
    echo "  A2: BSSID Correlation Analysis"
    echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
    echo ""
    echo "Grouped by OUI Prefix (Physical AP clusters):"
    
    # Extract BSSIDs, get OUIs, count occurrences
    # Field 1 is BSSID
    awk -F',' 'NR > 1 && $1 != "" && $1 != "BSSID" { print $1 }' "$A1_CSV" | cut -d':' -f1-3 | sort | uniq -c | sort -rn | while read -r count oui; do
        [[ -z "$oui" ]] && continue
        echo "[*] OUI Group: $oui ($count BSSIDs)"
        
        # List all SSIDs in this group using awk
        # BSSID is field 1, ESSID is field 14
        awk -F',' -v target="$oui" '
            $1 ~ "^"target {
                bssid = $1;
                ssid = $14;
                gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
                gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", ssid);
                print "    - " bssid " : " ssid
            }
        ' "$A1_CSV"
        echo ""
    done
} > "$OUTPUT_FILE"

echo "[+] Analysis complete. Results saved to $OUTPUT_FILE"

# Record finding
$ASTRA_BIN record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "BSSID Correlation Complete" \
    --severity INFO \
    --desc "Successfully mapped BSSID clusters by OUI. Results in $(basename "$OUTPUT_FILE")" \
    --target "Global" \
    --evidence "$OUTPUT_FILE" \
    --rationale "Correlating BSSIDs helps identify multi-AP networks and roaming configurations."

exit 0
