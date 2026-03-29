#!/usr/bin/env bash
# MODULE_META
# NAME="Hidden SSID Discovery"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,airodump-ng"
# DESC="Identify and reveal SSIDs of hidden networks by monitoring client traffic"
# REQS="monitor_iface"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a3_hidden_ssid.sh
#  A3: Hidden SSID Discovery (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Identify BSSIDs that were originally hidden (from A1 discovery).
#  2. Listen for Probe Response or Association Request frames where the SSID
#     is revealed in the clear.
#  3. Cross-reference new results against the baseline. Only report if a 
#     previously hidden BSSID now has a cleartext ESSID.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-120}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
OUTPUT_CSV="${OUTPUT_CSV:-${EVIDENCE_DIR}/a3_results.csv}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="A3"

# Baseline Discovery Data
A1_CSV="${EVIDENCE_DIR}/a1_results.csv"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ ! -f "$A1_CSV" ]]; then
    echo "[!] Baseline discovery (A1) not found. Run A1 first."
    exit 1
fi

# 1. Identify which BSSIDs were originally hidden
echo "[*] Loading baseline hidden networks from A1..."
# Airodump CSV: BSSID is field 1, ESSID is field 14
# We look for SSIDs that are empty, start with <length, or are <HIDDEN>
HIDDEN_BSSIDS=$(awk -F',' '
    NR > 1 {
        bssid = $1;
        ssid = $14;
        # Strip whitespace and quotes
        gsub(/^[ \t\r\n"<>]+|[ \t\r\n"<>]+$/, "", ssid);
        gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
        
        if (ssid == "" || ssid ~ /^length:/ || ssid == "HIDDEN") {
            print bssid;
        }
    }
' "$A1_CSV" | sort -u)

if [[ -z "$HIDDEN_BSSIDS" ]]; then
    echo "[+] No hidden networks detected in baseline scan. Nothing to deanonymize."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "A3 Audit Complete" \
        --severity INFO \
        --desc "Scan completed. No hidden networks were identified in the baseline discovery phase." \
        --rationale "Monitoring for hidden network leaks is a standard part of recon, but depends on the presence of hidden BSSIDs."
    exit 0
fi

echo "[*] Target Hidden BSSIDs:"
echo "$HIDDEN_BSSIDS"

# 2. Start targeted discovery
echo "[*] Initializing targeted SSID reveal on ${INTERFACE}..."
CSV_PREFIX="${OUTPUT_CSV%.csv}"
# Run airodump-ng in background to catch revealed SSIDs
# Redirect stdout/stderr to a log to prevent terminal pollution
airodump-ng "$INTERFACE" \
    --write "$CSV_PREFIX" \
    --output-format csv \
    --band abg > "${EVIDENCE_DIR}/a3_airodump.log" 2>&1 &
AIRODUMP_PID=$!

# Wait for discovery
sleep "$SCAN_TIME"

# Cleanup
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

# Standardize output path
if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 3. Intelligent Analysis & Reporting (Single Pass O(1) Subprocess)
REVEALED_FILE="${EVIDENCE_DIR}/a3_revealed.txt"

if [[ -f "$OUTPUT_CSV" ]]; then
    echo "[*] Analyzing revealed SSIDs..."
    
    # Use a single awk script to compare the baseline to the new results
    awk -F',' -v hidden_list="$HIDDEN_BSSIDS" '
        BEGIN {
            # Load hidden BSSIDs into an array for O(1) lookup
            split(hidden_list, hl, "\n");
            for (i in hl) {
                if (hl[i] != "") {
                    hidden_map[hl[i]] = 1;
                }
            }
        }
        # Process the new CSV
        NR > 1 {
            bssid = $1;
            ssid = $14;
            # Strip whitespace
            gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
            gsub(/^[ \t\r\n"<>]+|[ \t\r\n"<>]+$/, "", ssid);
            
            # If the BSSID was originally hidden, and now has a valid name
            if (bssid in hidden_map && ssid != "" && ssid !~ /^length:/ && ssid != "HIDDEN") {
                print bssid " -> " ssid;
                # Remove it from the map so we only report it once
                delete hidden_map[bssid];
            }
        }
    ' "$OUTPUT_CSV" > "$REVEALED_FILE"
fi

REVEALED_COUNT=0
if [[ -s "$REVEALED_FILE" ]]; then
    while read -r line; do
        [[ -z "$line" ]] && continue
        bssid="${line% -> *}"
        ssid="${line#* -> }"
        
        echo "[!] DEANONYMIZED: ${bssid} -> ${ssid}"
        
        $ASTRA_BIN record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Hidden SSID Revealed" \
            --severity MEDIUM \
            --desc "Successfully revealed hidden network name: ${ssid} (BSSID: ${bssid})" \
            --rationale "Hiding SSIDs is 'security by obscurity' and does not prevent discovery. Revealed names provide further targets for assessment and indicate that clients are actively connecting to the hidden infrastructure." \
            --evidence "$OUTPUT_CSV"
        
        ((REVEALED_COUNT++))
    done < "$REVEALED_FILE"
fi

if [[ $REVEALED_COUNT -eq 0 ]]; then
    echo "[+] No hidden SSIDs were deanonymized during this mission."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "A3 Audit Complete" \
        --severity INFO \
        --desc "Scan completed. No previously hidden SSIDs were revealed in this interval." \
        --rationale "Hidden SSID reveal is dependent on client interaction (reconnections) occurring during the monitoring window."
fi

exit 0
