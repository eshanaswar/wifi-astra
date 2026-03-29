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
#  2. Active Reveal: If clients are associated with hidden BSSIDs, perform 
#     surgical deauthentication to force reconnection and reveal SSID.
#  3. Listen for Probe Response or Association Request frames where the SSID
#     is revealed in the clear.
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

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# 1. Identify which BSSIDs were originally hidden
echo -e "${C_PROMPT}[*]${C_RESET} Loading baseline hidden networks from A1..."
# ...
# Extract hidden targets for the loop
HIDDEN_LIST=$(echo "$HIDDEN_BSSIDS")

# 2. Active Reveal Selection
echo -e "${C_PROMPT}[*]${C_RESET} Identifying clients associated with hidden BSSIDs for active reveal..."
DISC_PREFIX="${EVIDENCE_DIR}/a3_discovery"
airodump-ng "$INTERFACE" --write "$DISC_PREFIX" --output-format csv > /dev/null 2>&1 &
DISC_PID=$!
sleep 15
kill "$DISC_PID" || true
wait "$DISC_PID" 2>/dev/null || true

for bssid in $HIDDEN_LIST; do
    # Find a client for this BSSID from the new discovery
    client=$(awk -F',' -v b="$bssid" '$6 ~ b {print $1}' "${DISC_PREFIX}-01.csv" | head -1 | tr -d ' ' || true)
    
    if [[ -n "$client" ]]; then
        echo -e "${C_PROMPT}[?]${C_RESET} Hidden BSSID ${C_VAR}$bssid${C_RESET} has active client ${C_VAR}$client${C_RESET}."
        read -p "$(echo -e "${C_BOLD}[?] Force reveal via surgical deauth? [y/N]: ${C_RESET}")" choice
        if [[ "$choice" == "y" ]]; then
            echo -e "[*] Executing active de-cloaking for ${C_VAR}$bssid${C_RESET}..."
            aireplay-ng --deauth 5 -a "$bssid" -c "$client" "$INTERFACE" > /dev/null 2>&1 || true
        fi
    fi
done

# 3. Start targeted discovery monitoring
echo -e "${C_PROMPT}[*]${C_RESET} Initializing targeted SSID reveal monitoring on ${C_VAR}${INTERFACE}${C_RESET}..."
CSV_PREFIX="${OUTPUT_CSV%.csv}"
airodump-ng "$INTERFACE" \
    --write "$CSV_PREFIX" \
    --output-format csv \
    --band abg > "${EVIDENCE_DIR}/a3_airodump.log" 2>&1 &
AIRODUMP_PID=$!

sleep "$SCAN_TIME"
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 4. Intelligent Analysis & Reporting
REVEALED_FILE="${EVIDENCE_DIR}/a3_revealed.txt"
awk -F',' -v hidden_list="$HIDDEN_BSSIDS" '
    BEGIN {
        split(hidden_list, hl, "\n");
        for (i in hl) { if (hl[i] != "") hidden_map[hl[i]] = 1; }
    }
    NR > 1 {
        bssid = $1; ssid = $14;
        gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
        gsub(/^[ \t\r\n"<>]+|[ \t\r\n"<>]+$/, "", ssid);
        if (bssid in hidden_map && ssid != "" && ssid !~ /^length:/ && ssid != "HIDDEN") {
            print bssid " -> " ssid;
            delete hidden_map[bssid];
        }
    }
' "$OUTPUT_CSV" > "$REVEALED_FILE"

REVEALED_COUNT=0
if [[ -s "$REVEALED_FILE" ]]; then
    while read -r line; do
        [[ -z "$line" ]] && continue
        bssid="${line% -> *}"; ssid="${line#* -> }"
        echo "[!] DEANONYMIZED: ${bssid} -> ${ssid}"
        $ASTRA_BIN record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Hidden SSID Revealed" \
            --severity MEDIUM \
            --desc "Successfully revealed hidden network name: ${ssid} (BSSID: ${bssid})" \
            --rationale "Revealed names provide further targets for assessment and indicate that clients are actively connecting to the hidden infrastructure." \
            --evidence "$OUTPUT_CSV"
        ((REVEALED_COUNT++))
    done < "$REVEALED_FILE"
fi

if [[ $REVEALED_COUNT -eq 0 ]]; then
    echo "[+] No hidden SSIDs were deanonymized."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "A3 Audit Complete" \
        --severity INFO \
        --desc "Scan completed. No previously hidden SSIDs were revealed." \
        --rationale "Hidden SSID reveal is dependent on client interaction occurring during the monitoring window."
fi

exit 0
