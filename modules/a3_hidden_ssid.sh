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
# TIMED="yes"
# PROMPTS="active_reveal,pmf_guard"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a3_hidden_ssid.sh
#  A3: Hidden SSID Discovery (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Identify BSSIDs that were originally hidden (from A1 discovery).
#  2. Active Reveal: If ACTIVE_REVEAL is enabled, perform surgical deauth
#     to force reconnection and reveal cleartext SSID.
#  3. Listen for frames where the SSID is revealed.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SCAN_TIME="${SCAN_TIME:-120}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
OUTPUT_CSV="${OUTPUT_CSV:-${EVIDENCE_DIR}/a3_results.csv}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="A3"
ACTIVE_REVEAL="${ACTIVE_REVEAL:-no}" # From Go brain

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
echo -e "${C_PROMPT}[*]${C_RESET} Loading baseline hidden networks from A1..."
HIDDEN_BSSIDS=$(awk -F',' '
    NR > 1 {
        bssid = $1; ssid = $14;
        gsub(/^[ \t\r\n"<>]+|[ \t\r\n"<>]+$/, "", ssid);
        gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
        if (ssid == "" || ssid ~ /length:/ || ssid ~ /^</ || ssid == "HIDDEN") {
            if (bssid ~ /^[0-9A-Fa-f:]{17}$/) print bssid;
        }
    }
' "$A1_CSV" | sort -u)

if [[ -z "$HIDDEN_BSSIDS" ]]; then
    echo -e "[+] No hidden networks detected. Nothing to deanonymize."
    exit 0
fi

# 2. Active Reveal
if [[ "$ACTIVE_REVEAL" == "yes" ]]; then
    echo -e "${C_PROMPT}[*]${C_RESET} Executing active de-cloaking for hidden targets..."
    
    # Discovery scan: 20s to find associated clients on all channels
    DISC_PREFIX="${EVIDENCE_DIR}/a3_discovery"
    echo -e "${C_PROMPT}[*]${C_RESET} Scanning for associated clients (20s)..."
    timeout 20 airodump-ng "$INTERFACE" --write "$DISC_PREFIX" --output-format csv > /dev/null 2>&1 || true

    for bssid in $HIDDEN_BSSIDS; do
        # Look up the channel for this BSSID from A1 data so deauth reaches it
        bssid_channel=$(awk -F',' -v b="$bssid" '
            $1 ~ b { ch=$4; gsub(/[[:space:]]/, "", ch); print ch; exit }
        ' "$A1_CSV" || true)

        client=$(awk -F',' -v b="$bssid" '$6 ~ b {print $1}' "${DISC_PREFIX}-01.csv" 2>/dev/null | head -1 | tr -d ' ' || true)
        if [[ -n "$client" && "$client" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
            echo -e "[*] Deauthing ${C_VAR}$client${C_RESET} on ${C_VAR}$bssid${C_RESET} (ch ${bssid_channel:-?})..."
            if [[ -n "$bssid_channel" ]]; then
                iw dev "$INTERFACE" set channel "$bssid_channel" 2>/dev/null || true
                sleep 0.5
            fi
            aireplay-ng --deauth 5 -a "$bssid" -c "$client" "$INTERFACE" > /dev/null 2>&1 || true
        else
            echo -e "[*] No client found for ${C_VAR}$bssid${C_RESET} — skipping deauth."
        fi
    done
fi

# 3. Main Monitoring Phase (Passive Fallback)
echo -e "${C_PROMPT}[*]${C_RESET} Monitoring for SSID reveals on ${C_VAR}${INTERFACE}${C_RESET}..."
CSV_PREFIX="${OUTPUT_CSV%.csv}"

# Start telemetry background
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Monitoring for SSID reveals... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED+=5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout --foreground "$SCAN_TIME" airodump-ng "$INTERFACE" --write "$CSV_PREFIX" --output-format csv || true
else
    # Run with redirection
    airodump-ng "$INTERFACE" --write "$CSV_PREFIX" --output-format csv > /dev/null 2>&1 &
    TOOL_PID=$!
    # Wait for SCAN_TIME
    (sleep "$SCAN_TIME"; kill "$TOOL_PID" 2>/dev/null || true) &
    wait "$TOOL_PID" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Scan Complete"

if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 4. Analysis
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
        echo -e "[!] ${C_BOLD}DEANONYMIZED:${C_RESET} ${C_VAR}${bssid}${C_RESET} -> ${C_VAR}${ssid}${C_RESET}"
        $ASTRA_BIN record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Hidden SSID Revealed" \
            --severity MEDIUM \
            --desc "Successfully revealed hidden network name: ${ssid} (BSSID: ${bssid})" \
            --evidence "$OUTPUT_CSV"
        REVEALED_COUNT=$((REVEALED_COUNT + 1))
    done < "$REVEALED_FILE"
fi

if [[ $REVEALED_COUNT -eq 0 ]]; then
    echo -e "[+] No hidden SSIDs deanonymized in this window."
fi


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
