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
# CRITICAL: capture must START before deauth — the probe response with the SSID
# arrives within milliseconds of the deauth frame. Capture started after deauth
# will miss the reveal window entirely.
REVEALED_COUNT=0
declare -A ALREADY_REVEALED
if [[ "$ACTIVE_REVEAL" == "yes" ]]; then
    echo -e "${C_PROMPT}[*]${C_RESET} Executing active de-cloaking for hidden targets..."

    # Discovery scan: 20s to find associated clients on all channels
    DISC_PREFIX="${EVIDENCE_DIR}/a3_discovery"
    echo -e "${C_PROMPT}[*]${C_RESET} Scanning for associated clients (20s)..."
    timeout 20 airodump-ng "$INTERFACE" --write "$DISC_PREFIX" --output-format csv > /dev/null 2>&1 || true

    for bssid in $HIDDEN_BSSIDS; do
        bssid_channel=$(awk -F',' -v b="$bssid" '
            $1 ~ b { ch=$4; gsub(/[[:space:]]/, "", ch); print ch; exit }
        ' "$A1_CSV" || true)
        if [[ -z "$bssid_channel" ]]; then
            echo -e "[!] No channel info for ${C_VAR}$bssid${C_RESET} in A1 data — skipping."
            continue
        fi

        client=$(awk -F',' -v b="$bssid" '$6 ~ b {print $1}' "${DISC_PREFIX}-01.csv" 2>/dev/null | head -1 | tr -d ' ' || true)
        if [[ ! "$client" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
            echo -e "[*] No associated client found for ${C_VAR}$bssid${C_RESET} — skipping deauth."
            continue
        fi

        echo -e "[*] Target: ${C_VAR}$bssid${C_RESET} ch ${bssid_channel}, client ${C_VAR}$client${C_RESET}"
        iw dev "$INTERFACE" set channel "$bssid_channel" 2>/dev/null || true

        # Start focused capture BEFORE deauth — probe response window is milliseconds wide
        FOCUSED_PREFIX="${EVIDENCE_DIR}/a3_focused_${bssid//:/_}"
        timeout 12 airodump-ng "$INTERFACE" \
            --bssid "$bssid" --channel "$bssid_channel" \
            --write "$FOCUSED_PREFIX" --output-format csv > /dev/null 2>&1 &
        FOCUSED_PID=$!
        sleep 1  # Allow airodump-ng to initialize and start capturing

        # Deauth forces client to re-associate, sending probe request that reveals SSID
        aireplay-ng --deauth 5 -a "$bssid" -c "$client" "$INTERFACE" > /dev/null 2>&1 || true

        wait "$FOCUSED_PID" 2>/dev/null || true

        if [[ -f "${FOCUSED_PREFIX}-01.csv" ]]; then
            mv "${FOCUSED_PREFIX}-01.csv" "${FOCUSED_PREFIX}.csv"
            REVEALED_SSID=$(awk -F',' -v b="$bssid" '
                NR > 1 {
                    bssid_f = $1; ssid = $14;
                    gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid_f);
                    gsub(/^[ \t\r\n"<>]+|[ \t\r\n"<>]+$/, "", ssid);
                    if (bssid_f == b && ssid != "" && ssid !~ /^length:/ && ssid != "HIDDEN") {
                        print ssid; exit
                    }
                }
            ' "${FOCUSED_PREFIX}.csv" || true)
            if [[ -n "$REVEALED_SSID" ]]; then
                echo -e "[!] ${C_BOLD}DEANONYMIZED:${C_RESET} ${C_VAR}${bssid}${C_RESET} -> ${C_VAR}${REVEALED_SSID}${C_RESET}"
                "$ASTRA_BIN" record-finding \
                    --session-dir "$SESSION_DIR" \
                    --tc "$TC_ID" \
                    --type vulnerability \
                    --name "Hidden SSID Revealed" \
                    --severity MEDIUM \
                    --desc "Successfully revealed hidden network name: ${REVEALED_SSID} (BSSID: ${bssid})" \
                    --evidence "${FOCUSED_PREFIX}.csv"
                REVEALED_COUNT=$((REVEALED_COUNT + 1))
                ALREADY_REVEALED["$bssid"]=1
            fi
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
    timeout "$SCAN_TIME" airodump-ng "$INTERFACE" --write "$CSV_PREFIX" --output-format csv > /dev/null 2>&1 &
    TOOL_PID=$!
    wait "$TOOL_PID" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Scan Complete"

if [[ -f "${CSV_PREFIX}-01.csv" ]]; then
    mv "${CSV_PREFIX}-01.csv" "$OUTPUT_CSV"
fi

# 4. Passive Analysis — catches reveals that active deauth missed (no client found)
# or natural re-associations during the monitoring window.
REVEALED_FILE="${EVIDENCE_DIR}/a3_revealed.txt"
if [[ -f "$OUTPUT_CSV" ]]; then
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

    if [[ -s "$REVEALED_FILE" ]]; then
        while read -r line; do
            [[ -z "$line" ]] && continue
            bssid="${line% -> *}"; ssid="${line#* -> }"
            # Skip BSSIDs already recorded by the active reveal phase
            [[ "${ALREADY_REVEALED[$bssid]+_}" ]] && continue
            echo -e "[!] ${C_BOLD}DEANONYMIZED:${C_RESET} ${C_VAR}${bssid}${C_RESET} -> ${C_VAR}${ssid}${C_RESET}"
            "$ASTRA_BIN" record-finding \
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
fi

if [[ $REVEALED_COUNT -eq 0 ]]; then
    echo -e "[+] No hidden SSIDs deanonymized in this window."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[A3] Audit Complete" \
        --severity INFO \
        --desc "Hidden SSID discovery completed. No SSIDs were revealed during the scan window." \
        --evidence "$A1_CSV" \
        --rationale "Hidden SSIDs provide minimal security — a client probe response or natural re-association reveals them. Lack of reveal in this window may indicate no active clients or PMF-protected networks."
fi


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
