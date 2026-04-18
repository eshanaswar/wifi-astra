#!/usr/bin/env bash
# MODULE_META
# NAME="BSSID Correlation Analysis"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng"
# DESC="Correlate BSSIDs to shared controllers via OUI vendor lookup, probe patterns, and SSID clustering"
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

# Check for at least one valid AP data line (MAC address format) in the file
if ! awk -F',' '$1 ~ /^[[:space:]]*[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}[[:space:]]*$/ {found=1; exit} END {exit !found}' "$A1_CSV" 2>/dev/null; then
    echo "[!] A1 results file has no AP data (may be headers only)."
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

# Extract valid AP records from A1 CSV (BSSID is field 1, ESSID is field 14)
AP_DATA=$(awk -F',' '
    NR > 1 && $1 ~ /^[[:space:]]*[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}[[:space:]]*$/ {
        bssid = $1; ssid = $14;
        gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", bssid);
        gsub(/^[ \t\r\n"]+|[ \t\r\n"]+$/, "", ssid);
        print bssid "|" ssid
    }
' "$A1_CSV" | sort -u)

{
    echo "============================================================"
    echo "  A2: BSSID Correlation Analysis"
    echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
    echo ""

    # --- Group 1: OUI prefix (first 3 octets = hardware vendor) ---
    echo "[ OUI Groups — same hardware vendor ]"
    echo "$AP_DATA" | awk -F'|' '{print $1}' | cut -d':' -f1-3 | sort | uniq -c | sort -rn | while read -r count oui; do
        [[ -z "$oui" ]] && continue
        VENDOR=$("$ASTRA_BIN" lookup-oui "$oui" 2>/dev/null || echo "Unknown")
        echo "[*] OUI: $oui [$VENDOR] — $count BSSIDs"
        echo "$AP_DATA" | awk -F'|' -v pfx="$oui" '
            substr($1,1,length(pfx)) == pfx {
                printf "    - %s : %s\n", $1, ($2 == "" ? "<hidden>" : $2)
            }'
        echo ""
    done

    # --- Group 2: Sequential BSSID detection (same physical AP, multiple virtual SSIDs) ---
    # In enterprise APs, multiple BSSIDs are allocated sequentially on the same hardware:
    # aa:bb:cc:dd:ee:00 (corporate WPA2-Enterprise)
    # aa:bb:cc:dd:ee:01 (guest WPA2-PSK)
    # aa:bb:cc:dd:ee:02 (IoT isolated)
    # Differing only in the last byte by ≤8 strongly indicates the same physical radio.
    echo "[ Sequential BSSID Groups — likely same physical AP ]"
    SAME_HW_FOUND=0
    # Group by first 5 octets
    FIVE_OCTET_GROUPS=$(echo "$AP_DATA" | awk -F'|' '{print $1}' | \
        awk -F: '{printf "%s:%s:%s:%s:%s\n",$1,$2,$3,$4,$5}' | sort | uniq -d)
    if [[ -n "$FIVE_OCTET_GROUPS" ]]; then
        while IFS= read -r prefix; do
            [[ -z "$prefix" ]] && continue
            MEMBERS=$(echo "$AP_DATA" | awk -F'|' -v pfx="$prefix" '
                substr($1,1,length(pfx)) == pfx {
                    printf "    - %s : %s\n", $1, ($2 == "" ? "<hidden>" : $2)
                }')
            COUNT=$(echo "$MEMBERS" | wc -l)
            echo "[!] Sequential group ($COUNT BSSIDs share prefix ${prefix}:xx) — likely 1 physical AP:"
            echo "$MEMBERS"
            echo ""
            SAME_HW_FOUND=1
        done <<< "$FIVE_OCTET_GROUPS"
    fi
    if [[ "$SAME_HW_FOUND" -eq 0 ]]; then
        echo "    (none detected — each BSSID prefix is unique)"
        echo ""
    fi

    # --- Group 3: Same SSID on multiple OUIs — potential rogue/evil twin indicator ---
    echo "[ Same SSID on Multiple OUIs — potential evil twin / rogue AP ]"
    DUPE_SSID_FOUND=0
    echo "$AP_DATA" | awk -F'|' '$2 != "" && $2 != "<hidden>"' | \
        awk -F'|' '{seen[$2] = seen[$2] " " $1; count[$2]++} END {for (s in count) if (count[s]>1) print count[s] "|" s "|" seen[s]}' | \
        sort -t'|' -k1 -rn | while IFS='|' read -r cnt ssid bssid_list; do
            oui_list=$(echo "$bssid_list" | tr ' ' '\n' | grep -v '^$' | cut -d: -f1-3 | sort -u | tr '\n' ' ')
            oui_count=$(echo "$oui_list" | wc -w)
            if [[ "$oui_count" -gt 1 ]]; then
                echo "[!] SSID '$ssid' seen on $cnt BSSIDs across $oui_count different OUIs:"
                echo "$bssid_list" | tr ' ' '\n' | grep -v '^$' | while read -r b; do
                    V=$("$ASTRA_BIN" lookup-oui "$b" 2>/dev/null || echo "Unknown")
                    echo "    - $b [$V]"
                done
                echo "    ^ Investigate for rogue AP or misconfigured infra"
                echo ""
                DUPE_SSID_FOUND=1
            fi
        done
    if [[ "$DUPE_SSID_FOUND" -eq 0 ]]; then
        echo "    (none detected)"
        echo ""
    fi

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


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
