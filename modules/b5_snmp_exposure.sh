#!/usr/bin/env bash
# MODULE_META
# NAME="SNMP Exposure"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="snmp-check,onesixtyone"
# DESC="Probe for SNMP services with default/common communities"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

set -euo pipefail

#  modules/b5_snmp_exposure.sh
#  B5: SNMP Information Exposure

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
GATEWAY="${GATEWAY_IP:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B5"

if [[ -z "$GATEWAY" ]]; then
    GATEWAY=$(ip -4 route show dev "${INTERFACE:-}" | awk '/default/{print $3}' | head -1 || true)
fi

if [[ -z "$GATEWAY" ]]; then
    echo "[!] GATEWAY_IP not set and could not be detected."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
BRUTE_FILE="${EVIDENCE_PREFIX}_brute.txt"

echo "[*] [$TC_ID] Identifying SNMP exposure on ${GATEWAY}..."

# Identify & Target
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "SNMP scan active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            ELAPSED=$((ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing scan..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

# Locate SecLists SNMP wordlist — the correct filename on Kali is snmp-onesixtyone.txt.
# Fall back to a hardcoded minimal list that covers the most commonly found community
# strings in real-world pentest engagements if SecLists is not installed.
COMMUNITY_LIST=""
SECLISTS_SNMP="/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt"
FALLBACK_WORDLIST="${EVIDENCE_DIR}/${TC_ID}_communities.txt"

if [[ -f "$SECLISTS_SNMP" ]]; then
    COMMUNITY_LIST="$SECLISTS_SNMP"
else
    # Minimal high-yield list when SecLists is absent
    cat > "$FALLBACK_WORDLIST" <<'EOF'
public
private
community
manager
admin
cisco
snmp
monitor
agent
write
secret
internal
access
default
test
1234
EOF
    COMMUNITY_LIST="$FALLBACK_WORDLIST"
    echo "[*] SecLists not found — using built-in community string list (${FALLBACK_WORDLIST})"
fi

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" onesixtyone -c "$COMMUNITY_LIST" "$GATEWAY" | tee "$BRUTE_FILE" || true
else
    timeout "$SCAN_TIME" onesixtyone -c "$COMMUNITY_LIST" "$GATEWAY" > "$BRUTE_FILE" 2>&1 || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Verifying community strings..."
COMM_STRINGS=$(grep "\[" "$BRUTE_FILE" | awk '{print $2}' | tr -d '[]' || true)

if [[ -n "$COMM_STRINGS" ]]; then
    while read -r comm; do
        [[ -z "$comm" ]] && continue
        echo "[!] SNMP COMMUNITY STRING FOUND: ${comm}!"
        if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
            SYS_INFO=$(snmpwalk -v2c -c "$comm" "$GATEWAY" system | head -n 5 || true)
        else
            SYS_INFO=$(snmpwalk -v2c -c "$comm" "$GATEWAY" system 2>/dev/null | head -n 5 || true)
        fi
        
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "SNMP Community String Exposed" \
            --desc "Found valid SNMP community string: '${comm}' on $GATEWAY. Info: $SYS_INFO" \
            --severity "HIGH" \
            --evidence "$BRUTE_FILE" \
            --rationale "Publicly accessible SNMP community strings allow attackers to gather infrastructure info or modify device configuration."
    done <<< "$COMM_STRINGS"
else
    echo "[+] No SNMP exposure detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No common SNMP community strings were found on the gateway ($GATEWAY)." \
        --severity "INFO" \
        --evidence "$BRUTE_FILE" \
        --rationale "Ensuring SNMP is disabled or properly secured is a fundamental network security control."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0

