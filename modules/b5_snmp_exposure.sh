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
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing scan..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    if [[ -f "/usr/share/seclists/Discovery/SNMP/snmp-subs.txt" ]]; then
        onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-subs.txt "$GATEWAY"
    else
        onesixtyone "$GATEWAY"
    fi
    RET=$?
else
    if [[ -f "/usr/share/seclists/Discovery/SNMP/snmp-subs.txt" ]]; then
        onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-subs.txt "$GATEWAY" > "$BRUTE_FILE" 2>&1 &
    else
        onesixtyone "$GATEWAY" > "$BRUTE_FILE" 2>&1 &
    fi
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
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
exit 0

