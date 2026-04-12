#!/usr/bin/env bash
# MODULE_META
# NAME="AP Management Exposure"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Check if AP management interfaces (Web, SSH, SNMP) are accessible"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# 
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/b2_mgmt_exposure.sh
#  B2: AP Management Exposure (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
GATEWAY="${GATEWAY_IP:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/b2"
TC_ID="B2"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

if [[ -z "$GATEWAY" ]]; then
    # Auto-detect if not set
    GATEWAY=$(ip -4 route show dev "${INTERFACE:-}" | awk '/default/{print $3}' | head -1 || true)
    if [[ -z "$GATEWAY" ]]; then
        echo "[!] Gateway IP not set or detected. Connect to WiFi first."
        exit 1
    fi
fi

echo "[*] Testing Management Exposure on ${GATEWAY}..."

# Scan common management ports on the gateway
echo "[*] Running Nmap scan for common management ports..."
(
    while true; do
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 25 --status "Scanning management ports (nmap)..."
        sleep 5
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -vv -Pn -p 22,23,80,443,161,8080,8443 "$GATEWAY" -sV -oG "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml" || true
    RET=$?
else
    nmap -vv -Pn -p 22,23,80,443,161,8080,8443 "$GATEWAY" -sV -oG "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml" > "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."

# Improved Robust Parsing
if [[ -f "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" ]]; then
    # Extract lines containing "Ports:", then split by comma
    while read -r line; do
        # Extract the ports section: everything after "Ports: "
        ports_part=$(echo "$line" | sed -n 's/.*Ports: //p')
        [[ -z "$ports_part" ]] && continue

        # Split ports by ", "
        IFS=', ' read -r -a ports_array <<< "$ports_part"
        for p_entry in "${ports_array[@]}"; do
            # Format: port/state/protocol/owner/service/rpcinfo/version
            if echo "$p_entry" | grep -q "/open/"; then
                port=$(echo "$p_entry" | cut -d'/' -f1 | xargs)
                service=$(echo "$p_entry" | cut -d'/' -f5 | xargs)
                version=$(echo "$p_entry" | cut -d'/' -f7 | xargs)
                
                echo -e "[!] ${C_BOLD}VULNERABILITY CONFIRMED:${C_RESET} Exposed management port: ${C_VAR}$port${C_RESET} ($service $version)"
                
                $ASTRA_BIN record-finding \
                    --session-dir "$SESSION_DIR" \
                    --tc "$TC_ID" \
                    --type vulnerability \
                    --name "Exposed Management Port: $port" \
                    --severity MEDIUM \
                    --desc "The gateway ($GATEWAY) has an exposed management port $port ($service $version)." \
                    --target "$GATEWAY" \
                    --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
                    --rationale "Exposed management interfaces should not be accessible from client segments."
            fi
        done
    done < <(grep "Ports:" "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap")
fi

echo "[+] No management interfaces detected on the AP."
$ASTRA_BIN record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "[B2] Audit Complete" \
    --severity INFO \
    --desc "No common management ports were found open on the gateway ($GATEWAY)." \
    --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
    --rationale "Hiding management interfaces from client segments is a best practice to prevent unauthorized administrative attempts. No risks were found in this interval."


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
