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
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/b2_mgmt_exposure.sh
#  B2: AP Management Exposure (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
GATEWAY="${GATEWAY_IP:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/b2"
TC_ID="B2"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

# Color variables
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

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
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Scanning management ports (nmap)..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

# TCP scan — management web/SSH/Telnet
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -Pn -p 22,23,80,443,8080,8443 "$GATEWAY" -sV \
        -oG "${EVIDENCE_PREFIX}_nmap_tcp.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml" || true
else
    timeout "$SCAN_TIME" nmap -Pn -p 22,23,80,443,8080,8443 "$GATEWAY" -sV \
        -oG "${EVIDENCE_PREFIX}_nmap_tcp.gnmap" -oX "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
        > "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 || true
fi

# UDP scan for SNMP (separate — TCP scan silently misses UDP 161)
echo "[*] Scanning UDP port 161 (SNMP)..."
timeout 30 nmap -Pn -sU -p 161 "$GATEWAY" -sV \
    -oG "${EVIDENCE_PREFIX}_nmap_udp.gnmap" >> "${EVIDENCE_DIR}/${TC_ID}_nmap.log" 2>&1 || true
# Merge gnmap files for unified parsing
cat "${EVIDENCE_PREFIX}_nmap_tcp.gnmap" "${EVIDENCE_PREFIX}_nmap_udp.gnmap" 2>/dev/null \
    > "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" || true

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."

# Parse open ports from grepable nmap output
FOUND=0
if [[ -f "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap" ]]; then
    while read -r line; do
        ports_part=$(echo "$line" | sed -n 's/.*Ports: //p')
        [[ -z "$ports_part" ]] && continue

        IFS=', ' read -r -a ports_array <<< "$ports_part"
        for p_entry in "${ports_array[@]}"; do
            if echo "$p_entry" | grep -q "/open/"; then
                port=$(echo "$p_entry" | cut -d'/' -f1 | xargs)
                service=$(echo "$p_entry" | cut -d'/' -f5 | xargs)
                version=$(echo "$p_entry" | cut -d'/' -f7 | xargs)

                # Per-port severity: Telnet/HTTP cleartext admin = HIGH; SSH/HTTPS = MEDIUM; SNMP = HIGH
                case "$port" in
                    23|161)  PORT_SEV="HIGH" ;;
                    80|8080) PORT_SEV="MEDIUM" ;;
                    *)       PORT_SEV="MEDIUM" ;;
                esac

                echo -e "[!] ${C_BOLD}EXPOSED:${C_RESET} Management port ${C_VAR}${port}${C_RESET} (${service} ${version}) [${PORT_SEV}]"
                FOUND=1

                $ASTRA_BIN record-finding \
                    --session-dir "$SESSION_DIR" \
                    --tc "$TC_ID" \
                    --type vulnerability \
                    --name "Exposed Management Port: $port ($service)" \
                    --severity "$PORT_SEV" \
                    --desc "Gateway ($GATEWAY) exposes management port $port ($service $version) to the wireless client segment." \
                    --target "$GATEWAY" \
                    --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
                    --rationale "Exposed management interfaces allow attackers to attempt authentication brute-force or exploit cleartext protocols (Telnet/HTTP) from the client segment."
            fi
        done
    done < <(grep "Ports:" "${EVIDENCE_PREFIX}_nmap_mgmt.gnmap")
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No management interfaces detected on the gateway."
    $ASTRA_BIN record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[B2] Audit Complete" \
        --severity INFO \
        --desc "No common management ports (22,23,80,443,161,8080,8443) found open on gateway ($GATEWAY)." \
        --evidence "${EVIDENCE_PREFIX}_nmap_mgmt.xml" \
        --rationale "Hiding management interfaces from client segments is a best practice to prevent unauthorized administrative attempts."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
