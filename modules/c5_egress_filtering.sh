#!/usr/bin/env bash
# MODULE_META
# NAME="Egress Port Filtering"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Test which outbound ports are allowed through the wireless gateway"
# REQS="managed_iface"
# PCAP="no"
# TIMED="yes"
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/c5_egress_filtering.sh
#  C5: Egress Port Filtering (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
EGRESS_TARGET="${EGRESS_TARGET:-1.1.1.1}" 
TC_ID="C5"
OUTPUT_XML="${EVIDENCE_DIR}/${TC_ID}_nmap_egress.xml"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Testing outbound egress filtering from ${INTERFACE} to ${EGRESS_TARGET}..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Testing outbound port filtering (nmap)..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (nmap)
# TCP egress interpretation against an external host (e.g., 1.1.1.1):
#   open     = SYN-ACK received — firewall allowed AND service listening
#   closed   = RST received — firewall allowed, but no service on that port at target
#   filtered = no response — firewall is BLOCKING outbound (no RST reached target)
# Both "open" and "closed" confirm outbound traffic was NOT blocked by the firewall.
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -Pn -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080 "$EGRESS_TARGET" -oX "$OUTPUT_XML" || true
else
    timeout "$SCAN_TIME" nmap -Pn -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080 "$EGRESS_TARGET" -oX "$OUTPUT_XML" > /dev/null 2>&1 || true
fi

# 3. Cleanup
kill $TEL_PID 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."

# Parse allowed ports: both "open" (service responded) and "closed" (RST received) prove egress is not blocked.
# "filtered" means the firewall dropped the packet — those are correctly blocked.
ALLOWED_PORTS=$(awk -F'"' '/<port / {p=$4} /<state / {s=$4; if(s=="open" || s=="closed") print p}' "$OUTPUT_XML" \
    2>/dev/null | sort -n | xargs || true)

# Dangerous ports that should always be blocked on guest/WiFi segments
DANGEROUS_PORTS=("23" "25" "110" "139" "445" "1433" "3306" "3389")

FOUND=0
if [[ -n "$ALLOWED_PORTS" ]]; then
    FOUND=1
    ALLOWED_CSV=$(echo "$ALLOWED_PORTS" | sed 's/ /, /g')
    echo "[!] ALLOWED OUTBOUND PORTS: $ALLOWED_CSV"

    # Check for high-risk dangerous ports in the allowed set
    DANGEROUS_FOUND=()
    for dp in "${DANGEROUS_PORTS[@]}"; do
        for ap in $ALLOWED_PORTS; do
            if [[ "$ap" == "$dp" ]]; then
                DANGEROUS_FOUND+=("$dp")
                break
            fi
        done
    done

    if [[ ${#DANGEROUS_FOUND[@]} -gt 0 ]]; then
        DANGEROUS_CSV=$(printf "%s," "${DANGEROUS_FOUND[@]}" | sed 's/,$//')
        echo "[!] HIGH-RISK ports allowed outbound: ${DANGEROUS_CSV}"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Dangerous Outbound Ports Unfiltered" \
            --desc "High-risk ports are allowed outbound to ${EGRESS_TARGET}: ${DANGEROUS_CSV}. These ports facilitate C2, lateral movement, and data exfiltration (Telnet, SMTP, SMB, RDP, database protocols)." \
            --severity HIGH \
            --evidence "$OUTPUT_XML" \
            --rationale "Ports 23/25/445/3389/1433/3306 are primary attack channels. Allowing them outbound from a wireless segment enables C2 beaconing, credential theft via SMB, and database exfiltration."
    fi

    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Permissive Egress Filtering Policy" \
        --desc "The following outbound ports are not filtered (traffic reached ${EGRESS_TARGET}): ${ALLOWED_CSV}. Both open and closed states confirm traffic passed through the gateway firewall." \
        --severity MEDIUM \
        --evidence "$OUTPUT_XML" \
        --rationale "Strict egress filtering (deny-all, allow-list) is a key defense-in-depth control. Permissive egress allows C2 beaconing and data exfiltration from compromised wireless clients."
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] All tested ports filtered. Egress policy appears restrictive."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "All tested outbound ports (21,22,23,25,53,80,110,139,443,445,1433,3306,3389,8080) were filtered from the wireless segment to ${EGRESS_TARGET}." \
        --severity INFO \
        --evidence "$OUTPUT_XML" \
        --rationale "Strict egress filtering is present, reducing C2 beaconing and data exfiltration risk."
fi

# FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
