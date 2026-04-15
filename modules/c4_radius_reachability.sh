#!/usr/bin/env bash
# MODULE_META
# NAME="RADIUS Server Reachability"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Identify reachable RADIUS servers from target WiFi"
# REQS="managed_iface"
# PCAP="no"
# TIMED="yes"
# DECODE="none"
# PROMPTS="managed_connect"

#  modules/c4_radius_reachability.sh
#  C4: RADIUS Server Reachability

set -euo pipefail

# Inputs from Environment
SCAN_TIME="${SCAN_TIME:-60}"

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C4"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
OUTPUT_XML="${EVIDENCE_PREFIX}_nmap_radius.xml"

echo "[*] [$TC_ID] Identifying reachable RADIUS servers from ${INTERFACE}..."

# Build dynamic candidate list: include local gateway and DNS as RADIUS often co-locates with those
LOCAL_GW=$(ip -4 route show dev "$INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1 || true)
LOCAL_DNS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | grep -v "127\." | head -1 | awk '{print $2}' || true)

# Static RFC1918 candidates + dynamic local addresses
RADIUS_CANDIDATES=("10.0.0.10" "10.1.1.10" "172.16.0.10" "192.168.1.10" "10.0.0.1" "192.168.1.1")
[[ -n "$LOCAL_GW" ]]  && RADIUS_CANDIDATES+=("$LOCAL_GW")
[[ -n "$LOCAL_DNS" ]] && RADIUS_CANDIDATES+=("$LOCAL_DNS")

# Deduplicate
mapfile -t RADIUS_CANDIDATES < <(printf "%s\n" "${RADIUS_CANDIDATES[@]}" | sort -u | grep -v "^$")

echo "[*] Probing ${#RADIUS_CANDIDATES[@]} RADIUS candidates..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Probing RADIUS candidates (nmap)..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (nmap UDP)
# UDP RADIUS scan: RADIUS servers typically do not respond to invalid probes.
# nmap will show "open|filtered" (no response) for hosts that are listening but not answering the probe.
# "open" only appears if the server sends a RADIUS Access-Reject/Access-Accept to the probe packet.
# We flag BOTH "open" and "open|filtered" since both indicate the port is not firewall-blocked.
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" nmap -Pn -sU -p 1812,1813,1645,1646 "${RADIUS_CANDIDATES[@]}" -oX "$OUTPUT_XML" || true
else
    timeout "$SCAN_TIME" nmap -Pn -sU -p 1812,1813,1645,1646 "${RADIUS_CANDIDATES[@]}" -oX "$OUTPUT_XML" >/dev/null 2>&1 || true
fi

# 3. Cleanup
kill $TEL_PID 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."

# Verify
FOUND=0

# Definitive: port responded (RADIUS sent Access-Reject to probe)
OPEN_CONFIRMED=$(grep -E "state=\"open\"" "$OUTPUT_XML" 2>/dev/null || true)
if [[ -n "$OPEN_CONFIRMED" ]]; then
    FOUND=1
    OPEN_HOSTS=$(grep -B5 "state=\"open\"" "$OUTPUT_XML" 2>/dev/null | grep "addr=" | awk -F'"' '{print $2}' | sort -u | xargs || true)
    echo "[!] CRITICAL: RADIUS port confirmed open — server responded: ${OPEN_HOSTS}"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "RADIUS Server Reachable and Responding" \
        --desc "RADIUS authentication port confirmed open (server responded) on: ${OPEN_HOSTS}." \
        --severity "HIGH" \
        --evidence "$OUTPUT_XML" \
        --rationale "A reachable RADIUS server can be brute-forced or probed for EAP credential harvesting from the guest segment."
fi

# Inconclusive: no response — could be listening but not responding to probes, or filtered
OPEN_FILTERED=$(grep -E "state=\"open\|filtered\"" "$OUTPUT_XML" 2>/dev/null || true)
if [[ -n "$OPEN_FILTERED" ]]; then
    FOUND=1
    FILTERED_HOSTS=$(grep -B5 "state=\"open|filtered\"" "$OUTPUT_XML" 2>/dev/null | grep "addr=" | awk -F'"' '{print $2}' | sort -u | xargs || true)
    echo "[?] RADIUS port open|filtered on ${FILTERED_HOSTS} — may be reachable but not responding to probes."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "RADIUS Port Potentially Reachable (open|filtered)" \
        --desc "RADIUS UDP ports returned open|filtered on: ${FILTERED_HOSTS}. The firewall may not be blocking these ports — RADIUS typically does not respond to unauthenticated probes." \
        --severity "MEDIUM" \
        --evidence "$OUTPUT_XML" \
        --rationale "Open|filtered indicates traffic may be reaching the RADIUS service. Manual verification with a valid EAP exchange is needed to confirm reachability."
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No RADIUS servers detected (all ports closed or filtered)."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No RADIUS authentication services were reachable from the guest segment." \
        --severity "INFO" \
        --evidence "$OUTPUT_XML" \
        --rationale "Segmented guest networks should not communicate with core authentication infrastructure."
fi

# FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
