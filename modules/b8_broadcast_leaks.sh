#!/usr/bin/env bash
# MODULE_META
# NAME="Broadcast & Multicast Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Analyze UDP traffic for SSDP/LLMNR/NetBIOS storms bleeding from corporate"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

#  modules/b8_broadcast_leaks.sh
#  B8: Broadcast/Multicast Leaks

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B8"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_broadcast.pcap"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying broadcast/multicast leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# Identify & Target
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Capturing broadcast traffic..."
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Run in foreground
    timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "broadcast or multicast" || true
else
    # Run with redirection
    tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "broadcast or multicast" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    (sleep "$SCAN_TIME"; kill "$TOOL_PID" 2>/dev/null || true) &
    wait "$TOOL_PID" 2>/dev/null || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing traffic patterns..."

# Only flag security-relevant protocols — not ordinary network traffic like ARP, DHCP, mDNS
# LLMNR (5355), NetBIOS-NS (137), NetBIOS-DGM (138), SSDP (1900) are indicators of
# corporate traffic bleeding into guest segments.
declare -A SENSITIVE_PROTOS
SENSITIVE_PROTOS["LLMNR"]="HIGH"
SENSITIVE_PROTOS["NBNS"]="HIGH"
SENSITIVE_PROTOS["NBDGM"]="MEDIUM"
SENSITIVE_PROTOS["SSDP"]="MEDIUM"

FOUND=0
if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
    PROTOCOLS=$(tshark -r "$PCAP_FILE" -T fields -e _ws.col.Protocol 2>/dev/null | sort | uniq -c | sort -nr || true)

    if [[ -n "$PROTOCOLS" ]]; then
        while read -r count proto; do
            [[ -z "$proto" ]] && continue
            SEVERITY="${SENSITIVE_PROTOS[$proto]:-}"
            [[ -z "$SEVERITY" ]] && continue  # Skip non-sensitive protocols
            FOUND=1
            echo "[!] Sensitive broadcast protocol detected: ${proto} (${count} packets)"
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type "vulnerability" \
                --name "Sensitive Broadcast Traffic: $proto" \
                --desc "Detected ${count} packets of ${proto} broadcast/multicast on the wireless segment. This protocol typically originates from Windows hosts and can reveal hostnames, services, and enable spoofing attacks." \
                --severity "$SEVERITY" \
                --evidence "$PCAP_FILE" \
                --rationale "${proto} traffic on a guest/wireless segment indicates potential corporate traffic bleed. LLMNR/NBNS are exploited by Responder for NTLM credential capture."
        done <<< "$PROTOCOLS"
    fi
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No sensitive broadcast traffic detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No significant or sensitive broadcast/multicast leaks were detected." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Restricting broadcast traffic is a key network hardening measure."
fi

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
