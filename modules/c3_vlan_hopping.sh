#!/usr/bin/env bash
# MODULE_META
# NAME="VLAN Hopping"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="yersinia,tcpdump"
# DESC="Attempt 802.1Q double-tagging and DTP spoofing to reach other VLANs"
# REQS="managed_iface"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="managed_connect"
# DECODE="none"

#  modules/c3_vlan_hopping.sh
#  C3: VLAN Hopping / Trunking Test

set -euo pipefail

# Inputs
INTERFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="C3"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] INTERFACE not set."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/${TC_ID}"
PCAP_FILE="${EVIDENCE_PREFIX}_trunking.pcap"
YERSINIA_OUT="${EVIDENCE_PREFIX}_yersinia.txt"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_tcpdump.log"

echo "[*] [$TC_ID] Identifying VLAN hopping / DTP leaks on ${INTERFACE} for ${SCAN_TIME}s..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "VLAN hopping test active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5; ELAPSED=$((ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing trunking & DTP audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (tcpdump + yersinia)
# DTP multicast: 01:00:0c:cc:cc:cc — switch sends this when port is in dynamic mode.
# If any DTP frames are captured, the switch port is NOT hardcoded to access mode.
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:00 or ether host 01:00:0c:cc:cc:cd" 2>&1 | tee "$LOG_FILE" || true

    if command -v yersinia &>/dev/null; then
        echo "[*] Attempting DTP trunk negotiation..."
        timeout 30 yersinia dtp -i "$INTERFACE" -n 1 2>&1 | tee "$YERSINIA_OUT" || true
    fi
else
    # Background path: plain timeout (not --foreground which is for interactive TTYs)
    timeout "$SCAN_TIME" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
        "ether host 01:00:0c:cc:cc:cc or ether host 01:80:c2:00:00:00 or ether host 01:00:0c:cc:cc:cd" > "$LOG_FILE" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true

    if command -v yersinia &>/dev/null; then
        timeout 30 yersinia dtp -i "$INTERFACE" -n 1 > "$YERSINIA_OUT" 2>&1 || true
    fi
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing findings..."

# Verify
FOUND=0

# Check PCAP for captured DTP/VTP frames — reliable indicator that switch port is in dynamic mode.
# grep -qi "DTP" on yersinia output is NOT reliable: yersinia always prints "DTP" (it's the protocol name).
# The PCAP is authoritative — the filter only captures DTP/VTP/STP multicast addresses.
if [[ -f "$PCAP_FILE" ]]; then
    DTP_FRAMES=$(tcpdump -r "$PCAP_FILE" -q 2>/dev/null | wc -l || echo 0)
    if [[ "$DTP_FRAMES" -gt 0 ]]; then
        FOUND=1
        echo "[!] ${DTP_FRAMES} DTP/VTP frame(s) captured — switch port is in dynamic mode."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type "vulnerability" \
            --name "DTP Frames Detected — Switch Port in Dynamic Mode" \
            --desc "Captured ${DTP_FRAMES} DTP/VTP management frame(s) on the wireless segment. The switch port is not hardcoded to access mode." \
            --severity "HIGH" \
            --evidence "$PCAP_FILE" \
            --rationale "DTP frames indicate the switch port is in dynamic mode. An attacker can negotiate a trunk and access all VLANs traversing that switch, completely bypassing network segmentation."
    fi
fi

# Check yersinia output for trunk negotiation success (distinct from just "DTP" appearing in output)
if [[ -f "$YERSINIA_OUT" ]] && grep -qi "TRUNK" "$YERSINIA_OUT"; then
    FOUND=1
    echo "[!] CRITICAL: DTP trunk negotiation succeeded."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "DTP Trunk Negotiation Succeeded" \
        --desc "Yersinia successfully negotiated a 802.1Q trunk on the wireless segment. VLAN hopping is possible." \
        --severity "CRITICAL" \
        --evidence "$YERSINIA_OUT" \
        --rationale "A negotiated trunk exposes all VLANs traversing this switch, allowing the attacker to access any network segment on the same physical switch fabric."
fi

if [[ $FOUND -eq 0 ]]; then
    echo "[+] No trunking protocol leaks detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type "vulnerability" \
        --name "[$TC_ID] Audit Complete" \
        --desc "No DTP or VTP management frames were detected, and trunk negotiation was refused." \
        --severity "INFO" \
        --evidence "$PCAP_FILE" \
        --rationale "Hardcoded access ports prevent VLAN hopping and are a key security configuration for untrusted client segments."
fi

# FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
