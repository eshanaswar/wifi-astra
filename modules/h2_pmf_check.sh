#!/usr/bin/env bash
# MODULE_META
# NAME="802.11w PMF Configuration Check"
# CATEGORY="H"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airodump-ng"
# DESC="Passive check for Protected Management Frames (PMF) support"
# REQS="monitor_iface,target_bssid"
# PCAP="no"
# TIMED="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/h2_pmf_check.sh
#  H2: 802.11w PMF Configuration Check (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Capture a Beacon or Probe Response frame from the target AP.
#  2. Parse the RSN (Robust Security Network) capabilities field.
#  3. Verify the state of Protected Management Frames (PMF):
#     - Required: Mandatory 802.11w.
#     - Capable: Optional 802.11w.
#     - None: No protection against deauth/disassoc attacks.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/h2"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="H2"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] [$TC_ID] Checking for 802.11w PMF support on ${BSSID}..."
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 20 --status "Capturing management frames..."

MFP_FILE="${EVIDENCE_PREFIX}_mfp_status.txt"
PCAP_FILE="${EVIDENCE_PREFIX}_beacon.pcap"

# Cleanup function
cleanup() {
    [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "${TCPDUMP_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Capture and Parse
if command -v tshark &>/dev/null; then
    echo "[*] Analyzing RSN capabilities with tshark..."
    # Capture beacon frames (runs in background in both modes; killed after fixed wait)
    tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID and type mgt subtype beacon" > /dev/null 2>&1 &
    TCPDUMP_PID=$!
    
    # Wait with real-time progress updates
    ELAPSED=0
    WAIT_TIME=10
    while [[ $ELAPSED -lt $WAIT_TIME ]]; do
        PERCENT=$(( 20 + (ELAPSED * 40 / WAIT_TIME) )) # Start from 20%, up to 60%
        STATUS="Capturing management frames... ($(( WAIT_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        
        sleep 2
        ((ELAPSED+=2))
    done
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    
    if [[ -f "$PCAP_FILE" && -s "$PCAP_FILE" ]]; then
        # Extract RSN capability lines from the beacon — tshark verbose output contains:
        #   "Management Frame Protection Required: True/False"
        #   "Management Frame Protection Capable: True/False"
        # We must match "True" explicitly; "Required: False" must NOT fire the Required branch.
        tshark -r "$PCAP_FILE" -V 2>/dev/null | grep -Ei "Management Frame Protection" > "$MFP_FILE" || true

        if grep -qi "Management Frame Protection Required.*True" "$MFP_FILE"; then
            echo "[+] PMF IS REQUIRED BY THE AP."
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "PMF Required (802.11w)" \
                --severity "INFO" \
                --desc "Target AP (${BSSID}) strictly enforces Protected Management Frames (RSN Capable + Required both True)." \
                --evidence "$MFP_FILE" \
                --rationale "Mandatory PMF provides the highest level of protection against deauthentication and disassociation attacks. Clients must also support 802.11w to benefit."
        elif grep -qi "Management Frame Protection Capable.*True" "$MFP_FILE"; then
            echo "[+] PMF IS SUPPORTED (OPTIONAL) BY THE AP."
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "PMF Optional (802.11w)" \
                --severity "LOW" \
                --desc "Target AP (${BSSID}) advertises PMF Capable but does not require it. Clients that do not negotiate 802.11w remain unprotected." \
                --evidence "$MFP_FILE" \
                --rationale "Optional PMF (Capable but not Required) allows legacy client compatibility but means not all clients are protected. WIDS can still be bypassed by forcing legacy associations."
        else
            echo "[!] PMF IS NOT SUPPORTED BY THE AP."
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "Missing PMF (802.11w)" \
                --severity "MEDIUM" \
                --desc "Target AP (${BSSID}) RSN capabilities show no Management Frame Protection support. All clients on this BSSID are vulnerable to deauthentication attacks." \
                --evidence "$MFP_FILE" \
                --rationale "Without 802.11w, any attacker in radio range can forge deauth/disassoc frames to disconnect clients, enabling persistent DoS or forcing 4-way handshake captures for offline cracking."
        fi
    else
        echo "[!] No beacon captured for ${BSSID}."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Incomplete - No Beacon" \
            --severity "INFO" \
            --desc "Could not capture a beacon frame for ${BSSID} to verify PMF status." \
            --evidence "$PCAP_FILE" \
            --rationale "Unable to analyze RSN capabilities without a management frame from the target AP."
    fi
else
    echo "[!] tshark not found. Skipping deep analysis."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Skipped - Missing Tool" \
        --severity "INFO" \
        --desc "tshark is missing; unable to perform deep packet analysis of PMF capabilities." \
        --evidence "/dev/null" \
        --rationale "RSN capability parsing requires tshark for reliable interpretation of management frame protection bits."
fi

echo "[+] PMF check complete."
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "PMF configuration audit complete."

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
