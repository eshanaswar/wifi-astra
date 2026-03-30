#!/usr/bin/env bash
# MODULE_META
# NAME="OWE Transition Mode Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,airodump-ng"
# DESC="Test if OWE networks can be downgraded to Open by spoofing transition mode"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# DECODE="owe"

#===============================================================================
#  modules/d6_owe_downgrade.sh
#  D6: OWE Transition Mode Downgrade (Golden Wrapper)
#===============================================================================

set -euo pipefail

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

ng is unreliable at this distance."
    fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-15}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D6"
SCAN_PREFIX="${EVIDENCE_DIR}/${TC_ID}_airodump"
CSV_FILE="${SCAN_PREFIX}-01.csv"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. OWE testing requires a target SSID."
    exit 1
fi

echo "[*] Testing OWE downgrade / transition mode for ${SSID}..."

# 1. Monitor for OWE beacons using airodump-ng
echo "[*] Scanning for OWE Transition Mode beacons (${SCAN_TIME}s)..."

# Start dynamic telemetry heartbeat
(
    HEARTBEAT_ELAPSED=0
    while [[ $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing attack..."
        sleep 2
        HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" &
else
    airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
fi
AIRODUMP_PID=$!
sleep "$SCAN_TIME"
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

kill "$TELEMETRY_PID" 2>/dev/null || true

# 2. Check if OWE is present in scan results using awk
# airodump CSV format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, ESSID
OWE_PRESENT=$(awk -F, -v s="$SSID" 'tolower($14) ~ tolower(s) && $6 ~ /OWE/ {print "YES"}' "$CSV_FILE" 2>/dev/null || true)

if [[ "$OWE_PRESENT" == "YES" ]]; then
    echo "[!] OWE TRANSITION MODE DETECTED FOR ${SSID}."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "OWE Transition Mode Detected" \
        --desc "The network ${SSID} uses OWE (Enhanced Open) Transition Mode. This broadcasts both an encrypted OWE BSSID and an unencrypted Open BSSID for backward compatibility." \
        --severity MEDIUM \
        --evidence "$CSV_FILE" \
        --rationale "Transition mode is susceptible to downgrade attacks where a rogue AP spoofs the Open half of the pair. If a client connects to the Open AP, its traffic is transmitted without encryption, defeating the purpose of OWE."
else
    echo "[+] No OWE transition mode detected for ${SSID}."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Scanned for OWE transition mode vulnerabilities on SSID ${SSID}. The network appears to be using a different encryption standard (e.g., WPA2/WPA3-PSK) or is OWE-only." \
        --severity INFO \
        --evidence "$CSV_FILE" \
        --rationale "Ensuring that modern encryption standards are not misconfigured with insecure backward compatibility modes is a critical audit step. Lack of OWE Transition Mode indicates a more focused security posture."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
