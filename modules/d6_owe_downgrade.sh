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

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] OWE scanning/spoofing is unreliable at this distance."
    stty sane
    read -p "$(echo -e "${C_ACTION} [?] Continue anyway? [y/N]: ${C_RESET} ")" snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
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
echo "[*] Scanning for OWE Transition Mode beacons (15s)..."
airodump-ng --essid "$SSID" --write "$SCAN_PREFIX" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
AIRODUMP_PID=$!
sleep 15
kill "$AIRODUMP_PID" || true
wait "$AIRODUMP_PID" 2>/dev/null || true

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

exit 0
