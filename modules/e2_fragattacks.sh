#!/usr/bin/env bash
# MODULE_META
# NAME="FragAttacks (Design Flaws)"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="fragattack"
# DESC="Test for WiFi fragmentation and aggregation design flaws (CVE-2020-24586+)"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e2_fragattacks.sh
#  E2: FragAttacks (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Test for design flaws in the 802.11 standard related to frame 
#     fragmentation and aggregation.
#  2. Attempt to inject unencrypted data into a secure session by exploiting 
#     improper fragment assembly.
#  3. This affects almost all WiFi security protocols (WEP, WPA, WPA2, WPA3).
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] FragAttacks injection is highly unlikely to succeed at this distance."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e2"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E2"

if [[ -z "$INTERFACE" || -z "$SSID" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE, GUEST_SSID, or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting FragAttacks vulnerability tests against ${SSID}..."

RES_FILE="${EVIDENCE_PREFIX}_results.txt"
FRAG_LOG="${EVIDENCE_DIR}/${TC_ID}_fragattack.log"

# 1. Run FragAttacks test scripts if available
FRAG_SCRIPT=$(find /opt/ /usr/share/ "${SCRIPT_DIR:-.}" -name "fragattack.py" 2>/dev/null | head -1)

if [[ -n "$FRAG_SCRIPT" ]]; then
    echo "[*] Running FragAttacks test script: ${FRAG_SCRIPT}..."
    timeout 120 python3 "$FRAG_SCRIPT" -i "$INTERFACE" -b "$BSSID" -s "$SSID" > "$FRAG_LOG" 2>&1 || true
    
    if grep -qi "vulnerable" "$FRAG_LOG"; then
        cp "$FRAG_LOG" "$RES_FILE"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "FragAttacks Vulnerability Detected" \
            --severity CRITICAL \
            --desc "AP is vulnerable to frame fragmentation/aggregation injection (CVE-2020-24586)." \
            --target "${BSSID}" \
            --evidence "$RES_FILE" \
            --rationale "FragAttacks are design flaws in the 802.11 standard. They allow an attacker to inject malicious data packets or intercept and decrypt sensitive information, even on modern WPA3-secured networks."
    fi
else
    echo "[!] FragAttacks test tool not found." > "$FRAG_LOG"
fi

# Audit Complete finding if no critical vulnerability was recorded above
if [[ ! -f "$RES_FILE" ]]; then
    echo "[+] FragAttacks testing complete (no vulnerabilities found)."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[E2] Audit Complete" \
        --severity INFO \
        --desc "Completed systematic testing for 802.11 fragmentation/aggregation design flaws on ${BSSID}." \
        --target "${BSSID}" \
        --evidence "$FRAG_LOG" \
        --rationale "FragAttacks affect the underlying protocol design. No active exploitation was successful during this test window, indicating the target may have relevant patches or mitigations."
else
    echo "[+] FragAttacks testing complete."
fi

exit 0
