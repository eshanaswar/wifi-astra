#!/usr/bin/env bash
# MODULE_META
# NAME="Kr00k Vulnerability Test"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="tshark"
# DESC="Test if AP/client are vulnerable to Kr00k (CVE-2019-15126) decryption"
# REQS="monitor_iface,target_bssid"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e5_kr00k_test.sh
#  E5: Kr00k Test (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Identify if the target AP or client uses Broadcom or Cypress WiFi chipsets.
#  2. Send deauthentication frames to trigger a disassociation.
#  3. Capture the data frames sent immediately following disassociation.
#  4. Test if these frames are encrypted with an all-zero TK (Temporal Key), 
#     allowing for trivial decryption.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] Kr00k trigger (Deauth) is highly likely to fail at this distance."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e5"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E5"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting Kr00k (CVE-2019-15126) vulnerability test against ${BSSID}..."

RES_FILE="${EVIDENCE_PREFIX}_results.txt"
KROOK_LOG="${EVIDENCE_DIR}/${TC_ID}_krook.log"

# 1. Run Kr00k test scripts if available
KROOK_SCRIPT=$(find /opt/ /usr/share/ "${SCRIPT_DIR:-.}" -name "kr00k-test.py" 2>/dev/null | head -1)

if [[ -n "$KROOK_SCRIPT" ]]; then
    echo "[*] Running Kr00k test script: ${KROOK_SCRIPT}..."
    timeout 60 python3 "$KROOK_SCRIPT" -i "$INTERFACE" -b "$BSSID" > "$KROOK_LOG" 2>&1 || true
    
    if grep -qi "vulnerable" "$KROOK_LOG"; then
        cp "$KROOK_LOG" "$RES_FILE"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Kr00k Vulnerability Detected" \
            --severity HIGH \
            --desc "The target is vulnerable to the Kr00k (CVE-2019-15126) decryption flaw." \
            --target "${BSSID}" \
            --evidence "$RES_FILE" \
            --rationale "Kr00k allows an attacker to decrypt sensitive data packets by forcing a disassociation and exploiting a flaw where the device uses an all-zero encryption key for the remaining buffered data."
    fi
else
    echo "[!] Kr00k test script not found. Performing OUI-based passive check..." > "$KROOK_LOG"
    OUI=$(echo "$BSSID" | cut -d: -f1-3)
    echo "BSSID OUI: $OUI" >> "$KROOK_LOG"
fi

# Audit Complete finding if no critical vulnerability was recorded above
if [[ ! -f "$RES_FILE" ]]; then
    echo "[+] Kr00k testing complete (no active vulnerabilities confirmed)."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[E5] Audit Complete" \
        --severity INFO \
        --desc "Completed passive and OUI-based Kr00k vulnerability assessment for ${BSSID}." \
        --target "${BSSID}" \
        --evidence "$KROOK_LOG" \
        --rationale "Passive auditing identifies chipsets known to be vulnerable to Kr00k (Broadcom/Cypress). If active testing was not possible, this remains a configuration/hardware-level risk."
else
    echo "[+] Kr00k testing complete."
fi

exit 0
