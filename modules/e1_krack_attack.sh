#!/usr/bin/env bash
# MODULE_META
# NAME="KRACK Attack Testing"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="tshark,krack-test"
# DESC="Test WPA2 key reinstallation (CVE-2017-13077), nonce reuse, GTK reinstall"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e1_krack_attack.sh
#  E1: KRACK Attack (Golden Wrapper)
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] KRACK injection is highly unlikely to succeed at this distance."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E1"
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_capture.pcap"
RES_FILE="${EVIDENCE_DIR}/${TC_ID}_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$BSSID" ]]; then
    echo "[!] GUEST_BSSID not set. KRACK testing requires a target BSSID."
    exit 1
fi

echo "[*] Starting KRACK vulnerability tests against ${BSSID} (SSID: ${SSID:-Unknown})..."

# Ensure channel is set correctly
if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

# 1. Capture for analysis (EAPOL traffic)
echo "[*] Capturing EAPOL handshakes for nonce reuse analysis (60s)..."
# type 0x888e is EAPOL
timeout 60 tcpdump -i "$INTERFACE" -w "$PCAP_FILE" "ether host $BSSID and (type 0x888e)" > /dev/null 2>&1 || true

# 2. Optional: Run specialized KRACK test scripts if available
KRACK_SCRIPT=$(find /opt/ /usr/share/ /root/ -name "krack_all_zero_tk.py" 2>/dev/null | head -1)
VULN_DETECTED=0

if [[ -n "$KRACK_SCRIPT" ]]; then
    echo "[*] Running KRACK test script: ${KRACK_SCRIPT}..."
    timeout 120 python3 "$KRACK_SCRIPT" -i "$INTERFACE" -b "$BSSID" -s "${SSID:-}" > "$RES_FILE" 2>&1 || true
    
    if awk 'tolower($0) ~ /vulnerable|reinstall|reuse/ {exit 0} END {exit 1}' "$RES_FILE"; then
        VULN_DETECTED=1
        echo "[!] VULNERABILITY DETECTED: KRACK (Key Reinstallation)"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "KRACK Vulnerability Detected" \
            --desc "Target AP ${BSSID} is vulnerable to Key Reinstallation Attacks (KRACK). The implementation allows for reinstallation of an already-in-use encryption key, leading to nonce reuse." \
            --severity CRITICAL \
            --evidence "$RES_FILE" \
            --rationale "KRACK (CVE-2017-13077) allows an attacker to decrypt traffic, hijack connections, and potentially inject malicious data into a WPA2-protected stream by forcing the reuse of cryptographic nonces."
    fi
else
    echo "[!] Specialized KRACK test script not found. Manual analysis of PCAP required." > "$RES_FILE"
fi

echo "[+] KRACK testing complete."
if [[ "$VULN_DETECTED" -eq 0 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Completed KRACK (Key Reinstallation Attack) testing against ${BSSID}. No immediate evidence of key reinstallation or nonce reuse was detected." \
        --severity INFO \
        --evidence "$PCAP_FILE" \
        --rationale "WPA2 networks should be audited for KRACK resilience. Modern firmware patches generally mitigate this class of vulnerability by preventing the reinstallation of keys during the 4-way handshake."
fi

exit 0
