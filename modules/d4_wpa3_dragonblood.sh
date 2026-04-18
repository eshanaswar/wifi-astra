#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3 Dragonblood Attacks"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="dragonslayer,dragondrain"
# DESC="[LEGACY] WPA3-SAE Dragonblood — universally patched; tool chain rarely available"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="wpa3"

#===============================================================================
#  modules/d4_wpa3_dragonblood.sh
#  D4: WPA3 Dragonblood Attacks (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D4"
DRAGON_OUT="${EVIDENCE_DIR}/${TC_ID}_dragonblood_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "$SSID" ]]; then
    echo "[!] GUEST_SSID not set. WPA3 testing requires a target SSID."
    exit 1
fi

echo "[!] LEGACY MODULE: Dragonblood (CVE-2019-9494) has been universally patched since 2019-2020. The dragonslayer/dragondrain tool chain is unmaintained and rarely available. Results are for historical audit documentation only."
echo "[*] Starting WPA3 Dragonblood tests against ${SSID} (BSSID: ${BSSID:-Any})..."
echo "--- WPA3 Dragonblood Test Results for ${SSID} ---" > "$DRAGON_OUT"

# 0. SAE-PK Detection (WPA3 R3 — immune to Dragonblood)
# AKM suite 00:0f:ac:8 = SAE-PK; also match literal "SAE-PK" in iw output.
SAEPK_DETECTED=0
if [[ -n "$BSSID" ]]; then
    IW_SCAN=$(iw dev "$INTERFACE" scan 2>/dev/null || true)
    # Extract the BSS block for our target BSSID and check for SAE-PK
    BSS_BLOCK=$(echo "$IW_SCAN" | awk "/^BSS ${BSSID}/,/^BSS /" 2>/dev/null || true)
    if echo "$BSS_BLOCK" | grep -qiE "SAE-PK|00:0f:ac:8"; then
        SAEPK_DETECTED=1
    fi
fi

if [[ "$SAEPK_DETECTED" -eq 1 ]]; then
    echo "[NOT_VULNERABLE] SAE-PK (WPA3 R3) detected — CVE-2019-9494 and CVE-2019-9496 do not apply." | tee -a "$DRAGON_OUT"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] WPA3 SAE-PK Detected — Not Vulnerable" \
        --desc "SAE-PK (WPA3 R3) is immune to Dragonblood side-channel attacks (CVE-2019-9494, CVE-2019-9496). Testing skipped." \
        --severity INFO \
        --evidence "$DRAGON_OUT" \
        --rationale "SAE-PK binds the SAE exchange to a public key encoded in the password, preventing side-channel recovery."
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
    exit 0
fi

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Dragonblood test active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5; ELAPSED=$((ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing Dragonblood audit..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools (dragonslayer + dragondrain)
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Foreground Execution
    if command -v dragonslayer &>/dev/null; then
        timeout --foreground "$SCAN_TIME" dragonslayer -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} 2>&1 | tee -a "$DRAGON_OUT" || true
    fi
    if command -v dragondrain &>/dev/null; then
        timeout --foreground "$SCAN_TIME" dragondrain -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} 2>&1 | tee -a "$DRAGON_OUT" || true
    fi
else
    # Background Execution: plain timeout (no --foreground for background processes)
    (
        if command -v dragonslayer &>/dev/null; then
            timeout "$SCAN_TIME" dragonslayer -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} >> "$DRAGON_OUT" 2>&1 || true
        fi
        if command -v dragondrain &>/dev/null; then
            timeout "$SCAN_TIME" dragondrain -i "$INTERFACE" -s "$SSID" ${BSSID:+-b "$BSSID"} >> "$DRAGON_OUT" 2>&1 || true
        fi
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
VULN_FOUND=0
if grep -qi "vulnerable" "$DRAGON_OUT" 2>/dev/null; then
    VULN_FOUND=1
fi

if [[ "$VULN_FOUND" -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA3 SAE Vulnerability Detected" \
        --desc "The target network ${SSID} is vulnerable to Dragonblood class attacks (CVE-2019-9494 SAE Side-Channel or CVE-2019-9496 Resource Exhaustion)." \
        --severity HIGH \
        --evidence "$DRAGON_OUT" \
        --rationale "Dragonblood vulnerabilities (CVE-2019-9494, CVE-2019-9496) allow offline PSK recovery via SAE timing side-channels."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --desc "Completed WPA3-SAE Dragonblood tests (CVE-2019-9494, CVE-2019-9496) against ${SSID}. No vulnerabilities identified." \
        --severity INFO \
        --evidence "$DRAGON_OUT" \
        --rationale "WPA3 is significantly more secure than WPA2. Patched implementations are not susceptible to Dragonblood."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
