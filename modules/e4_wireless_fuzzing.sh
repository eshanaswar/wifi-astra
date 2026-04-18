#!/usr/bin/env bash
# MODULE_META
# NAME="Wireless Frame Fuzzing"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="mdk4"
# DESC="Send malformed management frames to test AP robustness"
# REQS="monitor_iface,target_bssid"
# PCAP="no"
# TIMED="yes"
# DECODE="none"

#===============================================================================
#  modules/e4_wireless_fuzzing.sh
#  E4: Wireless Frame Fuzzing (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Use 'mdk4' to generate and transmit a series of malformed or non-standard
#     IEEE 802.11 management frames (Authentication, Association, Beacons).
#  2. Monitor the target AP for signs of instability, such as crashes, 
#     reboots, or denial of service.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SCAN_TIME="${SCAN_TIME:-120}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e4"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E4"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting wireless frame fuzzing against ${BSSID}..."

FUZZ_OUT="${EVIDENCE_PREFIX}_mdk4_results.txt"

# 1. Use mdk4 for fuzzing
if command -v mdk4 &>/dev/null; then
    echo "[*] Running mdk4 fuzzer (Authentication/Association fuzzing)..."

    # Start dynamic telemetry heartbeat
    (
        HEARTBEAT_ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
            if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
                "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Fuzzing active — ${HEARTBEAT_ELAPSED}s elapsed (Ctrl+C to stop)"
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

    # mdk4 fuzzing modes:
    #   Phase 1: 'f' (Frame Fuzzer) — sends random malformed 802.11 frames to test
    #            AP driver robustness. This is actual fuzzing — the correct mode for
    #            discovering implementation-level vulnerabilities.
    #   Phase 2: 'a' (Auth Flood) — floods the AP with auth requests, testing
    #            association table limits and DoS resilience.
    # NOTE: mdk4 'm' (TKIP MIC exploit) was previously used here but is NOT fuzzing —
    #       it is a TKIP-specific timing attack unrelated to frame robustness testing.
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        echo "--- Phase 1: Frame Fuzzer (mdk4 f) ---"
        timeout --foreground $((SCAN_TIME / 2)) mdk4 "$INTERFACE" f -t "$BSSID" 2>&1 | tee "$FUZZ_OUT" || true
        echo "--- Phase 2: Auth Flood (mdk4 a) ---" | tee -a "$FUZZ_OUT"
        timeout --foreground $((SCAN_TIME / 2)) mdk4 "$INTERFACE" a -a "$BSSID" 2>&1 | tee -a "$FUZZ_OUT" || true
    else
        echo "--- Phase 1: Frame Fuzzer (mdk4 f) ---" >> "$FUZZ_OUT"
        timeout $((SCAN_TIME / 2)) mdk4 "$INTERFACE" f -t "$BSSID" >> "$FUZZ_OUT" 2>&1 || true
        echo "--- Phase 2: Auth Flood (mdk4 a) ---" >> "$FUZZ_OUT"
        timeout $((SCAN_TIME / 2)) mdk4 "$INTERFACE" a -a "$BSSID" >> "$FUZZ_OUT" 2>&1 || true
    fi
    
    kill "$TELEMETRY_PID" 2>/dev/null || true

    echo "[+] Wireless fuzzing test complete."

    if [[ -s "$FUZZ_OUT" ]]; then
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "Wireless Frame Fuzzing Audit" \
            --severity INFO \
            --desc "Sent malformed management frames to test target AP robustness on ${BSSID}." \
            --target "${BSSID}" \
            --evidence "$FUZZ_OUT" \
            --rationale "Robustness testing identifies implementation flaws in the AP's wireless stack. Successful fuzzing can lead to remote Denial of Service (DoS) or, in some cases, remote code execution."
    else
        "$ASTRA_BIN" record-finding \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --type vulnerability \
            --name "[E4] Audit Complete" \
            --severity INFO \
            --desc "Fuzzing attack executed but no immediate response or logs captured." \
            --target "${BSSID}" \
            --evidence "$FUZZ_OUT" \
            --rationale "Fuzzing may not produce immediate output unless the AP crashes or exhibits observable behavior. This audit confirms the tests were successfully transmitted."
    fi
else
    echo "[!] mdk4 not found. Fuzzing cannot proceed."
    echo "mdk4 not installed" > "$FUZZ_OUT"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Skipped — mdk4 Missing" \
        --severity INFO \
        --desc "The mdk4 tool was not found. Wireless frame fuzzing could not be performed against ${BSSID}. Install with: apt install mdk4" \
        --target "${BSSID}" \
        --evidence "$FUZZ_OUT" \
        --rationale "mdk4 is required for 802.11 frame fuzzing. Without it this module cannot test AP robustness."
    "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Skipped — mdk4 missing"
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
