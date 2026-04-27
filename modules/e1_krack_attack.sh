#!/usr/bin/env bash
# MODULE_META
# ID: E1
# NAME: KRACK Detection
# CATEGORY: E
# TOOLS: tshark,iw
# DESC: Passive KRACK (CVE-2017-13077) detection via EAPOL ANonce nonce-reuse analysis

#===============================================================================
#  modules/e1_krack_attack.sh
#  E1: KRACK Key-Reinstallation Detection (Passive)
#
#  METHODOLOGY:
#  1. Capture beacon + EAPOL frames for the target AP using tshark.
#  2. Extract ANonce values from WPA2 Message 1 frames (key_info == 0x008a).
#  3. Detect duplicate ANonces across separate 4-way handshake sessions —
#     each new handshake MUST use a fresh ANonce; reuse indicates KRACK-
#     style nonce mismanagement (CVE-2017-13077).
#  4. Report VULNERABLE / LIKELY_PATCHED / INCONCLUSIVE.
#===============================================================================

set -euo pipefail

INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SSID="${GUEST_SSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-120}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E1"
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_capture.pcap"
RES_FILE="${EVIDENCE_DIR}/${TC_ID}_results.txt"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE and GUEST_BSSID are required." >&2
    exit 1
fi

echo "[*] E1: KRACK Detection — passive EAPOL ANonce nonce-reuse analysis"

mkdir -p "$EVIDENCE_DIR"

if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

echo "[*] Capturing EAPOL + beacon frames for ${SCAN_TIME}s..."
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" \
            --percent "$PCT" --status "Capturing EAPOL frames (${ELAPSED}s / ${SCAN_TIME}s)"
        sleep 5
        (( ELAPSED += 5 )) || true
    done
) &
TEL_PID=$!

tshark -i "$INTERFACE" \
    -f "ether host ${BSSID} and (type mgt subtype beacon or eapol)" \
    -w "$PCAP_FILE" \
    -a duration:"$SCAN_TIME" 2>/dev/null || true

kill "$TEL_PID" 2>/dev/null || true

# Extract ANonce values from WPA2 Message 1 (key_info == 0x008a)
ANONCES=$(tshark -r "$PCAP_FILE" \
    -Y "eapol and wlan.sa == ${BSSID} and eapol.keydes.key_info == 0x008a" \
    -T fields -e eapol.keydes.nonce 2>/dev/null || echo "")

ANONCE_COUNT=0
DUPLICATE_COUNT=0
if [[ -n "$ANONCES" ]]; then
    ANONCE_COUNT=$(echo "$ANONCES" | grep -c . || echo 0)
    DUPLICATE_COUNT=$(echo "$ANONCES" | sort | uniq -d | grep -c . || echo 0)
fi

{
    echo "=== E1: KRACK Nonce-Reuse Detection ==="
    echo "Target: ${BSSID} (${SSID:-unknown})"
    echo ""
    echo "--- EAPOL ANonce Analysis ---"
    echo "Message-1 EAPOL frames captured: ${ANONCE_COUNT}"
    echo "Duplicate ANonces detected: ${DUPLICATE_COUNT}"
    if [[ -n "$ANONCES" ]]; then
        echo ""
        echo "--- ANonce Values ---"
        echo "$ANONCES"
    fi
} > "$RES_FILE"

# Verdict
SEVERITY="INFO"
if [[ "$ANONCE_COUNT" -eq 0 ]]; then
    FINDING_NAME="[E1] KRACK: Inconclusive — No EAPOL Handshakes Captured"
    RATIONALE="No WPA2 Message 1 EAPOL frames were captured from the target AP during the scan window. Increase SCAN_TIME or wait for clients to (re)associate."
elif [[ "$DUPLICATE_COUNT" -gt 0 ]]; then
    SEVERITY="HIGH"
    FINDING_NAME="[E1] KRACK: VULNERABLE — ANonce Reuse Detected"
    RATIONALE="The AP reused ANonce values across separate 4-way handshake sessions. ANonce reuse enables key reinstallation attacks (CVE-2017-13077) against connecting clients. Firmware update required immediately."
else
    FINDING_NAME="[E1] KRACK: Likely Patched — No ANonce Reuse Observed"
    RATIONALE="All captured 4-way handshake Message 1 frames used unique ANonces. No nonce reuse observed during the scan window (${ANONCE_COUNT} handshakes). This is consistent with a patched implementation but does not rule out KRACK variants in other paths."
fi

"$ASTRA_BIN" record-finding --session-dir "$SESSION_DIR" --tc "$TC_ID" \
    --type vulnerability --name "${FINDING_NAME}" --severity "${SEVERITY}" \
    --desc "KRACK (CVE-2017-13077) passive assessment for ${BSSID}. Handshakes captured: ${ANONCE_COUNT}. Duplicate ANonces: ${DUPLICATE_COUNT}." \
    --target "$BSSID" --evidence "$RES_FILE" \
    --rationale "${RATIONALE}"

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Complete"

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n[*] Mission Complete. Window closes in 5s..."
    sleep 5
fi
exit 0
