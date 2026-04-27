#!/usr/bin/env bash
# MODULE_META
# ID: E2
# NAME: FragAttacks Detection
# CATEGORY: E
# TOOLS: tshark,iw
# DESC: Passive FragAttacks (CVE-2020-24586/24587/24588) detection via beacon HT/Extended Capabilities analysis

#===============================================================================
#  modules/e2_fragattacks.sh
#  E2: FragAttacks Detection (Passive)
#
#  METHODOLOGY:
#  1. Capture beacon frames for the target AP using tshark.
#  2. Check HT Capabilities IE (tag 45): A-MSDU bit (bit 3 of HT Cap Info field).
#     A-MSDU support without SPP protection = CVE-2020-24588 risk indicator.
#  3. Check Extended Capabilities IE (tag 127): bit 73 (SPP A-MSDU capable).
#     SPP A-MSDU = the patch indicator for CVE-2020-24588.
#  4. Check RSN pairwise cipher suite: CCMP (00:0f:ac:4) = encrypted, lower risk.
#  5. Report POTENTIALLY_VULNERABLE / LIKELY_PATCHED / INCONCLUSIVE.
#===============================================================================

set -euo pipefail

INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SSID="${GUEST_SSID:-}"
CHANNEL="${GUEST_CHANNEL:-}"
SCAN_TIME="${SCAN_TIME:-30}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="E2"
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_capture.pcap"
RES_FILE="${EVIDENCE_DIR}/${TC_ID}_results.txt"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE and GUEST_BSSID are required." >&2
    exit 1
fi

echo "[*] E2: FragAttacks Detection — passive beacon capability analysis"

mkdir -p "$EVIDENCE_DIR"

if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

echo "[*] Capturing beacon frames for ${SCAN_TIME}s..."
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" \
            --percent "$PCT" --status "Capturing beacon frames (${ELAPSED}s / ${SCAN_TIME}s)"
        sleep 5
        (( ELAPSED += 5 )) || true
    done
) &
TEL_PID=$!

tshark -i "$INTERFACE" \
    -f "ether host ${BSSID} and type mgt subtype beacon" \
    -w "$PCAP_FILE" \
    -a duration:"$SCAN_TIME" 2>/dev/null || true

kill "$TEL_PID" 2>/dev/null || true

# Extract HT Capabilities Info field (tag 45, first 2 bytes = HT Cap Info)
HT_CAP_INFO=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.type_subtype == 8 and wlan.sa == ${BSSID}" \
    -T fields -e wlan.ht.capabilities -c 1 2>/dev/null | head -1 || echo "")

# Extended Capabilities IE (tag 127) — full field
EXT_CAPS=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.type_subtype == 8 and wlan.sa == ${BSSID}" \
    -T fields -e wlan.extcap -c 1 2>/dev/null | head -1 || echo "")

# RSN pairwise cipher
RSN_PAIRWISE=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.type_subtype == 8 and wlan.sa == ${BSSID}" \
    -T fields -e wlan.rsn.pcs.type -c 1 2>/dev/null | head -1 || echo "")

BEACON_COUNT=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.type_subtype == 8 and wlan.sa == ${BSSID}" \
    2>/dev/null | wc -l || echo 0)

# A-MSDU support: bit 3 of HT Cap Info (0x0008)
AMSDU_SUPPORT="unknown"
if [[ -n "$HT_CAP_INFO" ]]; then
    HT_INT=$(( 16#${HT_CAP_INFO//0x/} )) 2>/dev/null || HT_INT=0
    if (( HT_INT & 0x0008 )); then
        AMSDU_SUPPORT="yes"
    else
        AMSDU_SUPPORT="no"
    fi
fi

# SPP A-MSDU: bit 73 of Extended Capabilities (byte 9, bit 1 = 0x02)
SPP_AMSDU="unknown"
if [[ -n "$EXT_CAPS" ]]; then
    # Extended Capabilities is a hex string; byte 9 (index 18-19 in hex chars)
    EXT_CLEAN="${EXT_CAPS//:/}"
    EXT_CLEAN="${EXT_CLEAN//0x/}"
    if [[ "${#EXT_CLEAN}" -ge 20 ]]; then
        BYTE9="0x${EXT_CLEAN:18:2}"
        BYTE9_INT=$(( 16#${BYTE9//0x/} )) 2>/dev/null || BYTE9_INT=0
        if (( BYTE9_INT & 0x02 )); then
            SPP_AMSDU="yes (CVE-2020-24588 patch indicator)"
        else
            SPP_AMSDU="no"
        fi
    else
        SPP_AMSDU="not advertised (short ExtCap IE)"
    fi
fi

# CCMP pairwise: type 4 = CCMP
ENCRYPTION="unknown"
if echo "$RSN_PAIRWISE" | grep -q "4"; then
    ENCRYPTION="CCMP (encrypted)"
elif [[ -n "$RSN_PAIRWISE" ]]; then
    ENCRYPTION="non-CCMP: ${RSN_PAIRWISE}"
fi

{
    echo "=== E2: FragAttacks Beacon Analysis ==="
    echo "Target: ${BSSID} (${SSID:-unknown})"
    echo ""
    echo "--- HT Capabilities ---"
    echo "HT Capabilities Info: ${HT_CAP_INFO:-not parsed}"
    echo "A-MSDU support (CVE-2020-24588 risk): ${AMSDU_SUPPORT}"
    echo ""
    echo "--- Extended Capabilities ---"
    echo "Extended Capabilities IE: ${EXT_CAPS:-not present}"
    echo "SPP A-MSDU (patch indicator): ${SPP_AMSDU}"
    echo ""
    echo "--- RSN / Encryption ---"
    echo "Pairwise cipher: ${ENCRYPTION}"
    echo ""
    echo "Beacons captured: ${BEACON_COUNT}"
} > "$RES_FILE"

# Verdict
SEVERITY="INFO"
if [[ "$BEACON_COUNT" -eq 0 ]]; then
    FINDING_NAME="[E2] FragAttacks: Inconclusive — No Beacon Frames Captured"
    RATIONALE="No beacon frames captured from ${BSSID}. Verify the target BSSID, channel, and monitor interface are correct."
elif [[ "$AMSDU_SUPPORT" == "yes" && "$SPP_AMSDU" == "no" ]]; then
    SEVERITY="MEDIUM"
    FINDING_NAME="[E2] FragAttacks: Potentially Vulnerable — A-MSDU Without SPP Protection"
    RATIONALE="AP advertises A-MSDU support in HT Capabilities but does NOT advertise SPP A-MSDU in Extended Capabilities. SPP A-MSDU is the primary patch indicator for CVE-2020-24588 (mixed key attack). Firmware update recommended to enable SPP A-MSDU protection."
elif [[ "$SPP_AMSDU" == "yes (CVE-2020-24588 patch indicator)" ]]; then
    FINDING_NAME="[E2] FragAttacks: Likely Patched — SPP A-MSDU Advertised"
    RATIONALE="AP advertises SPP A-MSDU support in Extended Capabilities IE (bit 73). This is the beacon-level patch indicator for CVE-2020-24588. AP appears to have applied FragAttacks mitigations."
else
    FINDING_NAME="[E2] FragAttacks: Inconclusive — Insufficient Capability Data"
    RATIONALE="Beacon frames captured but HT/Extended Capability IEs could not be parsed sufficiently to determine FragAttacks patch status. Manual frame inspection of ${PCAP_FILE} recommended."
fi

"$ASTRA_BIN" record-finding --session-dir "$SESSION_DIR" --tc "$TC_ID" \
    --type vulnerability --name "${FINDING_NAME}" --severity "${SEVERITY}" \
    --desc "FragAttacks (CVE-2020-24586/24587/24588) passive assessment for ${BSSID}. A-MSDU: ${AMSDU_SUPPORT}, SPP A-MSDU: ${SPP_AMSDU}, Encryption: ${ENCRYPTION}." \
    --target "$BSSID" --evidence "$RES_FILE" \
    --rationale "${RATIONALE}"

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Complete"

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n[*] Mission Complete. Window closes in 5s..."
    sleep 5
fi
exit 0
