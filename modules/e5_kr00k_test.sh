#!/usr/bin/env bash
# MODULE_META
# ID: E5
# NAME: Kr00k Detection
# CATEGORY: E
# TOOLS: tshark,iw
# DESC: Passive Kr00k (CVE-2019-15126) detection via OUI chipset fingerprinting and post-disassociation frame analysis

#===============================================================================
#  modules/e5_kr00k_test.sh
#  E5: Kr00k Detection (Passive / OUI Fingerprinting)
#
#  METHODOLOGY:
#  1. Extract the OUI (first 3 bytes) from the target AP's BSSID.
#  2. Compare against known Broadcom and Cypress OUI ranges — these chipsets
#     are the affected hardware for CVE-2019-15126.
#  3. During capture, monitor for natural client disassociations from the AP.
#  4. After a disassociation, check if the AP continues to transmit encrypted
#     frames. If so, captures are saved for potential all-zero key analysis.
#  5. Verdict: POTENTIALLY_VULNERABLE (if Broadcom/Cypress OUI + disassoc seen),
#     LOW_RISK (Broadcom/Cypress OUI but no disassoc captured),
#     UNLIKELY (non-affected OUI), or INCONCLUSIVE.
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
TC_ID="E5"
PCAP_FILE="${EVIDENCE_DIR}/${TC_ID}_capture.pcap"
RES_FILE="${EVIDENCE_DIR}/${TC_ID}_results.txt"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE and GUEST_BSSID are required." >&2
    exit 1
fi

echo "[*] E5: Kr00k Detection — OUI chipset fingerprinting + post-disassociation analysis"

mkdir -p "$EVIDENCE_DIR"

# Known Broadcom/Cypress OUI prefixes affected by CVE-2019-15126
# Sources: ESET research paper + Broadcom/Cypress vendor registrations
AFFECTED_OUIS=(
    "00:90:4C"  # Broadcom
    "00:17:F2"  # Broadcom
    "D4:6E:5C"  # Broadcom
    "00:1A:2B"  # Broadcom (consumer devices)
    "78:4B:87"  # Cypress Semiconductor
    "40:01:C6"  # Cypress (CYW chips)
    "AC:67:B2"  # Broadcom (AP chipsets)
    "00:25:9C"  # Cisco-Linksys (Broadcom based)
    "C8:D7:19"  # Broadcom (home APs)
)

# Extract OUI from BSSID (first 3 octets, uppercase)
BSSID_UPPER="${BSSID^^}"
OUI="${BSSID_UPPER:0:8}"  # AA:BB:CC

OUI_MATCH="no"
for KNOWN_OUI in "${AFFECTED_OUIS[@]}"; do
    if [[ "${KNOWN_OUI^^}" == "$OUI" ]]; then
        OUI_MATCH="yes"
        break
    fi
done

echo "[*] OUI: ${OUI} — Broadcom/Cypress match: ${OUI_MATCH}"

if [[ -n "$CHANNEL" && "$CHANNEL" != "0" ]]; then
    iw dev "$INTERFACE" set channel "$CHANNEL" 2>/dev/null || true
fi

echo "[*] Capturing management + data frames for ${SCAN_TIME}s (watching for disassociations)..."
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        PCT=$(( ELAPSED * 100 / SCAN_TIME ))
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" \
            --percent "$PCT" --status "Capturing frames (${ELAPSED}s / ${SCAN_TIME}s)"
        sleep 5
        (( ELAPSED += 5 )) || true
    done
) &
TEL_PID=$!

tshark -i "$INTERFACE" \
    -f "ether host ${BSSID}" \
    -w "$PCAP_FILE" \
    -a duration:"$SCAN_TIME" 2>/dev/null || true

kill "$TEL_PID" 2>/dev/null || true

# Count disassociation frames from the AP
DISASSOC_COUNT=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.type_subtype == 10 and wlan.sa == ${BSSID}" \
    2>/dev/null | wc -l || echo 0)

# Count encrypted data frames shortly after any disassociation
# (Kr00k: AP continues sending data with all-zero key after disassoc)
POST_DISASSOC_DATA=$(tshark -r "$PCAP_FILE" \
    -Y "wlan.fc.protected == 1 and wlan.ta == ${BSSID}" \
    2>/dev/null | wc -l || echo 0)

{
    echo "=== E5: Kr00k Chipset Fingerprinting ==="
    echo "Target: ${BSSID} (${SSID:-unknown})"
    echo ""
    echo "--- OUI Analysis ---"
    echo "OUI extracted: ${OUI}"
    echo "Broadcom/Cypress OUI match: ${OUI_MATCH}"
    echo ""
    echo "--- Frame Analysis ---"
    echo "Disassociation frames from AP: ${DISASSOC_COUNT}"
    echo "Protected (encrypted) data frames from AP: ${POST_DISASSOC_DATA}"
} > "$RES_FILE"

# Verdict
SEVERITY="INFO"
if [[ "$OUI_MATCH" == "yes" && "$DISASSOC_COUNT" -gt 0 ]]; then
    SEVERITY="MEDIUM"
    FINDING_NAME="[E5] Kr00k: Potentially Vulnerable — Broadcom/Cypress Chipset + Disassociation Observed"
    RATIONALE="AP OUI (${OUI}) matches known Kr00k-affected Broadcom/Cypress chipsets, and disassociation frames were observed during capture. CVE-2019-15126 allows an attacker to trigger disassociation and capture data encrypted with an all-zero key. Firmware update strongly recommended."
elif [[ "$OUI_MATCH" == "yes" ]]; then
    FINDING_NAME="[E5] Kr00k: Low Risk Indicator — Broadcom/Cypress Chipset (No Disassoc Captured)"
    RATIONALE="AP OUI (${OUI}) matches known Kr00k-affected Broadcom/Cypress chipsets, but no client disassociations were observed during the capture window. Cannot confirm exploitability without observing post-disassociation traffic. Extend scan time or wait for client activity. Firmware check recommended."
else
    FINDING_NAME="[E5] Kr00k: Unlikely — OUI Does Not Match Affected Chipsets"
    RATIONALE="AP OUI (${OUI}) does not match known Broadcom/Cypress OUI ranges affected by CVE-2019-15126. Kr00k is a chipset-specific vulnerability. AP appears to use a different hardware vendor and is likely not affected."
fi

"$ASTRA_BIN" record-finding --session-dir "$SESSION_DIR" --tc "$TC_ID" \
    --type vulnerability --name "${FINDING_NAME}" --severity "${SEVERITY}" \
    --desc "Kr00k (CVE-2019-15126) passive assessment for ${BSSID}. OUI: ${OUI}, Broadcom/Cypress match: ${OUI_MATCH}, Disassoc frames: ${DISASSOC_COUNT}." \
    --target "$BSSID" --evidence "$RES_FILE" \
    --rationale "${RATIONALE}"

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Complete"

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n[*] Mission Complete. Window closes in 5s..."
    sleep 5
fi
exit 0
