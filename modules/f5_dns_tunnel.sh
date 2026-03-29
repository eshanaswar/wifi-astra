#!/usr/bin/env bash
# MODULE_META
# NAME="DNS Tunneling (Iodine)"
# CATEGORY="F"
# DEPS="none"
# CRITICAL="no"
# TOOLS="iodine"
# DESC="Bypass restrictive portals using DNS tunneling via iodine"
# REQS="managed_iface"
# PCAP="no"
# DECODE="dns"

#===============================================================================
#  modules/f5_dns_tunnel.sh
#  F5: DNS Tunneling (Golden Wrapper)
#
#  METHODOLOGY (SPEC SECTION 6.2):
#  1. Establish a DNS tunnel client connection to a remote iodine server.
#  2. Bypass Captive Portals that allow outbound DNS queries.
#  3. Provide a virtual tunnel interface (dns0) for encapsulated traffic.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Inherited from core)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F5"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Initializing DNS Tunnel tactical options..."

# 1. Interactive Selection
read -p "$(echo -e "${C_BOLD}[?] Enter iodine server tunnel domain: ${C_RESET}")" tunnel_domain
read -p "$(echo -e "${C_BOLD}[?] Enter tunnel password: ${C_RESET}")" tunnel_pass

if [[ -z "$tunnel_domain" || -z "$tunnel_pass" ]]; then
    echo "[!] Tunnel domain and password are required."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Attempting to establish DNS tunnel via ${C_VAR}${tunnel_domain}${C_RESET}..."

LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_iodine.log"

# 2. Execution
if command -v iodine &>/dev/null; then
    # -f: foreground, -P: password
    # Note: iodine requires root to create the tun interface
    iodine -f -P "$tunnel_pass" "$tunnel_domain" > "$LOG_FILE" 2>&1 &
    IODINE_PID=$!
    
    # Cleanup function
    cleanup() {
        echo "[*] Tearing down DNS tunnel..."
        kill "$IODINE_PID" 2>/dev/null || true
    }
    trap cleanup EXIT

    # 3. Monitor and Record Progress
    SCAN_TIME=120
    ELAPSED=0
    while [[ $ELAPSED -lt $SCAN_TIME ]]; do
        PERCENT=$(( ELAPSED * 100 / SCAN_TIME ))
        STATUS="Tunneling via $tunnel_domain... ($(( SCAN_TIME - ELAPSED ))s left)"
        "$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent "$PERCENT" --status "$STATUS"
        
        # Check if tunnel is up
        if ip addr show dns0 >/dev/null 2>&1; then
            echo "[!] SUCCESS: DNS TUNNEL ESTABLISHED (dns0)!"
            "$ASTRA_BIN" record-finding \
                --session-dir "$SESSION_DIR" \
                --tc "$TC_ID" \
                --type vulnerability \
                --name "DNS Tunneling Successful" \
                --severity HIGH \
                --desc "Successfully established an encapsulated DNS tunnel via $tunnel_domain." \
                --target "Global" \
                --evidence "$LOG_FILE" \
                --rationale "DNS tunneling allows an attacker to bypass firewalls and captive portals by encapsulating traffic within standard DNS queries."
            break
        fi
        
        sleep 5
        ((ELAPSED+=5))
    done
    
    wait "$IODINE_PID" 2>/dev/null || true
else
    echo "[!] iodine tool not found."
    exit 1
fi

exit 0
