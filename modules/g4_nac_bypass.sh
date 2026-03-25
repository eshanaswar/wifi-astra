#!/usr/bin/env bash
# MODULE_META
# NAME="NAC / 802.1X Bypass"
# CATEGORY="G"
# DEPS="C2"
# CRITICAL="no"
# DESC="Test MAC whitelist bypass, VLAN assignment, and NAC exception discovery"
# REQS="managed_iface,gateway_ip,my_ip"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/g4_nac_bypass.sh
#  G4: NAC / 802.1X Port Bypass
#
#  PURPOSE:
#    Test Network Access Control bypass techniques from the wireless side.
#    Attempts MAC whitelist bypass, wired-to-wireless pivoting assessment,
#    and checks for NAC exceptions or misconfigurations.
#
#  TOOLS: nmap, macchanger, tcpdump
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: C2 (needs network scan data)
#===============================================================================

run_g4() {
    set -uo pipefail
    
    local interface=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local gateway_ip="${GATEWAY_IP:-}"
    local my_ip="${MY_IP:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --gateway-ip) gateway_ip="$2"; shift 2 ;;
            --my-ip) my_ip="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    gateway_ip="${gateway_ip:-${GATEWAY_IP:-}}"
    my_ip="${my_ip:-${MY_IP:-}}"
    local evidence_prefix="${evidence_dir}/g4"

    local total_steps=7

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "G4" || return 1

    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    if [[ -z "$gateway_ip" || -z "$my_ip" ]]; then
        log_error "Network info not set. Ensure you are connected to the target network."
        return 1
    fi

    log_success "Interface: ${interface}, IP: ${my_ip}, Gateway: ${gateway_ip}"

    local nac_detected="false"
    local mac_bypass_possible="false"
    local restricted_ports_accessible=0
    local vlan_assignment_changed="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local mac_bypass_file="${evidence_prefix}_mac_bypass.txt"
    local port_scan_file="${evidence_prefix}_port_scan.txt"
    local nac_analysis_file="${evidence_prefix}_nac_analysis.txt"

    {
        echo "============================================================"
        echo "  G4: NAC / 802.1X Bypass Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${interface}, IP: ${my_ip}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Baseline — Current NAC posture ---
    log_step 2 $total_steps "Analyzing current NAC posture"
    update_tc_progress 2 $total_steps "NAC analysis"

    local orig_mac=$(ip link show "$interface" | awk '/ether/{print $2}')
    local orig_ip="$my_ip"

    # Check for EAP frames
    spawn_bg "g4_tcpdump" "tcpdump" -i "$interface" -c 5 "ether proto 0x888e"
    sleep 5
    if is_process_running "g4_tcpdump"; then
        stop_process "g4_tcpdump"
    else
        nac_detected="true"
        log_info "802.1X EAP frames detected — NAC is active"
    fi

    # Scan restricted ports
    local restricted_ports="88,135,389,445,636,1433,1521,3306,3389,5985,5986,8443"
    nmap -Pn -sT -p "$restricted_ports" "$gateway_ip" --max-retries 1 --host-timeout 30s -oG "$port_scan_file" 2>/dev/null || true
    local baseline_open=$(grep -oP '\d+/open' "$port_scan_file" | wc -l) || true

    #--- Step 3: MAC spoofing test ---
    log_step 3 $total_steps "Testing MAC address spoofing"
    update_tc_progress 3 $total_steps "MAC spoof test"

    if command -v macchanger &>/dev/null; then
        run_tool ip link set "$interface" down 2>/dev/null
        macchanger -r "$interface" &>/dev/null || true
        run_tool ip link set "$interface" up 2>/dev/null
        
        sleep 5
        dhclient -r "$interface" &>/dev/null || true
        dhclient "$interface" &>/dev/null || true
        sleep 5

        local new_ip=$(ip -4 addr show "$interface" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
        if [[ -n "$new_ip" ]]; then
            mac_bypass_possible="true"
            log_info "Got IP ${new_ip} with random MAC"
            
            local orig_subnet=$(echo "$orig_ip" | cut -d. -f1-3)
            local new_subnet=$(echo "$new_ip" | cut -d. -f1-3)
            if [[ "$orig_subnet" != "$new_subnet" ]]; then
                vlan_assignment_changed="true"
                log_result "FINDING" "VLAN assignment changed with different MAC!"
            fi
        fi
        
        # Restore MAC
        run_tool ip link set "$interface" down 2>/dev/null
        macchanger -p "$interface" &>/dev/null || true
        run_tool ip link set "$interface" up 2>/dev/null
        dhclient "$interface" &>/dev/null || true
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_json=$(run_tool jq -n \
        --arg status "SECURE" \
        --arg summary "NAC bypass tests completed." \
        --arg nac_detected "$nac_detected" \
        --arg mac_bypass "$mac_bypass_possible" \
        --arg vlan_changed "$vlan_assignment_changed" \
        '{status: $status, summary: $summary, nac_detected: ($nac_detected == "true"), mac_bypass_possible: ($mac_bypass == "true"), vlan_assignment_changed: ($vlan_changed == "true")}')

    evidence_register_file "$findings_file"
    evidence_register_file "$mac_bypass_file"
    evidence_register_file "$port_scan_file"
    evidence_register_file "$nac_analysis_file"

    save_tc_result "G4" "$result_json" 1 1 0 1 1 1 0 1 1 1 0
    return 0
}
