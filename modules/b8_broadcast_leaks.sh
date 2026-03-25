#!/usr/bin/env bash
# MODULE_META
# NAME="Broadcast & Multicast Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Analyze UDP traffic for SSDP/LLMNR/NetBIOS storms bleeding from corporate"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="l2_discovery"

#===============================================================================
#  modules/b8_broadcast_leaks.sh
#  B8: Broadcast & Multicast Leaks
#
#  PURPOSE:
#    Analyze UDP traffic for SSDP/LLMNR/NetBIOS storms bleeding from corporate
#    networks into the target WiFi, indicating poor VLAN isolation.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}
#  PHASE: 1B — Network & Service Recon (Connected)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - b8_bcast.pcap           (raw broadcast/multicast capture)
#    - b8_bcast_analysis.txt   (summary of noisy protocols/sources)
#
#  RESULT JSON FIELDS:
#    - protocol_counts: {ssdp, llmnr, mdns, nbtns, other}
#    - leakage_detected: bool
#===============================================================================

run_b8() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b8"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and network state"
    update_tc_progress 1 $total_steps "Checking"

    
    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    if [[ -z "${WIFI_INTERFACE:-}" ]]; then
        configure_network || return 1
    fi
    local iface="${WIFI_INTERFACE:-wlan0}"
    log_success "Using interface: ${iface}"

    #--- Step 2: Configure capture parameters ---
    log_step 2 $total_steps "Configuring capture parameters"
    update_tc_progress 2 $total_steps "Configuring"

    local capture_time=60
    local pcap_file="${evidence_prefix}_bcast.pcap"
    local analysis_file="${evidence_prefix}_bcast_analysis.txt"

    # Clean up previous evidence
    rm -f "$pcap_file" "$analysis_file" 2>/dev/null

    #--- Step 3: Listen for Broadcast/Multicast Traffic ---
    log_step 3 $total_steps "Listening for noisy protocols (${capture_time}s)"
    update_tc_progress 3 $total_steps "Capturing"

    check_abort || return 1

    log_info "Monitoring for SSDP, LLMNR, mDNS, and NetBIOS on ${iface}..."
    # Filter for common broadcast/multicast noisy UDP protocols
    local bcast_filter="udp port 1900 or udp port 5355 or udp port 5353 or udp port 137 or udp port 138"
    log_cmd "${TOOL_PATHS[tcpdump]} -i ${iface} -nn '${bcast_filter}' -w ${pcap_file}"

    # Run ${TOOL_PATHS[tcpdump]}
    start_countdown "$capture_time" "Analyzing broadcast/multicast leaks"
    timeout "$capture_time" "${TOOL_PATHS[tcpdump]}" -i "$iface" -nn -w "$pcap_file" udp port 1900 or udp port 5355 or udp port 5353 or udp port 137 or udp port 138 >/dev/null 2>&1 || true
    stop_countdown
    
    check_abort || return 1

    #--- Step 4: Validate capture ---
    log_step 4 $total_steps "Validating capture"
    update_tc_progress 4 $total_steps "Validating"

    if ! validate_pcap "$pcap_file" "Broadcast/Multicast leak capture"; then
        log_info "No significant broadcast/multicast leaks detected during window."
    fi

    #--- Step 5: Analyze protocols ---
    log_step 5 $total_steps "Analyzing traffic patterns"
    update_tc_progress 5 $total_steps "Analyzing"

    local ssdp_count=0
    local llmnr_count=0
    local mdns_count=0
    local nbtns_count=0
    local total_leaks=0
    local status="SECURE"
    local summary="No significant broadcast/multicast leakage from corporate VLANs."

    if [[ -f "$pcap_file" && -s "$pcap_file" ]]; then
        ensure_user_ownership "$pcap_file"
        ssdp_count=$(run_as_user tshark -r "$pcap_file" -Y "udp.port == 1900" 2>/dev/null | wc -l)
        llmnr_count=$(run_as_user tshark -r "$pcap_file" -Y "udp.port == 5355" 2>/dev/null | wc -l)
        mdns_count=$(run_as_user tshark -r "$pcap_file" -Y "udp.port == 5353" 2>/dev/null | wc -l)
        nbtns_count=$(run_as_user tshark -r "$pcap_file" -Y "udp.port == 137 or udp.port == 138" 2>/dev/null | wc -l)
        
        total_leaks=$((ssdp_count + llmnr_count + mdns_count + nbtns_count))
        
        {
            echo "============================================================"
            echo "  B8: Broadcast & Multicast Analysis"
            echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "============================================================"
            echo ""
            echo "PROTOCOL SUMMARY:"
            echo "  SSDP (1900):    ${ssdp_count}"
            echo "  LLMNR (5355):   ${llmnr_count}"
            echo "  mDNS (5353):    ${mdns_count}"
            echo "  NetBIOS (137):  ${nbtns_count}"
            echo "TOTAL LEAKS:    ${total_leaks}"
            echo ""
            echo "TOP SOURCES:"
            ensure_user_ownership "$pcap_file"
            run_as_user tshark -r "$pcap_file" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -10

        } > "$analysis_file"

        if [[ $total_leaks -gt 50 ]]; then
            local status="FINDING"
            local summary="High volume of broadcast/multicast traffic (${total_leaks} packets) leaking from corporate devices."
            log_result "FINDING" "${summary}"
        elif [[ $total_leaks -gt 0 ]]; then
            local status="INFO"
            local summary="Minor broadcast/multicast leakage detected (${total_leaks} packets)."
            log_result "INFO" "${summary}"
        else
            log_result "SECURE" "Broadcast traffic properly restricted."
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_json
    evidence_register_file "$pcap"
    evidence_register_file "$txt"

    local result_json=$(run_tool jq -n \
        --arg status "$status" \
        --arg summary "$summary" \
        --argjson ssdp "$ssdp_count" \
        --argjson llmnr "$llmnr_count" \
        --argjson mdns "$mdns_count" \
        --argjson nbtns "$nbtns_count" \
        --argjson total "$total_leaks" \
        --arg pcap "$(basename "$pcap_file")" \
        --arg txt "$(basename "$analysis_file")" \
        '{
            status: $status,
            summary: $summary,
            details: "Detected protocol counts - SSDP: \($ssdp), LLMNR: \($llmnr), mDNS: \($mdns), NetBIOS: \($nbtns). Total: \($total)",
            protocol_counts: {ssdp: $ssdp, llmnr: $llmnr, mdns: $mdns, nbtns: $nbtns},
            recommendations: (if $status == "FINDING" then "Enable broadcast/multicast suppression on the WLC/AP. Ensure VLAN isolation is strictly enforced at Layer 2." else "No action required." end),
                    }')

    save_tc_result "B8" "$result_json" "has_tool_output:1,clean_run:1"
    return 0
}
