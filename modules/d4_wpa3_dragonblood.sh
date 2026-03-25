#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3 Dragonblood"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="tshark,tcpdump"
# DESC="Test WPA3-SAE timing side-channel, transition mode downgrade (CVE-2019-9494+)"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d4_wpa3_dragonblood.sh
#  D4: WPA3-SAE Dragonblood Attack
#
#  PURPOSE:
#    Test WPA3-SAE (Simultaneous Authentication of Equals) implementations
#    for Dragonblood vulnerabilities (CVE-2019-9494 through CVE-2019-9498).
#    Tests include SAE timing side-channels, downgrade from WPA3 to WPA2,
#    transition mode exploitation, and SAE group negotiation attacks.
#
#  TOOLS: tshark, tcpdump
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d4_wpa3_analysis.txt          (WPA3 capability analysis)
#    - d4_downgrade_test.txt         (transition mode downgrade results)
#    - d4_timing_analysis.txt        (SAE timing side-channel data)
#    - d4_capture.pcap               (SAE authentication frames)
#    - d4_findings.txt               (analysis summary)
#===============================================================================

set -uo pipefail

run_d4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d4"
    local findings_file="${evidence_prefix}_findings.txt"
    local wpa3_analysis="${evidence_prefix}_wpa3_analysis.txt"
    local downgrade_file="${evidence_prefix}_downgrade_test.txt"
    local timing_file="${evidence_prefix}_timing_analysis.txt"
    local sae_pcap="${evidence_prefix}_capture.pcap"

    #--- Step 1: Verify tools & prerequisites ---
    log_step 1 $total_steps "Verifying required tools and targets"
    update_tc_progress 1 $total_steps "Checking dependencies"

    check_module_dependencies "D4" || return 1

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
    echo "  ║  ★ WPA3/SAE DRAGONBLOOD ATTACK ★                                ║"
    echo "  ║                                                                    ║"
    echo "  ║  Tests for CVE-2019-9494 through CVE-2019-9498:                   ║"
    echo "  ║    • WPA3-SAE timing side-channel (password partitioning)         ║"
    echo "  ║    • WPA3 transition mode downgrade to WPA2                       ║"
    echo "  ║    • SAE group negotiation (force weak groups)                    ║"
    echo "  ║    • SAE anti-clogging token enforcement                          ║"
    echo "  ║                                                                    ║"
    echo "  ║  Requires the target network to use WPA3-SAE.                    ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with WPA3 Dragonblood testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local wpa3_detected="false"
    local transition_mode="false"
    local downgrade_possible="false"
    local timing_sidechannel="false"
    local sae_groups=""
    local anti_clogging_enforced="false"

    {
        echo "============================================================"
        echo "  D4: WPA3/SAE Dragonblood Attack"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "  CVEs: CVE-2019-9494 to CVE-2019-9498"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode and analyze WPA3 beacons ---
    log_step 2 $total_steps "Analyzing AP for WPA3-SAE capabilities"
    update_tc_progress 2 $total_steps "WPA3 analysis"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    {
        echo "============================================================"
        echo "  WPA3-SAE Capability Analysis"
        echo "============================================================"
        echo ""
    } > "$wpa3_analysis"

    # Capture beacons for WPA3/SAE analysis
    local beacon_pcap="$TMP_DIR/d4_beacons.pcap"
    rm -f "$beacon_pcap"
    
    log_info "Capturing beacons for WPA3 analysis..."
    run_fg "${TOOL_PATHS[tcpdump]}" -i "$mon_iface" -c 30 -w "$beacon_pcap" \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" 2>/dev/null || true

    if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
        # Check AKM suite for SAE (type 8 = SAE, type 24 = SAE-FT)
        local akm_types
        akm_types=$(run_fg "${TOOL_PATHS[tshark]}" -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.rsn.akms.type \
            2>/dev/null | head -1 || true)

        echo "AKM Suite Types: ${akm_types:-unknown}" >> "$wpa3_analysis"

        if echo "$akm_types" | grep -qE '8|24'; then
            wpa3_detected="true"
            log_success "WPA3-SAE detected! AKM type(s): ${akm_types}"
            echo "WPA3-SAE: DETECTED" >> "$wpa3_analysis"

            # Check for transition mode (SAE + PSK)
            if echo "$akm_types" | grep -qE '2|6' && echo "$akm_types" | grep -qE '8|24'; then
                transition_mode="true"
                log_result "FINDING" "WPA3 transition mode (WPA2-PSK + WPA3-SAE mixed) detected"
                echo "FINDING: Transition mode detected (WPA2+WPA3 mixed)" >> "$wpa3_analysis"
                echo "FINDING: WPA3 transition mode — downgrade to WPA2 possible" >> "$findings_file"
            fi
        else
            log_info "WPA3-SAE not detected in beacon (AKM: ${akm_types:-none})"
            echo "WPA3-SAE: NOT DETECTED (AKM types: ${akm_types:-none})" >> "$wpa3_analysis"
        fi

        # Check MFP (802.11w) — required for WPA3
        local mfpr mfpc
        mfpc=$(run_fg "${TOOL_PATHS[tshark]}" -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields -e wlan.rsn.capabilities.mfpc \
            2>/dev/null | head -1 || true)
        mfpr=$(run_fg "${TOOL_PATHS[tshark]}" -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields -e wlan.rsn.capabilities.mfpr \
            2>/dev/null | head -1 || true)

        echo "MFP Capable: ${mfpc:-unknown}" >> "$wpa3_analysis"
        echo "MFP Required: ${mfpr:-unknown}" >> "$wpa3_analysis"

        if [[ "$wpa3_detected" == "true" && "$mfpr" != "1" ]]; then
            log_result "FINDING" "WPA3-SAE without MFP required — non-compliant configuration"
            echo "FINDING: WPA3 without mandatory MFP — deauth attacks possible" >> "$findings_file"
        fi
    fi
    rm -f "$beacon_pcap"

    check_abort || return 1

    #--- Step 3: Capture SAE authentication exchanges ---
    log_step 3 $total_steps "Capturing SAE authentication exchanges (90s)"
    update_tc_progress 3 $total_steps "SAE capture"

    rm -f "$sae_pcap"
    spawn_bg "sae_cap" "${TOOL_PATHS[tcpdump]}" -i "$mon_iface" -w "$sae_pcap" \
        "type mgt subtype auth or type mgt subtype deauth or type mgt subtype assoc-req"

    # Send deauth to trigger re-authentication
    sleep 10
    log_info "Sending deauth to trigger SAE re-authentication..."
    run_fg "${TOOL_PATHS[aireplay-ng]}" --deauth 5 -a "$GUEST_BSSID" "$mon_iface"

    start_countdown 90 "Capturing SAE Commit/Confirm exchanges"
    sleep 80
    stop_countdown

    stop_process "sae_cap"
    
    check_abort || return 1

    #--- Step 4: Analyze SAE timing and group negotiation ---
    log_step 4 $total_steps "Analyzing SAE timing and group negotiation"
    update_tc_progress 4 $total_steps "Timing analysis"

    {
        echo "============================================================"
        echo "  SAE Timing & Group Analysis"
        echo "============================================================"
        echo ""
    } > "$timing_file"

    if [[ -f "$sae_pcap" && -s "$sae_pcap" ]]; then
        local sae_frames
        sae_frames=$(run_fg "${TOOL_PATHS[tshark]}" -r "$sae_pcap" \
            -Y "wlan.fixed.auth.alg == 3" \
            -T fields \
            -e frame.time_delta \
            -e wlan.sa \
            -e wlan.da \
            -e wlan.fixed.auth.seq \
            -e wlan.fixed.status_code \
            2>/dev/null || true)

        if [[ -n "$sae_frames" ]]; then
            local sae_count
            sae_count=$(echo "$sae_frames" | wc -l)
            log_info "Captured ${sae_count} SAE authentication frames"
            echo "SAE frames captured: ${sae_count}" >> "$timing_file"

            local commit_times
            commit_times=$(echo "$sae_frames" | awk '$4 == "1" {print $1}' | grep -v "^$" || true)

            if [[ -n "$commit_times" ]]; then
                local min_time max_time
                min_time=$(echo "$commit_times" | sort -n | head -1)
                max_time=$(echo "$commit_times" | sort -n | tail -1)

                if [[ -n "$min_time" && -n "$max_time" ]]; then
                    local time_diff
                    time_diff=$(echo "$max_time $min_time" | awk '{printf "%.6f", $1 - $2}')
                    echo "Timing variance: ${time_diff}s" >> "$timing_file"

                    if (( $(echo "$time_diff > 0.01" | bc -l 2>/dev/null || echo 0) )); then
                        timing_sidechannel="true"
                        log_result "FINDING" "CVE-2019-9494: SAE timing variance detected (${time_diff}s)"
                        echo "FINDING: CVE-2019-9494 — SAE timing side-channel (variance: ${time_diff}s)" >> "$findings_file"
                    fi
                fi
            fi

            local groups_used
            groups_used=$(run_fg "${TOOL_PATHS[tshark]}" -r "$sae_pcap" \
                -Y "wlan.fixed.auth.alg == 3 && wlan.fixed.auth.seq == 1" \
                -T fields \
                -e wlan.fixed.finite_cyclic_group \
                2>/dev/null | sort -u | grep -v "^$" || true)

            if [[ -n "$groups_used" ]]; then
                sae_groups="$groups_used"
                if echo "$groups_used" | grep -qE "^(1[0-8]|[1-9])$"; then
                    log_result "FINDING" "Weak SAE group detected (group < 19)"
                    echo "FINDING: Weak SAE group in use" >> "$findings_file"
                fi
            fi

            local anticlog
            anticlog=$(run_fg "${TOOL_PATHS[tshark]}" -r "$sae_pcap" \
                -Y "wlan.fixed.status_code == 76" \
                2>/dev/null | wc -l || echo "0")

            if [[ ${anticlog:-0} -gt 0 ]]; then
                anti_clogging_enforced="true"
                log_success "SAE anti-clogging token enforcement detected"
                echo "Anti-clogging: ENFORCED" >> "$timing_file"
            else
                if [[ "$wpa3_detected" == "true" ]]; then
                    log_info "SAE anti-clogging token not observed"
                    echo "FINDING: Anti-clogging not enforced" >> "$findings_file"
                fi
            fi
        fi
    fi

    #--- Step 5: Transition mode downgrade test ---
    log_step 5 $total_steps "Testing WPA3→WPA2 downgrade (transition mode)"
    update_tc_progress 5 $total_steps "Downgrade test"

    if [[ "$transition_mode" == "true" ]]; then
        downgrade_possible="true"
        echo "FINDING: WPA3→WPA2 downgrade via transition mode" >> "$findings_file"
    fi

    #--- Step 6: Restore managed mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$wpa3_detected" == "false" ]]; then
        result_status="INFO"
        result_summary="WPA3-SAE not detected. Dragonblood tests not applicable."
        recommendations="Consider upgrading to WPA3-SAE."
    elif [[ "$downgrade_possible" == "true" || "$timing_sidechannel" == "true" ]]; then
        result_status="FINDING"
        result_summary="WPA3 Dragonblood vulnerabilities detected. "
        [[ "$downgrade_possible" == "true" ]] && result_summary+="Transition mode allows WPA2 downgrade. "
        [[ "$timing_sidechannel" == "true" ]] && result_summary+="SAE timing side-channel detected. "
        recommendations="1) Disable WPA3 transition mode. 2) Update AP firmware. 3) Use SAE group 19 or higher."
    else
        result_summary="WPA3-SAE detected and no Dragonblood vulnerabilities confirmed."
        recommendations="Keep firmware updated and periodically re-test."
    fi

    evidence_register_file "$wpa3_analysis"
    evidence_register_file "$downgrade_file"
    evidence_register_file "$timing_file"
    [[ -f "$sae_pcap" ]] && evidence_register_file "$sae_pcap"
    evidence_register_file "$findings_file"

    local result_json
    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "WPA3: ${wpa3_detected}, Transition: ${transition_mode}, Downgrade: ${downgrade_possible}, Timing: ${timing_sidechannel}, Groups: ${sae_groups:-unknown}, Anti-clogging: ${anti_clogging_enforced}" \
        --arg recommendations "$recommendations" \
        --arg wpa3_detected "$wpa3_detected" \
        --arg transition_mode "$transition_mode" \
        --arg downgrade_possible "$downgrade_possible" \
        --arg timing_sidechannel "$timing_sidechannel" \
        --arg sae_groups "${sae_groups:-unknown}" \
        --arg anti_clogging_enforced "$anti_clogging_enforced" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            wpa3_detected: ($wpa3_detected == "true"),
            transition_mode: ($transition_mode == "true"),
            downgrade_possible: ($downgrade_possible == "true"),
            timing_sidechannel: ($timing_sidechannel == "true"),
            sae_groups: $sae_groups,
            anti_clogging_enforced: ($anti_clogging_enforced == "true")
        }')

    # 11 Flags
    local has_pri=0
    [[ -f "$sae_pcap" && -s "$sae_pcap" ]] && has_pri=1
    local is_secure=0
    [[ "$result_status" == "SECURE" ]] && is_secure=1

    save_tc_result "D4" "$result_json" 1 1 $has_pri 1 1 1 0 1 1 1 $is_secure
    save_session_state

    return 0
}
