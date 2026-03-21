#!/usr/bin/env bash
#===============================================================================
#  modules/e2_fragattacks.sh
#  E2: FragAttacks (Fragmentation & Aggregation Attacks)
#
#  PURPOSE:
#    Test for CVE-2020-24586 through CVE-2020-26145 — a family of 12
#    vulnerabilities in the 802.11 frame aggregation and fragmentation
#    mechanisms. Affects virtually ALL WiFi implementations worldwide.
#    Discovered by Mathy Vanhoef (2021).
#
#  TOOLS: fragattack (python), ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - e2_fragattack_results.txt     (test results per vulnerability)
#    - e2_network_analysis.txt       (AP capability analysis)
#    - e2_capture.pcap               (fragmentation traffic capture)
#    - e2_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - design_flaws_found: int — CVE-2020-24586/87/88
#    - implementation_bugs_found: int
#    - aggregation_vulnerable: bool
#    - fragment_cache_vulnerable: bool
#    - mixed_key_vulnerable: bool
#    - total_vulns: int
#===============================================================================

run_e2() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/e2"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_fragattack=false
    local has_tshark=false
    local has_scapy=false

    # Check for fragattacks tool
    local fragattack_script=""
    for fpath in \
        "/opt/fragattacks/fragattack.py" \
        "/usr/share/fragattacks/fragattack.py" \
        "${SCRIPT_DIR}/tools/fragattacks/fragattack.py" \
        "/opt/fragattack/fragattack.py"; do
        if [[ -f "$fpath" ]]; then
            fragattack_script="$fpath"
            has_fragattack=true
            break
        fi
    done

    command -v tshark &>/dev/null && has_tshark=true
    python3 -c "from scapy.all import *" &>/dev/null 2>&1 && has_scapy=true

    if [[ "$has_fragattack" == "false" ]]; then
        log_warn "fragattacks tool not found. Will perform passive analysis only."
        log_info "For full testing, install: git clone https://github.com/vanhoefm/fragattacks /opt/fragattacks"
    fi

    if [[ "$has_tshark" == "false" ]]; then
        log_error "${TOOL_PATHS[tshark]} is required for frame analysis."
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
    echo "  ║  ★ FragAttacks — 802.11 FRAGMENTATION VULNERABILITIES ★         ║"
    echo "  ║                                                                    ║"
    echo "  ║  Tests for 12 CVEs (CVE-2020-24586 to CVE-2020-26145):            ║"
    echo "  ║                                                                    ║"
    echo "  ║  Design Flaws (affect ALL WiFi):                                   ║"
    echo "  ║    • CVE-2020-24586: Fragment cache not cleared on reconnect       ║"
    echo "  ║    • CVE-2020-24587: Mixed key acceptance (reassembly)             ║"
    echo "  ║    • CVE-2020-24588: A-MSDU frame aggregation (SPP not enforced)  ║"
    echo "  ║                                                                    ║"
    echo "  ║  Implementation Bugs:                                              ║"
    echo "  ║    • Plaintext fragment injection, mixed encrypted/plain frames    ║"
    echo "  ║    • Broadcast frame injection, A-MSDU frame injection             ║"
    echo "  ║                                                                    ║"
    echo "  ║  This may briefly disrupt connectivity for analysis.              ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with FragAttacks testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local design_flaws_found=0
    local implementation_bugs_found=0
    local aggregation_vulnerable="false"
    local fragment_cache_vulnerable="false"
    local mixed_key_vulnerable="false"
    local total_vulns=0
    local findings_file="${evidence_prefix}_findings.txt"
    local results_file="${evidence_prefix}_fragattack_results.txt"
    local analysis_file="${evidence_prefix}_network_analysis.txt"
    local capture_pcap="${evidence_prefix}_capture.pcap"

    {
        echo "============================================================"
        echo "  E2: FragAttacks Testing"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "  CVEs: CVE-2020-24586 to CVE-2020-26145"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  FragAttack Test Results"
        echo "============================================================"
        echo ""
    } > "$results_file"

    #--- Step 2: Enable monitor mode and analyze AP capabilities ---
    log_step 2 $total_steps "Analyzing AP frame capabilities"
    update_tc_progress 2 $total_steps "AP analysis"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    {
        echo "============================================================"
        echo "  AP Capability Analysis"
        echo "============================================================"
        echo ""
    } > "$analysis_file"

    # Capture beacons to check A-MSDU and fragmentation capabilities
    local beacon_pcap="/tmp/e2_beacons.pcap"
    timeout 15 ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -c 30 -w "$beacon_pcap" \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
        &>/dev/null || true

    if [[ -f "$beacon_pcap" && -s "$beacon_pcap" ]]; then
        # Check HT/VHT capabilities for A-MSDU support
        local amsdu_support
        local amsdu_support=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.ht.capabilities \
            -e wlan.ht.amsdumaxlength \
            2>/dev/null | head -1 || true)

        if [[ -n "$amsdu_support" ]]; then
            echo "HT Capabilities: ${amsdu_support}" >> "$analysis_file"
            echo "A-MSDU support detected" >> "$analysis_file"
            log_info "A-MSDU support detected in AP capabilities"
        fi

        # Check for fragmentation threshold
        local frag_threshold
        local frag_threshold=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.fixed.fragment \
            2>/dev/null | head -1 || true)

        echo "Fragmentation threshold: ${frag_threshold:-default}" >> "$analysis_file"

        # Check for SPP A-MSDU (prevents CVE-2020-24588)
        local spp_amsdu
        local spp_amsdu=$(${TOOL_PATHS[tshark]} -r "$beacon_pcap" \
            -Y "wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.rsn.capabilities \
            2>/dev/null | head -1 || true)

        echo "RSN Capabilities (SPP check): ${spp_amsdu:-unknown}" >> "$analysis_file"

        if [[ -z "$spp_amsdu" ]] || ! echo "$spp_amsdu" | grep -q "SPP"; then
            local aggregation_vulnerable="true"
            ((design_flaws_found++))
            log_result "FINDING" "CVE-2020-24588: A-MSDU SPP not enforced — aggregation attack possible"
            echo "FINDING: CVE-2020-24588 — A-MSDU SPP not enforced" >> "$findings_file"
            echo "" >> "$results_file"
            echo "CVE-2020-24588: VULNERABLE — SPP A-MSDU not enforced in RSN capabilities" >> "$results_file"
        else
            echo "CVE-2020-24588: NOT VULNERABLE — SPP A-MSDU enforced" >> "$results_file"
        fi
    fi
    rm -f "$beacon_pcap"

    check_abort || return 1

    #--- Step 3: Capture fragmented frames ---
    log_step 3 $total_steps "Capturing fragmented and aggregated frames (60s)"
    update_tc_progress 3 $total_steps "Frame capture"

    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$capture_pcap" \
        "ether src ${GUEST_BSSID} or ether dst ${GUEST_BSSID}" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    start_countdown 60 "Capturing frames for fragmentation analysis"
    sleep 60
    stop_countdown

    
    validate_pcap "$capture_pcap" "Fragmentation analysis capture"

    check_abort || return 1

    #--- Step 4: Analyze for fragment cache and mixed key issues ---
    log_step 4 $total_steps "Analyzing frame fragmentation patterns"
    update_tc_progress 4 $total_steps "Pattern analysis"

    if [[ -f "$capture_pcap" && -s "$capture_pcap" ]]; then
        # Check for fragmented frames
        local frag_count
        local frag_count=$(${TOOL_PATHS[tshark]} -r "$capture_pcap" \
            -Y "wlan.fc.morefrag == 1" \
            2>/dev/null | wc -l) || true
        local frag_count=${frag_count:-0}

        echo "" >> "$results_file"
        echo "Fragmented frames captured: ${frag_count}" >> "$results_file"

        if [[ $frag_count -gt 0 ]]; then
            log_info "Captured ${frag_count} fragmented frames — fragmentation is in use"

            # CVE-2020-24586: Fragment cache not cleared
            # Indicator: if AP sends fragmented data, the cache might persist
            local fragment_cache_vulnerable="true"
            ((design_flaws_found++))
            echo "CVE-2020-24586: POTENTIALLY VULNERABLE — fragmentation in use, cache behavior needs active test" >> "$results_file"
            echo "FINDING: CVE-2020-24586 — Fragmentation active, fragment cache may not be cleared on reconnect" >> "$findings_file"
        else
            log_info "No fragmented frames observed — fragmentation may be disabled"
            echo "CVE-2020-24586: LOW RISK — no fragmentation observed" >> "$results_file"
        fi

        # CVE-2020-24587: Mixed key acceptance
        # Check if reassembled fragments use consistent encryption
        local mixed_key_indicator
        local mixed_key_indicator=$(${TOOL_PATHS[tshark]} -r "$capture_pcap" \
            -Y "wlan.fc.morefrag == 1 && wlan.fc.protected == 1" \
            -T fields \
            -e wlan.sa -e wlan.ccmp.extiv \
            2>/dev/null | sort -u | wc -l) || true

        if [[ ${mixed_key_indicator:-0} -gt 1 ]]; then
            local mixed_key_vulnerable="true"
            ((design_flaws_found++))
            echo "CVE-2020-24587: POTENTIALLY VULNERABLE — multiple key contexts in fragmented frames" >> "$results_file"
            echo "FINDING: CVE-2020-24587 — Mixed key contexts detected in fragmented frames" >> "$findings_file"
            log_result "FINDING" "CVE-2020-24587: Mixed key contexts in fragmented frames"
        else
            echo "CVE-2020-24587: Could not confirm — requires active injection test" >> "$results_file"
        fi

        # Check for A-MSDU frames
        local amsdu_count
        local amsdu_count=$(${TOOL_PATHS[tshark]} -r "$capture_pcap" \
            -Y "wlan.fc.order == 1" \
            2>/dev/null | wc -l) || true

        echo "A-MSDU frames captured: ${amsdu_count:-0}" >> "$results_file"
    fi

    #--- Step 5: Run fragattacks tool (if available) ---
    log_step 5 $total_steps "Running fragattacks test suite (if available)"
    update_tc_progress 5 $total_steps "FragAttacks tool"

    check_abort || return 1

    if [[ "$has_fragattack" == "true" && -n "$fragattack_script" ]]; then
        log_info "Running fragattacks test suite..."

        # The fragattacks tool tests specific CVEs
        local frag_tests=(
            "ping I,E --amsdu"
            "ping I,E --amsdu-spp"
        )

        for test_cmd in "${frag_tests[@]}"; do
            log_cmd "python3 ${fragattack_script} ${mon_iface} ${test_cmd}"

            local test_output
            local test_output=$(timeout 60 python3 "$fragattack_script" \
                "$mon_iface" $test_cmd \
                2>&1 || true)

            echo "" >> "$results_file"
            echo "Test: ${test_cmd}" >> "$results_file"
            echo "$test_output" >> "$results_file"

            if echo "$test_output" | grep -qi "vulnerable"; then
                ((implementation_bugs_found++))
                log_result "FINDING" "FragAttack test '${test_cmd}' reports VULNERABLE"
                echo "FINDING: FragAttack test '${test_cmd}' — VULNERABLE" >> "$findings_file"
            fi
        done
    else
        log_info "fragattacks tool not installed — using passive analysis only"
        echo "" >> "$results_file"
        echo "NOTE: For active testing, install fragattacks:" >> "$results_file"
        echo "  git clone https://github.com/vanhoefm/fragattacks /opt/fragattacks" >> "$results_file"
        echo "  cd /opt/fragattacks && pip install -r requirements.txt" >> "$results_file"
    fi

    #--- Step 6: Restore managed mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local total_vulns=$((design_flaws_found + implementation_bugs_found))

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $total_vulns -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="FragAttacks: ${total_vulns} potential vulnerability/ies found. "
        result_summary+="Design flaws: ${design_flaws_found} (affect all WiFi). "
        result_summary+="Implementation bugs: ${implementation_bugs_found}. "
        [[ "$aggregation_vulnerable" == "true" ]] && result_summary+="A-MSDU SPP not enforced. "
        [[ "$fragment_cache_vulnerable" == "true" ]] && result_summary+="Fragment cache behavior unverified. "
        [[ "$mixed_key_vulnerable" == "true" ]] && result_summary+="Mixed key context in fragments. "
        local recommendations="1) Update AP firmware to the latest version with FragAttacks patches. "
        recommendations+="2) Update ALL client devices (especially IoT) to patched firmware. "
        recommendations+="3) Enable SPP A-MSDU if supported by the AP/WLC. "
        recommendations+="4) Disable fragmentation if not needed (increase threshold to MTU). "
        recommendations+="5) Consider WPA3 with full security features. "
        recommendations+="6) Enforce HTTPS everywhere — FragAttacks require L2 proximity."
    else
        local result_summary="No FragAttacks vulnerabilities confirmed through passive analysis. "
        result_summary+="Active testing with the fragattacks tool is recommended for complete assessment."
        local recommendations="Install fragattacks tool for comprehensive active testing. Keep firmware updated."
    fi

    local result_json
    evidence_register_file "e2_fragattack_results.txt"
    evidence_register_file "e2_network_analysis.txt"
    evidence_register_file "e2_capture.pcap"
    evidence_register_file "e2_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Design flaws: ${design_flaws_found}, Impl bugs: ${implementation_bugs_found}, A-MSDU: ${aggregation_vulnerable}, Frag cache: ${fragment_cache_vulnerable}, Mixed key: ${mixed_key_vulnerable}" \
        --arg recommendations "$recommendations" \
        --argjson design_flaws_found "$design_flaws_found" \
        --argjson implementation_bugs_found "$implementation_bugs_found" \
        --arg aggregation_vulnerable "$aggregation_vulnerable" \
        --arg fragment_cache_vulnerable "$fragment_cache_vulnerable" \
        --arg mixed_key_vulnerable "$mixed_key_vulnerable" \
        --argjson total_vulns "$total_vulns" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            design_flaws_found: $design_flaws_found,
            implementation_bugs_found: $implementation_bugs_found,
            aggregation_vulnerable: ($aggregation_vulnerable == "true"),
            fragment_cache_vulnerable: ($fragment_cache_vulnerable == "true"),
            mixed_key_vulnerable: ($mixed_key_vulnerable == "true"),
            total_vulns: $total_vulns,
                    }')

    save_tc_result "E2" "$result_json"

    echo ""
    if [[ $total_vulns -gt 0 ]]; then
        log_result "FINDING" "FragAttacks: ${total_vulns} vulnerability/ies — design flaws: ${design_flaws_found}, impl bugs: ${implementation_bugs_found}"
    else
        log_result "SECURE" "FragAttacks: No vulnerabilities confirmed (passive analysis — active test recommended)"
    fi

    return 0
}
