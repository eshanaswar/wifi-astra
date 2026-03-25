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

    local mon_iface="${MONITOR_INTERFACE:-}"
    local target_ssid="${GUEST_SSID:-}"
    local target_bssid="${GUEST_BSSID:-}"
    local target_channel="${GUEST_CHANNEL:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --monitor-interface) mon_iface="$2"; shift 2 ;;
            --target-ssid) target_ssid="$2"; shift 2 ;;
            --target-bssid) target_bssid="$2"; shift 2 ;;
            --target-channel) target_channel="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    local total_steps=5
    local evidence_prefix="${evidence_dir}/h2"
    
    log_step 1 $total_steps "Detecting PMF Support"
    update_tc_progress 1 $total_steps "Detection"

    check_module_dependencies "H2" || return 1

    check_abort || return 1

    if [[ -z "$target_ssid" || -z "$target_bssid" ]]; then
        log_error "Target SSID/BSSID not set. Run A1 first."; return 1
    fi

    # Check scan results for RSN PMF flags via Assessment Engine
    local pmf_supported="false"
    if [[ -n "${ENGINE_SOCKET:-}" && -S "$ENGINE_SOCKET" ]]; then
        local networks_json
        networks_json=$(run_engine_api GET "/v1/networks" 2>/dev/null || echo "[]")
        
        # We can extract the PMF status if we parse encryption or if A1 captured it,
        # but realistically we just check if it's in the network list output.
        # As a simplified check matching original logic:
        if echo "$networks_json" | run_fg jq -r ".[] | select(.bssid == \"$target_bssid\") | .encryption" | grep -qi "WPA3\|PMF"; then
            pmf_supported="true"
            log_info "PMF (802.11w) implicitly detected or WPA3 in use."
        fi
    fi

    log_step 2 $total_steps "Enabling Monitor Mode"
    if [[ -z "$mon_iface" ]]; then
        enable_monitor_mode || return 1
        mon_iface="${MONITOR_INTERFACE}"
    fi

    # Set channel
    if [[ -n "$target_channel" ]]; then
        run_fg --quiet iw dev "$mon_iface" set channel "$target_channel" || true
    fi

    check_abort || return 1

    log_step 3 $total_steps "Selecting Target Client"
    # Try to find an active client on the target AP
    log_info "Listening for clients on ${target_bssid}..."
    local target_client
    target_client=$(run_as_user tshark -i "$mon_iface" -a duration:10 -Y "wlan.bssid == ${target_bssid}" -T fields -e wlan.sa 2>/dev/null | sort | uniq | head -1)
    
    if [[ -z "$target_client" ]]; then
        log_warn "No active clients detected on ${target_ssid}. Cannot test PMF enforcement."
        return 1
    fi
    log_info "Target Client: ${target_client}"

    log_step 4 $total_steps "Attempting Unprotected Deauth"
    update_tc_progress 4 $total_steps "Attack Test"

    check_abort || return 1

    local log_file="${evidence_prefix}_deauth_test.txt"
    log_info "Sending 10 deauth frames to ${target_client}..."
    
    # Send deauths
    run_fg aireplay-ng --deauth 10 -a "${target_bssid}" -c "${target_client}" "${mon_iface}" > "$log_file" 2>&1
    
    # Check if client reconnects immediately (indicator of success)
    log_info "Monitoring for client re-association..."
    local reauth
    reauth=$(timeout 15 run_as_user tshark -i "$mon_iface" -Y "wlan.fc.type_subtype == 0x00 and wlan.addr == ${target_client}" -c 1 2>/dev/null) || true
    
    local vulnerability="SECURE"
    if [[ -n "$reauth" ]]; then
        log_result "FINDING" "PMF BYPASSED: Client responded to unprotected deauth."
        vulnerability="VULNERABLE"
    else
        log_success "PMF ENFORCED: Client ignored unprotected deauth."
    fi

    log_step 5 $total_steps "Saving Results"
    local result_json=$(run_fg jq -n \
        --arg status "$vulnerability" \
        --arg summary "PMF Enforcement: ${vulnerability}" \
        --arg details "AP: ${target_bssid}, Client: ${target_client}" \
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
