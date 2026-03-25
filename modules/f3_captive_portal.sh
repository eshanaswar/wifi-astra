#!/usr/bin/env bash
# MODULE_META
# NAME="Captive Portal Pre-Auth Bypass"
# CATEGORY="F"
# DEPS="none"
# CRITICAL="no"
# TOOLS="dig,curl"
# DESC="Optional: Test for DNS and ICMP tunneling before authentication"
# REQS="managed_iface"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/f3_captive_portal.sh
#  F3: Captive Portal Pre-Auth Bypass
#
#  PURPOSE:
#    Test for common captive portal bypass vulnerabilities in the 
#    pre-authentication state (e.g., DNS/ICMP/HTTP leakage).
#
#  TOOLS: ping, ${TOOL_PATHS[dig]}, curl
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - f3_preauth_results.txt      (summary of leakage tests)
#
#  RESULT JSON FIELDS:
#    - icmp_bypass: bool
#    - dns_external_bypass: bool
#    - dns_txt_bypass: bool
#===============================================================================

run_f3() {
    set -euo pipefail
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/f3"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and network state"
    update_tc_progress 1 $total_steps "Checking"

    if ! check_module_dependencies "F3"; then
        return 1
    fi

    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    if [[ -z "${WIFI_INTERFACE:-}" ]]; then
        configure_network || return 1
    fi
    log_success "Using interface: ${WIFI_INTERFACE}"

    #--- Step 2: Confirm captive portal context ---
    log_step 2 $total_steps "Confirming captive portal context"
    update_tc_progress 2 $total_steps "Confirming"

    if [[ "${CAPTIVE_PORTAL:-}" == "no" ]]; then
        log_info "Skipping F3: Session state confirmed no captive portal is present."
        save_tc_result "F3" '{"status":"INFO","summary":"Skipped: No portal present","details":"Inherited from A1/Session context."}' "clean_run:1"
        return 0
    fi

    echo ""
    echo -e "  This test MUST be run while in the pre-authenticated state"
    echo -e "  (connected to WiFi but not yet logged into the portal)."
    echo ""
    
    if [[ "${CAPTIVE_PORTAL:-}" != "yes" ]]; then
        get_or_request_param "has_cp" "  Is there a captive portal in the environment? [y/N]"
        if [[ "${has_cp,,}" != "y" ]]; then
            log_info "Skipping F3: No captive portal present."
            save_tc_result "F3" '{"status":"INFO","summary":"Skipped: No portal present","details":"User confirmed no portal."}' "clean_run:1"
            return 0
        fi
    fi

    get_or_request_param "preauth" "  Are you currently PRE-AUTHENTICATED? [Y/n]"
    [[ "${preauth,,}" == "n" ]] && log_warn "Test may yield false positives if already authenticated."

    local txt_file="${evidence_prefix}_preauth_results.txt"
    > "$txt_file"

    #--- Step 3: Test ICMP Leakage ---
    log_step 3 $total_steps "Testing ICMP leakage (ping 8.8.8.8)"
    update_tc_progress 3 $total_steps "ICMP Test"

    check_abort || return 1

    local icmp_bypass="false"
    log_cmd "ping -c 3 -W 2 8.8.8.8"
    if ping -c 3 -W 2 8.8.8.8 &>/dev/null; then
        icmp_bypass="true"
        log_result "FINDING" "ICMP traffic leaks through portal before authentication!"
        echo "ICMP_LEAK: YES" >> "$txt_file"
    else
        log_info "ICMP traffic is correctly blocked."
        echo "ICMP_LEAK: NO" >> "$txt_file"
    fi

    #--- Step 4: Test External DNS Leakage ---
    log_step 4 $total_steps "Testing external DNS leakage (${TOOL_PATHS[dig]} @8.8.8.8)"
    update_tc_progress 4 $total_steps "DNS Test"

    check_abort || return 1

    local dns_ext_bypass="false"
    log_cmd "${TOOL_PATHS[dig]} @8.8.8.8 google.com +short +time=2"
    if ${TOOL_PATHS[dig]} @8.8.8.8 google.com +short +time=2 &>/dev/null; then
        dns_ext_bypass="true"
        log_result "FINDING" "External DNS queries leak through portal!"
        echo "DNS_EXT_LEAK: YES" >> "$txt_file"
    else
        log_info "External DNS is correctly blocked."
        echo "DNS_EXT_LEAK: NO" >> "$txt_file"
    fi

    #--- Step 5: Test DNS TXT Record Leakage ---
    log_step 5 $total_steps "Testing DNS TXT record leakage"
    update_tc_progress 5 $total_steps "TXT Test"

    check_abort || return 1

    local dns_txt_bypass="false"
    log_cmd "${TOOL_PATHS[dig]} TXT google.com +short +time=2"
    if ${TOOL_PATHS[dig]} TXT google.com +short +time=2 &>/dev/null; then
        dns_txt_bypass="true"
        log_info "DNS TXT records are resolvable (potential tunnel vector)."
        echo "DNS_TXT_LEAK: YES" >> "$txt_file"
    else
        echo "DNS_TXT_LEAK: NO" >> "$txt_file"
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local status="SECURE"
    local summary="Portal correctly blocks pre-auth traffic."
    
    if [[ "$icmp_bypass" == "true" || "$dns_ext_bypass" == "true" ]]; then
        status="FINDING"
        summary="Pre-auth ACL bypass detected (ICMP/DNS leakage)."
    fi

    local result_json
    evidence_register_file "$txt_file"

    result_json=$(run_fg --quiet jq -n \
        --arg status "$status" \
        --arg summary "$summary" \
        --arg icmp "$icmp_bypass" \
        --arg dns_ext "$dns_ext_bypass" \
        --arg dns_txt "$dns_txt_bypass" \
        --arg txt "$(basename "$txt_file")" \
        '{
            status: $status,
            summary: $summary,
            icmp_bypass: ($icmp == "true"),
            dns_external_bypass: ($dns_ext == "true"),
            dns_txt_bypass: ($dns_txt == "true"),
            recommendations: (if $status == "FINDING" then "Implement strict pre-auth ACLs to drop ALL traffic except DHCP and DNS to the portal itself." else "No action required." end)
                    }')

    local has_tool_output=0
    [[ -f "$txt_file" ]] && has_tool_output=1

    # save_tc_result: pcap_req, tool_out, prim_art, cmds, vers, env, confirm, known_target, runtime, clean, secure
    save_tc_result "F3" "$result_json" 0 $has_tool_output 0 1 1 1 0 1 1 1 0
    save_session_state
    return 0
}
