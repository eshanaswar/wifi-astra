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
#  TOOLS: ping, dig, curl
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: None
#===============================================================================

run_f3() {
    set -uo pipefail
    
    local interface=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local is_captive_portal="${CAPTIVE_PORTAL:-unknown}"
    local is_preauth="yes"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --is-captive-portal) is_captive_portal="$2"; shift 2 ;;
            --is-preauthenticated) is_preauth="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    local evidence_prefix="${evidence_dir}/f3"

    local total_steps=6

    #--- Step 1: Verify tools and network state ---
    log_step 1 $total_steps "Verifying tools and network state"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "F3" || return 1

    # Ensure monitor mode is globally disabled (we need to be connected)
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    log_success "Using interface: ${interface}"

    #--- Step 2: Confirm captive portal context ---
    log_step 2 $total_steps "Confirming captive portal context"
    update_tc_progress 2 $total_steps "Confirming"

    if [[ "$is_captive_portal" == "no" ]]; then
        log_info "Skipping F3: No captive portal is present."
        save_tc_result "F3" '{"status":"INFO","summary":"Skipped: No portal present","details":"Inherited from A1/Session context."}' 1 0 0 1 1 1 0 1 1 1 0
        return 0
    fi

    if [[ "$is_preauth" == "no" ]]; then
        log_warn "Test may yield false positives if already authenticated."
    fi

    local txt_file="${evidence_prefix}_preauth_results.txt"
    > "$txt_file"

    #--- Step 3: Test ICMP Leakage ---
    log_step 3 $total_steps "Testing ICMP leakage (ping 8.8.8.8)"
    update_tc_progress 3 $total_steps "ICMP Test"

    check_abort || return 1

    local icmp_bypass="false"
    if ping -c 3 -W 2 8.8.8.8 &>/dev/null; then
        icmp_bypass="true"
        log_result "FINDING" "ICMP traffic leaks through portal before authentication!"
        echo "ICMP_LEAK: YES" >> "$txt_file"
    else
        log_info "ICMP traffic is correctly blocked."
        echo "ICMP_LEAK: NO" >> "$txt_file"
    fi

    #--- Step 4: Test External DNS Leakage ---
    log_step 4 $total_steps "Testing external DNS leakage (dig @8.8.8.8)"
    update_tc_progress 4 $total_steps "DNS Test"

    check_abort || return 1

    local dns_ext_bypass="false"
    if dig @8.8.8.8 google.com +short +time=2 &>/dev/null; then
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
    if dig TXT google.com +short +time=2 &>/dev/null; then
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

    local result_json=$(run_tool jq -n \
        --arg status "$status" \
        --arg summary "$summary" \
        --arg icmp "$icmp_bypass" \
        --arg dns_ext "$dns_ext_bypass" \
        --arg dns_txt "$dns_txt_bypass" \
        '{
            status: $status,
            summary: $summary,
            icmp_bypass: ($icmp == "true"),
            dns_external_bypass: ($dns_ext == "true"),
            dns_txt_bypass: ($dns_txt == "true"),
            recommendations: (if $status == "FINDING" then "Implement strict pre-auth ACLs to drop ALL traffic except DHCP and DNS to the portal itself." else "No action required." end)
        }')

    evidence_register_file "$txt_file"

    save_tc_result "F3" "$result_json" 0 1 0 1 1 1 0 1 1 1 0
    return 0
}
