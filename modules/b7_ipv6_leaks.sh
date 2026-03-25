#!/usr/bin/env bash
# MODULE_META
# NAME="IPv6 SLAAC & RA Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark,ip"
# DESC="Listen for corporate IPv6 router advertisements bleeding into target VLAN"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="none"

#===============================================================================
#  modules/b7_ipv6_leaks.sh
#  B7: IPv6 SLAAC/RA Leaks
#
#  PURPOSE:
#    Listen for corporate IPv6 router advertisements (RA) bleeding into 
#    the target VLAN, which could allow clients to bypass IPv4 firewalls.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}
#  PHASE: 1B — Network & Service Recon (Connected)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - b7_ipv6_ra.pcap         (raw ICMPv6 RA capture)
#    - b7_ipv6_ra.txt          (extracted prefixes and sources)
#
#  RESULT JSON FIELDS:
#    - ra_count: number of RAs detected
#    - leaked_prefixes[]: list of prefixes found
#===============================================================================

run_b7() {
    set -uo pipefail

    local iface="${WIFI_INTERFACE:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local timeout=45

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) iface="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Finalize local variables
    local interface="${iface:-${WIFI_INTERFACE:-wlan0}}"
    local evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"
    local total_steps=6
    local evidence_prefix="${evidence_dir}/b7"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and network state"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "B7" || return 1
    
    # Ensure monitor mode is globally disabled (we need to be connected)
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    if [[ -z "$interface" ]]; then
        configure_network || return 1
        interface="${WIFI_INTERFACE:-wlan0}"
    fi
    log_success "Using interface: ${interface}"

    #--- Step 2: Configure capture parameters ---
    log_step 2 $total_steps "Configuring capture parameters"
    update_tc_progress 2 $total_steps "Configuring"

    local capture_time="$timeout"
    local pcap_file="${evidence_prefix}_ipv6_ra.pcap"
    local txt_file="${evidence_prefix}_ipv6_ra.txt"

    # Clean up previous evidence
    rm -f "$pcap_file" "$txt_file" 2>/dev/null

    #--- Step 3: Listen for IPv6 Router Advertisements ---
    log_step 3 $total_steps "Listening for IPv6 Router Advertisements (${capture_time}s)"
    update_tc_progress 3 $total_steps "Capturing RA"

    check_abort || return 1

    log_info "Listening for ICMPv6 type 134 on ${interface}..."
    log_cmd "${TOOL_PATHS[tcpdump]} -i ${interface} -nn -v 'icmp6 and ip6[40] == 134' -w ${pcap_file}"

    # Run ${TOOL_PATHS[tcpdump]} in foreground with timeout
    start_countdown "$capture_time" "Listening for IPv6 RA leaks"
    timeout "$capture_time" "${TOOL_PATHS[tcpdump]}" -i "$interface" -nn -v 'icmp6 and ip6[40] == 134' -w "$pcap_file" >/dev/null 2>&1 || true
    stop_countdown

    check_abort || return 1

    #--- Step 4: Validate capture ---
    log_step 4 $total_steps "Validating capture"
    update_tc_progress 4 $total_steps "Validating"

    if ! validate_pcap "$pcap_file" "IPv6 Router Advertisement capture"; then
        # No packets found is a valid "Secure" result
        log_info "No IPv6 Router Advertisements detected during scan window."
    fi

    #--- Step 5: Parse results ---
    log_step 5 $total_steps "Parsing and analyzing capture"
    update_tc_progress 5 $total_steps "Parsing"

    local ra_count=0
    local leaked_prefixes="[]"
    local status="SECURE"
    local summary="No IPv6 Router Advertisements detected."

    if [[ -f "$pcap_file" && -s "$pcap_file" ]]; then
        ensure_user_ownership "$pcap_file"
        log_cmd "${TOOL_PATHS[tshark]} -r ${pcap_file} -Y 'icmpv6.type == 134' -T fields -e ipv6.src -e icmpv6.opt.prefix"
        
        # Extract unique sources and prefixes
        local raw_data
        raw_data=$(run_as_user tshark -r "${pcap_file}" -Y 'icmpv6.type == 134' -T fields -e ipv6.src -e icmpv6.opt.prefix 2>/dev/null | sort -u)
        
        if [[ -n "$raw_data" ]]; then
            echo "$raw_data" > "$txt_file"
            ra_count=$(echo "$raw_data" | wc -l)
            
            while IFS=$'\t' read -r src prefix; do
                [[ -z "$src" ]] && continue
                leaked_prefixes=$(echo "$leaked_prefixes" | run_fg jq --arg s "$src" --arg p "$prefix" '. += [{"src": $s, "prefix": $p}]')
            done <<< "$raw_data"
            
            status="FINDING"
            summary="Detected ${ra_count} unique IPv6 Router Advertisement source/prefix combinations."
            log_result "FINDING" "${summary}"
        else
            log_result "SECURE" "No IPv6 RAs detected. Network is isolated from corporate IPv6 infrastructure."
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    evidence_register_file "$pcap_file"
    evidence_register_file "$txt_file"

    local result_json=$(run_fg jq -n \
        --arg status "$status" \
        --arg summary "$summary" \
        --argjson ra_count "$ra_count" \
        --argjson leaked "$leaked_prefixes" \
        --arg pcap "$(basename "$pcap_file")" \
        --arg txt "$(basename "$txt_file")" \
        '{
            status: $status,
            summary: $summary,
            details: (if $status == "FINDING" then "Found IPv6 router advertisements. This indicates IPv6 isolation is failing, potentially allowing target clients to bypass IPv4 firewalls via IPv6 auto-configuration." else "No rogue IPv6 RAs found." end),
            ra_count: $ra_count,
            leaked_prefixes: $leaked,
            recommendations: (if $status == "FINDING" then "Enable RA Guard on switches. Filter ICMPv6 type 134 (Router Advertisements) at the WLC/Gateway for the target VLAN." else "No action required." end),
                    }')

    local has_tool_output=0
    [[ -f "$txt_file" ]] && has_tool_output=1
    local has_primary=0
    [[ -f "$pcap_file" && -s "$pcap_file" ]] && has_primary=1

    local is_secure_claim=0
    [[ "$status" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "B7" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state
    return 0
}
