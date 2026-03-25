#!/usr/bin/env bash
# MODULE_META
# NAME="RADIUS / NAC Server Reachability"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="yes"
# TOOLS="nmap"
# DESC="Attempt direct communication to auth servers via restricted ports"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/c4_radius_reachability.sh
#  C4: RADIUS / NAC Server Reachability ★CRITICAL★
#
#  PURPOSE:
#    Test if authentication servers (RADIUS/NAC) are directly reachable from
#    the target WiFi network over standard authentication or management ports.
#
#  TOOLS: ${TOOL_PATHS[nmap]}
#  PHASE: 1B — Network & Service Recon (Connected)
#  DEPENDENCIES: None
#  CRITICAL: YES
#
#  EVIDENCE PRODUCED:
#    - c4_radius_scan.nmap         (UDP auth port scan)
#    - c4_radius_scan_tcp.nmap     (TCP admin port scan)
#
#  RESULT JSON FIELDS:
#    - open_ports[]: list of open auth/admin ports
#    - targets_scanned[]: list of IPs tested
#===============================================================================

set -uo pipefail

run_c4() {
    set -uo pipefail

    local interface=""
    local nac_ip=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --nac-ip) nac_ip="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals if not provided
    interface="${interface:-${WIFI_INTERFACE:-wlan0}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"

    local total_steps=6
    local evidence_prefix="${evidence_dir}/c4"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and network state"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "C4" || return 1
    
    # Ensure monitor mode is globally disabled (we need to be connected)
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    local gateway_ip="${GATEWAY_IP:-}"

    if [[ -z "$gateway_ip" ]]; then
        gateway_ip=$(run_fg --quiet ip route 2>/dev/null | awk '/default/{print $3}' | head -1)
    fi

    if [[ -z "$gateway_ip" ]]; then
        log_error "Gateway IP not found. Cannot determine network context."
        return 1
    fi
    log_success "Using interface: ${interface}, Gateway: ${gateway_ip}"

    #--- Step 2: Configure scan targets ---
    log_step 2 $total_steps "Configuring scan targets"
    update_tc_progress 2 $total_steps "Configuring"

    echo ""
    echo -e "  To test for RADIUS/NAC reachability, we scan standard auth ports"
    echo -e "  (1812, 1813, 1645, 1646) against the controller/gateway and"
    echo -e "  known internal NAC IP addresses."
    echo ""
    
    if [[ -z "$nac_ip" ]]; then
        stty echo 2>/dev/null
        read -t 0.1 -n 10000 discard 2>/dev/null || true
        printf "  Do you know the IP of the corporate RADIUS/NAC server? (IP or Enter to skip): "
        read nac_ip
    fi
    
    local scan_targets="$gateway_ip"
    [[ -n "$nac_ip" ]] && scan_targets="${gateway_ip} ${nac_ip}"

    local scan_base="${evidence_prefix}_radius_scan"

    #--- Step 3: Scan RADIUS Auth Ports (UDP) ---
    log_step 3 $total_steps "Scanning RADIUS Auth Ports (UDP)"
    update_tc_progress 3 $total_steps "UDP Scan"

    check_abort || return 1

    # Typical ports: 1812 (auth), 1813 (acct), 1645 (old auth), 1646 (old acct), 3799 (CoA)
    log_info "Scanning UDP ports 1812, 1813, 1645, 1646, 3799..."
    run_fg nmap -sU -p 1812,1813,1645,1646,3799 --max-retries 1 -T4 $scan_targets -oA "${scan_base}"

    #--- Step 4: Scan NAC Admin Ports (TCP) ---
    log_step 4 $total_steps "Scanning NAC Admin Ports (TCP)"
    update_tc_progress 4 $total_steps "TCP Scan"

    check_abort || return 1

    log_info "Scanning TCP ports 80, 443, 8443, 4443..."
    run_fg nmap -sT -p 80,443,8443,4443 --max-retries 1 -T4 $scan_targets -oA "${scan_base}_tcp"

    #--- Step 5: Analyze results ---
    log_step 5 $total_steps "Analyzing scan results"
    update_tc_progress 5 $total_steps "Analyzing"

    local nmap_file="${scan_base}.nmap"
    local nmap_tcp_file="${scan_base}_tcp.nmap"
    local open_ports="[]"
    local status="SECURE"
    local summary="No RADIUS/NAC ports found open."

    # Parse UDP results
    if [[ -f "$nmap_file" ]]; then
        local udp_open
        udp_open=$(grep "open " "$nmap_file" | awk '{print $1}' || true)
        while read -r port; do
            [[ -z "$port" ]] && continue
            open_ports=$(echo "$open_ports" | run_fg jq --arg p "$port" '. += [$p]')
        done <<< "$udp_open"
    fi

    # Parse TCP results
    if [[ -f "$nmap_tcp_file" ]]; then
        local tcp_open
        tcp_open=$(grep "open " "$nmap_tcp_file" | awk '{print $1}' || true)
        while read -r port; do
            [[ -z "$port" ]] && continue
            open_ports=$(echo "$open_ports" | run_fg jq --arg p "$port" '. += [$p]')
        done <<< "$tcp_open"
    fi

    local port_count
    port_count=$(echo "$open_ports" | run_fg jq 'length')

    if [[ $port_count -gt 0 ]]; then
        status="FINDING"
        summary="Potential RADIUS/NAC ports (${port_count}) are reachable from the target VLAN."
        log_result "FINDING" "${summary}"
    else
        log_result "SECURE" "All tested RADIUS/NAC ports appear closed/filtered."
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_json
    evidence_register_file "${nmap_file}"
    evidence_register_file "${nmap_tcp_file}"

    result_json=$(run_fg jq -n \
        --arg status "$status" \
        --arg summary "$summary" \
        --argjson ports "$open_ports" \
        --arg nmap_udp "$(basename "$nmap_file")" \
        --arg nmap_tcp "$(basename "$nmap_tcp_file")" \
        '{
            status: $status,
            summary: $summary,
            details: "Detected open RADIUS/NAC ports: \($ports | join(", "))",
            open_ports: $ports,
            recommendations: (if $status == "FINDING" then "Filter UDP 1812/1813 and other RADIUS management ports from the target VLAN. The NAC should drop packets from untrusted subnets." else "No action required." end),
                    }')

    save_tc_result "C4" "$result_json" 0 1 0 1 1 1 0 1 1 1 1
    save_session_state
    return 0
}
