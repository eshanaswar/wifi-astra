#!/usr/bin/env bash
# MODULE_META
# NAME="DHCP Architecture Analysis"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# DESC="Analyze DHCP configuration and check for rogue DHCP servers"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/b6_dhcp_analysis.sh
#  B6: DHCP Analysis
#
#  PURPOSE:
#    Analyze the DHCP configuration provided to target WiFi clients.
#    Check for information leaks in DHCP options: domain name, DNS servers,
#    WINS servers, NTP servers, gateway, subnet size. Test for DHCP
#    starvation resilience and rogue DHCP detection.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}, dhclient, ${TOOL_PATHS[nmap]}
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - b6_dhcp_capture.pcap        (DHCP exchange capture)
#    - b6_dhcp_options.txt         (parsed DHCP options)
#    - b6_dhcp_findings.txt        (analysis findings)
#
#  RESULT JSON FIELDS:
#    - dhcp_server: IP of DHCP server
#    - domain_name: domain leaked via DHCP
#    - dns_servers[]: DNS servers provided
#    - wins_servers[]: WINS/NetBIOS name servers
#    - ntp_servers[]: NTP servers
#    - lease_time: DHCP lease duration
#    - subnet_size: subnet mask provided
#    - information_leaked: bool
#===============================================================================

run_b6() {
    set -uo pipefail
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b6"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "B6" || return 1
    
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    if [[ -z "${WIFI_INTERFACE:-}" ]]; then
        configure_network || return 1
    fi

    local iface="${WIFI_INTERFACE}"
    log_success "Using interface: ${iface}"

    #--- Step 2: Capture DHCP traffic ---
    log_step 2 $total_steps "Capturing DHCP exchange"
    update_tc_progress 2 $total_steps "DHCP capture"

    check_abort || return 1

    local capture_file="${evidence_prefix}_dhcp_capture.pcap"

    # Start DHCP capture
    local bpf_filter="udp port 67 or udp port 68"
    log_cmd "${TOOL_PATHS[tcpdump]} -i ${iface} -w ${capture_file} '${bpf_filter}'"

    ${TOOL_PATHS[tcpdump]} -i "$iface" -w "$capture_file" "$bpf_filter" &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # Force a DHCP renewal to capture the exchange
    log_info "Forcing DHCP renewal to capture full exchange..."

    if command -v dhclient &>/dev/null; then
        dhclient -r "$iface" 2>/dev/null || true
        sleep 2
        dhclient "$iface" 2>/dev/null || true
    elif command -v dhcpcd &>/dev/null; then
        dhcpcd -k "$iface" 2>/dev/null || true
        sleep 2
        dhcpcd "$iface" 2>/dev/null || true
    else
        log_warn "No DHCP client tool found — relying on passive capture"
    fi

    # Wait for DHCP exchange to complete
    start_countdown 15 "Waiting for DHCP exchange to complete"
    sleep 15
    stop_countdown

    # Also capture any additional DHCP traffic (rogue server detection)
    start_countdown 30 "Listening for additional DHCP servers (rogue detection)"
    sleep 30
    stop_countdown

    
    validate_pcap "$capture_file" "DHCP exchange capture"

    check_abort || return 1

    # Update IP after DHCP renewal
    MY_IP=$(run_tool ip -4 addr show "$iface" 2>/dev/null | awk '/inet/{print $2}' | head -1)
    GATEWAY_IP=$(run_tool ip route show dev "$iface" 2>/dev/null | awk '/default/{print $3}' | head -1)

    log_success "Post-DHCP: IP=${MY_IP}, Gateway=${GATEWAY_IP}"

    #--- Step 3: Parse DHCP options ---
    log_step 3 $total_steps "Parsing DHCP options"
    update_tc_progress 3 $total_steps "Parsing"

    check_abort || return 1

    local options_file="${evidence_prefix}_dhcp_options.txt"
    local dhcp_server=""
    local domain_name=""
    local dns_servers="[]"
    local wins_servers="[]"
    local ntp_servers="[]"
    local lease_time=""
    local subnet_mask=""
    local gateway=""

    {
        echo "============================================================"
        echo "  B6: DHCP Options Analysis"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$options_file"
if [[ -f "$capture_file" ]]; then
    ensure_user_ownership "$capture_file"
    # Extract DHCP ACK (most complete set of options)
    local dhcp_ack
    local dhcp_ack=$(run_as_user tshark -r "$capture_file" \
        -Y "bootp.option.dhcp == 5" \
        -T fields \
        -e ip.src \
...

            -e bootp.option.subnet_mask \
            -e bootp.option.router \
            -e bootp.option.domain_name_server \
            -e bootp.option.domain_name \
            -e bootp.option.broadcast_address \
            -e bootp.option.ip_address_lease_time \
            -e bootp.option.dhcp_server_id \
            -e bootp.option.ntp_server \
            -e bootp.option.netbios_over_tcpip_name_server \
            -e bootp.option.renewal_time_value \
            -e bootp.option.rebinding_time_value \
            -e bootp.ip.your \
            -E separator='|' \
            2>/dev/null | head -1 || true)

        if [[ -n "$dhcp_ack" ]]; then
            local IFS='|' read -r src_ip subnet_mask_val router_val dns_val domain_val broadcast_val \
                lease_val server_id_val ntp_val wins_val renewal_val rebind_val your_ip <<< "$dhcp_ack"

            local dhcp_server="${server_id_val:-${src_ip}}"
            local subnet_mask="${subnet_mask_val}"
            local gateway="${router_val}"
            local domain_name="${domain_val}"
            local lease_time="${lease_val}"

            # Parse DNS servers
            if [[ -n "$dns_val" ]]; then
                for dns in $(echo "$dns_val" | tr ',' ' '); do
                    dns=$(echo "$dns" | xargs)
                    [[ -n "$dns" ]] && dns_servers=$(echo "$dns_servers" | run_fg jq --arg d "$dns" '. += [$d]')
                done
            fi

            # Parse WINS servers
            if [[ -n "$wins_val" ]]; then
                for wins in $(echo "$wins_val" | tr ',' ' '); do
                    wins=$(echo "$wins" | xargs)
                    [[ -n "$wins" ]] && wins_servers=$(echo "$wins_servers" | run_fg jq --arg w "$wins" '. += [$w]')
                done
            fi

            # Parse NTP servers
            if [[ -n "$ntp_val" ]]; then
                for ntp in $(echo "$ntp_val" | tr ',' ' '); do
                    ntp=$(echo "$ntp" | xargs)
                    [[ -n "$ntp" ]] && ntp_servers=$(echo "$ntp_servers" | run_fg jq --arg n "$ntp" '. += [$n]')
                done
            fi

            # Write parsed options
            {
                echo "DHCP Server:      ${dhcp_server}"
                echo "Assigned IP:      ${your_ip:-${MY_IP}}"
                echo "Subnet Mask:      ${subnet_mask}"
                echo "Gateway:          ${gateway}"
                echo "Broadcast:        ${broadcast_val}"
                echo "Domain Name:      ${domain_name}"
                echo "DNS Servers:      $(echo "$dns_servers" | run_fg jq -r 'join(", ")')"
                echo "WINS Servers:     $(echo "$wins_servers" | run_fg jq -r 'join(", ")')"
                echo "NTP Servers:      $(echo "$ntp_servers" | run_fg jq -r 'join(", ")')"
                echo "Lease Time:       ${lease_time}s"
                echo "Renewal Time:     ${renewal_val}s"
                echo "Rebinding Time:   ${rebind_val}s"
                echo ""
            } >> "$options_file"

            log_success "DHCP options parsed successfully"
        else
            log_warn "No DHCP ACK captured — may need to retry"
        fi

        # Check for multiple DHCP servers (rogue detection)
        local dhcp_servers_seen
        local dhcp_servers_seen=$(run_as_user tshark -r "$capture_file" \
            -Y "bootp.option.dhcp == 2" \
            -T fields \
            -e ip.src \
            -e bootp.option.dhcp_server_id \
            2>/dev/null | sort -u || true)

        local server_count
        local server_count=$(echo "$dhcp_servers_seen" | grep -c '[0-9]' 2>/dev/null) || true

        if [[ $server_count -gt 1 ]]; then
            log_result "CRITICAL" "Multiple DHCP servers detected — possible rogue DHCP server!"
            echo "" >> "$options_file"
            echo "*** MULTIPLE DHCP SERVERS DETECTED ***" >> "$options_file"
            echo "$dhcp_servers_seen" | sed 's/^/  /' >> "$options_file"
        fi
    fi

    #--- Step 4: Analyze DHCP information leaks ---
    log_step 4 $total_steps "Analyzing DHCP information leaks"
    update_tc_progress 4 $total_steps "Analyzing"

    check_abort || return 1

    local findings_file="${evidence_prefix}_dhcp_findings.txt"
    local information_leaked="false"
    local findings="[]"

    {
        echo "============================================================"
        echo "  B6: DHCP Findings"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    # Check: Domain name in DHCP Option 15?
    if [[ -n "$domain_name" && "$domain_name" != " " ]]; then
        local information_leaked="true"
        local finding
        # Private/non-routable TLDs indicate internal naming exposure (higher severity)
        if echo "$domain_name" | grep -qiP '\.(local|internal|corp|lan|home|localdomain|ad|private|intra|test)$'; then
            local finding="Private domain name disclosed via DHCP Option 15: '${domain_name}' — reveals internal naming convention"
        else
            # Public/corporate domain — organization identity disclosure
            local finding="Organization domain name disclosed via DHCP Option 15: '${domain_name}' — unnecessary info disclosure on target network"
        fi
        log_result "FINDING" "$finding"
        echo "FINDING: ${finding}" >> "$findings_file"
        findings=$(echo "$findings" | run_fg jq --arg f "$finding" '. += [$f]')
    fi

    # Check: WINS servers provided? (indicates Windows/AD environment)
    local wins_count
    wins_count=$(echo "$wins_servers" | run_fg jq 'length')
    if [[ $wins_count -gt 0 ]]; then
        local information_leaked="true"
        local finding="WINS/NetBIOS name servers provided: $(echo "$wins_servers" | run_fg jq -r 'join(", ")'). This reveals Windows/AD infrastructure."
        log_result "FINDING" "$finding"
        echo "FINDING: ${finding}" >> "$findings_file"
        findings=$(echo "$findings" | run_fg jq --arg f "$finding" '. += [$f]')
    fi

    # Check: DNS servers are internal?
    while IFS= read -r dns; do
        [[ -z "$dns" ]] && continue
        if echo "$dns" | grep -qP '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
            local information_leaked="true"
            local finding="Internal DNS server provided via DHCP: ${dns}"
            log_result "FINDING" "$finding"
            echo "FINDING: ${finding}" >> "$findings_file"
            findings=$(echo "$findings" | run_fg jq --arg f "$finding" '. += [$f]')
        fi
    done < <(echo "$dns_servers" | run_fg jq -r '.[]')

    # Check: NTP servers are internal?
    while IFS= read -r ntp; do
        [[ -z "$ntp" ]] && continue
        if echo "$ntp" | grep -qP '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
            local information_leaked="true"
            local finding="Internal NTP server provided via DHCP: ${ntp}"
            log_result "FINDING" "$finding"
            echo "FINDING: ${finding}" >> "$findings_file"
            findings=$(echo "$findings" | run_fg jq --arg f "$finding" '. += [$f]')
        fi
    done < <(echo "$ntp_servers" | run_fg jq -r '.[]')

    # Check: Subnet too large? (/16 or larger could allow scanning)
    if [[ -n "$subnet_mask" ]]; then
        local cidr_bits
        local cidr_bits=$(_mask_to_cidr "$subnet_mask")
        if [[ $cidr_bits -lt 24 ]]; then
            local information_leaked="true"
            local finding="target subnet is /${cidr_bits} (mask: ${subnet_mask}). Large subnets increase attack surface."
            log_result "FINDING" "$finding"
            echo "FINDING: ${finding}" >> "$findings_file"
            findings=$(echo "$findings" | run_fg jq --arg f "$finding" '. += [$f]')
        fi
    fi

    # Check: DHCP server is internal?
    if [[ -n "$dhcp_server" ]] && echo "$dhcp_server" | grep -qP '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
        # This is expected for internal networks
        log_info "DHCP server is on internal address: ${dhcp_server}"
    fi

    #--- Step 5: Test DHCP starvation resilience ---
    log_step 5 $total_steps "Checking DHCP pool size and configuration"
    update_tc_progress 5 $total_steps "Pool analysis"

    check_abort || return 1

    # Calculate approximate pool size from subnet mask
    if [[ -n "$subnet_mask" ]]; then
        local cidr_bits
        local cidr_bits=$(_mask_to_cidr "$subnet_mask")
        local pool_size=$(( (2 ** (32 - cidr_bits)) - 2 ))

        log_info "Estimated DHCP pool size: ~${pool_size} addresses (/${cidr_bits})"
        echo "" >> "$findings_file"
        echo "DHCP Pool Analysis:" >> "$findings_file"
        echo "  Subnet: /${cidr_bits} (${subnet_mask})" >> "$findings_file"
        echo "  Estimated pool: ~${pool_size} addresses" >> "$findings_file"

        if [[ $pool_size -gt 1000 ]]; then
            local finding="Large DHCP pool (${pool_size} addresses). Consider limiting to actual expected target count."
            log_result "INFO" "$finding"
            echo "  INFO: ${finding}" >> "$findings_file"
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    local findings_count
    findings_count=$(echo "$findings" | run_fg jq 'length')

    if [[ "$information_leaked" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="DHCP configuration leaks internal infrastructure information. ${findings_count} finding(s): "
        result_summary+=$(echo "$findings" | run_fg jq -r 'join("; ")')
        local recommendations="1) Remove organization domain name from DHCP options for target VLAN (Option 15). "
        recommendations+="2) Use public DNS servers (8.8.8.8, 1.1.1.1) or a dedicated target DNS for DHCP Option 6. "
        recommendations+="3) Remove WINS server options (Option 44/46) from target DHCP scope. "
        recommendations+="4) Use public NTP servers for target DHCP. "
        recommendations+="5) Limit target subnet size to /24 or smaller. "
        recommendations+="6) Enable DHCP snooping to prevent rogue DHCP servers."
    else
        local result_summary="DHCP configuration does not leak significant internal infrastructure information. DHCP server: ${dhcp_server}."
        local recommendations="No action needed. DHCP options are appropriate for target use."
    fi

    local result_json
    evidence_register_file "b6_dhcp_capture.pcap"
    evidence_register_file "b6_dhcp_options.txt"
    evidence_register_file "b6_dhcp_findings.txt"

    local result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Server: ${dhcp_server}, Domain: ${domain_name:-none}, Findings: ${findings_count}" \
        --arg recommendations "$recommendations" \
        --arg dhcp_server "${dhcp_server:-unknown}" \
        --arg domain_name "${domain_name:-none}" \
        --argjson dns_servers "$dns_servers" \
        --argjson wins_servers "$wins_servers" \
        --argjson ntp_servers "$ntp_servers" \
        --arg lease_time "${lease_time:-unknown}" \
        --arg subnet_mask "${subnet_mask:-unknown}" \
        --arg gateway "${gateway:-${GATEWAY_IP}}" \
        --arg information_leaked "$information_leaked" \
        --argjson findings "$findings" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            dhcp_server: $dhcp_server,
            domain_name: $domain_name,
            dns_servers: $dns_servers,
            wins_servers: $wins_servers,
            ntp_servers: $ntp_servers,
            lease_time: $lease_time,
            subnet_size: $subnet_mask,
            gateway: $gateway,
            information_leaked: ($information_leaked == "true"),
            findings: $findings,
                    }')

    local has_tool_output=0
    [[ -f "$options_file" || -f "$findings_file" ]] && has_tool_output=1
    local has_primary=0
    [[ -f "$capture_file" ]] && has_primary=1

    local is_secure_claim=0
    [[ "$result_status" == "SECURE" ]] && is_secure_claim=1

    save_tc_result "B6" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 $is_secure_claim
    save_session_state

    # Display summary
    echo ""
    if [[ "$information_leaked" == "true" ]]; then
        log_result "FINDING" "DHCP leaks internal infrastructure info (${findings_count} finding(s))"
    else
        log_result "SECURE" "DHCP configuration appropriate for target WiFi"
    fi
    log_result "INFO" "DHCP Server: ${dhcp_server}, Domain: ${domain_name:-none}, DNS: $(echo "$dns_servers" | run_fg jq -r 'join(", ")')"

    return 0
}

#--- Helper: Convert subnet mask to CIDR notation ---
_mask_to_cidr() {
    local mask="$1"
    local cidr=0
    for octet in $(echo "$mask" | tr '.' ' '); do
        case $octet in
            255) ((cidr+=8)) ;;
            254) ((cidr+=7)) ;;
            252) ((cidr+=6)) ;;
            248) ((cidr+=5)) ;;
            240) ((cidr+=4)) ;;
            224) ((cidr+=3)) ;;
            192) ((cidr+=2)) ;;
            128) ((cidr+=1)) ;;
            0) ;;
        esac
    done
    echo "$cidr"
}