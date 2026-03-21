#!/usr/bin/env bash
#===============================================================================
#  modules/c1_dns_resolution.sh
#  C1: Internal DNS Resolution
#
#  PURPOSE:
#    Test whether the DNS server provided to target WiFi clients can resolve
#    internal/corporate hostnames. If the target network uses the same DNS
#    as corporate, internal hostnames and IP addresses may be discoverable.
#
#  TOOLS: ${TOOL_PATHS[dig]}, nslookup
#  PHASE: 1C — Segmentation Testing (Core)
#  DEPENDENCIES: None
#
#  METHODOLOGY:
#    1. Identify DNS server(s) assigned to target WiFi
#    2. Test resolution of common internal hostnames
#    3. Test DNS zone transfer attempts
#    4. Check if DNS server itself is on an internal network
#    5. Test reverse DNS for RFC1918 ranges
#
#  EVIDENCE PRODUCED:
#    - c1_dns_config.txt             (DNS configuration details)
#    - c1_internal_resolution.txt    (internal hostname resolution results)
#    - c1_zone_transfer.txt          (zone transfer attempt results)
#    - c1_reverse_dns.txt            (reverse DNS results)
#
#  RESULT JSON FIELDS:
#    - dns_server: IP of DNS server assigned to guest
#    - internal_resolves: bool — can resolve internal names?
#    - resolved_hostnames[]: array of {hostname, ${TOOL_PATHS[ip]}, type}
#    - zone_transfer_possible: bool
#    - dns_is_internal: bool — is DNS server on RFC1918?
#===============================================================================

run_c1() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/c1"

    #--- Step 1: Verify tools and get DNS config ---
    log_step 1 $total_steps "Identifying DNS configuration"
    update_tc_progress 1 $total_steps "DNS config"

    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    # Get DNS server - prefer value gathered during pre-flight (internal DNS)
    if [[ -z "${DNS_SERVER:-}" ]]; then
        DNS_SERVER=$(resolvectl status "${WIFI_INTERFACE:-wlan0}" 2>/dev/null | grep "DNS Servers:" | awk '{print $NF}' | head -1)
        [[ -z "$DNS_SERVER" ]] && DNS_SERVER=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
    else
        echo ""
        echo -e "  Current DNS Server: ${C_BOLD}${DNS_SERVER}${C_RESET}"
        get_or_request_param "_change_dns" "  Change DNS server for this test? [y/N]"
        if [[ "${_change_dns,,}" == "y" ]]; then
            get_or_request_param "DNS_SERVER" "  Enter INTERNAL DNS server IP"
        fi
    fi

    if [[ -z "$DNS_SERVER" ]]; then
        log_error "Could not identify DNS server."
        get_or_request_param "DNS_SERVER" "  Enter INTERNAL DNS server IP for the target network"
        DNS_SERVER=$(echo "$DNS_SERVER" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
        [[ -z "$DNS_SERVER" ]] && return 1
    fi

    # Clean up DNS_SERVER (remove trailing spaces, multiple IPs, etc.)
    DNS_SERVER=$(echo "$DNS_SERVER" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)

    # Validate that DNS_SERVER looks like an IPv4 address
    if [[ ! "$DNS_SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "DNS server '${DNS_SERVER}' does not look like a valid IPv4 address."
        return 1
    fi

    local dns_config_file="${evidence_prefix}_dns_config.txt"
    {
        echo "============================================================"
        echo "  C1: DNS Configuration"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "DNS Server: ${DNS_SERVER}"
        echo "Interface: ${WIFI_INTERFACE:-unknown}"
        echo "Our IP: ${MY_IP:-unknown}"
        echo ""
        echo "--- /etc/resolv.conf ---"
        cat /etc/resolv.conf 2>/dev/null
        echo ""
        echo "--- resolvectl status ---"
        resolvectl status "${WIFI_INTERFACE:-wlan0}" 2>/dev/null || echo "resolvectl not available"
    } > "$dns_config_file"

    # Check if DNS is internal
    local dns_is_internal="false"
    if echo "$DNS_SERVER" | grep -qP '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
        local dns_is_internal="true"
        log_result "FINDING" "DNS server ${DNS_SERVER} is on an RFC1918 (private) address — internal DNS exposed to target WiFi"
    else
        log_info "DNS server ${DNS_SERVER} appears to be a public DNS"
    fi

    log_success "DNS Server: ${DNS_SERVER} (Internal: ${dns_is_internal})"

    #--- Step 2: Test common internal hostname patterns ---
    log_step 2 $total_steps "Testing resolution of common internal hostnames"
    update_tc_progress 2 $total_steps "Internal DNS"

    check_abort || return 1

    local resolution_file="${evidence_prefix}_internal_resolution.txt"
    local resolved_hostnames="[]"
    local internal_resolves="false"
    local resolve_count=0

    # Common internal hostname patterns to test
    local internal_names=(
        "dc01"
        "dc02"
        "dc1"
        "ad01"
        "ad1"
        "exchange"
        "mail"
        "smtp"
        "imap"
        "owa"
        "autodiscover"
        "intranet"
        "sharepoint"
        "portal"
        "vpn"
        "citrix"
        "fileserver"
        "fs01"
        "print"
        "printer"
        "nas"
        "backup"
        "sql"
        "db01"
        "web01"
        "app01"
        "sccm"
        "wsus"
        "wlc"
        "wireless"
        "switch01"
        "core-sw"
        "fw01"
        "firewall"
        "proxy"
        "siem"
        "splunk"
        "nagios"
        "zabbix"
        "jenkins"
        "gitlab"
        "jira"
        "confluence"
    )

    {
        echo "============================================================"
        echo "  C1: Internal Hostname Resolution Test"
        echo "  DNS Server: ${DNS_SERVER}"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$resolution_file"

    log_info "Preparing internal domain resolution tests..."
    
    # Prompt user for known internal domains
    local custom_domains=()
    local custom_domain_input=""
    get_or_request_param "custom_domain_input" "  [?] Do you know any internal domains to test? (comma-separated, leave blank to skip)"
    if [[ -n "$custom_domain_input" ]]; then
        local IFS=',' read -ra parsed_domains <<< "$custom_domain_input"
        for dom in "${parsed_domains[@]}"; do
            dom=$(echo "$dom" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^\.//')
            if [[ -n "$dom" ]]; then
                custom_domains+=("$dom")
                log_info "Added custom internal domain: ${dom}"
            fi
        done
    fi

    # First, try to discover the internal domain by querying the DNS server
    log_info "Attempting to discover internal domain via reverse DNS & SOA..."
    local internal_domain=""

    # Method 1: Reverse DNS on the DNS server itself
    local rdns
    local rdns=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" -x "$DNS_SERVER" +short +time=1 +tries=1 2>&1 | head -1)
    [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$rdns" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
    if [[ "$rdns" == ";;"* ]]; then rdns=""; fi
    if [[ -n "$rdns" ]]; then
        local internal_domain=$(echo "$rdns" | awk -F. '{for(i=2;i<NF;i++) printf "%s.", $i; print ""}' | sed 's/\.$//')
        log_info "Possible internal domain from reverse DNS: ${internal_domain}"
    fi

    # Method 2: SOA query
    if [[ -z "$internal_domain" ]]; then
        local soa
        local soa=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" . SOA +short +time=1 +tries=1 2>&1 | head -1)
        [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$soa" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
        if [[ "$soa" == ";;"* ]]; then soa=""; fi
        log_debug "SOA query result: ${soa}"
    fi

    # Method 3: Check common domain suffixes
    local domain_suffixes=()
    
    # Add custom user domains first (format with leading dot for FQDN testing)
    for c_dom in "${custom_domains[@]}"; do
        domain_suffixes+=(".${c_dom}")
    done
    
    # Add discovered internal domain
    if [[ -n "$internal_domain" ]]; then
        domain_suffixes+=(".${internal_domain}")
    fi
    
    # Add standard fallback suffixes
    domain_suffixes+=(
        ".local"
        ".internal"
        ".corp"
        ".ad"
        ".lan"
        ".intranet"
        ".company.com"
    )

    # Test each hostname with each domain suffix
    local total_tests=$(( ${#internal_names[@]} * ${#domain_suffixes[@]} ))
    local test_num=0

    local timeout_count=0
    for hostname in "${internal_names[@]}"; do
        check_abort || return 1

        # First try bare hostname
        local result
        local result=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" "$hostname" A +short +time=1 +tries=1 2>&1 | head -1)
        [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$result" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true

        if [[ "$result" == ";;"* ]]; then
            ((timeout_count++))
            if [[ $timeout_count -ge 3 ]]; then
                log_warn "DNS server is unresponsive. Aborting internal resolution tests."
                break
            fi
            local result=""
        else
            local timeout_count=0
        fi

        if [[ -n "$result" ]] && [[ "$result" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            local internal_resolves="true"
            ((resolve_count++))
            log_result "FINDING" "Resolved: ${hostname} → ${result}"

            echo "  ${hostname} → ${result}" >> "$resolution_file"

            resolved_hostnames=$(echo "$resolved_hostnames" | ${TOOL_PATHS[jq]} \
                --arg hostname "$hostname" \
                --arg ip "$result" \
                --arg type "A" \
                '. += [{hostname: $hostname, ip: $c_ip, type: $type}]')
        fi

        # Try with domain suffixes
        for suffix in "${domain_suffixes[@]}"; do
            ((test_num++))
            local fqdn="${hostname}${suffix}"

            local result=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" "$fqdn" A +short +time=1 +tries=1 2>&1 | head -1)
            [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$result" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true

            if [[ "$result" == ";;"* ]]; then
                ((timeout_count++))
                if [[ $timeout_count -ge 3 ]]; then
                    break 2 # Break out of both loops
                fi
                local result=""
            else
                local timeout_count=0
            fi

            if [[ -n "$result" ]] && [[ "$result" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
                local internal_resolves="true"
                ((resolve_count++))
                log_result "FINDING" "Resolved: ${fqdn} → ${result}"

                echo "  ${fqdn} → ${result}" >> "$resolution_file"

                resolved_hostnames=$(echo "$resolved_hostnames" | ${TOOL_PATHS[jq]} \
                    --arg hostname "$fqdn" \
                    --arg ip "$result" \
                    --arg type "A" \
                    '. += [{hostname: $hostname, ip: $c_ip, type: $type}]')

                # Found domain — remember it for remaining tests
                if [[ -z "$internal_domain" ]]; then
                    local internal_domain=$(echo "$suffix" | sed 's/^\.//')
                    log_info "Internal domain discovered: ${internal_domain}"
                fi

                break  # Found for this hostname, skip other suffixes
            fi
        done
    done

    log_info "Resolved ${resolve_count} internal hostname(s)"

    #--- Step 3: Test DNS zone transfer ---
    log_step 3 $total_steps "Attempting DNS zone transfer"
    update_tc_progress 3 $total_steps "Zone transfer"

    check_abort || return 1

    local zone_file="${evidence_prefix}_zone_transfer.txt"
    local zone_transfer_possible="false"

    {
        echo "============================================================"
        echo "  C1: DNS Zone Transfer Attempts"
        echo "  DNS Server: ${DNS_SERVER}"
        echo "============================================================"
        echo ""
    } > "$zone_file"

    # Try zone transfer for custom, discovered, and common domains
    local domains_to_try=()
    
    # Add custom user domains
    for c_dom in "${custom_domains[@]}"; do
        domains_to_try+=("$c_dom")
    done
    
    [[ -n "$internal_domain" ]] && domains_to_try+=("$internal_domain")
    domains_to_try+=("." "local" "internal" "corp")

    for domain in "${domains_to_try[@]}"; do
        log_cmd "${TOOL_PATHS[dig]} @${DNS_SERVER} ${domain} AXFR"
        local axfr_result
        local axfr_result=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" "$domain" AXFR +time=2 +tries=1 2>&1 || true)
        [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$axfr_result" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true

        echo "--- Zone Transfer: ${domain} ---" >> "$zone_file"
        echo "$axfr_result" >> "$zone_file"
        echo "" >> "$zone_file"

        # Check if transfer succeeded (look for multiple records)
        local record_count=0
        local record_count=$(echo "$axfr_result" | grep -c "IN\s" 2>/dev/null) || true
        local record_count=${record_count:-0}

        if [[ $record_count -gt 5 ]]; then
            local zone_transfer_possible="true"
            log_result "CRITICAL" "DNS zone transfer succeeded for '${domain}' — ${record_count} records obtained!"

            # Extract hostnames from zone transfer
            while IFS= read -r zt_line; do
                local zt_name zt_ip
                local zt_name=$(echo "$zt_line" | awk '{print $1}')
                local zt_ip=$(echo "$zt_line" | awk '/IN\s+A\s/{print $NF}')
                if [[ -n "$zt_ip" ]] && [[ "$zt_ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
                    resolved_hostnames=$(echo "$resolved_hostnames" | ${TOOL_PATHS[jq]} \
                        --arg hostname "$zt_name" \
                        --arg ip "$zt_ip" \
                        --arg type "AXFR" \
                        '. += [{hostname: $hostname, ip: $c_ip, type: $type}]')
                fi
            done <<< "$axfr_result"
        fi
    done

    #--- Step 4: Reverse DNS on common internal ranges ---
    log_step 4 $total_steps "Reverse DNS on RFC1918 ranges"
    update_tc_progress 4 $total_steps "Reverse DNS"

    check_abort || return 1

    local reverse_file="${evidence_prefix}_reverse_dns.txt"
    local reverse_count=0

    {
        echo "============================================================"
        echo "  C1: Reverse DNS Results"
        echo "  DNS Server: ${DNS_SERVER}"
        echo "============================================================"
        echo ""
    } > "$reverse_file"

    # Test reverse DNS on the gateway's subnet and common management ranges
    local reverse_ranges=()
    if [[ -n "$GATEWAY_IP" ]]; then
        local gw_base
        local gw_base=$(echo "$GATEWAY_IP" | cut -d. -f1-3)
        reverse_ranges+=("$gw_base")
    fi
    reverse_ranges+=("10.0.0" "10.1.1" "192.168.1" "172.16.0")

    for range in "${reverse_ranges[@]}"; do
        for octet in 1 2 3 5 10 20 50 100 200 254; do
            local test_ip="${range}.${octet}"
            local ptr_result
            local ptr_result=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" -x "$test_ip" +short +time=1 +tries=1 2>&1 | head -1)
            [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$ptr_result" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true

            if [[ "$ptr_result" == ";;"* ]]; then
                break 2 # Stop all reverse lookups if server is dead
                local ptr_result=""
            fi

            if [[ -n "$ptr_result" && "$ptr_result" != *"NXDOMAIN"* ]]; then
                ((reverse_count++))
                local internal_resolves="true"
                log_result "FINDING" "Reverse DNS: ${test_ip} → ${ptr_result}"
                echo "  ${test_ip} → ${ptr_result}" >> "$reverse_file"

                resolved_hostnames=$(echo "$resolved_hostnames" | ${TOOL_PATHS[jq]} \
                    --arg hostname "$ptr_result" \
                    --arg ip "$test_ip" \
                    --arg type "PTR" \
                    '. += [{hostname: $hostname, ip: $c_ip, type: $type}]')
            fi
        done
    done

    log_info "Reverse DNS entries found: ${reverse_count}"

    #--- Step 5: Test DNS rebinding / DNS server version ---
    log_step 5 $total_steps "Gathering DNS server fingerprint"
    update_tc_progress 5 $total_steps "Fingerprint"

    check_abort || return 1

    local dns_version
    local dns_version=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" version.bind TXT CH +short +time=1 +tries=1 2>&1 | head -1)
    local dns_hostname
    local dns_hostname=$(${TOOL_PATHS[dig]} @"$DNS_SERVER" hostname.bind TXT CH +short +time=1 +tries=1 2>&1 | head -1)
    
    if [[ "$dns_version" == ";;"* ]]; then dns_version=""; fi
    if [[ "$dns_hostname" == ";;"* ]]; then dns_hostname=""; fi
    
    if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
        printf "%s\n" "$dns_version" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
        printf "%s\n" "$dns_hostname" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
    fi

    if [[ -n "$dns_version" ]]; then
        log_result "FINDING" "DNS server version exposed: ${dns_version}"
    fi
    if [[ -n "$dns_hostname" ]]; then
        log_result "FINDING" "DNS server hostname exposed: ${dns_hostname}"
    fi

    #--- Step 6: Test if public DNS is blocked (forced to use internal) ---
    log_step 6 $total_steps "Testing if public DNS is accessible"
    update_tc_progress 6 $total_steps "Public DNS"

    check_abort || return 1

    local public_dns_blocked="unknown"
    local public_dns_servers=("8.8.8.8" "1.1.1.1" "9.9.9.9")

    for pdns in "${public_dns_servers[@]}"; do
        local pdns_test
        local pdns_test=$(${TOOL_PATHS[dig]} @"$pdns" google.com A +short +time=1 +tries=1 2>&1 | head -1)
        [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]] && printf "%s\n" "$pdns_test" >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true

        if [[ "$pdns_test" == ";;"* ]]; then pdns_test=""; fi
        if [[ -n "$pdns_test" ]]; then
            local public_dns_blocked="no"
            log_info "Public DNS (${pdns}) is accessible from target WiFi"
            break
        fi
    done

    if [[ "$public_dns_blocked" != "no" ]]; then
        local public_dns_blocked="yes"
        log_info "Public DNS appears blocked — target clients forced to use ${DNS_SERVER}"
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local total_resolved
    total_resolved=$(echo "$resolved_hostnames" | ${TOOL_PATHS[jq]} 'length')

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$internal_resolves" == "true" || "$zone_transfer_possible" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="Target WiFi DNS server (${DNS_SERVER}) resolves internal hostnames. ${total_resolved} internal name(s) discovered. "
        [[ "$zone_transfer_possible" == "true" ]] && result_summary+="CRITICAL: DNS zone transfer is possible — entire internal DNS database exposed. "
        [[ "$dns_is_internal" == "true" ]] && result_summary+="DNS server is on internal (RFC1918) network. "
        local recommendations="1) Provide a separate DNS server for target WiFi that only resolves external names. 2) Use split-horizon DNS to prevent internal name resolution from target VLAN. 3) Disable zone transfers (allow only to secondary DNS servers). 4) Block DNS (UDP/TCP 53) to internal DNS from target VLAN and redirect to a dedicated target DNS resolver. 5) Hide DNS version information."
    else
        local result_summary="Target WiFi DNS server (${DNS_SERVER}) does not resolve internal hostnames. DNS segregation is properly configured."
        local recommendations="No action needed. DNS isolation is effective."
    fi

    local result_json
    evidence_register_file "c1_dns_config.txt"
    evidence_register_file "c1_internal_resolution.txt"
    evidence_register_file "c1_zone_transfer.txt"
    evidence_register_file "c1_reverse_dns.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "DNS: ${DNS_SERVER}, Internal resolves: ${internal_resolves}, Zone xfer: ${zone_transfer_possible}, Entries: ${total_resolved}" \
        --arg recommendations "$recommendations" \
        --arg dns_server "$DNS_SERVER" \
        --arg internal_resolves "$internal_resolves" \
        --arg zone_transfer_possible "$zone_transfer_possible" \
        --arg dns_is_internal "$dns_is_internal" \
        --arg public_dns_blocked "$public_dns_blocked" \
        --arg dns_version "${dns_version:-unknown}" \
        --arg dns_hostname "${dns_hostname:-unknown}" \
        --arg internal_domain "${internal_domain:-unknown}" \
        --argjson resolved_hostnames "$resolved_hostnames" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            dns_server: $dns_server,
            internal_resolves: ($internal_resolves == "true"),
            zone_transfer_possible: ($zone_transfer_possible == "true"),
            dns_is_internal: ($dns_is_internal == "true"),
            public_dns_blocked: ($public_dns_blocked == "yes"),
            dns_version: $dns_version,
            dns_hostname: $dns_hostname,
            internal_domain: $internal_domain,
            resolved_hostnames: $resolved_hostnames,
                    }')

    save_tc_result "C1" "$result_json"

    # Display summary
    echo ""
    if [[ "$internal_resolves" == "true" ]]; then
        log_result "FINDING" "Internal DNS resolution possible from target WiFi (${total_resolved} names)"
        [[ "$zone_transfer_possible" == "true" ]] && log_result "CRITICAL" "DNS zone transfer possible!"
    else
        log_result "SECURE" "Internal DNS resolution not possible from target WiFi"
    fi
    log_result "INFO" "DNS server: ${DNS_SERVER} (Internal: ${dns_is_internal}, Public DNS blocked: ${public_dns_blocked})"

    return 0
}