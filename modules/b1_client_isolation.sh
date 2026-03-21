#!/usr/bin/env bash
#===============================================================================
#  modules/b1_client_isolation.sh
#  B1: Client-to-Client Isolation Test
#
#  PURPOSE:
#    Test whether clients connected to the same target WiFi network can
#    communicate with each other. Proper target WiFi should enforce
#    client isolation (AP isolation / peer-to-peer blocking).
#
#  TOOLS: ${TOOL_PATHS[arping]}, ${TOOL_PATHS[fping]}, ${TOOL_PATHS[nmap]}, ${TOOL_PATHS[ip]}
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  METHODOLOGY:
#    1. Discover other clients on the same subnet (ARP scan)
#    2. Attempt ping to discovered clients
#    3. Attempt ARP requests to discovered clients
#    4. Attempt TCP connection to common ports on other clients
#    5. Determine if AP isolation is enforced
#
#  EVIDENCE PRODUCED:
#    - b1_arp_scan.txt             (ARP scan results)
#    - b1_client_reach_test.txt    (reachability test results)
#
#  RESULT JSON FIELDS:
#    - clients_discovered: count of other clients found
#    - clients_reachable: count that responded to probes
#    - isolation_enforced: bool
#    - reachable_clients[]: array of {${TOOL_PATHS[ip]}, mac, responded_to}
#===============================================================================

run_b1() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b1"

    #--- Step 1: Verify connectivity and tools ---
    log_step 1 $total_steps "Verifying target WiFi connectivity and tools"
    update_tc_progress 1 $total_steps "Checking"

    
    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    # Detect or configure interface
    if [[ -z "${WIFI_INTERFACE:-}" ]]; then
        configure_network || return 1
    fi

    # Get current IP
    MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    if [[ -z "$MY_IP" ]]; then
        log_error "No IP address on ${WIFI_INTERFACE}. Are you connected to the target WiFi?"
        echo ""
        echo -e "${C_YELLOW}  Please connect to the target WiFi network first.${C_RESET}"
        echo -e "${C_YELLOW}  SSID to connect to: ${GUEST_SSID:-<set during A1>}${C_RESET}"
        echo ""
        get_or_request_param "_wait" "  Press Enter after connecting (or Q to quit)"
        [[ "${_wait^^}" == "Q" ]] && return 1

        MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
        if [[ -z "$MY_IP" ]]; then
            log_error "Still no IP. Cannot proceed."
            return 1
        fi
    fi

    # Verify WiFi link status and SSID
    local link_info current_ssid
    local link_info=$(iw dev "$WIFI_INTERFACE" link 2>/dev/null || true)
    if echo "$link_info" | grep -q "Not connected"; then
        echo ""
        log_warn "Wireless interface ${WIFI_INTERFACE} is not associated with any AP."
        echo -e "${C_YELLOW}  Please connect to the target WiFi network first.${C_RESET}"
        echo -e "${C_YELLOW}  SSID to connect to: ${GUEST_SSID:-<set during A1>}${C_RESET}"
        echo ""
        get_or_request_param "_wait2" "  Press Enter after connecting (or Q to quit)"
        [[ "${_wait2^^}" == "Q" ]] && return 1
    else
        local current_ssid=$(echo "$link_info" | sed -n 's/.*SSID: //p' | xargs)
        if [[ -n "${GUEST_SSID:-}" && -n "$current_ssid" && "$current_ssid" != "$GUEST_SSID" ]]; then
            echo ""
            log_warn "You appear to be connected to SSID '${current_ssid}', not '${GUEST_SSID}'."
            get_or_request_param "_cont" "  Continue B1 on current network? [y/N]"
            if [[ "${_cont,,}" != "y" ]]; then
                return 1
            fi
        fi
    fi

    local subnet
    subnet=$(echo "$MY_IP" | sed 's|\([0-9]*\.[0-9]*\.[0-9]*\.\).*|\10/24|')
    # Get CIDR from interface
    local cidr
    cidr=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | head -1)

    GATEWAY_IP=$(${TOOL_PATHS[ip]} route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
    MY_MAC=$(${TOOL_PATHS[ip]} link show "$WIFI_INTERFACE" 2>/dev/null | awk '/ether/{print $2}')

    log_success "Connected: IP=${MY_IP}, Gateway=${GATEWAY_IP}, MAC=${MY_MAC}"

    # Prompt for additional test requirements
    echo ""
    echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_CYAN}│  CLIENT ISOLATION TEST                                          │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}│  For best results, connect a SECOND device to the same target    │${C_RESET}"
    echo -e "${C_CYAN}│  WiFi network. This toolkit will try to discover and reach it.  │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}│  If you have a second device connected, enter its IP below.     │${C_RESET}"
    echo -e "${C_CYAN}│  Otherwise, press Enter to scan for all clients.                │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""
    get_or_request_param "second_device_ip" "  Second device IP (or Enter to skip)"

    #--- Step 2: ARP scan to discover clients ---
    log_step 2 $total_steps "ARP scan to discover other clients on ${cidr}"
    update_tc_progress 2 $total_steps "ARP scan"

    check_abort || return 1

    local arp_scan_file="${evidence_prefix}_arp_scan"

    # Method 1: Nmap ARP scan
    run_with_spinner "${TOOL_PATHS[nmap]} -sn -PR ${cidr} -oA ${arp_scan_file}" "Performing ARP discovery scan"

    # Parse discovered hosts
    local discovered_clients=()
    if [[ -f "${arp_scan_file}.nmap" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ "Nmap scan report for" ]]; then
                local c_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                # Skip ourselves and gateway
                if [[ -n "$c_ip" ]] && [[ "$c_ip" != "${MY_IP}" ]] && [[ "$c_ip" != "${GATEWAY_IP}" ]]; then
                    discovered_clients+=("$c_ip")
                fi
            fi
        done < "${arp_scan_file}.nmap"
    fi

    # Add manual second device if provided
    if [[ -n "${second_device_ip:-}" ]]; then
        local found=false
        for c in "${discovered_clients[@]}"; do [[ "$c" == "$second_device_ip" ]] && found=true && break; done
        [[ "$found" == "false" ]] && discovered_clients+=("$second_device_ip")
    fi

    local client_count=${#discovered_clients[@]}

    # Fallback to fping if nothing found
    if [[ $client_count -eq 0 ]]; then
        log_info "No clients found via ARP scan. Trying ping sweep..."
        local fping_out=$(run_attack_tool --timeout 10 --cmd "${TOOL_PATHS[fping]} -a -q -g ${cidr} 2>/dev/null")
        while IFS= read -r c_ip; do
            if [[ -n "$c_ip" ]] && [[ "$c_ip" != "${MY_IP}" ]] && [[ "$c_ip" != "${GATEWAY_IP}" ]]; then
                discovered_clients+=("$c_ip")
            fi
        done <<< "$fping_out"
        client_count=${#discovered_clients[@]}
    fi

    log_info "Testing isolation against ${client_count} target(s)"

    #--- Step 3: Reachability Tests (ICMP, ARP, TCP) ---
    log_step 3 $total_steps "Testing reachability to discovered clients"
    update_tc_progress 3 $total_steps "Reachability"

    local reach_file="${evidence_prefix}_client_reach_test.txt"
    local reachable_count=0
    local reachable_json="[]"

    {
        echo "============================================================"
        echo "  B1: Client Isolation Test Results"
        echo "  Target: ${GUEST_SSID:-unknown}"
        echo "============================================================"
    } > "$reach_file"

    if [[ $client_count -eq 0 ]]; then
        log_warn "No other clients discovered on the network. Isolation cannot be fully verified."
        echo "RESULT: INCONCLUSIVE — No peers found to test against." >> "$reach_file"
    else
        for client_ip in "${discovered_clients[@]}"; do
            echo "" >> "$reach_file"
            echo "--- Target: ${client_ip} ---" >> "$reach_file"
            
            local is_reachable=false
            local methods=()

            # 1. ICMP
            if ping -c 2 -W 2 "$client_ip" &>/dev/null; then
                is_reachable=true
                methods+=("icmp")
                echo "  [+] ICMP: REACHABLE" >> "$reach_file"
            fi

            # 2. ARP
            local arp_out=$(${TOOL_PATHS[arping]} -c 2 -w 2 -I "$WIFI_INTERFACE" "$client_ip" 2>/dev/null)
            if echo "$arp_out" | grep -q "reply from"; then
                is_reachable=true
                methods+=("arp")
                echo "  [+] ARP:  REACHABLE" >> "$reach_file"
            fi

            # 3. TCP (Port 80, 443, 22)
            if ${TOOL_PATHS[nmap]} -sT -Pn -p 22,80,443 --open "$client_ip" 2>/dev/null | grep -q "open"; then
                is_reachable=true
                methods+=("tcp")
                echo "  [+] TCP:  REACHABLE (Common ports open)" >> "$reach_file"
            fi

            if [[ "$is_reachable" == "true" ]]; then
                ((reachable_count++))
                log_result "FINDING" "Client ${client_ip} is REACHABLE via: ${methods[*]}"
                reachable_json=$(echo "$reachable_json" | ${TOOL_PATHS[jq]} \
                    --arg ip "$client_ip" --arg m "${methods[*]}" \
                    '. += [{ip: $ip, methods: $m}]')
            fi
        done
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local isolation_enforced="true"
    local summary="Client isolation appears enforced. No peers reachable."

    if [[ $reachable_count -gt 0 ]]; then
        result_status="FINDING"
        isolation_enforced="false"
        summary="Client isolation NOT enforced. ${reachable_count} client(s) are reachable."
    elif [[ $client_count -eq 0 ]]; then
        result_status="INFO"
        summary="Test inconclusive: No other clients found on the network to test against."
    fi

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$summary" \
        --argjson clients_found "$client_count" \
        --argjson clients_reachable "$reachable_count" \
        --arg isolation_enforced "$isolation_enforced" \
        --argjson reachable_clients "$reachable_json" \
        '{
            status: $status,
            summary: $summary,
            clients_discovered: $clients_found,
            clients_reachable: $clients_reachable,
            isolation_enforced: ($isolation_enforced == "true"),
            reachable_data: $reachable_clients
        }')

    save_tc_result "B1" "$result_json"
    save_session_state

    log_result "$result_status" "$summary"
    return 0
}