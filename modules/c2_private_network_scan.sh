#!/usr/bin/env bash
#===============================================================================
#  modules/c2_private_network_scan.sh
#  C2: Private Network Scan ★CRITICAL★
#
#  PURPOSE:
#    This is the CORE segmentation test. Scan all RFC1918 private IP ranges
#    from the target WiFi to determine if any corporate/internal hosts are
#    reachable. This directly tests network segregation effectiveness.
#
#  TOOLS: ${TOOL_PATHS[masscan]}, ${TOOL_PATHS[nmap]}, ${TOOL_PATHS[fping]}, ${TOOL_PATHS[nbtscan]}
#  PHASE: 1C — Segmentation Testing (Core)
#  DEPENDENCIES: None
#  CRITICAL: YES — This test directly verifies network segregation
#
#  METHODOLOGY:
#    1. Scan 10.0.0.0/8 (Class A)     — fast ping sweep then port scan
#    2. Scan 172.16.0.0/12 (Class B)   — fast ping sweep then port scan
#    3. Scan 192.168.0.0/16 (Class C)  — fast ping sweep then port scan
#    4. Exclude our own subnet (expected to be reachable)
#    5. Port scan any live hosts found
#    6. NetBIOS name scan for Windows hosts
#
#  EVIDENCE PRODUCED:
#    - c2_masscan_10.txt           (10.0.0.0/8 scan results)
#    - c2_masscan_172.txt          (172.16.0.0/12 scan results)
#    - c2_masscan_192.txt          (192.168.0.0/16 scan results)
#    - c2_live_hosts.txt           (all reachable hosts)
#    - c2_port_scan.nmap           (detailed port scan of live hosts)
#    - c2_netbios_scan.txt         (NetBIOS names of Windows hosts)
#
#  RESULT JSON FIELDS:
#    - total_hosts_reachable: count
#    - hosts_outside_target_subnet: count
#    - live_hosts[]: array of {${TOOL_PATHS[ip]}, ports[], services[], netbios_name}
#    - segmentation_bypass: bool — can reach hosts outside target VLAN?
#    - ranges_scanned: which RFC1918 ranges were tested
#===============================================================================

run_c2() {
    local total_steps=8
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/c2"

    #--- Step 1: Verify tools and connectivity ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    local has_masscan=true
    if ! command -v masscan &>/dev/null; then
        has_masscan=false
        log_warn "${TOOL_PATHS[masscan]} not available — will use ${TOOL_PATHS[nmap]} (significantly slower)"
    fi

        # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1


    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    if [[ -z "${MY_IP:-}" ]]; then
        MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "${WIFI_INTERFACE:-wlan0}" 2>/dev/null | awk '/inet/{print $2}' | head -1)
    fi
    if [[ -z "${GATEWAY_IP:-}" ]]; then
        GATEWAY_IP=$(${TOOL_PATHS[ip]} route 2>/dev/null | awk '/default/{print $3}' | head -1)
    fi

    local our_subnet
    our_subnet=$(echo "${MY_IP%%/*}" | cut -d. -f1-3).0/24
    local our_subnet_base
    our_subnet_base=$(echo "${MY_IP%%/*}" | cut -d. -f1-3)

    log_success "Our network: ${MY_IP} on ${our_subnet}"
    log_info "Hosts on ${our_subnet} will be noted but excluded from 'bypass' count"

    #--- Warning banner & subnet targeting ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ CRITICAL SEGMENTATION TEST ★                                  ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test scans private IP ranges from target WiFi to detect      ║"
    echo "  ║  if corporate/internal hosts are reachable (segmentation bypass).  ║"
    echo "  ║                                                                    ║"
    echo "  ║  This generates significant network traffic.                       ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""

    # Ask user for target subnets
    echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_CYAN}│  TARGET SUBNET SELECTION                                        │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}│  Do you know which subnet(s) to target?                         │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}│  Enter one or more subnets in CIDR notation, one per line.      │${C_RESET}"
    echo -e "${C_CYAN}│  Examples: 10.10.0.0/16, 172.16.5.0/24, 192.168.1.0/24         │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}│  Press Enter on empty line when done.                           │${C_RESET}"
    echo -e "${C_CYAN}│  Press Enter immediately (no input) to scan ALL RFC1918 ranges. │${C_RESET}"
    echo -e "${C_CYAN}│                                                                 │${C_RESET}"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""

    local -a user_subnets=()
    local subnet_input=""
    while true; do
        get_or_request_param "subnet_input" "  Subnet (or Enter to finish)"
        [[ -z "$subnet_input" ]] && break
        # Basic validation: must contain /
        if [[ "$subnet_input" == *"/"* ]]; then
            user_subnets+=("$subnet_input")
            log_info "Added target: ${subnet_input}"
        else
            log_warn "Invalid format. Use CIDR notation (e.g. 10.0.0.0/24)"
        fi
    done

    local scan_mode="all"
    if [[ ${#user_subnets[@]} -gt 0 ]]; then
        scan_mode="targeted"
        log_success "Targeted scan: ${#user_subnets[@]} subnet(s)"
        for s in "${user_subnets[@]}"; do
            echo -e "    → ${s}"
        done
    else
        log_info "No subnets specified — scanning ALL RFC1918 ranges"
        log_info "Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
        log_info "Estimated time: 5-15 minutes"
    fi

    echo ""
    get_or_request_param "confirm" "  Proceed with scan? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    #--- Steps 2+: Scan target ranges ---
    local live_hosts="[]"
    local -a scan_targets=()
    local -a ranges_scanned=()

    if [[ "$scan_mode" == "targeted" ]]; then
        local scan_targets=("${user_subnets[@]}")
    else
        scan_targets=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
    fi

    # Recalculate total_steps: 1(check) + N(scans) + 4(classify, port scan, netbios, save)
    total_steps=$(( 1 + ${#scan_targets[@]} + 4 ))
    local step_num=2

    for target_range in "${scan_targets[@]}"; do
        log_step $step_num $total_steps "Scanning ${target_range}"
        update_tc_progress $step_num $total_steps "Scan ${target_range}"

        check_abort || return 1

        ranges_scanned+=("$target_range")
        local range_label
        range_label=$(echo "$target_range" | tr './' '__')
        local mass_file="${evidence_prefix}_scan_${range_label}.txt"

        if [[ "$has_masscan" == "true" ]]; then
            log_cmd "${TOOL_PATHS[masscan]} ${target_range} --ports 22,80,443,445,3389,8080 --rate ${MASSCAN_RATE} --exclude ${our_subnet}"
            start_spinner "Scanning ${target_range} with ${TOOL_PATHS[masscan]} (rate: ${MASSCAN_RATE} pps)"

            local exclude_arg=""
            [[ -n "${our_subnet}" ]] && exclude_arg="--exclude ${our_subnet}"

            ${TOOL_PATHS[masscan]} "$target_range" \
                --ports 22,80,443,445,3389,8080 \
                --rate "$MASSCAN_RATE" \
                $exclude_arg \
                -oL "$mass_file" \
                -oX "${mass_file%.txt}.xml" \
                2>/dev/null || true

            stop_spinner
        else
            # Nmap fallback — sample subnets for large ranges, scan directly for /24s or smaller
            local mask="${target_range##*/}"
            if [[ $mask -le 24 ]]; then
                log_cmd "${TOOL_PATHS[nmap]} -sn -PE -PP ${target_range}"
                start_spinner "Scanning ${target_range} with ${TOOL_PATHS[nmap]}"
                local nmap_exclude_arg=""
                [[ -n "${our_subnet}" ]] && nmap_exclude_arg="--exclude ${our_subnet}"
                ${TOOL_PATHS[nmap]} -sn -PE -PP "$target_range" $nmap_exclude_arg -oA "${mass_file%.txt}" 2>/dev/null || true
                stop_spinner
            else
                # Large range — sample common subnets
                local range_base
                range_base=$(echo "$target_range" | cut -d. -f1)
                local sample_ranges="${range_base}.0.0.0/24 ${range_base}.0.1.0/24 ${range_base}.1.0.0/24 ${range_base}.1.1.0/24 ${range_base}.10.0.0/24 ${range_base}.10.10.0/24 ${range_base}.100.0.0/24"
                log_info "Large range — sampling common subnets in ${target_range}"
                log_cmd "${TOOL_PATHS[nmap]} -sn -PE -PP (sampled subnets)"
                start_spinner "Scanning sample subnets in ${target_range} with ${TOOL_PATHS[nmap]}"
                nmap_exclude_arg=""
                [[ -n "${our_subnet}" ]] && nmap_exclude_arg="--exclude ${our_subnet}"
                ${TOOL_PATHS[nmap]} -sn -PE -PP $sample_ranges $nmap_exclude_arg -oA "${mass_file%.txt}" 2>/dev/null || true
                stop_spinner
            fi
        fi

        # Parse results — ${TOOL_PATHS[masscan]} reads .txt (list format), ${TOOL_PATHS[nmap]} reads .gnmap
        local parse_file="$mass_file"
        if [[ "$has_masscan" != "true" ]]; then
            parse_file="${mass_file%.txt}.gnmap"
        fi
        local hosts_found
        hosts_found=$(_parse_scan_results "$parse_file" "$has_masscan")
        live_hosts=$(echo "$live_hosts" | ${TOOL_PATHS[jq]} --argjson new "$hosts_found" '. + $new')
        local range_count
        range_count=$(echo "$hosts_found" | ${TOOL_PATHS[jq]} 'length')
        log_info "Hosts found in ${target_range}: ${range_count}"

        check_abort || return 1
        ((step_num++))
    done

    #--- Next step: Deduplicate and classify ---
    log_step $step_num $total_steps "Deduplicating and classifying discovered hosts"
    update_tc_progress $step_num $total_steps "Classifying"

    # Deduplicate by IP
    live_hosts=$(echo "$live_hosts" | ${TOOL_PATHS[jq]} '[group_by(.ip)[] | .[0]]')

    local total_hosts
    total_hosts=$(echo "$live_hosts" | ${TOOL_PATHS[jq]} 'length')

    # Separate into target subnet vs outside
    local outside_hosts
    outside_hosts=$(echo "$live_hosts" | ${TOOL_PATHS[jq]} --arg subnet "$our_subnet_base" '[.[] | select(.ip | startswith($subnet) | not)]')
    local outside_count
    outside_count=$(echo "$outside_hosts" | ${TOOL_PATHS[jq]} 'length')

    local target_hosts
    target_hosts=$(echo "$live_hosts" | ${TOOL_PATHS[jq]} --arg subnet "$our_subnet_base" '[.[] | select(.ip | startswith($subnet))]')
    local target_count
    target_count=$(echo "$target_hosts" | ${TOOL_PATHS[jq]} 'length')

    log_info "Total live hosts: ${total_hosts}"
    log_info "  On target subnet (${our_subnet}): ${target_count}"
    log_info "  Outside target subnet: ${outside_count}"

    if [[ $outside_count -gt 0 ]]; then
        log_result "CRITICAL" "${outside_count} host(s) OUTSIDE target subnet are reachable — SEGMENTATION BYPASS!"
    fi

    # Save live hosts list
    local live_hosts_file="${evidence_prefix}_live_hosts.txt"
    {
        echo "============================================================"
        echo "  C2: Live Hosts Discovered"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Our subnet: ${our_subnet}"
        echo "============================================================"
        echo ""
        echo "--- Outside target subnet (SEGMENTATION BYPASS) ---"
        echo "$outside_hosts" | ${TOOL_PATHS[jq]} -r '.[] | "  \(.ip) (port: \(.port // "ping"))"'
        echo ""
        echo "--- On target subnet (Expected) ---"
        echo "$target_hosts" | ${TOOL_PATHS[jq]} -r '.[] | "  \(.ip) (port: \(.port // "ping"))"'
    } > "$live_hosts_file"

    ((step_num++))
    log_step $step_num $total_steps "Port scanning hosts outside target subnet"
    update_tc_progress $step_num $total_steps "Port scan"

    check_abort || return 1

    local detailed_hosts="[]"
    local port_scan_file="${evidence_prefix}_port_scan.nmap"

    if [[ $outside_count -gt 0 ]]; then
        # Get unique IPs of outside hosts (max 50 to avoid excessive scanning)
        local outside_ips
        local outside_ips=$(echo "$outside_hosts" | ${TOOL_PATHS[jq]} -r '.[0:50] | .[].ip' | sort -u)
        local ip_list
        local ip_list=$(echo "$outside_ips" | paste -sd' ' -)

        log_cmd "${TOOL_PATHS[nmap]} -sT -sV --top-ports 100 ${NMAP_TIMING} ${ip_list}"
        run_with_spinner "${TOOL_PATHS[nmap]} -sT -sV --top-ports 100 ${NMAP_TIMING} ${ip_list} -oA ${port_scan_file%.nmap}" \
            "Detailed port scan of ${outside_count} reachable host(s)"

        # Parse ${TOOL_PATHS[nmap]} results
        local current_host=""
        local current_ports="[]"

        while IFS= read -r line; do
            if [[ "$line" =~ "Nmap scan report for" ]]; then
                # Save previous host
                if [[ -n "$current_host" ]]; then
                    detailed_hosts=$(echo "$detailed_hosts" | ${TOOL_PATHS[jq]} \
                        --arg ip "$current_host" \
                        --argjson ports "$current_ports" \
                        '. += [{ip: $c_ip, ports: $ports}]')
                fi
                current_host=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                current_ports="[]"
            elif [[ "$line" =~ ^[0-9]+/ ]] && [[ "$line" =~ "open" ]]; then
                local port service version
                local port=$(echo "$line" | awk -F'/' '{print $1}')
                local service=$(echo "$line" | awk '{print $3}')
                local version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)

                current_ports=$(echo "$current_ports" | ${TOOL_PATHS[jq]} \
                    --arg port "$port" \
                    --arg service "$service" \
                    --arg version "$version" \
                    '. += [{port: $port, service: $service, version: $version}]')

                log_result "CRITICAL" "Reachable from guest: ${current_host}:${port} (${service} ${version})"
            fi
        done < "$port_scan_file"

        # Save last host
        if [[ -n "$current_host" ]]; then
            detailed_hosts=$(echo "$detailed_hosts" | ${TOOL_PATHS[jq]} \
                --arg ip "$current_host" \
                --argjson ports "$current_ports" \
                '. += [{ip: $c_ip, ports: $ports}]')
        fi
    else
        echo "No hosts outside target subnet to scan." > "$port_scan_file"
    fi

    ((step_num++))
    log_step $step_num $total_steps "NetBIOS name scan"
    update_tc_progress $step_num $total_steps "NetBIOS"

    check_abort || return 1

    local netbios_file="${evidence_prefix}_netbios_scan.txt"

    if [[ $outside_count -gt 0 ]] && command -v nbtscan &>/dev/null; then
        local outside_ips_space
        outside_ips_space=$(echo "$outside_hosts" | ${TOOL_PATHS[jq]} -r '.[0:50] | .[].ip' | sort -u)

        log_cmd "${TOOL_PATHS[nbtscan]} on ${outside_count} hosts"
        {
            echo "============================================================"
            echo "  C2: NetBIOS Name Scan"
            echo "============================================================"
            echo ""
        } > "$netbios_file"

        while IFS= read -r c_ip; do
            [[ -z "$c_ip" ]] && continue
            local nbt_result
            local nbt_result=$(timeout 5 ${TOOL_PATHS[nbtscan]} -s '|' "$c_ip" 2>/dev/null | grep -v "^$" || true)
            if [[ -n "$nbt_result" ]]; then
                echo "$nbt_result" >> "$netbios_file"
                local nbt_name
                local nbt_name=$(echo "$nbt_result" | awk -F'|' '{print $2}' | xargs)
                if [[ -n "$nbt_name" ]]; then
                    log_result "CRITICAL" "NetBIOS name: ${c_ip} = ${nbt_name}"
                    # Update detailed_hosts with netbios info
                    detailed_hosts=$(echo "$detailed_hosts" | ${TOOL_PATHS[jq]} \
                        --arg ip "$c_ip" \
                        --arg name "$nbt_name" \
                        '[.[] | if .ip == $c_ip then .netbios_name = $name else . end]')
                fi
            fi
        done <<< "$outside_ips_space"
    else
        echo "${TOOL_PATHS[nbtscan]} not available or no outside hosts to scan." > "$netbios_file"
    fi

    ((step_num++))
    log_step $step_num $total_steps "Saving results"
    update_tc_progress $step_num $total_steps "Saving"

    local segmentation_bypass="false"
    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $outside_count -gt 0 ]]; then
        local segmentation_bypass="true"
        local result_status="FINDING"
        local result_summary="CRITICAL SEGMENTATION BYPASS: ${outside_count} host(s) outside the target subnet (${our_subnet}) are reachable from target WiFi. This means the target WiFi is NOT properly segregated from corporate/internal networks. "
        local scanned_str
        local scanned_str=$(printf '%s, ' "${ranges_scanned[@]}")
        local scanned_str=${scanned_str%, }
        result_summary+="Ranges scanned: ${scanned_str}. "
        result_summary+="Detailed port scan reveals services accessible to target WiFi clients."
        local recommendations="IMMEDIATE ACTION REQUIRED: 1) Review and fix VLAN ACLs to block ALL traffic from target VLAN to internal RFC1918 ranges. 2) Implement inter-VLAN routing restrictions on the core switch/firewall. 3) Ensure the target VLAN can only reach the Internet (default route), not internal subnets. 4) Verify firewall rules between Target and internal zones. 5) Consider placing target WiFi on a completely separate network segment with its own Internet breakout."
    else
        local scanned_str
        local scanned_str=$(printf '%s, ' "${ranges_scanned[@]}")
        local scanned_str=${scanned_str%, }
        local result_summary="No hosts outside the target subnet are reachable. Network segmentation appears effective. Scanned: ${scanned_str}."
        local recommendations="Segmentation is working. Re-test periodically, especially after network changes."
    fi

    local ranges_str_jq
    local ranges_str_jq=$(printf '%s,' "${ranges_scanned[@]}")
    local ranges_str_jq=${ranges_str_jq%,}

    local result_json
    evidence_register_file "c2_live_hosts.txt"
    evidence_register_file "c2_port_scan.nmap"
    evidence_register_file "c2_netbios_scan.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Total: ${total_hosts}, target subnet: ${target_count}, Outside: ${outside_count}" \
        --arg recommendations "$recommendations" \
        --argjson total_hosts_reachable "$total_hosts" \
        --argjson hosts_outside_target_subnet "$outside_count" \
        --arg segmentation_bypass "$segmentation_bypass" \
        --arg our_subnet "$our_subnet" \
        --arg ranges_str "$ranges_str_jq" \
        --argjson live_hosts "$detailed_hosts" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            total_hosts_reachable: $total_hosts_reachable,
            hosts_outside_target_subnet: $hosts_outside_target_subnet,
            segmentation_bypass: ($segmentation_bypass == "true"),
            our_subnet: $our_subnet,
            ranges_scanned: ($ranges_str | split(",") | map(ltrimstr(" "))),
            live_hosts: $live_hosts,
                    }')

    save_tc_result "C2" "$result_json"

    # Display summary
    echo ""
    if [[ "$segmentation_bypass" == "true" ]]; then
        log_result "CRITICAL" "★ SEGMENTATION BYPASS: ${outside_count} internal host(s) reachable from target WiFi"
        echo ""
        echo -e "  ${C_RED}${C_BOLD}  Reachable internal hosts:${C_RESET}"
        echo "$detailed_hosts" | ${TOOL_PATHS[jq]} -r '.[] | "    \(.ip) — Ports: \(.ports | map(.port + "/" + .service) | join(", ")) \(if .netbios_name then "(" + .netbios_name + ")" else "" end)"'
    else
        log_result "SECURE" "Network segmentation effective — no internal hosts reachable from target WiFi"
    fi

    return 0
}

#--- Helper: Parse ${TOOL_PATHS[masscan]} or ${TOOL_PATHS[nmap]} results into JSON array ---
_parse_scan_results() {
    local file="$1"
    local is_masscan="$2"
    local result="[]"

    [[ ! -f "$file" ]] && echo "[]" && return

    if [[ "$is_masscan" == "true" ]]; then
        # Masscan list format: open tcp PORT IP TIMESTAMP
        while IFS=' ' read -r status proto port ${TOOL_PATHS[ip]} timestamp; do
            [[ "$status" != "open" ]] && continue
            [[ -z "$c_ip" ]] && continue

            result=$(echo "$result" | ${TOOL_PATHS[jq]} \
                --arg ip "$c_ip" \
                --arg port "$port" \
                --arg proto "$proto" \
                '. += [{ip: $c_ip, port: $port, proto: $proto}]')
        done < "$file"
    else
        # Nmap greppable format
        while IFS= read -r line; do
            if [[ "$line" =~ "Status: Up" ]] || [[ "$line" =~ "Ports:" ]]; then
                local c_ip
                ${TOOL_PATHS[ip]}=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                [[ -z "$c_ip" ]] && continue

                result=$(echo "$result" | ${TOOL_PATHS[jq]} --arg ip "$c_ip" '. += [{ip: $c_ip, port: "ping", proto: "icmp"}]')
            fi
        done < "$file"
    fi

    echo "$result"
}