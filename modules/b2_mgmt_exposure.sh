#!/usr/bin/env bash
# MODULE_META
# NAME="Gateway & WLC Management Exposure"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap,curl,wget,ip,jq"
# DESC="Check if gateway/WLC admin panels are reachable from target WiFi"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# DECODE="none"

set -uo pipefail

#===============================================================================
#  modules/b2_mgmt_exposure.sh
#  B2: Gateway & WLC Management Exposure
#
#  PURPOSE:
#    Test if administrative/management interfaces of the default gateway,
#    wireless controller, or other infrastructure devices are accessible
#    from the target WiFi network. Management interfaces should NEVER be
#    reachable from untrusted networks.
#
#  TOOLS: nmap, curl, wget, ip, jq
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  METHODOLOGY:
#    1. Identify the default gateway IP
#    2. Scan gateway for management ports (SSH, HTTP, HTTPS, SNMP, Telnet)
#    3. Scan common WLC IP ranges (x.x.x.1, x.x.x.254, etc.)
#    4. Attempt to access web management interfaces
#    5. Check for additional management services
#
#  EVIDENCE PRODUCED:
#    - b2_gateway_scan.nmap        (gateway port scan)
#    - b2_wlc_scan.nmap            (WLC port scan)
#    - b2_mgmt_interfaces.txt      (accessible management interfaces)
#    - b2_web_screenshots/         (web interface responses)
#
#  RESULT JSON FIELDS:
#    - gateway_mgmt_exposed: bool
#    - exposed_services[]: array of {ip, port, service, protocol}
#    - web_interfaces[]: accessible web management URLs
#    - wlc_identified: bool
#===============================================================================

run_b2() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b2"

    #--- Step 1: Verify connectivity ---
    log_step 1 $total_steps "Verifying target WiFi connectivity"
    update_tc_progress 1 $total_steps "Checking"

    if ! check_module_dependencies "B2"; then
        return 1
    fi

    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    # Ensure we're connected
    if [[ -z "${MY_IP:-}" ]]; then
        MY_IP=$(run_fg --quiet ip -4 addr show "${WIFI_INTERFACE:-wlan0}" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    fi
    if [[ -z "${GATEWAY_IP:-}" ]]; then
        GATEWAY_IP=$(run_fg --quiet ip route 2>/dev/null | awk '/default/{print $3}' | head -1)
    fi

    if [[ -z "$MY_IP" || -z "$GATEWAY_IP" ]]; then
        log_error "Not connected to network. IP=${MY_IP:-none}, GW=${GATEWAY_IP:-none}"
        return 1
    fi

    log_success "Connected: IP=${MY_IP}, Gateway=${GATEWAY_IP}"

    # Determine subnet
    local subnet_base
    subnet_base=$(echo "$GATEWAY_IP" | cut -d. -f1-3)

    #--- Step 2: Scan gateway for management ports ---
    log_step 2 $total_steps "Scanning gateway (${GATEWAY_IP}) for management services"
    update_tc_progress 2 $total_steps "Gateway scan"

    check_abort || return 1

    local gw_scan_file="${evidence_prefix}_gateway_scan.nmap"
    local mgmt_ports="22,23,80,161,162,443,830,8080,8443,8888,4343,5998,9090,3389,4786"

    run_with_spinner "Scanning gateway for management ports" "${TOOL_PATHS[nmap]}" -sT -sV -Pn -p "$mgmt_ports" $NMAP_TIMING "$GATEWAY_IP" -oA "${gw_scan_file%.nmap}"

    # Parse open ports
    local gw_open_ports
    gw_open_ports=$(grep -E "^[0-9]+/" "$gw_scan_file" 2>/dev/null | grep "open")

    local exposed_services="[]"
    local gateway_mgmt_exposed="false"

    if [[ -n "$gw_open_ports" ]]; then
        gateway_mgmt_exposed="true"
        log_result "FINDING" "Gateway (${GATEWAY_IP}) has management ports accessible from target WiFi:"

        while IFS= read -r line; do
            local port protocol state service version
            port=$(echo "$line" | awk -F'/' '{print $1}')
            protocol=$(echo "$line" | awk -F'/' '{print $2}' | awk '{print $1}')
            state=$(echo "$line" | awk '{print $2}')
            service=$(echo "$line" | awk '{print $3}')
            version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)

            log_output "${port}/${protocol} — ${service} ${version}"

            exposed_services=$(echo "$exposed_services" | run_fg jq \
                --arg ip "$GATEWAY_IP" \
                --arg port "$port" \
                --arg protocol "$protocol" \
                --arg service "$service" \
                --arg version "$version" \
                --arg type "gateway" \
                '. += [{ip: $ip, port: $port, protocol: $protocol, service: $service, version: $version, type: $type}]')
        done <<< "$gw_open_ports"
    else
        log_result "SECURE" "No management ports accessible on gateway (${GATEWAY_IP})"
    fi

    #--- Step 3: Discover potential WLC/infrastructure IPs ---
    log_step 3 $total_steps "Scanning for wireless controller and infrastructure devices"
    update_tc_progress 3 $total_steps "WLC discovery"

    check_abort || return 1

    # Common WLC/infrastructure IPs to check
    local wlc_candidates=()
    wlc_candidates+=("${subnet_base}.1")      # Common gateway
    wlc_candidates+=("${subnet_base}.2")      # Secondary
    wlc_candidates+=("${subnet_base}.254")    # Common alt gateway
    wlc_candidates+=("${subnet_base}.253")    # Management device
    wlc_candidates+=("${subnet_base}.10")     # WLC common
    wlc_candidates+=("${subnet_base}.100")    # WLC common

    # Remove gateway (already scanned) and our IP
    local unique_candidates=()
    for candidate in "${wlc_candidates[@]}"; do
        if [[ "$candidate" != "$GATEWAY_IP" && "$candidate" != "${MY_IP%%/*}" ]]; then
            unique_candidates+=("$candidate")
        fi
    done

    local wlc_scan_file="${evidence_prefix}_wlc_scan.nmap"
    local wlc_targets
    wlc_targets=$(printf "%s " "${unique_candidates[@]}" | sed 's/ $//')

    # WLC-specific ports: Cisco 5508/9800 common ports
    local wlc_ports="22,23,80,443,4343,5246,5247,8443,16113,161"

    run_with_spinner "Scanning for WLC/infrastructure devices" "${TOOL_PATHS[nmap]}" -sT -sV -Pn -p "$wlc_ports" $NMAP_TIMING $wlc_targets -oA "${wlc_scan_file%.nmap}"

    local wlc_identified="false"

    # Parse WLC scan results
    local current_host=""
    while IFS= read -r line; do
        if [[ "$line" =~ "Nmap scan report for" ]]; then
            current_host=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        elif [[ "$line" =~ ^[0-9]+/ ]] && [[ "$line" =~ "open" ]]; then
            [[ -z "$current_host" ]] && continue

            local port protocol service version
            port=$(echo "$line" | awk -F'/' '{print $1}')
            protocol=$(echo "$line" | awk -F'/' '{print $2}' | awk '{print $1}')
            service=$(echo "$line" | awk '{print $3}')
            version=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)

            wlc_identified="true"
            log_result "FINDING" "Infrastructure device ${current_host} — port ${port}/${protocol} (${service} ${version})"

            exposed_services=$(echo "$exposed_services" | run_fg jq \
                --arg ip "$current_host" \
                --arg port "$port" \
                --arg protocol "$protocol" \
                --arg service "$service" \
                --arg version "$version" \
                --arg type "infrastructure" \
                '. += [{ip: $ip, port: $port, protocol: $protocol, service: $service, version: $version, type: $type}]')
        fi
    done < "$wlc_scan_file"

    #--- Step 4: Probe web management interfaces ---
    log_step 4 $total_steps "Probing web management interfaces"
    update_tc_progress 4 $total_steps "Web probing"

    check_abort || return 1

    local web_interfaces="[]"
    local mgmt_file="${evidence_prefix}_mgmt_interfaces.txt"

    {
        echo "============================================================"
        echo "  B2: Management Interface Discovery"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$mgmt_file"

    # Collect all IPs with HTTP/HTTPS ports
    local web_targets
    web_targets=$(echo "$exposed_services" | run_fg jq -r '.[] | select(.service | test("http|ssl|https|web"; "i")) | "\(.ip):\(.port)"' | sort -u)

    # Also try common web ports on gateway
    for web_url_combo in "${GATEWAY_IP}:80" "${GATEWAY_IP}:443" "${GATEWAY_IP}:8443" "${GATEWAY_IP}:8080" "${GATEWAY_IP}:4343"; do
        if ! echo "$web_targets" | grep -q "$web_url_combo"; then
            web_targets+=$'\n'"$web_url_combo"
        fi
    done

    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        local c_ip port
        c_ip=$(echo "$target" | cut -d: -f1)
        port=$(echo "$target" | cut -d: -f2)

        # Try HTTPS first, then HTTP
        for scheme in "https" "http"; do
            local url="${scheme}://${c_ip}:${port}"
            local response_file="${evidence_prefix}_web_${c_ip}_${port}_${scheme}.txt"

            local http_code
            http_code=$(run_fg --quiet curl -sk -o "$response_file" -w "%{http_code}" \
                --connect-timeout 5 --max-time 10 \
                "$url" 2>/dev/null || echo "000")

            # Only consider real HTTP responses (must be 3-digit, 1xx-5xx)
            if [[ "$http_code" =~ ^[1-5][0-9][0-9]$ ]]; then
                # Extract title from response
                local page_title
                page_title=$(grep -ioP '(?<=<title>).*?(?=</title>)' "$response_file" 2>/dev/null | head -1 | xargs)
                [[ -z "$page_title" ]] && page_title="(No title)"

                # Extract server header
                local server_header
                server_header=$(run_fg --quiet curl -skI --connect-timeout 5 --max-time 10 "$url" 2>/dev/null | grep -i "^server:" | head -1 | sed 's/server: //i' | xargs)

                log_result "FINDING" "Web interface accessible: ${url} (HTTP ${http_code}) — ${page_title}"

                web_interfaces=$(echo "$web_interfaces" | run_fg jq \
                    --arg url "$url" \
                    --arg status "$http_code" \
                    --arg title "$page_title" \
                    --arg server "${server_header:-unknown}" \
                    '. += [{url: $url, http_status: $status, title: $title, server: $server}]')

                {
                    echo "URL: ${url}"
                    echo "  HTTP Status: ${http_code}"
                    echo "  Title: ${page_title}"
                    echo "  Server: ${server_header:-unknown}"
                    echo "  Response saved: $(basename "$response_file")"
                    echo ""
                } >> "$mgmt_file"

                break  # Don't try HTTP if HTTPS worked
            else
                rm -f "$response_file" 2>/dev/null
            fi
        done
    done <<< "$web_targets"

    #--- Step 5: Check for Cisco-specific endpoints ---
    log_step 5 $total_steps "Checking for vendor-specific management endpoints"
    update_tc_progress 5 $total_steps "Vendor check"

    check_abort || return 1

    # Cisco WLC common endpoints
    local cisco_paths=(
        "/webui"
        "/login.html"
        "/screens/login.html"
        "/admin/login.html"
    )

    # Aruba specific
    local aruba_paths=(
        "/login.html"
        "/arubaui/login"
    )

    for target_ip in "$GATEWAY_IP" "${unique_candidates[@]}"; do
        for path in "${cisco_paths[@]}" "${aruba_paths[@]}"; do
            for scheme in "https" "http"; do
                local url="${scheme}://${target_ip}${path}"
                local http_code
                http_code=$(run_fg --quiet curl -sk -o /dev/null -w "%{http_code}" \
                    --connect-timeout 3 --max-time 5 \
                    "$url" 2>/dev/null || echo "000")

                if [[ "$http_code" =~ ^(200|301|302|401|403)$ ]]; then
                    local page_title
                    page_title=$(run_fg --quiet curl -sk --connect-timeout 3 --max-time 5 "$url" 2>/dev/null | grep -ioP '(?<=<title>).*?(?=</title>)' | head -1 | xargs)

                    # Check for WLC indicators
                    if echo "${page_title:-}" | grep -qiE "cisco|aruba|ruckus|meraki|unifi|fortinet|wireless|controller|wlc"; then
                        log_result "CRITICAL" "WLC management interface found: ${url} — ${page_title}"
                        wlc_identified="true"

                        web_interfaces=$(echo "$web_interfaces" | run_fg jq \
                            --arg url "$url" \
                            --arg status "$http_code" \
                            --arg title "${page_title:-WLC Login}" \
                            --arg server "WLC" \
                            '. += [{url: $url, http_status: $status, title: $title, server: $server}]')
                    fi
                fi
            done
        done
    done

    #--- Step 6: Check SNMP accessibility on gateway ---
    log_step 6 $total_steps "Checking SNMP accessibility on gateway"
    update_tc_progress 6 $total_steps "SNMP check"

    check_abort || return 1

    # Quick SNMP check (detailed SNMP testing is B5)
    if [[ -n "${TOOL_PATHS[snmpwalk]:-}" ]]; then
        for community in "public" "private"; do
            local snmp_result
            snmp_result=$(run_fg --quiet snmpwalk -v2c -c "$community" "$GATEWAY_IP" system 2>/dev/null | head -5)

            if [[ -n "$snmp_result" ]]; then
                log_result "FINDING" "SNMP accessible on gateway with community '${community}'"
                echo "SNMP on ${GATEWAY_IP} community '${community}':" >> "$mgmt_file"
                echo "$snmp_result" | sed 's/^/  /' >> "$mgmt_file"
                echo "" >> "$mgmt_file"

                exposed_services=$(echo "$exposed_services" | run_fg jq \
                    --arg ip "$GATEWAY_IP" \
                    --arg community "$community" \
                    '. += [{ip: $ip, port: "161", protocol: "udp", service: "snmp", version: ("community: " + $community), type: "gateway"}]')
            fi
        done
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local exposed_count
    exposed_count=$(echo "$exposed_services" | run_fg jq 'length')
    local web_count
    web_count=$(echo "$web_interfaces" | run_fg jq 'length')

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $exposed_count -gt 0 ]]; then
        result_status="FINDING"
        result_summary="${exposed_count} management service(s) accessible from target WiFi. ${web_count} web management interface(s) found. "
        if [[ "$wlc_identified" == "true" ]]; then
            result_summary+="CRITICAL: Wireless controller management interface is accessible from target network."
        fi
        recommendations="1) Block all management ports (SSH:22, Telnet:23, HTTP:80/8080/8443, HTTPS:443, SNMP:161) from target VLAN using ACLs. 2) Restrict WLC management to a dedicated management VLAN. 3) Implement management ACLs on the WLC itself. 4) Disable HTTP and use HTTPS-only for remaining management access."
    else
        result_summary="No management services accessible from target WiFi. Gateway and infrastructure devices properly restrict management access from untrusted networks."
        recommendations="Continue monitoring. Ensure management ACLs are maintained during firmware updates."
    fi

    evidence_register_file "$gw_scan_file"
    evidence_register_file "$wlc_scan_file"
    evidence_register_file "$mgmt_file"

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg recommendations "$recommendations" \
        --arg gateway_mgmt_exposed "$gateway_mgmt_exposed" \
        --arg wlc_identified "$wlc_identified" \
        --argjson exposed_services "$exposed_services" \
        --argjson web_interfaces "$web_interfaces" \
        --arg gateway_ip "$GATEWAY_IP" \
        '{
            status: $status,
            summary: $summary,
            details: ("Exposed services: \($exposed_services | length). Web interfaces: \($web_interfaces | length). WLC found: \($wlc_identified)."),
            recommendations: $recommendations,
            gateway_mgmt_exposed: ($gateway_mgmt_exposed == "true"),
            wlc_identified: ($wlc_identified == "true"),
            exposed_services: $exposed_services,
            web_interfaces: $web_interfaces,
            gateway_ip: $gateway_ip,
                    }')

    save_tc_result "B2" "$result_json" 0 1 0 1 1 1 0 1 1 1 0
    save_session_state

    # Display summary
    echo ""
    if [[ $exposed_count -gt 0 ]]; then
        log_result "FINDING" "${exposed_count} management service(s) accessible from target WiFi"
        if [[ "$wlc_identified" == "true" ]]; then
            log_result "CRITICAL" "Wireless controller management interface is accessible!"
        fi
    else
        log_result "SECURE" "No management services accessible from target WiFi"
    fi

    return 0
}