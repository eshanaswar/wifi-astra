#!/usr/bin/env bash
#===============================================================================
#  modules/b4_mdns_leaks.sh
#  B4: mDNS/Bonjour Information Leaks
#
#  PURPOSE:
#    Detect multicast DNS (mDNS) / Bonjour / SSDP service announcements
#    visible on the target WiFi network. Corporate devices (printers, AirPlay,
#    file shares, IoT) may broadcast services that reveal internal infrastructure.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[avahi-browse]}
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - b4_mdns_capture.pcap          (raw mDNS/SSDP capture)
#    - b4_mdns_services.txt          (parsed service list)
#    - b4_ssdp_devices.txt           (parsed SSDP/UPnP devices)
#
#  RESULT JSON FIELDS:
#    - mdns_services_found: count
#    - ssdp_devices_found: count
#    - services[]: array of {name, type, host, ${TOOL_PATHS[ip]}, port}
#    - corporate_services_leaked: bool
#===============================================================================

run_b4() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b4"

    #--- Step 1: Verify tools and connectivity ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    
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

    #--- Step 2: Capture mDNS traffic ---
    log_step 2 $total_steps "Capturing mDNS/Bonjour traffic (${MDNS_CAPTURE_TIME}s)"
    update_tc_progress 2 $total_steps "mDNS capture"

    check_abort || return 1

    local capture_file="${evidence_prefix}_mdns_capture.pcap"

    # mDNS: UDP port 5353, multicast 224.0.0.251 / ff02::fb
    # SSDP: UDP port 1900, multicast 239.255.255.250
    local bpf_filter="(udp port 5353) or (udp port 1900)"

    log_cmd "${TOOL_PATHS[tcpdump]} -i ${iface} -w ${capture_file} '${bpf_filter}' (timeout: ${MDNS_CAPTURE_TIME}s)"

    ${TOOL_PATHS[tcpdump]} -i "$iface" -w "$capture_file" "$bpf_filter" &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # Also run ${TOOL_PATHS[avahi-browse]} in parallel if available
    local avahi_file="${evidence_prefix}_avahi_browse.txt"
    local avahi_pid=""
    if command -v avahi-browse &>/dev/null; then
        log_cmd "${TOOL_PATHS[avahi-browse]} -a -t -r -p (timeout: ${MDNS_CAPTURE_TIME}s)"
        timeout "$MDNS_CAPTURE_TIME" ${TOOL_PATHS[avahi-browse]} -a -t -r -p > "$avahi_file" 2>/dev/null &
        avahi_pid=$!
        register_cleanup "kill -TERM $avahi_pid 2>/dev/null || true; sleep 0.5; kill -9 $avahi_pid 2>/dev/null || true; wait $avahi_pid 2>/dev/null || true"
    fi

    start_countdown "$MDNS_CAPTURE_TIME" "Capturing mDNS/Bonjour and SSDP announcements"
    sleep "$MDNS_CAPTURE_TIME"
    stop_countdown

    # Stop captures
        if [[ -n "$avahi_pid" ]]; then
        kill -TERM "$avahi_pid" 2>/dev/null
        wait "$avahi_pid" 2>/dev/null
    fi

    validate_pcap "$capture_file" "mDNS/Bonjour and SSDP traffic capture"

    check_abort || return 1

    #--- Step 3: Parse mDNS services ---
    log_step 3 $total_steps "Parsing mDNS service announcements"
    update_tc_progress 3 $total_steps "Parsing mDNS"

    check_abort || return 1

    local services_file="${evidence_prefix}_mdns_services.txt"
    local services_json="[]"
    local mdns_count=0

    {
        echo "============================================================"
        echo "  B4: mDNS/Bonjour Service Discovery"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$services_file"

    # Parse from ${TOOL_PATHS[tshark]}
    if [[ -f "$capture_file" ]]; then
        local mdns_data
        local mdns_data=$(${TOOL_PATHS[tshark]} -r "$capture_file" \
            -Y "mdns && dns.resp.type == 33" \
            -T fields \
            -e ip.src \
            -e dns.srv.name \
            -e dns.srv.target \
            -e dns.srv.port \
            -E separator='|' \
            2>/dev/null | sort -u || true)

        while IFS='|' read -r src_ip srv_name srv_target srv_port; do
            [[ -z "$srv_name" ]] && continue
            ((mdns_count++))

            srv_name=$(echo "$srv_name" | xargs)
            local srv_target=$(echo "$srv_target" | xargs)
            local srv_port=$(echo "$srv_port" | xargs)

            echo "  Service: ${srv_name}" >> "$services_file"
            echo "    Host: ${srv_target}" >> "$services_file"
            echo "    IP: ${src_ip}" >> "$services_file"
            echo "    Port: ${srv_port}" >> "$services_file"
            echo "" >> "$services_file"

            services_json=$(echo "$services_json" | ${TOOL_PATHS[jq]} \
                --arg name "$srv_name" \
                --arg host "$srv_target" \
                --arg ip "${src_ip:-unknown}" \
                --arg port "${srv_port:-0}" \
                --arg type "mDNS" \
                '. += [{name: $name, host: $host, ip: $c_ip, port: $port, protocol: $type}]')

        done <<< "$mdns_data"

        # Also extract PTR records (service types)
        local ptr_data
        local ptr_data=$(${TOOL_PATHS[tshark]} -r "$capture_file" \
            -Y "mdns && dns.resp.type == 12" \
            -T fields \
            -e ip.src \
            -e dns.qry.name \
            -e dns.ptr.domain_name \
            -E separator='|' \
            2>/dev/null | sort -u || true)

        while IFS='|' read -r src_ip query_name ptr_domain; do
            [[ -z "$ptr_domain" ]] && continue

            # Skip if already counted (avoid duplicates)
            local already_counted
            local already_counted=$(echo "$services_json" | ${TOOL_PATHS[jq]} --arg n "$ptr_domain" '[.[] | select(.name == $n)] | length')
            [[ $already_counted -gt 0 ]] && continue

            ((mdns_count++))

            echo "  Service Type: ${query_name}" >> "$services_file"
            echo "    Instance: ${ptr_domain}" >> "$services_file"
            echo "    Source IP: ${src_ip}" >> "$services_file"
            echo "" >> "$services_file"

            services_json=$(echo "$services_json" | ${TOOL_PATHS[jq]} \
                --arg name "$ptr_domain" \
                --arg host "unknown" \
                --arg ip "${src_ip:-unknown}" \
                --arg port "0" \
                --arg type "mDNS-PTR" \
                --arg service_type "${query_name}" \
                '. += [{name: $name, host: $host, ip: $c_ip, port: $port, protocol: $type, service_type: $service_type}]')
        done <<< "$ptr_data"
    fi

    # Parse ${TOOL_PATHS[avahi-browse]} results
    if [[ -f "$avahi_file" && -s "$avahi_file" ]]; then
        while IFS=';' read -r event iface ipver service_name service_type domain hostname ${TOOL_PATHS[ip]} port txt; do
            [[ "$event" != "=" ]] && continue
            [[ -z "$service_name" ]] && continue

            # Check if not already in list
            local already
            local already=$(echo "$services_json" | ${TOOL_PATHS[jq]} --arg n "$service_name" '[.[] | select(.name == $n)] | length')
            [[ $already -gt 0 ]] && continue

            ((mdns_count++))

            services_json=$(echo "$services_json" | ${TOOL_PATHS[jq]} \
                --arg name "$service_name" \
                --arg host "${hostname:-unknown}" \
                --arg ip "${c_ip:-unknown}" \
                --arg port "${port:-0}" \
                --arg type "avahi" \
                --arg service_type "${service_type}" \
                '. += [{name: $name, host: $host, ip: $c_ip, port: $port, protocol: $type, service_type: $service_type}]')
        done < "$avahi_file"
    fi

    log_info "mDNS services found: ${mdns_count}"

    #--- Step 4: Parse SSDP/UPnP ---
    log_step 4 $total_steps "Parsing SSDP/UPnP announcements"
    update_tc_progress 4 $total_steps "Parsing SSDP"

    check_abort || return 1

    local ssdp_file="${evidence_prefix}_ssdp_devices.txt"
    local ssdp_count=0

    {
        echo "============================================================"
        echo "  B4: SSDP/UPnP Device Discovery"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$ssdp_file"

    if [[ -f "$capture_file" ]]; then
        local ssdp_data
        local ssdp_data=$(${TOOL_PATHS[tshark]} -r "$capture_file" \
            -Y "ssdp" \
            -T fields \
            -e ip.src \
            -e http.server \
            -e http.location \
            -E separator='|' \
            2>/dev/null | sort -u || true)

        while IFS='|' read -r src_ip server location; do
            [[ -z "$src_ip" ]] && continue
            # Filter out wireshark protocol dissector artifacts (false positives)
            if echo "${server}${location}" | grep -qiE 'proto_name=|description=|wireshark'; then
                continue
            fi
            ((ssdp_count++))

            echo "  Device: ${src_ip}" >> "$ssdp_file"
            echo "    Server: ${server:-unknown}" >> "$ssdp_file"
            echo "    Location: ${location:-unknown}" >> "$ssdp_file"
            echo "" >> "$ssdp_file"

            services_json=$(echo "$services_json" | ${TOOL_PATHS[jq]} \
                --arg name "SSDP: ${server:-unknown}" \
                --arg host "${src_ip}" \
                --arg ip "$src_ip" \
                --arg port "1900" \
                --arg type "SSDP" \
                --arg location "${location:-}" \
                '. += [{name: $name, host: $host, ip: $c_ip, port: $port, protocol: $type, location: $location}]')
        done <<< "$ssdp_data"
    fi

    log_info "SSDP devices found: ${ssdp_count}"

    #--- Step 5: Classify leaked services ---
    log_step 5 $total_steps "Classifying leaked services (corporate vs expected)"
    update_tc_progress 5 $total_steps "Classifying"

    check_abort || return 1

    local corporate_leak="false"
    local sensitive_services="[]"

    # Patterns that indicate corporate/internal service leaks
    local corp_patterns=(
        "_smb._tcp"            # Windows file sharing
        "_afpovertcp._tcp"     # Apple file sharing
        "_rfb._tcp"            # VNC remote desktop
        "_ssh._tcp"            # SSH servers
        "_rdp._tcp"            # Remote Desktop
        "_printer._tcp"        # Printers
        "_ipp._tcp"            # Internet Printing Protocol
        "_pdl-datastream._tcp" # Printer data stream
        "_airplay._tcp"        # AirPlay
        "_raop._tcp"           # AirPlay audio
        "_companion-link._tcp" # Apple Companion
        "_homekit._tcp"        # HomeKit
        "_googlecast._tcp"     # Chromecast
        "_spotify-connect"     # Spotify
        "_http._tcp"           # Web servers
        "_https._tcp"          # HTTPS servers
        "_nfs._tcp"            # NFS shares
        "_ftp._tcp"            # FTP servers
    )

    # Use index-based ${TOOL_PATHS[jq]} iteration to avoid shell word-splitting issues with ${TOOL_PATHS[jq]} -c output
    local svc_count
    svc_count=$(echo "$services_json" | ${TOOL_PATHS[jq]} 'length')
    
    for (( si=0; si < svc_count; si++ )); do
        local svc_name svc_type
        local svc_name=$(echo "$services_json" | ${TOOL_PATHS[jq]} -r ".[$si].name // \"\"")
        local svc_type=$(echo "$services_json" | ${TOOL_PATHS[jq]} -r ".[$si].service_type // \"\"")

        for pattern in "${corp_patterns[@]}"; do
            if echo "${svc_name}${svc_type}" | grep -qi "$pattern"; then
                local corporate_leak="true"
                local svc_entry
                local svc_entry=$(echo "$services_json" | ${TOOL_PATHS[jq]} ".[$si]")
                sensitive_services=$(echo "$sensitive_services" | ${TOOL_PATHS[jq]} --argjson svc "$svc_entry" '. += [$svc]')
                log_result "FINDING" "Corporate service leaked: ${svc_name} (${svc_type})"
                break
            fi
        done
    done

    local sensitive_count
    sensitive_count=$(echo "$sensitive_services" | ${TOOL_PATHS[jq]} 'length')

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local total_services=$(( mdns_count + ssdp_count ))
    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$corporate_leak" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="${total_services} service(s) discovered via mDNS/SSDP on target WiFi. ${sensitive_count} appear to be corporate/internal services (printers, file shares, AirPlay, etc.) that should not be visible to target clients."
        local recommendations="1) Enable mDNS/IGMP filtering on the target VLAN to block multicast 224.0.0.251 and 239.255.255.250. "
        recommendations+="2) Configure the wireless controller to suppress multicast/broadcast on the target SSID. "
        recommendations+="3) Use a Bonjour gateway to control service advertisement across VLANs. "
        recommendations+="4) Ensure IGMP snooping is enabled to prevent multicast flooding to target ports."
    elif [[ $total_services -gt 0 ]]; then
        local result_status="INFO"
        local result_summary="${total_services} service(s) discovered but none appear to be sensitive corporate services."
        local recommendations="Monitor for new service announcements. Consider mDNS filtering as defence-in-depth."
    else
        local result_summary="No mDNS/Bonjour/SSDP service announcements detected on target WiFi. Multicast is properly filtered."
        local recommendations="No action needed. Multicast filtering is effective."
    fi

    local result_json
    evidence_register_file "b4_mdns_capture.pcap"
    evidence_register_file "b4_mdns_services.txt"
    evidence_register_file "b4_ssdp_devices.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "mDNS services: ${mdns_count}, SSDP devices: ${ssdp_count}, Sensitive leaks: ${sensitive_count}" \
        --arg recommendations "$recommendations" \
        --argjson mdns_services_found "$mdns_count" \
        --argjson ssdp_devices_found "$ssdp_count" \
        --argjson services "$services_json" \
        --argjson sensitive_services "$sensitive_services" \
        --arg corporate_services_leaked "$corporate_leak" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            mdns_services_found: $mdns_services_found,
            ssdp_devices_found: $ssdp_devices_found,
            services: $services,
            sensitive_services: $sensitive_services,
            corporate_services_leaked: ($corporate_services_leaked == "true"),
                    }')

    save_tc_result "B4" "$result_json"

    # Display summary
    echo ""
    if [[ "$corporate_leak" == "true" ]]; then
        log_result "FINDING" "${sensitive_count} corporate service(s) leaked via mDNS/SSDP on target WiFi"
    elif [[ $total_services -gt 0 ]]; then
        log_result "INFO" "${total_services} service(s) found but no sensitive corporate leaks"
    else
        log_result "SECURE" "No mDNS/SSDP services visible on target WiFi"
    fi

    return 0
}