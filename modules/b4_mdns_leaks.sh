#!/usr/bin/env bash
# MODULE_META
# NAME="mDNS/Bonjour Information Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark,avahi-browse"
# DESC="Detect mDNS/Bonjour service announcements from corporate devices"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="dns"

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
#    - services[]: array of {name, type, host, ip, port}
#    - corporate_services_leaked: bool
#===============================================================================

run_b4() {
    set -uo pipefail

    local iface="${WIFI_INTERFACE:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local timeout="${MDNS_CAPTURE_TIME:-120}"

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
    local tc_id="B4"
    local total_steps=6
    local evidence_prefix="${evidence_dir}/b4"

    #--- Step 1: Verify tools and connectivity ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "$tc_id" || return 1
    
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    if [[ -z "$interface" ]]; then
        configure_network || return 1
        interface="$WIFI_INTERFACE"
    fi

    log_success "Using interface: ${interface}"

    #--- Step 2: Capture mDNS traffic ---
    log_step 2 $total_steps "Capturing mDNS/Bonjour traffic (${timeout}s)"
    update_tc_progress 2 $total_steps "mDNS capture"

    check_abort || return 1

    local capture_file="${evidence_prefix}_mdns_capture.pcap"

    # mDNS: UDP port 5353, multicast 224.0.0.251 / ff02::fb
    # SSDP: UDP port 1900, multicast 239.255.255.250
    local bpf_filter="(udp port 5353) or (udp port 1900)"

    log_cmd "${TOOL_PATHS[tcpdump]} -i ${interface} -w ${capture_file} '${bpf_filter}' (timeout: ${timeout}s)"

    spawn_bg "b4_tcpdump" "${TOOL_PATHS[tcpdump]}" -i "$interface" -w "$capture_file" "$bpf_filter"

    # Also run avahi-browse in parallel if available
    local avahi_file="${evidence_prefix}_avahi_browse.txt"
    if command -v avahi-browse &>/dev/null; then
        log_cmd "${TOOL_PATHS[avahi-browse]} -a -t -r -p (timeout: ${timeout}s)"
        spawn_bg "b4_avahi" "bash" -c "timeout $timeout ${TOOL_PATHS[avahi-browse]} -a -t -r -p > \"$avahi_file\" 2>/dev/null"
    fi

    start_countdown "$timeout" "Capturing mDNS/Bonjour and SSDP announcements"
    sleep "$timeout"
    stop_countdown

    # Stop captures
    stop_process "b4_avahi"
    stop_process "b4_tcpdump"

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

    # Parse from tshark
    if [[ -f "$capture_file" ]]; then
        ensure_user_ownership "$capture_file"
        local mdns_data
        mdns_data=$(run_as_user tshark -r "$capture_file" \
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
            srv_target=$(echo "$srv_target" | xargs)
            srv_port=$(echo "$srv_port" | xargs)

            echo "  Service: ${srv_name}" >> "$services_file"
            echo "    Host: ${srv_target}" >> "$services_file"
            echo "    IP: ${src_ip}" >> "$services_file"
            echo "    Port: ${srv_port}" >> "$services_file"
            echo "" >> "$services_file"

            services_json=$(echo "$services_json" | run_fg jq \
                --arg name "$srv_name" \
                --arg host "$srv_target" \
                --arg ip "${src_ip:-unknown}" \
                --arg port "${srv_port:-0}" \
                --arg type "mDNS" \
                '. += [{name: $name, host: $host, ip: $ip, port: $port, protocol: $type}]')

        done <<< "$mdns_data"

        # Also extract PTR records (service types)
        local ptr_data
        ptr_data=$(run_as_user tshark -r "$capture_file" \
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
            already_counted=$(echo "$services_json" | run_fg jq --arg n "$ptr_domain" '[.[] | select(.name == $n)] | length')
            [[ $already_counted -gt 0 ]] && continue

            ((mdns_count++))

            echo "  Service Type: ${query_name}" >> "$services_file"
            echo "    Instance: ${ptr_domain}" >> "$services_file"
            echo "    Source IP: ${src_ip}" >> "$services_file"
            echo "" >> "$services_file"

            services_json=$(echo "$services_json" | run_fg jq \
                --arg name "$ptr_domain" \
                --arg host "unknown" \
                --arg ip "${src_ip:-unknown}" \
                --arg port "0" \
                --arg type "mDNS-PTR" \
                --arg service_type "${query_name}" \
                '. += [{name: $name, host: $host, ip: $ip, port: $port, protocol: $type, service_type: $service_type}]')
        done <<< "$ptr_data"
    fi

    # Parse avahi-browse results
    if [[ -f "$avahi_file" && -s "$avahi_file" ]]; then
        while IFS=';' read -r event iface ipver service_name service_type domain hostname a_ip port txt; do
            [[ "$event" != "=" ]] && continue
            [[ -z "$service_name" ]] && continue

            # Check if not already in list
            local already
            already=$(echo "$services_json" | run_fg jq --arg n "$service_name" '[.[] | select(.name == $n)] | length')
            [[ $already -gt 0 ]] && continue

            ((mdns_count++))

            services_json=$(echo "$services_json" | run_fg jq \
                --arg name "$service_name" \
                --arg host "${hostname:-unknown}" \
                --arg ip "${a_ip:-unknown}" \
                --arg port "${port:-0}" \
                --arg type "avahi" \
                --arg service_type "${service_type}" \
                '. += [{name: $name, host: $host, ip: $ip, port: $port, protocol: $type, service_type: $service_type}]')
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
        ssdp_data=$(run_as_user tshark -r "$capture_file" \
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

            services_json=$(echo "$services_json" | run_fg jq \
                --arg name "SSDP: ${server:-unknown}" \
                --arg host "${src_ip}" \
                --arg ip "$src_ip" \
                --arg port "1900" \
                --arg type "SSDP" \
                --arg location "${location:-}" \
                '. += [{name: $name, host: $host, ip: $ip, port: $port, protocol: $type, location: $location}]')
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

    # Use index-based jq iteration to avoid shell word-splitting issues
    local svc_count
    svc_count=$(echo "$services_json" | run_fg jq 'length')
    
    for (( si=0; si < svc_count; si++ )); do
        local svc_name svc_type
        svc_name=$(echo "$services_json" | run_fg jq -r ".[$si].name // \"\"")
        svc_type=$(echo "$services_json" | run_fg jq -r ".[$si].service_type // \"\"")

        for pattern in "${corp_patterns[@]}"; do
            if echo "${svc_name}${svc_type}" | grep -qi "$pattern"; then
                corporate_leak="true"
                local svc_entry
                svc_entry=$(echo "$services_json" | run_fg jq ".[$si]")
                sensitive_services=$(echo "$sensitive_services" | run_fg jq --argjson svc "$svc_entry" '. += [$svc]')
                log_result "FINDING" "Corporate service leaked: ${svc_name} (${svc_type})"
                break
            fi
        done
    done

    local sensitive_count
    sensitive_count=$(echo "$sensitive_services" | run_fg jq 'length')

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local total_services=$(( mdns_count + ssdp_count ))
    local result_status="SECURE"
    local result_summary=""
    local recommendations=""
    local is_secure_claim=1

    if [[ "$corporate_leak" == "true" ]]; then
        result_status="FINDING"
        is_secure_claim=0
        result_summary="${total_services} service(s) discovered via mDNS/SSDP on target WiFi. ${sensitive_count} appear to be corporate/internal services (printers, file shares, AirPlay, etc.) that should not be visible to target clients."
        recommendations="1) Enable mDNS/IGMP filtering on the target VLAN to block multicast 224.0.0.251 and 239.255.255.250. "
        recommendations+="2) Configure the wireless controller to suppress multicast/broadcast on the target SSID. "
        recommendations+="3) Use a Bonjour gateway to control service advertisement across VLANs. "
        recommendations+="4) Ensure IGMP snooping is enabled to prevent multicast flooding to target ports."
    elif [[ $total_services -gt 0 ]]; then
        result_status="INFO"
        is_secure_claim=0
        result_summary="${total_services} service(s) discovered but none appear to be sensitive corporate services."
        recommendations="Monitor for new service announcements. Consider mDNS filtering as defence-in-depth."
    else
        result_summary="No mDNS/Bonjour/SSDP service announcements detected on target WiFi. Multicast is properly filtered."
        recommendations="No action needed. Multicast filtering is effective."
    fi

    local evidence_files='["b4_mdns_capture.pcap", "b4_mdns_services.txt", "b4_ssdp_devices.txt"]'

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "mDNS services: ${mdns_count}, SSDP devices: ${ssdp_count}, Sensitive leaks: ${sensitive_count}" \
        --arg recommendations "$recommendations" \
        --argjson mdns_services_found "$mdns_count" \
        --argjson ssdp_devices_found "$ssdp_count" \
        --argjson services "$services_json" \
        --argjson sensitive_services "$sensitive_services" \
        --arg corporate_services_leaked "$corporate_leak" \
        --argjson evidence_files "$evidence_files" \
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
            evidence_files: $evidence_files
        }')

    # save_tc_result: pcap_req, tool_out, prim_art, cmds, vers, env, confirm, known_target, runtime, clean, secure
    save_tc_result "$tc_id" "$result_json" 1 1 1 1 1 1 0 1 1 1 "$is_secure_claim"
    save_session_state

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
