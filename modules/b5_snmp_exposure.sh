#!/usr/bin/env bash
#===============================================================================
#  modules/b5_snmp_exposure.sh
#  B5: SNMP Exposure
#
#  PURPOSE:
#    Probe for SNMP services accessible from the target WiFi network.
#    Test common community strings. If SNMP is accessible, extract
#    device information (sysDescr, sysName, sysLocation, interfaces,
#    routing tables, ARP tables).
#
#  TOOLS: ${TOOL_PATHS[onesixtyone]}, ${TOOL_PATHS[snmpwalk]}, ${TOOL_PATHS[nmap]}
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - b5_snmp_sweep.txt           (${TOOL_PATHS[onesixtyone]} sweep results)
#    - b5_snmp_walk_<${TOOL_PATHS[ip]}>.txt       (full SNMP walk per device)
#    - b5_snmp_findings.txt        (summary of findings)
#
#  RESULT JSON FIELDS:
#    - snmp_hosts_found: count of devices with SNMP accessible
#    - communities_found[]: working community strings
#    - device_info[]: array of {${TOOL_PATHS[ip]}, community, sysDescr, sysName, sysLocation}
#    - sensitive_data_exposed: bool (routing tables, ARP, etc.)
#===============================================================================

run_b5() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    local has_onesixtyone=true
    local has_snmpwalk=true

    if ! command -v onesixtyone &>/dev/null; then
        has_onesixtyone=false
        log_warn "${TOOL_PATHS[onesixtyone]} not available — will use ${TOOL_PATHS[nmap]} for SNMP scanning"
    fi
    if ! command -v snmpwalk &>/dev/null; then
        has_snmpwalk=false
        log_warn "${TOOL_PATHS[snmpwalk]} not available — limited SNMP enumeration"
    fi

        # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1


    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    if [[ -z "${GATEWAY_IP:-}" ]]; then
        GATEWAY_IP=$(${TOOL_PATHS[ip]} route 2>/dev/null | awk '/default/{print $3}' | head -1)
    fi

    if [[ -z "${MY_IP:-}" ]]; then
        MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "${WIFI_INTERFACE:-wlan0}" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    fi

    local subnet_base
    subnet_base=$(echo "${GATEWAY_IP:-${MY_IP}}" | cut -d. -f1-3)
    local scan_range="${subnet_base}.0/24"

    log_success "Scanning ${scan_range} for SNMP services"

    #--- Step 2: Build community string list ---
    log_step 2 $total_steps "Preparing SNMP community string list"
    update_tc_progress 2 $total_steps "Preparing"

    local community_file="${evidence_prefix}_communities.txt"
    local custom_wordlist="${WORDLIST_DIR}/snmp_communities.txt"

    # Default common communities
    {
        echo "public"
        echo "private"
        echo "community"
        echo "snmp"
        echo "default"
        echo "cisco"
        echo "aruba"
        echo "ruckus"
        echo "target"
        echo "monitor"
        echo "manager"
        echo "admin"
        echo "read"
        echo "write"
        echo "ILMI"
        echo "cable-docsis"
        echo "internal"
        echo "secret"
        echo "test"
    } > "$community_file"

    # Append custom wordlist if exists
    if [[ -f "$custom_wordlist" ]]; then
        cat "$custom_wordlist" >> "$community_file"
        log_info "Appended custom community list: ${custom_wordlist}"
    fi

    # Deduplicate
    sort -u -o "$community_file" "$community_file"
    local community_count
    local community_count=$(wc -l < "$community_file")
    log_info "Testing ${community_count} community strings"

    #--- Step 3: SNMP sweep ---
    log_step 3 $total_steps "Sweeping subnet for SNMP services"
    update_tc_progress 3 $total_steps "SNMP sweep"

    check_abort || return 1

    local sweep_file="${evidence_prefix}_snmp_sweep.txt"
    local snmp_hosts="[]"
    local communities_found="[]"

    {
        echo "============================================================"
        echo "  B5: SNMP Exposure Sweep"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Range: ${scan_range}"
        echo "  Communities: ${community_count}"
        echo "============================================================"
        echo ""
    } > "$sweep_file"

    if [[ "$has_onesixtyone" == "true" ]]; then
        # Use ${TOOL_PATHS[onesixtyone]} for fast SNMP sweep
        log_cmd "${TOOL_PATHS[onesixtyone]} -c ${community_file} ${scan_range}"
        run_with_spinner "${TOOL_PATHS[onesixtyone]} -c ${community_file} ${scan_range}" \
            "Sweeping ${scan_range} for SNMP services"

        echo "$CMD_OUTPUT" >> "$sweep_file"

        # Parse ${TOOL_PATHS[onesixtyone]} output: "IP [community] description"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^Scanning ]] && continue

            local c_ip community desc
            local c_ip=$(echo "$line" | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
            local community=$(echo "$line" | grep -oP '\[.*?\]' | tr -d '[]')
            local desc=$(echo "$line" | sed 's/^[^ ]* \[.*\] //')

            [[ -z "$c_ip" ]] && continue

            log_result "FINDING" "SNMP accessible: ${c_ip} [${community}] — ${desc}"

            snmp_hosts=$(echo "$snmp_hosts" | ${TOOL_PATHS[jq]} \
                --arg ip "$c_ip" \
                --arg community "$community" \
                --arg desc "$desc" \
                '. += [{ip: $c_ip, community: $community, sysDescr: $desc}]')

            communities_found=$(echo "$communities_found" | ${TOOL_PATHS[jq]} --arg c "$community" 'if (. | index($c)) then . else . += [$c] end')
        done <<< "$CMD_OUTPUT"
    else
        # Fallback: use ${TOOL_PATHS[nmap]} SNMP brute
        log_cmd "${TOOL_PATHS[nmap]} -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=${community_file} ${scan_range}"
        run_with_spinner "${TOOL_PATHS[nmap]} -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=${community_file} ${scan_range} -oA ${sweep_file%.txt}" \
            "Scanning for SNMP services (UDP scan — may take a few minutes)"

        # Parse ${TOOL_PATHS[nmap]} output
        local current_host=""
        while IFS= read -r line; do
            if [[ "$line" =~ "Nmap scan report for" ]]; then
                current_host=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
            elif [[ "$line" =~ "161/udp" ]] && [[ "$line" =~ "open" ]]; then
                [[ -z "$current_host" ]] && continue
                log_result "FINDING" "SNMP port open: ${current_host}"
                snmp_hosts=$(echo "$snmp_hosts" | ${TOOL_PATHS[jq]} --arg ip "$current_host" '. += [{ip: $c_ip, community: "unknown", sysDescr: "port open"}]')
            elif [[ "$line" =~ "Valid credentials" ]] || [[ "$line" =~ "snmp-brute:" ]]; then
                local community
                community=$(echo "$line" | grep -oP '\b\w+\b' | tail -1)
                communities_found=$(echo "$communities_found" | ${TOOL_PATHS[jq]} --arg c "$community" 'if (. | index($c)) then . else . += [$c] end')
            fi
        done < "${sweep_file%.txt}.nmap"
    fi

    local host_count
    host_count=$(echo "$snmp_hosts" | ${TOOL_PATHS[jq]} 'length')
    log_info "SNMP hosts found: ${host_count}"

    check_abort || return 1

    #--- Step 4: Deep SNMP enumeration ---
    log_step 4 $total_steps "Deep SNMP enumeration of discovered hosts"
    update_tc_progress 4 $total_steps "SNMP walk"

    check_abort || return 1

    local device_info="[]"
    local sensitive_data="false"

    if [[ $host_count -gt 0 && "$has_snmpwalk" == "true" ]]; then
        # Enumerate each host
        while IFS= read -r host_entry; do
            local c_ip community
            local c_ip=$(echo "$host_entry" | ${TOOL_PATHS[jq]} -r '.ip')
            community=$(echo "$host_entry" | ${TOOL_PATHS[jq]} -r '.community')

            [[ -z "$c_ip" || "$community" == "unknown" ]] && continue

            local walk_file="${evidence_prefix}_snmp_walk_${c_ip//\./_}.txt"

            {
                echo "============================================================"
                echo "  SNMP Walk: ${c_ip} [${community}]"
                echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "============================================================"
                echo ""
            } > "$walk_file"

            # System information
            echo "--- System Information ---" >> "$walk_file"
            local sys_info
            local sys_info=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" system 2>/dev/null || true)
            echo "$sys_info" >> "$walk_file"

            local sys_descr sys_name sys_location sys_contact
            local sys_descr=$(echo "$sys_info" | grep "sysDescr" | head -1 | sed 's/.*STRING: //')
            local sys_name=$(echo "$sys_info" | grep "sysName" | head -1 | sed 's/.*STRING: //')
            local sys_location=$(echo "$sys_info" | grep "sysLocation" | head -1 | sed 's/.*STRING: //')
            local sys_contact=$(echo "$sys_info" | grep "sysContact" | head -1 | sed 's/.*STRING: //')

            log_result "FINDING" "SNMP data from ${c_ip}:"
            log_output "  sysName: ${sys_name}"
            log_output "  sysDescr: ${sys_descr}"
            log_output "  sysLocation: ${sys_location}"

            # Interface table
            echo "" >> "$walk_file"
            echo "--- Interfaces ---" >> "$walk_file"
            local iface_data
            local iface_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ifDescr 2>/dev/null || true)
            echo "$iface_data" >> "$walk_file"

            local iface_count
            local iface_count=$(echo "$iface_data" | grep -c "ifDescr" 2>/dev/null) || true

            # IP addresses
            echo "" >> "$walk_file"
            echo "--- IP Addresses ---" >> "$walk_file"
            local ip_data
            local ip_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ipAdEntAddr 2>/dev/null || true)
            echo "$ip_data" >> "$walk_file"

            # ARP table (sensitive!)
            echo "" >> "$walk_file"
            echo "--- ARP Table ---" >> "$walk_file"
            local arp_data
            local arp_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ipNetToMediaPhysAddress 2>/dev/null || true)
            echo "$arp_data" >> "$walk_file"

            if [[ -n "$arp_data" && $(echo "$arp_data" | wc -l) -gt 2 ]]; then
                local sensitive_data="true"
                log_result "CRITICAL" "ARP table accessible via SNMP from ${c_ip} — reveals internal hosts"
            fi

            # Routing table (sensitive!)
            echo "" >> "$walk_file"
            echo "--- Routing Table ---" >> "$walk_file"
            local route_data
            local route_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ipRouteDest 2>/dev/null || true)
            echo "$route_data" >> "$walk_file"

            if [[ -n "$route_data" && $(echo "$route_data" | wc -l) -gt 2 ]]; then
                local sensitive_data="true"
                log_result "CRITICAL" "Routing table accessible via SNMP from ${c_ip} — reveals network topology"
            fi

            # VLAN information (Cisco specific)
            echo "" >> "$walk_file"
            echo "--- VLAN Table (Cisco) ---" >> "$walk_file"
            local vlan_data
            local vlan_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" 1.3.6.1.4.1.9.9.46.1.3.1.1.2 2>/dev/null || true)
            echo "$vlan_data" >> "$walk_file"

            device_info=$(echo "$device_info" | ${TOOL_PATHS[jq]} \
                --arg ip "$c_ip" \
                --arg community "$community" \
                --arg sys_descr "$sys_descr" \
                --arg sys_name "$sys_name" \
                --arg sys_location "$sys_location" \
                --arg sys_contact "$sys_contact" \
                --argjson iface_count "$iface_count" \
                --arg has_arp "$(if [[ -n "$arp_data" ]]; then echo "true"; else echo "false"; fi)" \
                --arg has_routes "$(if [[ -n "$route_data" ]]; then echo "true"; else echo "false"; fi)" \
                '. += [{
                    ip: $c_ip,
                    community: $community,
                    sysDescr: $sys_descr,
                    sysName: $sys_name,
                    sysLocation: $sys_location,
                    sysContact: $sys_contact,
                    interface_count: $iface_count,
                    arp_table_accessible: ($has_arp == "true"),
                    routing_table_accessible: ($has_routes == "true")
                }]')

        done < <(echo "$snmp_hosts" | ${TOOL_PATHS[jq]} -c '.[]')
    fi

    #--- Step 5: Check for SNMP write access ---
    log_step 5 $total_steps "Testing for SNMP write access"
    update_tc_progress 5 $total_steps "Write test"

    check_abort || return 1

    local write_access="false"

    if [[ "$has_snmpwalk" == "true" ]]; then
        while IFS= read -r host_entry; do
            local c_ip
            local c_ip=$(echo "$host_entry" | ${TOOL_PATHS[jq]} -r '.ip')
            [[ -z "$c_ip" ]] && continue

            # Test 'private' community for write
            for write_community in "private" "write" "admin" "secret"; do
                local write_test
                local write_test=$(timeout 5 ${TOOL_PATHS[snmpwalk]} -v2c -c "$write_community" "$c_ip" sysContact 2>/dev/null || true)

                if [[ -n "$write_test" ]]; then
                    # Found read access with potential write community
                    # Don't actually write — just note it
                    log_result "CRITICAL" "SNMP community '${write_community}' has read access on ${c_ip} — may have WRITE access"
                    local write_access="true"
                fi
            done
        done < <(echo "$snmp_hosts" | ${TOOL_PATHS[jq]} -c '.[]')
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local findings_file="${evidence_prefix}_snmp_findings.txt"
    {
        echo "============================================================"
        echo "  B5: SNMP Exposure Summary"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "SNMP Hosts Found: ${host_count}"
        echo "Working Communities: $(echo "$communities_found" | ${TOOL_PATHS[jq]} -r 'join(", ")')"
        echo "Sensitive Data Exposed: ${sensitive_data}"
        echo "Write Access Possible: ${write_access}"
        echo ""
        echo "Device Information:"
        echo "$device_info" | ${TOOL_PATHS[jq]} -r '.[] | "  \(.ip): \(.sysName) (\(.sysDescr))"'
    } > "$findings_file"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $host_count -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="SNMP is accessible from target WiFi on ${host_count} device(s). Working community strings: $(echo "$communities_found" | ${TOOL_PATHS[jq]} -r 'join(", ")'). "
        if [[ "$sensitive_data" == "true" ]]; then
            result_summary+="CRITICAL: ARP tables and/or routing tables are accessible — full network topology exposed. "
        fi
        if [[ "$write_access" == "true" ]]; then
            result_summary+="CRITICAL: Write-capable community strings may be in use. "
        fi
        local recommendations="1) Block UDP port 161/162 from target VLAN in ACLs. 2) Change default SNMP community strings on all devices. 3) Restrict SNMP access to management VLAN only using SNMP ACLs. 4) Migrate to SNMPv3 with authentication and encryption. 5) Disable SNMP on target-facing interfaces."
    else
        local result_summary="No SNMP services accessible from target WiFi. SNMP is properly filtered."
        local recommendations="No action needed. Maintain SNMP filtering during network changes."
    fi

    local result_json
    evidence_register_file "b5_snmp_sweep.txt"
    evidence_register_file "b5_snmp_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Hosts: ${host_count}, Communities: $(echo "$communities_found" | ${TOOL_PATHS[jq]} 'length'), Sensitive: ${sensitive_data}, Write: ${write_access}" \
        --arg recommendations "$recommendations" \
        --argjson snmp_hosts_found "$host_count" \
        --argjson communities_found "$communities_found" \
        --argjson device_info "$device_info" \
        --arg sensitive_data_exposed "$sensitive_data" \
        --arg write_access "$write_access" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            snmp_hosts_found: $snmp_hosts_found,
            communities_found: $communities_found,
            device_info: $device_info,
            sensitive_data_exposed: ($sensitive_data_exposed == "true"),
            write_access_possible: ($write_access == "true"),
                    }')

    save_tc_result "B5" "$result_json"

    # Display summary
    echo ""
    if [[ $host_count -gt 0 ]]; then
        log_result "FINDING" "${host_count} device(s) with SNMP accessible from target WiFi"
        [[ "$sensitive_data" == "true" ]] && log_result "CRITICAL" "ARP/routing tables exposed — network topology leak"
        [[ "$write_access" == "true" ]] && log_result "CRITICAL" "SNMP write access may be possible"
    else
        log_result "SECURE" "No SNMP services accessible from target WiFi"
    fi

    return 0
}