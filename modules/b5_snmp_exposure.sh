#!/usr/bin/env bash
# MODULE_META
# NAME="SNMP Exposure"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap,onesixtyone,snmpwalk"
# DESC="Probe for SNMP services with default/common communities"
# REQS="managed_iface,gateway_ip"
# PCAP="no"
# DECODE="none"

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
#    - b5_snmp_walk_<ip>.txt       (full SNMP walk per device)
#    - b5_snmp_findings.txt        (summary of findings)
#
#  RESULT JSON FIELDS:
#    - snmp_hosts_found: count of devices with SNMP accessible
#    - communities_found[]: working community strings
#    - device_info[]: array of {ip, community, sysDescr, sysName, sysLocation}
#    - sensitive_data_exposed: bool (routing tables, ARP, etc.)
#===============================================================================

run_b5() {
    set -uo pipefail

    local iface="${WIFI_INTERFACE:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local gateway="${GATEWAY_IP:-}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) iface="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            --gateway) gateway="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Finalize local variables
    local interface="${iface:-${WIFI_INTERFACE:-wlan0}}"
    local evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"
    local gateway_ip="${gateway:-${GATEWAY_IP:-}}"
    local tc_id="B5"
    local total_steps=6
    local evidence_prefix="${evidence_dir}/b5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "$tc_id" || return 1

    local has_onesixtyone=true
    local has_snmpwalk=true

    if ! command -v onesixtyone &>/dev/null; then
        has_onesixtyone=false
        log_warn "onesixtyone not available — will use nmap for SNMP scanning"
    fi
    if ! command -v snmpwalk &>/dev/null; then
        has_snmpwalk=false
        log_warn "snmpwalk not available — limited SNMP enumeration"
    fi

    # Ensure monitor mode is globally disabled (we need to be connected)
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    local my_ip="${MY_IP:-}"
    if [[ -z "$my_ip" ]]; then
        my_ip=$(run_fg --quiet ip -4 addr show "$interface" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    fi

    if [[ -z "$gateway_ip" ]]; then
        gateway_ip=$(run_fg --quiet ip route 2>/dev/null | awk '/default/{print $3}' | head -1)
    fi

    local subnet_base
    subnet_base=$(echo "${gateway_ip:-${my_ip}}" | cut -d. -f1-3)
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
    community_count=$(wc -l < "$community_file")
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
        # Use onesixtyone for fast SNMP sweep
        log_cmd "${TOOL_PATHS[onesixtyone]} -c ${community_file} ${scan_range}"
        run_with_spinner "Sweeping ${scan_range} for SNMP services" "${TOOL_PATHS[onesixtyone]}" -c "$community_file" "$scan_range"

        echo "$CMD_OUTPUT" >> "$sweep_file"

        # Parse onesixtyone output and build findings list in one pass
        # Output format: "IP [community] description"
        local found_list
        found_list=$(echo "$CMD_OUTPUT" | grep -oP '^[0-9.]+\s+\[.*?\]\s+.*' | sed 's/ /|/g')
        
        # Build JSON in one batch call
        if [[ -n "$found_list" ]]; then
            snmp_hosts=$(echo "$found_list" | run_fg jq -R -s 'split("\n") | map(select(length > 0)) | map(split("|")) | map({ip: .[0], community: (.[1]|gsub("[\\[\\]]"; "")), sysDescr: (.[2:]|join(" "))})')
            communities_found=$(echo "$snmp_hosts" | run_fg jq -c 'map(.community) | unique')
        fi
    else
        # Fallback: use nmap SNMP brute
        log_cmd "${TOOL_PATHS[nmap]} -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=${community_file} ${scan_range}"
        run_with_spinner "Scanning for SNMP services (UDP scan — may take a few minutes)" "${TOOL_PATHS[nmap]}" -sU -p 161 --script snmp-brute --script-args "snmp-brute.communitiesdb=${community_file}" "$scan_range" -oA "${sweep_file%.txt}"

        # Optimized Nmap parsing
        local nmap_hosts
        nmap_hosts=$(grep "Nmap scan report for" "${sweep_file%.txt}.nmap" | grep -oP '[0-9.]+')
        local nmap_creds
        nmap_creds=$(grep -E "Valid credentials|snmp-brute:" "${sweep_file%.txt}.nmap" | grep -oP '\b\w+\b' | tail -n +2)
        
        # Simplified batch assembly for Nmap results
        if [[ -n "$nmap_hosts" ]]; then
            snmp_hosts=$(echo "$nmap_hosts" | run_fg jq -R -s 'split("\n") | map(select(length > 0)) | map({ip: ., community: "unknown", sysDescr: "port open"})')
            communities_found=$(echo "$nmap_creds" | run_fg jq -R -s 'split("\n") | map(select(length > 0)) | unique')
        fi
    fi

    local host_count
    host_count=$(echo "$snmp_hosts" | run_fg jq 'length')
    log_info "SNMP hosts found: ${host_count}"

    check_abort || return 1

    #--- Step 4: Deep SNMP enumeration ---
    log_step 4 $total_steps "Deep SNMP enumeration of discovered hosts"
    update_tc_progress 4 $total_steps "SNMP walk"

    check_abort || return 1

    local device_info="[]"
    local sensitive_data="false"

    if [[ $host_count -gt 0 && "$has_snmpwalk" == "true" ]]; then
        # Build temp data for batch JSON assembly
        local device_info_raw
        device_info_raw=$(mktemp)
        
        # Enumerate each host
        while IFS= read -r host_entry; do
            local c_ip community
            c_ip=$(echo "$host_entry" | run_fg jq -r '.ip')
            community=$(echo "$host_entry" | run_fg jq -r '.community')

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
            sys_info=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" system 2>/dev/null || true)
            echo "$sys_info" >> "$walk_file"

            local sys_descr sys_name sys_location sys_contact
            sys_descr=$(echo "$sys_info" | grep "sysDescr" | head -1 | sed 's/.*STRING: //' | tr -d '"')
            sys_name=$(echo "$sys_info" | grep "sysName" | head -1 | sed 's/.*STRING: //' | tr -d '"')
            sys_location=$(echo "$sys_info" | grep "sysLocation" | head -1 | sed 's/.*STRING: //' | tr -d '"')
            sys_contact=$(echo "$sys_info" | grep "sysContact" | head -1 | sed 's/.*STRING: //' | tr -d '"')

            log_result "FINDING" "SNMP data from ${c_ip}: ${sys_name:-unknown}"

            # Interface table
            local iface_data
            iface_data=$(timeout 15 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ifDescr 2>/dev/null || true)
            local iface_count
            iface_count=$(echo "$iface_data" | grep -c "ifDescr" 2>/dev/null || echo "0")

            # ARP & Routes (Sensitive!)
            local arp_data
            arp_data=$(timeout 10 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ipNetToMediaPhysAddress 2>/dev/null || true)
            local route_data
            route_data=$(timeout 10 ${TOOL_PATHS[snmpwalk]} -v2c -c "$community" "$c_ip" ipRouteDest 2>/dev/null || true)

            local has_arp="false"; [[ $(echo "$arp_data" | grep -c . || echo "0") -gt 2 ]] && has_arp="true" && sensitive_data="true"
            local has_routes="false"; [[ $(echo "$route_data" | grep -c . || echo "0") -gt 2 ]] && has_routes="true" && sensitive_data="true"

            # Log to temp file for batch JSON
            echo "${c_ip}|${community}|${sys_descr:-}|${sys_name:-}|${sys_location:-}|${sys_contact:-}|${iface_count}|${has_arp}|${has_routes}" >> "$device_info_raw"

        done < <(echo "$snmp_hosts" | run_fg jq -c '.[]')
        
        # Batch assemble device_info JSON
        if [[ -s "$device_info_raw" ]]; then
            device_info=$(cat "$device_info_raw" | run_fg jq -R -s 'split("\n") | map(select(length > 0)) | map(split("|")) | map({ip: .[0], community: .[1], sysDescr: .[2], sysName: .[3], sysLocation: .[4], sysContact: .[5], interface_count: (.[6]|tonumber), arp_table_accessible: (.[7]=="true"), routing_table_accessible: (.[8]=="true")})')
        fi
        rm -f "$device_info_raw"
    fi

    #--- Step 5: Check for SNMP write access ---
    log_step 5 $total_steps "Testing for SNMP write access"
    update_tc_progress 5 $total_steps "Write test"

    check_abort || return 1

    local write_access="false"

    if [[ "$has_snmpwalk" == "true" ]]; then
        while IFS= read -r host_entry; do
            local c_ip
            c_ip=$(echo "$host_entry" | run_fg jq -r '.ip')
            [[ -z "$c_ip" ]] && continue

            # Test 'private' community for write
            for write_community in "private" "write" "admin" "secret"; do
                local write_test
                write_test=$(timeout 5 ${TOOL_PATHS[snmpwalk]} -v2c -c "$write_community" "$c_ip" sysContact 2>/dev/null || true)

                if [[ -n "$write_test" ]]; then
                    # Found read access with potential write community
                    # Don't actually write — just note it
                    log_result "CRITICAL" "SNMP community '${write_community}' has read access on ${c_ip} — may have WRITE access"
                    write_access="true"
                fi
            done
        done < <(echo "$snmp_hosts" | run_fg jq -c '.[]')
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
        echo "Working Communities: $(echo "$communities_found" | run_fg jq -r 'join(", ")')"
        echo "Sensitive Data Exposed: ${sensitive_data}"
        echo "Write Access Possible: ${write_access}"
        echo ""
        echo "Device Information:"
        echo "$device_info" | run_fg jq -r '.[] | "  \(.ip): \(.sysName) (\(.sysDescr))"'
    } > "$findings_file"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""
    local is_secure_claim=1

    if [[ $host_count -gt 0 ]]; then
        result_status="FINDING"
        is_secure_claim=0
        result_summary="SNMP is accessible from target WiFi on ${host_count} device(s). Working community strings: $(echo "$communities_found" | run_fg jq -r 'join(", ")'). "
        if [[ "$sensitive_data" == "true" ]]; then
            result_summary+="CRITICAL: ARP tables and/or routing tables are accessible — full network topology exposed. "
        fi
        if [[ "$write_access" == "true" ]]; then
            result_summary+="CRITICAL: Write-capable community strings may be in use. "
        fi
        recommendations="1) Block UDP port 161/162 from target VLAN in ACLs. 2) Change default SNMP community strings on all devices. 3) Restrict SNMP access to management VLAN only using SNMP ACLs. 4) Migrate to SNMPv3 with authentication and encryption. 5) Disable SNMP on target-facing interfaces."
    else
        result_summary="No SNMP services accessible from target WiFi. SNMP is properly filtered."
        recommendations="No action needed. Maintain SNMP filtering during network changes."
    fi

    local evidence_files='["b5_snmp_sweep.txt", "b5_snmp_findings.txt"]'

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Hosts: ${host_count}, Communities: $(echo "$communities_found" | run_fg jq 'length'), Sensitive: ${sensitive_data}, Write: ${write_access}" \
        --arg recommendations "$recommendations" \
        --argjson snmp_hosts_found "$host_count" \
        --argjson communities_found "$communities_found" \
        --argjson device_info "$device_info" \
        --arg sensitive_data_exposed "$sensitive_data" \
        --arg write_access "$write_access" \
        --argjson evidence_files "$evidence_files" \
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
            evidence_files: $evidence_files
        }')

    # save_tc_result: pcap_req, tool_out, prim_art, cmds, vers, env, confirm, known_target, runtime, clean, secure
    save_tc_result "$tc_id" "$result_json" 0 1 0 1 1 1 0 1 1 1 "$is_secure_claim"
    save_session_state

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
