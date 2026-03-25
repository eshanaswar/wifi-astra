#!/usr/bin/env bash
# MODULE_META
# NAME="CDP/LLDP Information Leaks"
# CATEGORY="B"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark"
# DESC="Capture CDP/LLDP frames leaking infrastructure details"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="l2_discovery"

#===============================================================================
#  modules/b3_cdp_lldp_leaks.sh
#  B3: CDP/LLDP Information Leaks
#
#  PURPOSE:
#    Capture Cisco Discovery Protocol (CDP) and Link Layer Discovery Protocol
#    (LLDP) frames on the target WiFi network. These protocols leak critical
#    infrastructure details: switch hostnames, port IDs, VLAN assignments,
#    management IPs, device models, firmware versions, and network topology.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}
#  PHASE: 1B — Active Recon (Connected to Target WiFi)
#  DEPENDENCIES: None
#
#  METHODOLOGY:
#    1. Capture CDP frames (multicast 01:00:0c:cc:cc:cc, EtherType 0x2000)
#    2. Capture LLDP frames (multicast 01:80:c2:00:00:0e, EtherType 0x88cc)
#    3. Parse: device ID, platform, management IP, port ID, native VLAN
#    4. Assess information exposure risk
#
#  EVIDENCE PRODUCED:
#    - b3_cdp_lldp_capture.pcap    (raw packet capture)
#    - b3_cdp_parsed.txt           (parsed CDP frame details)
#    - b3_lldp_parsed.txt          (parsed LLDP frame details)
#    - b3_infrastructure_info.txt  (summary of leaked information)
#
#  RESULT JSON FIELDS:
#    - cdp_frames_captured: count
#    - lldp_frames_captured: count
#    - leaked_info[]: array of {source, device_id, platform, mgmt_ip, port, vlan}
#    - switch_names[]: discovered switch hostnames
#    - management_ips[]: discovered management IPs
#    - native_vlans[]: discovered VLAN IDs
#===============================================================================

run_b3() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b3"

    #--- Step 1: Verify tools and connectivity ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    
    # Ensure we're connected (not in monitor mode)
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        log_info "Disabling monitor mode for connected testing..."
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

    #--- Step 2: Capture CDP and LLDP frames ---
    log_step 2 $total_steps "Capturing CDP/LLDP frames (${CDP_CAPTURE_TIME}s)"
    update_tc_progress 2 $total_steps "Capturing"

    check_abort || return 1

    local capture_file="${evidence_prefix}_cdp_lldp_capture.pcap"

    # CDP filter: ether[20:2] == 0x2000 OR ether proto 0x88cc (LLDP)
    # Simplified BPF: capture CDP multicast + LLDP multicast
    local bpf_filter="(ether dst 01:00:0c:cc:cc:cc) or (ether proto 0x88cc) or (ether dst 01:80:c2:00:00:0e)"

    log_cmd "${TOOL_PATHS[tcpdump]} -i ${iface} -w ${capture_file} '${bpf_filter}' (timeout: ${CDP_CAPTURE_TIME}s)"

    # CDP is sent every 60s by default; LLDP every 30s
    # We capture for the configured time (default 120s) to catch at least 2 cycles
    ${TOOL_PATHS[tcpdump]} -i "$iface" -w "$capture_file" "$bpf_filter" &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    start_countdown "$CDP_CAPTURE_TIME" "Capturing CDP/LLDP frames (CDP interval: 60s, LLDP interval: 30s)"
    sleep "$CDP_CAPTURE_TIME"
    stop_countdown

    
    check_abort || return 1

    # Validate capture file
    if ! validate_pcap "$capture_file" "CDP/LLDP frame capture (${CDP_CAPTURE_TIME}s listen)"; then
        local result_json
        result_json=$(run_tool jq -n \
            '{
                status: "SECURE",
                summary: "No CDP or LLDP frames captured on target WiFi. The network does not leak infrastructure discovery protocol data to target clients.",
                details: "Captured for '"${CDP_CAPTURE_TIME}"' seconds. Zero CDP/LLDP frames detected.",
                recommendations: "No action needed. CDP/LLDP is properly filtered on target-facing ports.",
                cdp_frames_captured: 0,
                lldp_frames_captured: 0,
                leaked_info: [],
                switch_names: [],
                management_ips: [],
                native_vlans: [],
                evidence_files: []
            }')
        save_tc_result "B3" "$result_json" "has_tool_output:1,clean_run:1"
        return 0
    fi

    local capture_size
    local capture_size=$(stat -c%s "$capture_file" 2>/dev/null || echo "unknown")
    log_success "Capture complete: $(basename "$capture_file") (${capture_size} bytes)"

    #--- Step 3: Parse CDP frames ---
    log_step 3 $total_steps "Parsing CDP frames"
    update_tc_progress 3 $total_steps "Parsing CDP"

    check_abort || return 1

    local cdp_parsed_file="${evidence_prefix}_cdp_parsed.txt"
    local cdp_count=0
    local leaked_info="[]"
    local switch_names="[]"
    local management_ips="[]"
    local native_vlans="[]"

    {
        echo "============================================================"
        echo "  B3: CDP Frame Analysis"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$cdp_parsed_file"

    # Extract CDP frames using ${TOOL_PATHS[tshark]}
    local cdp_data
    local cdp_data=$(${TOOL_PATHS[tshark]} -r "$capture_file" \
        -Y "cdp" \
        -T fields \
        -e eth.src \
        -e cdp.deviceid \
        -e cdp.platform \
        -e cdp.portid \
        -e cdp.nativevlan \
        -e cdp.addr.ip \
        -e cdp.software_version \
        -E separator='|' \
        2>/dev/null || true)

    if [[ -n "$cdp_data" ]]; then
        while IFS='|' read -r src_mac device_id platform port_id native_vlan mgmt_ip software_ver; do
            [[ -z "$device_id" && -z "$platform" ]] && continue
            ((cdp_count++))

            # Clean up fields
            device_id=$(echo "$device_id" | xargs)
            local platform=$(echo "$platform" | xargs)
            local port_id=$(echo "$port_id" | xargs)
            local native_vlan=$(echo "$native_vlan" | xargs)
            local mgmt_ip=$(echo "$mgmt_ip" | xargs)
            local software_ver=$(echo "$software_ver" | xargs)

            log_result "FINDING" "CDP leak from ${src_mac}:"
            log_output "  Device: ${device_id}"
            log_output "  Platform: ${platform}"
            log_output "  Port: ${port_id}"
            log_output "  VLAN: ${native_vlan}"
            log_output "  Mgmt IP: ${mgmt_ip}"

            {
                echo "CDP Frame #${cdp_count}:"
                echo "  Source MAC:       ${src_mac}"
                echo "  Device ID:        ${device_id}"
                echo "  Platform:         ${platform}"
                echo "  Port ID:          ${port_id}"
                echo "  Native VLAN:      ${native_vlan}"
                echo "  Management IP:    ${mgmt_ip}"
                echo "  Software Version: ${software_ver}"
                echo ""
            } >> "$cdp_parsed_file"

            # Add to JSON arrays
            leaked_info=$(echo "$leaked_info" | run_tool jq \
                --arg proto "CDP" \
                --arg src "$src_mac" \
                --arg device "$device_id" \
                --arg platform "$platform" \
                --arg port "$port_id" \
                --arg vlan "$native_vlan" \
                --arg mgmt_ip "$mgmt_ip" \
                --arg software "$software_ver" \
                '. += [{protocol: $proto, source_mac: $src, device_id: $device, platform: $platform, port_id: $port, native_vlan: $vlan, management_ip: $mgmt_ip, software_version: $software}]')

            [[ -n "$device_id" ]] && switch_names=$(echo "$switch_names" | run_tool jq --arg n "$device_id" 'if (. | index($n)) then . else . += [$n] end')
            [[ -n "$mgmt_ip" ]] && management_ips=$(echo "$management_ips" | run_tool jq --arg n "$mgmt_ip" 'if (. | index($n)) then . else . += [$n] end')
            [[ -n "$native_vlan" ]] && native_vlans=$(echo "$native_vlans" | run_tool jq --arg n "$native_vlan" 'if (. | index($n)) then . else . += [$n] end')

        done <<< "$cdp_data"
    fi

    log_info "CDP frames parsed: ${cdp_count}"

    #--- Step 4: Parse LLDP frames ---
    log_step 4 $total_steps "Parsing LLDP frames"
    update_tc_progress 4 $total_steps "Parsing LLDP"

    check_abort || return 1

    local lldp_parsed_file="${evidence_prefix}_lldp_parsed.txt"
    local lldp_count=0

    {
        echo "============================================================"
        echo "  B3: LLDP Frame Analysis"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$lldp_parsed_file"

    local lldp_data
    local lldp_data=$(${TOOL_PATHS[tshark]} -r "$capture_file" \
        -Y "lldp" \
        -T fields \
        -e eth.src \
        -e lldp.chassis.id \
        -e lldp.port.id \
        -e lldp.port.desc \
        -e lldp.tlv.system.name \
        -e lldp.tlv.system.desc \
        -e lldp.mgn.addr.ip4 \
        -e lldp.ieee.802_1.port_vlan.id \
        -E separator='|' \
        2>/dev/null || true)

    if [[ -n "$lldp_data" ]]; then
        while IFS='|' read -r src_mac chassis_id port_id port_desc sys_name sys_desc mgmt_ip vlan_id; do
            [[ -z "$chassis_id" && -z "$sys_name" ]] && continue
            ((lldp_count++))

            chassis_id=$(echo "$chassis_id" | xargs)
            local port_id=$(echo "$port_id" | xargs)
            local port_desc=$(echo "$port_desc" | xargs)
            local sys_name=$(echo "$sys_name" | xargs)
            local sys_desc=$(echo "$sys_desc" | xargs)
            local mgmt_ip=$(echo "$mgmt_ip" | xargs)
            local vlan_id=$(echo "$vlan_id" | xargs)

            log_result "FINDING" "LLDP leak from ${src_mac}:"
            log_output "  System: ${sys_name}"
            log_output "  Chassis: ${chassis_id}"
            log_output "  Port: ${port_id} (${port_desc})"
            log_output "  Mgmt IP: ${mgmt_ip}"
            log_output "  VLAN: ${vlan_id}"

            {
                echo "LLDP Frame #${lldp_count}:"
                echo "  Source MAC:       ${src_mac}"
                echo "  Chassis ID:       ${chassis_id}"
                echo "  System Name:      ${sys_name}"
                echo "  System Desc:      ${sys_desc}"
                echo "  Port ID:          ${port_id}"
                echo "  Port Description: ${port_desc}"
                echo "  Management IP:    ${mgmt_ip}"
                echo "  VLAN ID:          ${vlan_id}"
                echo ""
            } >> "$lldp_parsed_file"

            leaked_info=$(echo "$leaked_info" | run_tool jq \
                --arg proto "LLDP" \
                --arg src "$src_mac" \
                --arg device "${sys_name:-${chassis_id}}" \
                --arg platform "${sys_desc}" \
                --arg port "${port_id}" \
                --arg vlan "${vlan_id}" \
                --arg mgmt_ip "$mgmt_ip" \
                --arg port_desc "$port_desc" \
                '. += [{protocol: $proto, source_mac: $src, device_id: $device, platform: $platform, port_id: $port, native_vlan: $vlan, management_ip: $mgmt_ip, port_description: $port_desc}]')

            [[ -n "$sys_name" ]] && switch_names=$(echo "$switch_names" | run_tool jq --arg n "$sys_name" 'if (. | index($n)) then . else . += [$n] end')
            [[ -n "$mgmt_ip" ]] && management_ips=$(echo "$management_ips" | run_tool jq --arg n "$mgmt_ip" 'if (. | index($n)) then . else . += [$n] end')
            [[ -n "$vlan_id" ]] && native_vlans=$(echo "$native_vlans" | run_tool jq --arg n "$vlan_id" 'if (. | index($n)) then . else . += [$n] end')

        done <<< "$lldp_data"
    fi

    log_info "LLDP frames parsed: ${lldp_count}"

    #--- Step 5: Check for DTP frames (VLAN trunking) ---
    log_step 5 $total_steps "Checking for DTP/VTP frames"
    update_tc_progress 5 $total_steps "DTP/VTP check"

    check_abort || return 1

    local dtp_count=0
    local dtp_count=$(${TOOL_PATHS[tshark]} -r "$capture_file" -Y "dtp" 2>/dev/null | wc -l) || true

    if [[ $dtp_count -gt 0 ]]; then
        log_result "CRITICAL" "DTP (Dynamic Trunking Protocol) frames detected! Port may be trunk-negotiable — VLAN hopping risk."
        leaked_info=$(echo "$leaked_info" | run_tool jq '. += [{protocol: "DTP", device_id: "N/A", platform: "Trunk negotiation detected", port_id: "N/A", native_vlan: "N/A", management_ip: "N/A"}]')
    fi

    local vtp_count=0
    local vtp_count=$(${TOOL_PATHS[tshark]} -r "$capture_file" -Y "vtp" 2>/dev/null | wc -l) || true

    if [[ $vtp_count -gt 0 ]]; then
        log_result "FINDING" "VTP (VLAN Trunking Protocol) frames detected — VLAN database information leaking."
    fi

    #--- Step 6: Compile infrastructure info ---
    log_step 6 $total_steps "Compiling infrastructure information summary"
    update_tc_progress 6 $total_steps "Compiling"

    local infra_file="${evidence_prefix}_infrastructure_info.txt"
    {
        echo "============================================================"
        echo "  B3: Leaked Infrastructure Information Summary"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "CDP Frames Captured:  ${cdp_count}"
        echo "LLDP Frames Captured: ${lldp_count}"
        echo "DTP Frames:           ${dtp_count}"
        echo "VTP Frames:           ${vtp_count}"
        echo ""
        echo "--- Discovered Switch/Device Names ---"
        echo "$switch_names" | run_tool jq -r '.[]' 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "--- Discovered Management IPs ---"
        echo "$management_ips" | run_tool jq -r '.[]' 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "--- Discovered VLAN IDs ---"
        echo "$native_vlans" | run_tool jq -r '.[]' 2>/dev/null | sed 's/^/  /'
        echo ""
        echo "--- Risk Assessment ---"
        if [[ $cdp_count -gt 0 || $lldp_count -gt 0 ]]; then
            echo "  HIGH: Infrastructure discovery protocols are leaking to target WiFi."
            echo "  Attackers can use this information to:"
            echo "    - Map internal network topology"
            echo "    - Identify switch models and firmware versions"
            echo "    - Target specific management IPs"
            echo "    - Attempt VLAN hopping using discovered VLAN IDs"
            echo "    - Craft targeted exploits based on platform information"
        else
            echo "  LOW: No infrastructure protocol leaks detected."
        fi
    } > "$infra_file"

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local total_leaks=$(( cdp_count + lldp_count ))
    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $total_leaks -gt 0 || $dtp_count -gt 0 ]]; then
        local result_status="FINDING"
        local switch_count
        switch_count=$(echo "$switch_names" | run_tool jq 'length')
        local mgmt_ip_count
        local mgmt_ip_count=$(echo "$management_ips" | run_tool jq 'length')
        local vlan_count
        local vlan_count=$(echo "$native_vlans" | run_tool jq 'length')

        local result_summary="Infrastructure protocol leaks detected: ${cdp_count} CDP frames, ${lldp_count} LLDP frames. "
        result_summary+="Leaked: ${switch_count} device name(s), ${mgmt_ip_count} management IP(s), ${vlan_count} VLAN ID(s). "
        [[ $dtp_count -gt 0 ]] && result_summary+="CRITICAL: DTP frames detected — trunk negotiation possible. "

        local recommendations="1) Disable CDP on all target-facing switch ports: 'no cdp enable' (interface level). "
        recommendations+="2) Disable LLDP on target-facing ports: 'no lldp transmit' / 'no lldp receive'. "
        recommendations+="3) Set target ports to 'switchport mode access' and 'switchport nonegotiate' to prevent DTP/trunk negotiation. "
        recommendations+="4) Apply BPDU guard and port security on target-facing ports. "
        recommendations+="5) Consider using a separate physical infrastructure for target access."
    else
        local result_summary="No CDP, LLDP, or DTP frames captured on target WiFi. Discovery protocols are properly filtered on target-facing ports."
        local recommendations="No action needed. Continue to verify that this filtering persists after switch/firmware updates."
    fi

    local evidence_files='["b3_cdp_lldp_capture.pcap", "b3_cdp_parsed.txt", "b3_lldp_parsed.txt", "b3_infrastructure_info.txt"]'

    local result_json
    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "CDP: ${cdp_count}, LLDP: ${lldp_count}, DTP: ${dtp_count}, VTP: ${vtp_count}" \
        --arg recommendations "$recommendations" \
        --argjson cdp_frames_captured "$cdp_count" \
        --argjson lldp_frames_captured "$lldp_count" \
        --argjson dtp_frames "$dtp_count" \
        --argjson leaked_info "$leaked_info" \
        --argjson switch_names "$switch_names" \
        --argjson management_ips "$management_ips" \
        --argjson native_vlans "$native_vlans" \
        --argjson evidence_files "$evidence_files" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            cdp_frames_captured: $cdp_frames_captured,
            lldp_frames_captured: $lldp_frames_captured,
            dtp_frames: $dtp_frames,
            leaked_info: $leaked_info,
            switch_names: $switch_names,
            management_ips: $management_ips,
            native_vlans: $native_vlans,
            evidence_files: $evidence_files
        }')

    save_tc_result "B3" "$result_json" "has_tool_output:1,clean_run:1"

    # Display summary
    echo ""
    if [[ $total_leaks -gt 0 ]]; then
        log_result "FINDING" "CDP/LLDP leaking infrastructure details to target WiFi"
        log_result "INFO" "  Devices: $(echo "$switch_names" | run_tool jq -r 'join(", ")')"
        log_result "INFO" "  Mgmt IPs: $(echo "$management_ips" | run_tool jq -r 'join(", ")')"
        log_result "INFO" "  VLANs: $(echo "$native_vlans" | run_tool jq -r 'join(", ")')"
        [[ $dtp_count -gt 0 ]] && log_result "CRITICAL" "DTP detected — trunk negotiation possible!"
    else
        log_result "SECURE" "No CDP/LLDP/DTP frames captured on target WiFi"
    fi

    return 0
}