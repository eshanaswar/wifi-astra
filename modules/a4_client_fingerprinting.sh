#!/usr/bin/env bash
#===============================================================================
#  modules/a4_client_fingerprinting.sh
#  A4: Client Fingerprinting & Profiling
#
#  PURPOSE:
#    Passively fingerprint wireless clients to identify device types, operating
#    systems, and behavior patterns. Uses probe requests, OUI lookup, signal
#    strength, and 802.11 capability flags to build device profiles. Inspired
#    by WiFi Pineapple recon module and wifi-arsenal profiling tools.
#
#  TOOLS: ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[airodump-ng]}
#  PHASE: 1A — Passive Recon
#  DEPENDENCIES: none (standalone passive module)
#
#  EVIDENCE PRODUCED:
#    - a4_client_profiles.txt         (detailed per-client profiles)
#    - a4_oui_analysis.txt            (vendor breakdown)
#    - a4_probe_ssids.txt             (all probed SSIDs by all clients)
#    - a4_signal_map.txt              (client signal strength map)
#    - a4_capture.pcap                (raw capture)
#    - a4_findings.txt                (analysis summary)
#
#  RESULT JSON FIELDS:
#    - total_clients: int
#    - unique_vendors: int
#    - unique_probed_ssids: int
#    - os_fingerprints: object (OS → count)
#    - high_value_targets: int — devices probing corp/enterprise SSIDs
#===============================================================================

# --- OUI Vendor lookup ---
_oui_lookup() {
    local mac="$1"
    python3 "${SCRIPT_DIR}/utils/parsers/oui_lookup.py" "$mac" 2>/dev/null || echo "Unknown"
}

# --- OS fingerprint from probe patterns ---
_guess_os() {
    local probed_ssids="$1"
    local ht_caps="$2"

    # Heuristic OS guessing from probe behavior
    if echo "$probed_ssids" | grep -qi "eduroam\|1x"; then
        echo "Enterprise (802.1X client)"
    elif echo "$probed_ssids" | grep -qi "iPhone\|iPad"; then
        echo "iOS"
    elif echo "$probed_ssids" | grep -qi "DIRECT-"; then
        echo "Windows (WiFi Direct)"
    elif echo "$probed_ssids" | grep -qi "AndroidAP\|ANDROID"; then
        echo "Android"
    elif echo "$probed_ssids" | grep -qi "xfinitywifi\|CableWiFi\|attwifi"; then
        echo "Mobile (carrier hotspot client)"
    elif [[ -n "$ht_caps" ]] && echo "$ht_caps" | grep -q "0x"; then
        echo "Modern (HT/VHT capable)"
    else
        echo "Unknown"
    fi
}

run_a4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/a4"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_tshark=false
    local has_airodump=false

    command -v tshark &>/dev/null && has_tshark=true
    command -v airodump-ng &>/dev/null && has_airodump=true

    if [[ "$has_tshark" == "false" ]]; then
        log_error "${TOOL_PATHS[tshark]} is required for client fingerprinting."
        return 1
    fi

    log_success "Tools verified"

    #--- Info banner (this is PASSIVE) ---
    echo ""
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  ${C_BOLD}CLIENT FINGERPRINTING & PROFILING${C_RESET}${C_CYAN}                                ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  This is a PASSIVE reconnaissance module. It will:                ║${C_RESET}"
    echo -e "${C_CYAN}║    • Monitor all probe requests from nearby devices                ║${C_RESET}"
    echo -e "${C_CYAN}║    • Identify device vendors via MAC OUI lookup                    ║${C_RESET}"
    echo -e "${C_CYAN}║    • Fingerprint OS/device type from 802.11 capabilities           ║${C_RESET}"
    echo -e "${C_CYAN}║    • Map saved WiFi networks per device                            ║${C_RESET}"
    echo -e "${C_CYAN}║    • Track signal strength for proximity estimation                 ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  Duration: ~120 seconds of passive monitoring                     ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    local total_clients=0
    local unique_vendors=0
    local unique_probed_ssids=0
    local high_value_targets=0
    local findings_file="${evidence_prefix}_findings.txt"
    local profiles_file="${evidence_prefix}_client_profiles.txt"
    local oui_file="${evidence_prefix}_oui_analysis.txt"
    local probe_file="${evidence_prefix}_probe_ssids.txt"
    local signal_file="${evidence_prefix}_signal_map.txt"
    local cap_file="${evidence_prefix}_capture.pcap"

    {
        echo "============================================================"
        echo "  A4: Client Fingerprinting & Profiling"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    check_abort || return 1

    #--- Step 3: Channel hopping capture ---
    log_step 3 $total_steps "Capturing client probe requests (120s, all channels)"
    update_tc_progress 3 $total_steps "Probe capture"

    # Capture probe requests, probe responses, and beacon responses
    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$cap_file" \
        "type mgt subtype probe-req or type mgt subtype probe-resp or type mgt subtype assoc-req" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # Channel hop in background for broader coverage
    (
        for ch in 1 6 11 2 3 4 5 7 8 9 10 12 13 36 40 44 48 52 56 60 64 149 153 157 161 165; do
            iw dev "$mon_iface" set channel "$ch" 2>/dev/null || true
            sleep 4
        done
        # Loop 2.4 GHz channels again
        for ch in 1 6 11 1 6 11; do
            iw dev "$mon_iface" set channel "$ch" 2>/dev/null || true
            sleep 4
        done
    ) &
    local hop_pid=$!
    register_cleanup "kill -TERM $hop_pid 2>/dev/null || true; sleep 0.5; kill -9 $hop_pid 2>/dev/null || true; wait $hop_pid 2>/dev/null || true"

    start_countdown 120 "Scanning all channels for client probes"
    sleep 120
    stop_countdown

    # Stop hopping and capture
    kill -TERM $hop_pid 2>/dev/null; wait $hop_pid 2>/dev/null
    kill -SIGINT $tcpdump_pid 2>/dev/null; wait $tcpdump_pid 2>/dev/null

    validate_pcap "$cap_file" "Client probe capture"

    check_abort || return 1

    #--- Step 4: Extract and profile clients ---
    log_step 4 $total_steps "Building client profiles"
    update_tc_progress 4 $total_steps "Profiling"

    {
        echo "============================================================"
        echo "  Client Profiles"
        echo "============================================================"
        echo ""
    } > "$profiles_file"

    if [[ -f "$cap_file" && -s "$cap_file" ]]; then
        # Extract all unique client MACs from probe requests
        local all_clients
        local all_clients=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x04" \
            -T fields \
            -e wlan.sa \
            2>/dev/null | sort -u | grep -v "^$" | grep -v "ff:ff:ff:ff:ff:ff" || true)

        if [[ -n "$all_clients" ]]; then
            local total_clients=$(echo "$all_clients" | wc -l)
            log_info "Found ${total_clients} unique client devices"

            local -A vendor_counts
            local -A os_counts

            while IFS= read -r client_mac; do
                [[ -z "$client_mac" ]] && continue

                # Get vendor
                local vendor
                local vendor=$(_oui_lookup "$client_mac")

                # Count vendor
                vendor_counts["$vendor"]=$(( ${vendor_counts["$vendor"]:-0} + 1 ))

                # Get probed SSIDs for this client
                local client_ssids
                local client_ssids=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
                    -Y "wlan.sa == ${client_mac} && wlan.fc.type_subtype == 0x04" \
                    -T fields -e wlan.ssid \
                    2>/dev/null | sort -u | grep -v "^$" || true)

                local ssid_count=0
                [[ -n "$client_ssids" ]] && ssid_count=$(echo "$client_ssids" | wc -l)

                # Get signal strength (best seen)
                local signal
                local signal=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
                    -Y "wlan.sa == ${client_mac}" \
                    -T fields -e wlan_radio.signal_dbm \
                    2>/dev/null | sort -rn | head -1 || true)

                # Get HT capabilities
                local ht_caps
                local ht_caps=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
                    -Y "wlan.sa == ${client_mac}" \
                    -T fields -e wlan.ht.capabilities \
                    2>/dev/null | head -1 || true)

                # Guess OS
                local os_guess
                local os_guess=$(_guess_os "$client_ssids" "$ht_caps")
                os_counts["$os_guess"]=$(( ${os_counts["$os_guess"]:-0} + 1 ))

                # Check for high-value probes (enterprise SSIDs)
                local is_high_value="no"
                if echo "$client_ssids" | grep -qiE "corp|office|internal|enterprise|eduroam|radius|1x|vpn|secure"; then
                    local is_high_value="yes"
                    ((high_value_targets++))
                fi

                # Write profile
                {
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "  Client: ${client_mac}"
                    echo "  Vendor: ${vendor}"
                    echo "  OS/Type: ${os_guess}"
                    echo "  Signal: ${signal:-N/A} dBm"
                    echo "  Probed SSIDs (${ssid_count}):"
                    if [[ -n "$client_ssids" ]]; then
                        echo "$client_ssids" | sed 's/^/    • /'
                    else
                        echo "    (broadcast probe only)"
                    fi
                    [[ "$is_high_value" == "yes" ]] && echo "  ★ HIGH VALUE: Probing enterprise/corporate SSIDs"
                    echo ""
                } >> "$profiles_file"

            done <<< "$all_clients"

            # Build vendor summary
            {
                echo "============================================================"
                echo "  Vendor Breakdown (${total_clients} devices)"
                echo "============================================================"
                echo ""
            } > "$oui_file"

            local unique_vendors=0
            for vendor in "${!vendor_counts[@]}"; do
                ((unique_vendors++))
                echo "  ${vendor_counts[$vendor]}x  ${vendor}" >> "$oui_file"
            done
            sort -t'x' -k1 -rn -o "$oui_file" "$oui_file" 2>/dev/null || true

            # Build OS summary
            echo "" >> "$oui_file"
            echo "  OS/Type Breakdown:" >> "$oui_file"
            for os in "${!os_counts[@]}"; do
                echo "    ${os_counts[$os]}x  ${os}" >> "$oui_file"
            done
        fi

        # Extract all unique probed SSIDs
        local all_ssids
        local all_ssids=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x04" \
            -T fields -e wlan.ssid \
            2>/dev/null | sort | uniq -c | sort -rn | grep -v "^\s*$" || true)

        if [[ -n "$all_ssids" ]]; then
            local unique_probed_ssids=$(echo "$all_ssids" | wc -l)

            {
                echo "============================================================"
                echo "  All Probed SSIDs (by frequency)"
                echo "============================================================"
                echo ""
                echo "$all_ssids"
            } > "$probe_file"
        fi
    fi

    #--- Step 5: Signal strength mapping ---
    log_step 5 $total_steps "Building signal strength map"
    update_tc_progress 5 $total_steps "Signal map"

    {
        echo "============================================================"
        echo "  Client Signal Strength Map"
        echo "============================================================"
        echo "  (Proximity estimation: >-50dBm=close, -50 to -70=medium, <-70=far)"
        echo ""
    } > "$signal_file"

    if [[ -f "$cap_file" && -s "$cap_file" ]]; then
        local signal_data
        local signal_data=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x04" \
            -T fields \
            -e wlan.sa \
            -e wlan_radio.signal_dbm \
            2>/dev/null | sort -u | sort -t$'\t' -k2 -rn || true)

        if [[ -n "$signal_data" ]]; then
            local close=0 medium=0 far=0
            while IFS=$'\t' read -r smac ssig; do
                [[ -z "$smac" || -z "$ssig" ]] && continue
                local proximity="far"
                if [[ ${ssig%.*} -gt -50 ]]; then
                    local proximity="CLOSE"
                    ((close++))
                elif [[ ${ssig%.*} -gt -70 ]]; then
                    local proximity="medium"
                    ((medium++))
                else
                    ((far++))
                fi
                echo "  ${smac}  ${ssig} dBm  [${proximity}]" >> "$signal_file"
            done <<< "$signal_data"

            echo "" >> "$signal_file"
            echo "  Summary: ${close} close, ${medium} medium, ${far} far" >> "$signal_file"
        fi
    fi

    #--- Step 6: Restore managed mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="INFO"
    local result_summary=""
    local recommendations=""

    if [[ $high_value_targets -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="${total_clients} wireless clients fingerprinted. ${high_value_targets} device(s) are probing for corporate/enterprise SSIDs — "
        result_summary+="these are high-value targets for evil twin/karma attacks. "
        result_summary+="${unique_probed_ssids} unique SSIDs broadcast by ${unique_vendors} vendor types."
        local recommendations="1) Configure managed devices to NOT broadcast probe requests for saved networks. "
        recommendations+="2) Use MAC address randomization for probe requests (supported in iOS 14+, Android 10+). "
        recommendations+="3) Remove old/unused WiFi profiles from managed devices via MDM. "
        recommendations+="4) Deploy WIDS to detect probe-based recon. "
        recommendations+="5) Use 802.1X with certificates — immune to probe-based attacks."
    elif [[ $total_clients -gt 0 ]]; then
        local result_summary="${total_clients} wireless clients fingerprinted from ${unique_vendors} vendors. ${unique_probed_ssids} unique SSIDs broadcast. "
        result_summary+="No devices probing for obviously corporate SSIDs."
        local recommendations="Good client hygiene. Continue enforcing probe request randomization."
    else
        local result_summary="No wireless clients detected during the monitoring window."
        local recommendations="Re-run during business hours for accurate client profiling."
    fi

    echo "" >> "$findings_file"
    echo "Summary: ${total_clients} clients, ${unique_vendors} vendors, ${unique_probed_ssids} SSIDs, ${high_value_targets} high-value" >> "$findings_file"

    local result_json
    evidence_register_file "a4_client_profiles.txt"
    evidence_register_file "a4_oui_analysis.txt"
    evidence_register_file "a4_probe_ssids.txt"
    evidence_register_file "a4_signal_map.txt"
    evidence_register_file "a4_capture.pcap"
    evidence_register_file "a4_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Clients: ${total_clients}, Vendors: ${unique_vendors}, SSIDs: ${unique_probed_ssids}, High-value: ${high_value_targets}" \
        --arg recommendations "$recommendations" \
        --argjson total_clients "$total_clients" \
        --argjson unique_vendors "$unique_vendors" \
        --argjson unique_probed_ssids "${unique_probed_ssids:-0}" \
        --argjson high_value_targets "$high_value_targets" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            total_clients: $total_clients,
            unique_vendors: $unique_vendors,
            unique_probed_ssids: $unique_probed_ssids,
            high_value_targets: $high_value_targets,
                    }')

    save_tc_result "A4" "$result_json"

    echo ""
    if [[ $high_value_targets -gt 0 ]]; then
        log_result "FINDING" "★ ${high_value_targets} device(s) probing corporate SSIDs (${total_clients} total clients)"
    elif [[ $total_clients -gt 0 ]]; then
        log_result "INFO" "${total_clients} clients profiled (${unique_vendors} vendors, ${unique_probed_ssids} SSIDs)"
    else
        log_result "INFO" "No clients detected during monitoring window"
    fi

    return 0
}
