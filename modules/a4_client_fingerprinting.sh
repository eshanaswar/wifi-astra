#!/usr/bin/env bash
# MODULE_META
# NAME="Client Fingerprinting & Profiling"
# CATEGORY="A"
# DEPS="none"
# CRITICAL="no"
# TOOLS="tcpdump,tshark,python3"
# DESC="Passive device profiling via probe requests, OUI lookup, signal mapping"
# REQS="monitor_iface"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a4_client_fingerprinting.sh
#  A4: Client Fingerprinting & Profiling
#
#  PURPOSE:
#    Passively fingerprint wireless clients to identify device types, operating
#    systems, and behavior patterns. Uses probe requests, OUI lookup, signal
#    strength, and 802.11 capability flags to build device profiles.
#
#  TOOLS: tcpdump, tshark, iw
#  PHASE: 1A — Passive Recon
#  DEPENDENCIES: none
#
#  EVIDENCE PRODUCED:
#    - a4_client_profiles.txt         (detailed per-client profiles)
#    - a4_oui_analysis.txt            (vendor breakdown)
#    - a4_probe_ssids.txt             (all probed SSIDs by all clients)
#    - a4_signal_map.txt              (client signal strength map)
#    - a4_capture.pcap                (raw capture)
#    - a4_findings.txt                (analysis summary)
#===============================================================================

set -uo pipefail

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
    local tc_id="A4"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    if ! check_module_dependencies "$tc_id"; then
        return 1
    fi

    log_success "Tools verified"

    ui_banner "Client Fingerprinting & Profiling" \
        "This is a PASSIVE reconnaissance module." \
        "It monitors all probe requests from nearby devices." \
        "Identifies device vendors via MAC OUI lookup." \
        "Fingerprints OS/device type from 802.11 capabilities." \
        "Maps saved WiFi networks per device." \
        "Tracks signal strength for proximity estimation." \
        "Duration: ~120 seconds of passive monitoring."

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    check_abort || return 1

    #--- Step 3: Channel hopping capture ---
    log_step 3 $total_steps "Capturing client probe requests (120s, all channels)"
    update_tc_progress 3 $total_steps "Probe capture"

    local cap_file="${evidence_prefix}_capture.pcap"
    rm -f "$cap_file" 2>/dev/null

    # Capture probe requests, responses, and associations
    spawn_bg "a4_capture" "tcpdump" --log "/dev/null" \
        -i "$mon_iface" -w "$cap_file" \
        "type mgt subtype probe-req or type mgt subtype probe-resp or type mgt subtype assoc-req"

    # Channel hop in background
    (
        local channels=(1 6 11 2 3 4 5 7 8 9 10 12 13 36 40 44 48 52 56 60 64 149 153 157 161 165)
        while true; do
            for ch in "${channels[@]}"; do
                run_fg --quiet "iw" dev "$mon_iface" set channel "$ch" 2>/dev/null || true
                sleep 4
            done
        done
    ) &
    local hop_pid=$!
    register_cleanup "kill -TERM $hop_pid 2>/dev/null || true; wait $hop_pid 2>/dev/null || true"

    start_countdown 120 "Scanning all channels for client probes"
    sleep 120
    stop_countdown

    # Stop hopping and capture
    kill -TERM $hop_pid 2>/dev/null; wait $hop_pid 2>/dev/null
    stop_process "a4_capture"

    if [[ ! -f "$cap_file" ]] || [[ ! -s "$cap_file" ]]; then
        log_warn "No packets captured during A4 monitoring."
    else
        evidence_register_file "$cap_file" "Client probe capture"
    fi

    check_abort || return 1

    #--- Step 4: Extract and profile clients ---
    log_step 4 $total_steps "Building client profiles"
    update_tc_progress 4 $total_steps "Profiling"

    local -A vendor_counts_init
    local -A client_os_map
    local -A client_signal_map
    local -A client_ssid_map
    local -A vendor_counts
    local -A os_counts

    local total_clients=0
    local unique_vendors=0
    local unique_probed_ssids=0
    local high_value_targets=0
    local profiles_file="${evidence_prefix}_client_profiles.txt"
    local oui_file="${evidence_prefix}_oui_analysis.txt"
    local probe_file="${evidence_prefix}_probe_ssids.txt"
    local signal_file="${evidence_prefix}_signal_map.txt"
    local findings_file="${evidence_prefix}_findings.txt"

    {
        echo "============================================================"
        echo "  A4: Client Fingerprinting & Profiling"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  Client Profiles"
        echo "============================================================"
        echo ""
    } > "$profiles_file"

    if [[ -f "$cap_file" && -s "$cap_file" ]]; then
        log_info "Analyzing capture data (single-pass optimized extraction)..."
        
        # Ensure user can read the capture file
        ensure_user_ownership "$cap_file"

        # Optimized single-pass extraction: MAC, SSID, Signal, HT Capabilities
        # We stream this to avoid loading everything into a Bash variable
        while IFS=$'\t' read -r client_mac ssid signal ht_caps; do
            [[ -z "$client_mac" || "$client_mac" == "ff:ff:ff:ff:ff:ff" ]] && continue

            # Track total unique clients (first time we see a MAC)
            if [[ -z "${vendor_counts_init[$client_mac]:-}" ]]; then
                ((total_clients++))
                vendor_counts_init["$client_mac"]=1
                
                # Get vendor (OUI lookup)
                local vendor
                vendor=$(run_as_user python3 "${SCRIPT_DIR}/utils/parsers/oui_lookup.py" "$client_mac" 2>/dev/null || echo "Unknown")
                vendor_counts["$vendor"]=$(( ${vendor_counts["$vendor"]:-0} + 1 ))
                
                # Initialize profile data
                client_os_map["$client_mac"]="Unknown"
                client_signal_map["$client_mac"]="-100"
                client_ssid_map["$client_mac"]=""
            fi

            # Update best signal
            if [[ -n "$signal" ]]; then
                local sig_int="${signal%.*}"
                local old_sig="${client_signal_map[$client_mac]}"
                if [[ $sig_int -gt $old_sig ]]; then
                    client_signal_map["$client_mac"]="$sig_int"
                fi
            fi

            # Update probed SSIDs (comma-separated list)
            if [[ -n "$ssid" ]]; then
                if [[ ",${client_ssid_map[$client_mac]}," != *",$ssid,"* ]]; then
                    client_ssid_map["$client_mac"]="${client_ssid_map[$client_mac]}$ssid,"
                fi
            fi

            # Update HT capabilities/OS Guess (only if not already guessed)
            if [[ "${client_os_map[$client_mac]}" == "Unknown" ]]; then
                local os_guess
                os_guess=$(_guess_os "$ssid" "$ht_caps")
                if [[ "$os_guess" != "Unknown" ]]; then
                    client_os_map["$client_mac"]="$os_guess"
                fi
            fi

        done < <(run_as_user tshark -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x04" \
            -T fields \
            -e wlan.sa -e wlan.ssid -e wlan_radio.signal_dbm -e wlan.ht.capabilities \
            2>/dev/null)

        log_info "Profiling ${total_clients} unique devices..."

        # Now build the final reports from the in-memory maps
        for client_mac in "${!client_signal_map[@]}"; do
            local ssids="${client_ssid_map[$client_mac]%,}"
            local os_guess="${client_os_map[$client_mac]}"
            local signal="${client_signal_map[$client_mac]}"
            local vendor=$(run_as_user python3 "${SCRIPT_DIR}/utils/parsers/oui_lookup.py" "$client_mac" 2>/dev/null || echo "Unknown")
            
            local ssid_count=$(echo "$ssids" | tr ',' '\n' | grep -c . || echo "0")
            
            # Check for high-value targets
            if echo "$ssids" | grep -qiE "corp|office|internal|enterprise|eduroam|radius|1x|vpn|secure"; then
                ((high_value_targets++))
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$profiles_file"
                echo "  Client: ${client_mac} ★ HIGH VALUE" >> "$profiles_file"
            else
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$profiles_file"
                echo "  Client: ${client_mac}" >> "$profiles_file"
            fi

            {
                echo "  Vendor: ${vendor}"
                echo "  OS/Type: ${os_guess}"
                echo "  Best Signal: ${signal} dBm"
                echo "  Probed SSIDs (${ssid_count}):"
                if [[ -n "$ssids" ]]; then
                    echo "$ssids" | tr ',' '\n' | sed 's/^/    • /'
                else
                    echo "    (broadcast probe only)"
                fi
                echo ""
            } >> "$profiles_file"
            
            os_counts["$os_guess"]=$(( ${os_counts["$os_guess"]:-0} + 1 ))
        done

        # --- Sync with Assessment Engine ---
        log_info "Syncing discoveries with assessment engine..."
        local clients_json_array
        clients_json_array=$( (
            echo "["
            local first=1
            for client_mac in "${!client_signal_map[@]}"; do
                [[ $first -eq 0 ]] && echo ","
                local ssids="${client_ssid_map[$client_mac]%,}"
                local os_guess="${client_os_map[$client_mac]}"
                local signal="${client_signal_map[$client_mac]}"
                local vendor
                vendor=$(run_as_user python3 "${SCRIPT_DIR}/utils/parsers/oui_lookup.py" "$client_mac" 2>/dev/null || echo "Unknown")
                
                # Convert comma SSIDs to JSON array
                local probe_json
                probe_json=$(echo "$ssids" | tr ',' '\n' | grep . | run_tool jq -R . | run_tool jq -s . -c || echo "[]")
                
                run_tool jq -n \
                    --arg mac "$client_mac" \
                    --arg vendor "$vendor" \
                    --argjson sig "$signal" \
                    --arg os "$os_guess" \
                    --argjson probes "$probe_json" \
                    '{mac: $mac, vendor: $vendor, last_signal: $sig, last_bssid: "", os_guess: $os, probes: $probes}' -c
                first=0
            done
            echo "]"
        ) | tr -d '\n' )

        if [[ -n "${SESSION_DB_FILE:-}" && "$clients_json_array" != "[]" ]]; then
            run_tool astra-engine --db "$SESSION_DB_FILE" ingest batch-clients --json "$clients_json_array"
        fi

        # Build vendor summary
            {
                echo "============================================================"
                echo "  Vendor Breakdown (${total_clients} devices)"
                echo "============================================================"
                echo ""
            } > "$oui_file"

            for vendor in "${!vendor_counts[@]}"; do
                ((unique_vendors++))
                echo "  ${vendor_counts[$vendor]}x  ${vendor}" >> "$oui_file"
            done
            sort -t'x' -k1 -rn -o "$oui_file" "$oui_file" 2>/dev/null || true

            echo -e "\n  OS/Type Breakdown:" >> "$oui_file"
            for os in "${!os_counts[@]}"; do
                echo "    ${os_counts[$os]}x  ${os}" >> "$oui_file"
            done
        fi

        # Extract all unique probed SSIDs across all clients
        local all_ssids
        all_ssids=$(run_fg --quiet "tshark" -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x04" \
            -T fields -e wlan.ssid \
            2>/dev/null | sort | uniq -c | sort -rn | grep -v "^\s*$" || true)

        if [[ -n "$all_ssids" ]]; then
            unique_probed_ssids=$(echo "$all_ssids" | wc -l)
            {
                echo "============================================================"
                echo "  All Probed SSIDs"
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
        signal_data=$(run_fg --quiet "tshark" -r "$cap_file" \
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
                local sig_int="${ssig%.*}"
                if [[ $sig_int -gt -50 ]]; then
                    proximity="CLOSE"
                    ((close++))
                elif [[ $sig_int -gt -70 ]]; then
                    proximity="medium"
                    ((medium++))
                else
                    ((far++))
                fi
                echo "  ${smac}  ${ssig} dBm  [${proximity}]" >> "$signal_file"
            done <<< "$signal_data"
            echo -e "\n  Summary: ${close} close, ${medium} medium, ${far} far" >> "$signal_file"
        fi
    fi

    #--- Step 6: Restore managed mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 2

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="INFO"
    local result_summary=""
    local recommendations=""

    if [[ $high_value_targets -gt 0 ]]; then
        result_status="FINDING"
        result_summary="${total_clients} clients profiled. ${high_value_targets} device(s) are probing for enterprise/corp SSIDs (High-Value targets)."
        recommendations="1) Audit managed device saved WiFi profiles via MDM. 2) Enforce MAC randomization. 3) Deploy WIDS."
    elif [[ $total_clients -gt 0 ]]; then
        result_summary="${total_clients} clients profiled from ${unique_vendors} vendors. No obviously corporate SSID probes detected."
        recommendations="Monitor for growth in client numbers or new vendor types."
    else
        result_summary="No wireless clients detected in this window."
        recommendations="Re-run during active business hours."
    fi

    evidence_register_file "$profiles_file" "Client profiles"
    evidence_register_file "$oui_file" "Vendor analysis"
    evidence_register_file "$probe_file" "Probed SSIDs list"
    evidence_register_file "$signal_file" "Signal strength map"
    evidence_register_file "$findings_file" "Analysis summary"

    # Build OS fingerprints JSON in one pass (optimized to avoid iterative jq forks)
    local os_json
    os_json=$(for os in "${!os_counts[@]}"; do
        echo "$os:${os_counts[$os]}"
    done | run_tool jq -R -s 'split("\n") | map(select(length > 0)) | map(split(":")) | map({(.[0]): (.[1]|tonumber)}) | add // {}')

    local result_json
    result_json=$(run_fg --quiet "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Clients: ${total_clients}, Vendors: ${unique_vendors}, SSIDs: ${unique_probed_ssids}, High-value: ${high_value_targets}" \
        --arg recommendations "$recommendations" \
        --argjson total_clients "$total_clients" \
        --argjson unique_vendors "$unique_vendors" \
        --argjson unique_probed_ssids "${unique_probed_ssids:-0}" \
        --argjson high_value_targets "$high_value_targets" \
        --argjson os_fingerprints "$os_json" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            total_clients: $total_clients,
            unique_vendors: $unique_vendors,
            unique_probed_ssids: $unique_probed_ssids,
            high_value_targets: $high_value_targets,
            os_fingerprints: $os_fingerprints
        }')

    save_tc_result "A4" "$result_json" "pcap_required:1,has_tool_output:1,has_primary_artifact:1,clean_run:1"

    echo ""
    if [[ $high_value_targets -gt 0 ]]; then
        log_result "FINDING" "★ ${high_value_targets} device(s) probing corporate SSIDs (${total_clients} total clients)"
    elif [[ $total_clients -gt 0 ]]; then
        log_result "INFO" "${total_clients} clients profiled (${unique_vendors} vendors)"
    else
        log_result "INFO" "No clients detected"
    fi

    return 0
}
