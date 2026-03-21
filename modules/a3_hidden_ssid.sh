#!/usr/bin/env bash
#===============================================================================
#  modules/a3_hidden_ssid.sh
#  A3: Discover Hidden SSIDs
#
#  PURPOSE:
#    Identify hidden SSIDs by capturing probe request/response frames.
#    Optionally send targeted deauthentication to force clients to
#    reconnect and reveal hidden SSID names.
#
#  TOOLS: ${TOOL_PATHS[airodump-ng]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[tshark]}
#  PHASE: 1A — Passive Recon (Monitor Mode)
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - a3_hidden_ssid_capture.cap    (probe response captures)
#    - a3_hidden_ssids_revealed.txt  (discovered hidden SSID list)
#
#  RESULT JSON FIELDS:
#    - hidden_networks_found: count from A1
#    - hidden_ssids_revealed: array of revealed SSIDs
#    - deauth_used: bool — was deauth required?
#===============================================================================

run_a3() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/a3"

    #--- Step 1: Load A1 data, identify hidden networks ---
    log_step 1 $total_steps "Loading A1 data and identifying hidden networks"
    update_tc_progress 1 $total_steps "Loading data"

    if ! has_tc_results "A1"; then
        log_error "A1 results not found. Run A1 first."
        return 1
    fi

    
    local a1_data
    a1_data=$(load_tc_result "A1")

    # Get hidden networks from A1
    local hidden_networks
    hidden_networks=$(echo "$a1_data" | ${TOOL_PATHS[jq]} -c '[.networks[] | select(.hidden == true)]')
    local hidden_count
    hidden_count=$(echo "$hidden_networks" | ${TOOL_PATHS[jq]} 'length')

    if [[ $hidden_count -eq 0 ]]; then
        log_success "No hidden SSIDs were detected in A1 scan."

        local result_json
        result_json=$(${TOOL_PATHS[jq]} -n \
            --arg status "SECURE" \
            --arg summary "No hidden SSIDs detected. All networks broadcast their SSID." \
            '{
                status: $status,
                summary: $summary,
                details: "No hidden networks found during A1 passive scan.",
                hidden_networks_found: 0,
                hidden_ssids_revealed: [],
                deauth_used: false,
                evidence_files: [],
                recommendations: "No action needed."
            }')
        save_tc_result "A3" "$result_json"
        return 0
    fi

    log_info "Found ${hidden_count} hidden network(s) to investigate"

    # List hidden networks
    echo ""
    echo -e "  ${C_BOLD}Hidden Networks:${C_RESET}"
    echo "$hidden_networks" | ${TOOL_PATHS[jq]} -r '.[] | "    BSSID: \(.bssid)  CH: \(.channel)  Signal: \(.signal)dBm  Enc: \(.encryption)"'

    #--- Step 2: Ensure monitor mode ---
    log_step 2 $total_steps "Verifying monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1

    #--- Step 3: Passive capture for probe responses ---
    log_step 3 $total_steps "Passive capture for probe request/response frames (60s)"
    update_tc_progress 3 $total_steps "Passive capture"

    check_abort || return 1

    local capture_file="${evidence_prefix}_hidden_ssid_capture"
    rm -f "${capture_file}"* 2>/dev/null

    # Target the channels of hidden networks
    local target_channels
    local target_channels=$(echo "$hidden_networks" | ${TOOL_PATHS[jq]} -r '.[].channel' | sort -un | paste -sd',' -)

    log_cmd "${TOOL_PATHS[airodump-ng]} ${MONITOR_INTERFACE} --channel ${target_channels} --write ${capture_file} --output-format pcap"

    ${TOOL_PATHS[airodump-ng]} "$MONITOR_INTERFACE" \
        --channel "$target_channels" \
        --write "$capture_file" \
        --output-format pcap \
        &>/dev/null &
    local capture_pid=$!
    register_cleanup "kill -SIGINT $capture_pid 2>/dev/null || true; wait $capture_pid 2>/dev/null || true"

    start_countdown 60 "Passively capturing probe responses"
    sleep 60
    stop_countdown

    
    check_abort || return 1

    # Check passive results
    local cap_file
    local cap_file=$(ls "${capture_file}"*.cap 2>/dev/null | head -1)
    local revealed_ssids=()

    if [[ -n "$cap_file" && -f "$cap_file" ]]; then
        # Extract probe responses with SSIDs using ${TOOL_PATHS[tshark]}
        local probe_results
        local probe_results=$(${TOOL_PATHS[tshark]} -r "$cap_file" \
            -Y "wlan.fc.type_subtype == 0x05" \
            -T fields \
            -e wlan.ta \
            -e wlan.ssid \
            2>/dev/null | sort -u)

        while IFS=$'\t' read -r ta ssid; do
            [[ -z "$ssid" || -z "$ta" ]] && continue
            # Check if this TA matches a hidden network BSSID
            local matches
            local matches=$(echo "$hidden_networks" | ${TOOL_PATHS[jq]} --arg bssid "$ta" '[.[] | select(.bssid == $bssid)] | length')
            if [[ $matches -gt 0 ]]; then
                revealed_ssids+=("$ssid")
                log_result "FINDING" "Hidden SSID revealed (passive): ${ssid} (BSSID: ${ta})"
            fi
        done <<< "$probe_results"
    fi

    #--- Step 4: Active deauth (if hidden SSIDs still unresolved) ---
    log_step 4 $total_steps "Active deauthentication to reveal remaining hidden SSIDs"
    update_tc_progress 4 $total_steps "Deauth attack"

    check_abort || return 1

    local unrevealed_count=$(( hidden_count - ${#revealed_ssids[@]} ))
    local deauth_used="false"

    if [[ $unrevealed_count -gt 0 ]]; then
        echo ""
        echo -e "${C_YELLOW}  ${unrevealed_count} hidden SSID(s) still unresolved.${C_RESET}"
        echo -e "${C_YELLOW}  Deauthentication can force clients to reconnect, revealing the SSID.${C_RESET}"
        echo -e "${C_YELLOW}  This will briefly disconnect any clients on the target AP.${C_RESET}"
        echo ""
        get_or_request_param "deauth_confirm" "  Send deauth frames? [Y/n]"

        if [[ "${deauth_confirm,,}" != "n" ]]; then
            local deauth_used="true"

            # Start a fresh capture in background
            local deauth_cap="${evidence_prefix}_deauth_capture"
            rm -f "${deauth_cap}"* 2>/dev/null

            ${TOOL_PATHS[airodump-ng]} "$MONITOR_INTERFACE" \
                --channel "$target_channels" \
                --write "$deauth_cap" \
                --output-format pcap \
                &>/dev/null &
            local deauth_cap_pid=$!
            register_cleanup "kill -SIGINT $deauth_cap_pid 2>/dev/null || true; wait $deauth_cap_pid 2>/dev/null || true"

            # Send deauth to each hidden network BSSID
            while IFS= read -r hidden_net; do
                local h_bssid h_channel
                local h_bssid=$(echo "$hidden_net" | ${TOOL_PATHS[jq]} -r '.bssid')
                local h_channel=$(echo "$hidden_net" | ${TOOL_PATHS[jq]} -r '.channel')

                # Check if already revealed
                local already_found="false"
                for rev in "${revealed_ssids[@]}"; do
                    # We can't easily match by BSSID here, so skip check
                    :
                done

                log_cmd "${TOOL_PATHS[aireplay-ng]} --deauth 5 -a ${h_bssid} ${MONITOR_INTERFACE}"
                echo -e "  ${C_DIM}  Sending 5 deauth frames to ${h_bssid} on CH ${h_channel}...${C_RESET}"

                # Set channel first
                iwconfig "$MONITOR_INTERFACE" channel "$h_channel" 2>/dev/null

                ${TOOL_PATHS[aireplay-ng]} --deauth 5 -a "$h_bssid" "$MONITOR_INTERFACE" &>/dev/null || true
                sleep 3

            done < <(echo "$hidden_networks" | ${TOOL_PATHS[jq]} -c '.[]')

            # Wait for reconnections
            start_countdown 30 "Waiting for clients to reconnect and reveal SSIDs"
            sleep 30
            stop_countdown

            # Stop capture
            
            # Parse deauth capture
            local deauth_cap_file
            local deauth_cap_file=$(ls "${deauth_cap}"*.cap 2>/dev/null | head -1)

            if [[ -n "$deauth_cap_file" && -f "$deauth_cap_file" ]]; then
                local deauth_probes
                local deauth_probes=$(${TOOL_PATHS[tshark]} -r "$deauth_cap_file" \
                    -Y "wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x04" \
                    -T fields \
                    -e wlan.ta \
                    -e wlan.ssid \
                    2>/dev/null | sort -u)

                while IFS=$'\t' read -r ta ssid; do
                    [[ -z "$ssid" || -z "$ta" ]] && continue
                    local matches
                    local matches=$(echo "$hidden_networks" | ${TOOL_PATHS[jq]} --arg bssid "$ta" '[.[] | select(.bssid == $bssid)] | length')
                    if [[ $matches -gt 0 ]]; then
                        # Check not already in list
                        local already="false"
                        for rev in "${revealed_ssids[@]}"; do
                            [[ "$rev" == "$ssid" ]] && already="true" && break
                        done
                        if [[ "$already" == "false" ]]; then
                            revealed_ssids+=("$ssid")
                            log_result "FINDING" "Hidden SSID revealed (deauth): ${ssid} (BSSID: ${ta})"
                        fi
                    fi
                done <<< "$deauth_probes"
            fi
        fi
    fi

    #--- Step 5: Compile results ---
    log_step 5 $total_steps "Compiling results"
    update_tc_progress 5 $total_steps "Compiling"

    local revealed_file="${evidence_prefix}_hidden_ssids_revealed.txt"
    {
        echo "============================================================"
        echo "  A3: Hidden SSID Discovery Results"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
        echo "Hidden networks detected: ${hidden_count}"
        echo "SSIDs revealed: ${#revealed_ssids[@]}"
        echo "Deauth used: ${deauth_used}"
        echo ""
        echo "Revealed SSIDs:"
        for ssid in "${revealed_ssids[@]}"; do
            echo "  - ${ssid}"
        done
        echo ""
        echo "Still hidden (could not reveal):"
        echo "  $(( hidden_count - ${#revealed_ssids[@]} )) network(s)"
    } > "$revealed_file"

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="INFO"
    local result_summary=""
    local recommendations=""

    if [[ ${#revealed_ssids[@]} -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="${#revealed_ssids[@]} hidden SSID(s) were revealed out of ${hidden_count} hidden networks. Hidden SSIDs provide no real security — they are trivially discoverable."
        local recommendations="Hidden SSIDs are a cosmetic measure only. If these are corporate networks, ensure they rely on WPA2/3-Enterprise authentication, not obscurity. Consider if hiding SSIDs adds operational complexity without security benefit."
    else
        local result_summary="${hidden_count} hidden network(s) detected but SSIDs could not be revealed (no clients connected). Hidden SSIDs can still be discovered when clients connect."
        local recommendations="Monitor during business hours when clients are active to reveal hidden SSIDs. Hidden SSIDs are not a security control."
    fi

    # Build revealed array for JSON
    local revealed_json="[]"
    for ssid in "${revealed_ssids[@]}"; do
        revealed_json=$(echo "$revealed_json" | ${TOOL_PATHS[jq]} --arg s "$ssid" '. += [$s]')
    done

    local evidence_files='["a3_hidden_ssids_revealed.txt"]'
    [[ -n "${cap_file:-}" ]] && evidence_files=$(echo "$evidence_files" | ${TOOL_PATHS[jq]} '. += ["a3_hidden_ssid_capture.cap"]')

    local result_json
    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg recommendations "$recommendations" \
        --argjson hidden_networks_found "${hidden_count:-0}" \
        --argjson hidden_ssids_revealed "$revealed_json" \
        --arg deauth_used "$deauth_used" \
        --argjson evidence_files "$evidence_files" \
        '{
            status: $status,
            summary: $summary,
            details: ("\(.hidden_networks_found) hidden networks found. \(.hidden_ssids_revealed | length) revealed."),
            recommendations: $recommendations,
            hidden_networks_found: $hidden_networks_found,
            hidden_ssids_revealed: $hidden_ssids_revealed,
            deauth_used: ($deauth_used == "true"),
            evidence_files: $evidence_files
        }')

    save_tc_result "A3" "$result_json"

    return 0
}