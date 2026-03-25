#!/usr/bin/env bash
# MODULE_META
# NAME="Identify All Wireless Networks"
# CATEGORY="A"
# DEPS="none"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng,python3"
# DESC="Enumerate all SSIDs, BSSIDs, channels, encryption using monitor mode"
# REQS="monitor_iface"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a1_identify_networks.sh
#  A1: Identify All Wireless Networks
#
#  PURPOSE:
#    Enumerate all visible SSIDs, BSSIDs, channels, encryption types,
#    and signal strengths using monitor mode passive scanning.
#
#  TOOLS: ${TOOL_PATHS[airmon-ng]}, ${TOOL_PATHS[airodump-ng]}
#  PHASE: 1A — Passive Recon (Monitor Mode)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - a1_airodump.csv          (${TOOL_PATHS[airodump-ng]} CSV output)
#    - a1_airodump.cap          (raw packet capture)
#    - a1_networks_summary.txt  (parsed network list)
#
#  RESULT JSON FIELDS:
#    - network_count: total SSIDs found
#    - networks[]: array of {ssid, bssid, channel, encryption, signal}
#    - hidden_count: number of hidden networks
#    - target_identified: bool — was the target SSID found?
#===============================================================================

run_a1() {
    set -uo pipefail
    
    local interface=""
    local scan_time="${AIRODUMP_SCAN_TIME:-60}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --timeout) scan_time="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals if not provided (for transition)
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"

    local total_steps=7
    local evidence_prefix="${evidence_dir}/a1"

    #--- Step 1: Verify prerequisites ---
    log_step 1 $total_steps "Verifying required tools"
    update_tc_progress 1 $total_steps "Checking tools"

    check_module_dependencies "A1" || return 1
    log_success "All required tools available"

    #--- Step 2: Select wireless interface ---
    log_step 2 $total_steps "Selecting wireless interface"
    update_tc_progress 2 $total_steps "Interface selection"

    if [[ -z "$interface" ]]; then
        configure_network || return 1
        interface="$WIFI_INTERFACE"
    fi
    log_success "Using interface: ${interface}"

    #--- Step 3: Enable monitor mode ---
    log_step 3 $total_steps "Enabling monitor mode"
    update_tc_progress 3 $total_steps "Monitor mode"

    # Note: enable_monitor_mode still uses globals internally for now,
    # but we'll transition it later. For now, we ensure globals are set if needed.
    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="$MONITOR_INTERFACE"
    log_success "Monitor mode active: ${mon_iface}"

    #--- Step 4: Run airodump-ng scan ---
    log_step 4 $total_steps "Scanning for wireless networks (${scan_time}s)"
    update_tc_progress 4 $total_steps "Scanning WiFi"

    local airodump_prefix="${evidence_prefix}_airodump"

    # Remove any previous output files
    rm -f "${airodump_prefix}"* 2>/dev/null

    # Spawn via assessment engine process supervisor
    spawn_bg "a1_scan" "airodump-ng" \
        "$mon_iface" \
        --write "$airodump_prefix" \
        --output-format csv,pcap \
        --band abg

    # Countdown while scanning
    start_countdown "$scan_time" "Scanning for wireless networks"
    sleep "$scan_time"
    stop_countdown

    # Stop airodump
    stop_process "a1_scan"
    
    check_abort || return 1

    # Find the output files (airodump adds -01 suffix)
    local csv_file
    csv_file=$(ls "${airodump_prefix}"*.csv 2>/dev/null | head -1)
    local cap_file
    cap_file=$(ls "${airodump_prefix}"*.cap 2>/dev/null | head -1)

    if [[ -z "$csv_file" || ! -s "$csv_file" ]]; then
        log_error "Airodump-ng produced no output. Check your wireless adapter."
        log_error "Ensure the adapter supports monitor mode and packet injection."
        return 1
    fi

    log_success "Scan complete. CSV: $(basename "$csv_file"), CAP: $(basename "${cap_file:-none}")"

    #--- Step 5: Ingest into Assessment Engine ---
    log_step 5 $total_steps "Ingesting results into assessment engine"
    update_tc_progress 5 $total_steps "Ingesting"
    
    # Use the Go engine to ingest the airodump CSV into the session database
    if [[ -n "${ENGINE_SOCKET:-}" && -S "$ENGINE_SOCKET" ]]; then
        log_info "Ingesting scan data into assessment engine..."
        run_engine_api POST "/v1/ingest/airodump?file=${csv_file}" >/dev/null
    else
        log_warn "Assessment engine not available; skipping ingestion."
    fi

    #--- Step 6: Parse results for report ---
    log_step 6 $total_steps "Parsing scan results"
    update_tc_progress 6 $total_steps "Parsing"

    check_abort || return 1

    # Parse airodump CSV with Python parser
    local summary_file="${evidence_prefix}_networks_summary.txt"
    
    local networks_json
    ensure_user_ownership "$csv_file"
    networks_json=$(run_as_user python3 "${SCRIPT_DIR}/utils/parsers/airodump_parser.py" "$csv_file" 2>/dev/null)
    
    if [[ -z "$networks_json" || "$networks_json" == *"error"* ]]; then
        log_error "Failed to parse Airodump CSV."
        networks_json="[]"
    fi

    local network_count
    network_count=$(echo "$networks_json" | run_tool jq length)
    local hidden_count
    hidden_count=$(echo "$networks_json" | run_tool jq '[.[] | select(.hidden == true)] | length')
    local open_networks
    open_networks=$(echo "$networks_json" | run_tool jq '[.[] | select(.encryption | contains("OPN"))] | length')

    # Header for summary file
    {
        echo "============================================================"
        echo "  A1: Wireless Network Scan Results"
        echo "  Scan Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Scan Duration: ${AIRODUMP_SCAN_TIME}s"
        echo "  Interface: ${MONITOR_INTERFACE}"
        echo "============================================================"
        echo ""
        printf "%-35s %-20s %-5s %-15s %-8s %-6s\n" "SSID" "BSSID" "CH" "ENCRYPTION" "SIGNAL" "BEACONS"
        printf "%s\n" "$(printf '─%.0s' {1..95})"
    } > "$summary_file"

    local target_found="false"
    if [[ -n "${GUEST_SSID:-}" ]]; then
        local target_net
        target_net=$(echo "$networks_json" | run_tool jq -r --arg ssid "$GUEST_SSID" '.[] | select(.ssid == $ssid) | .bssid' | head -1)
        if [[ -n "$target_net" && "$target_net" != "null" && "$target_net" != "" ]]; then
            target_found="true"
            GUEST_BSSID="$target_net"
            GUEST_CHANNEL=$(echo "$networks_json" | run_tool jq -r --arg ssid "$GUEST_SSID" '.[] | select(.ssid == $ssid) | .channel' | head -1)
            log_info "Target network found: ${GUEST_SSID} (${GUEST_BSSID}) on channel ${GUEST_CHANNEL}"
        fi
    fi

    # Write to summary
    echo "$networks_json" | run_tool jq -r '.[] | "\(.ssid)\t\(.bssid)\t\(.channel)\t\(.encryption)\t\(.signal)\t\(.beacons)"' | \
    while IFS=$'\t' read -r ssid bssid channel encryption signal beacons; do
        printf "%-35s %-20s %-5s %-15s %-8s %-6s\n" "$ssid" "$bssid" "$channel" "$encryption" "${signal}dBm" "$beacons" >> "$summary_file"
    done

    # Append summary stats
    {
        echo ""
        echo "$(printf '─%.0s' {1..95})"
        echo "Total Networks: ${network_count}"
        echo "Hidden Networks: ${hidden_count}"
        echo "Target SSID (${GUEST_SSID:-not set}): $(if [[ "$target_found" == "true" ]]; then echo "FOUND"; else echo "NOT FOUND"; fi)"
    } >> "$summary_file"

    log_success "Found ${network_count} networks (${hidden_count} hidden)"

    # Display top networks
    echo ""
    echo -e "  ${C_BOLD}Top Networks Detected:${C_RESET}"
    head -20 "$summary_file" | tail -15 | while IFS= read -r line; do
        echo -e "  ${C_GRAY}${line}${C_RESET}"
    done

    #--- Step 7: Save results & prompt for target selection ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    # If target SSID already identified, ask if the user wants to change it
    local _prompt_selection=false
    if [[ -z "${GUEST_SSID:-}" ]]; then
        _prompt_selection=true
    else
        echo ""
        echo -e "  Current Target SSID: ${C_BOLD}${GUEST_SSID}${C_RESET}"
        local _change_target=""
        stty echo 2>/dev/null
        read -t 0.1 -n 10000 discard 2>/dev/null || true
        
        local old_ifs="$IFS"
        IFS=$' \t\n'
        printf "  Change target network? [y/N]: "
        read _change_target
        IFS="$old_ifs"
        if [[ "${_change_target,,}" == "y" ]]; then
            _prompt_selection=true
        fi
    fi

    if [[ "$_prompt_selection" == "true" ]]; then
        echo ""
        echo -e "${C_YELLOW}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
        echo -e "${C_YELLOW}│  TARGET SELECTION                                               │${C_RESET}"
        echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
        echo -e "${C_YELLOW}│  Select the target WiFi network to test.                        │${C_RESET}"
        echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
        echo -e "${C_YELLOW}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
        echo ""

        # List unique networks for selection (SSID + BSSID)
        local -a ssid_list=()
        local -a bssid_list=()
        local ssid_idx=1
        
        while IFS=$'\t' read -r ssid bssid channel signal; do
            [[ -z "$ssid" || "$ssid" == "<HIDDEN>" ]] && continue
            printf "    [%2d]  %-25s  %-18s  CH %-2s  (%sdBm)\n" "$ssid_idx" "$ssid" "$bssid" "$channel" "$signal"
            ssid_list+=("$ssid")
            bssid_list+=("$bssid")
            ((ssid_idx++))
        done < <(echo "$networks_json" | run_tool jq -r '.[] | "\(.ssid)\t\(.bssid)\t\(.channel)\t\(.signal)"' | sort -u)

        if [[ ${#ssid_list[@]} -gt 0 ]]; then
            echo ""
            local ssid_choice=""
            
            # Sanitization pass
            stty echo 2>/dev/null
            read -t 0.1 -n 10000 discard 2>/dev/null || true # Flush buffer
            
            local old_ifs="$IFS"
            IFS=$' \t\n'
            printf "  Select target [1-%d] or type SSID manually: " "$((ssid_idx-1))"
            read ssid_choice
            IFS="$old_ifs"

            if [[ -z "$ssid_choice" ]]; then
                log_warn "No selection made."
            elif [[ "$ssid_choice" =~ ^[0-9]+$ ]] && [[ $ssid_choice -ge 1 ]] && [[ $ssid_choice -le ${#ssid_list[@]} ]]; then
                GUEST_SSID="${ssid_list[$((ssid_choice-1))]}"
                GUEST_BSSID="${bssid_list[$((ssid_choice-1))]}"
                export GUEST_SSID GUEST_BSSID
            else
                GUEST_SSID="$ssid_choice"
                # Try to find BSSID for manually entered SSID
                GUEST_BSSID=$(echo "$networks_json" | run_tool jq -r --arg ssid "$GUEST_SSID" '[.[] | select(.ssid == $ssid)] | .[0].bssid // ""')
                export GUEST_SSID GUEST_BSSID
            fi
        else
            echo -e "    ${C_GRAY}(No non-hidden networks detected in scan)${C_RESET}"
            local manual_ssid=""
            stty echo 2>/dev/null
            read -t 0.1 -n 10000 discard 2>/dev/null || true
            printf "  Enter target SSID manually: "
            read manual_ssid
            if [[ -n "$manual_ssid" ]]; then
                GUEST_SSID="$manual_ssid"
                GUEST_BSSID=$(echo "$networks_json" | run_tool jq -r --arg ssid "$GUEST_SSID" '[.[] | select(.ssid == $ssid)] | .[0].bssid // ""')
                export GUEST_SSID GUEST_BSSID
            fi
        fi

        # Find channel for selected network
        GUEST_CHANNEL=$(echo "$networks_json" | run_tool jq -r --arg bssid "$GUEST_BSSID" '[.[] | select(.bssid == $bssid)] | .[0].channel // ""')
        [[ -z "$GUEST_CHANNEL" ]] && GUEST_CHANNEL=$(echo "$networks_json" | run_tool jq -r --arg ssid "$GUEST_SSID" '[.[] | select(.ssid == $ssid)] | .[0].channel // ""')

        log_success "Target set: ${GUEST_SSID} (${GUEST_BSSID:-unknown BSSID}) on channel ${GUEST_CHANNEL:-unknown}"
        target_found="true"
    fi

    # Optional: Select an INTERNAL/CORPORATE SSID for segregation reference
    if [[ -z "${INTERNAL_SSID:-}" ]]; then
        echo ""
        echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
        echo -e "${C_CYAN}│  INTERNAL NETWORK REFERENCE (Optional)                          │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}│  Select the CORPORATE or INTERNAL SSID to test for              │${C_RESET}"
        echo -e "${C_CYAN}│  segregation/leaks from the target network.                     │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
        echo ""

        # List unique networks for selection
        local -a int_ssid_list=()
        local -a int_bssid_list=()
        local int_idx=1
        
        while IFS=$'\t' read -r ssid bssid; do
            [[ "$bssid" == "$GUEST_BSSID" ]] && continue
            
            local display_name="$ssid"
            [[ "$ssid" == "<HIDDEN>" ]] && display_name="${C_YELLOW}<HIDDEN>${C_RESET} (${bssid})"
            
            echo -e "    [${int_idx}] ${display_name}"
            int_ssid_list+=("$ssid")
            int_bssid_list+=("$bssid")
            ((int_idx++))
        done < <(echo "$networks_json" | run_tool jq -r '.[] | "\(.ssid)\t\(.bssid)"' | sort -u)

        if [[ ${#int_ssid_list[@]} -gt 0 || -z "$GUEST_SSID" ]]; then
            echo ""
            echo -e "    [${C_BOLD}Enter${C_RESET}] Skip / No internal reference"
            echo ""
            
            # Use read directly here for more control over 'skip' vs 'manual'
            local int_choice=""
            stty echo 2>/dev/null
            read -t 0.1 -n 10000 discard 2>/dev/null || true
            
            local old_ifs="$IFS"
            IFS=$' \t\n'
            printf "  Select internal network [1-%d] or type SSID manually: " "$((int_idx-1))"
            read int_choice
            IFS="$old_ifs"
            
            if [[ -z "$int_choice" ]]; then
                log_info "Internal reference skipped."
                INTERNAL_SSID="NONE" # Mark as skipped to avoid re-prompting
                export INTERNAL_SSID
            elif [[ "$int_choice" =~ ^[0-9]+$ ]] && [[ $int_choice -ge 1 ]] && [[ $int_choice -le ${#int_ssid_list[@]} ]]; then
                local idx=$((int_choice-1))
                INTERNAL_SSID="${int_ssid_list[$idx]}"
                INTERNAL_BSSID="${int_bssid_list[$idx]}"
                
                if [[ "$INTERNAL_SSID" == "<HIDDEN>" ]]; then
                    read -p "  Hidden network selected. Enter known SSID (optional): " known_ssid
                    [[ -n "$known_ssid" ]] && INTERNAL_SSID="$known_ssid"
                fi
                log_info "Internal reference set: ${INTERNAL_SSID} (${INTERNAL_BSSID})"
                export INTERNAL_SSID INTERNAL_BSSID
            else
                # Manual entry
                INTERNAL_SSID="$int_choice"
                # Try to find BSSID for manually entered SSID
                INTERNAL_BSSID=$(echo "$networks_json" | run_tool jq -r --arg ssid "$INTERNAL_SSID" '[.[] | select(.ssid == $ssid)] | .[0].bssid // ""')
                log_info "Internal reference set manually: ${INTERNAL_SSID} (${INTERNAL_BSSID:-unknown BSSID})"
                export INTERNAL_SSID INTERNAL_BSSID
            fi
        fi
        save_session_state
    fi

    # Ask about captive portal (informational — test continues either way)
    local _prompt_cp=false
    if [[ -z "${CAPTIVE_PORTAL:-}" ]]; then
        _prompt_cp=true
    elif [[ "$_prompt_selection" == "true" ]]; then
        _prompt_cp=true
    fi

    if [[ "$_prompt_cp" == "true" ]]; then
        echo ""
        echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
        echo -e "${C_CYAN}│  CAPTIVE PORTAL CONTEXT                                         │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}│  Does the target WiFi (${GUEST_SSID:-N/A}) require a login      │${C_RESET}"
        echo -e "${C_CYAN}│  or splash page before granting internet access?                │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}│  Setting this to 'no' will automatically skip related           │${C_RESET}"
        echo -e "${C_CYAN}│  assessment modules (F3, F4) later in the audit.                │${C_RESET}"
        echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
        echo ""
        get_or_request_param "cp_answer" "  Does the target WiFi use a captive portal? [Y/n]"

        if [[ "${cp_answer,,}" == "n" ]]; then
            CAPTIVE_PORTAL="no"
            log_info "Captive portal: No"
            # Pre-save skipped status for F3 and F4 to update the menu
            save_tc_result "F3" '{"status":"INFO","summary":"Skipped: No portal present","details":"Inherited from A1 context."}' "clean_run:1"
            save_tc_result "F4" '{"status":"INFO","summary":"Skipped: No portal present","details":"Inherited from A1 context."}' "clean_run:1"
        else
            CAPTIVE_PORTAL="yes"
            log_info "Captive portal: Yes"
            # Reset F3 and F4 if they were previously skipped via engine API
            local f3_status=$(run_engine_api GET "/v1/status/get?tc=F3" || echo "not_run")
            if [[ "$f3_status" == "done" ]]; then
                run_engine_api POST "/v1/status/set?tc=F3&status=not_run" >/dev/null
                rm -f $(get_tc_result_file "F3") 2>/dev/null
            fi
            local f4_status=$(run_engine_api GET "/v1/status/get?tc=F4" || echo "not_run")
            if [[ "$f4_status" == "done" ]]; then
                run_engine_api POST "/v1/status/set?tc=F4&status=not_run" >/dev/null
                rm -f $(get_tc_result_file "F4") 2>/dev/null
            fi
        fi
        export CAPTIVE_PORTAL
        save_session_state
    fi

    # Determine result status
    local result_status="SECURE"
    local result_summary="${network_count} wireless networks discovered. ${hidden_count} hidden SSIDs."
    local result_details=""

    if [[ $open_networks -gt 0 ]]; then
        local result_status="FINDING"
        result_details+="FINDING: ${open_networks} open (unencrypted) network(s) detected.\n"
    fi

    if [[ $hidden_count -gt 0 ]]; then
        result_details+="INFO: ${hidden_count} hidden SSID(s) detected — investigate in A3.\n"
    fi

    # Count networks sharing OUI prefix (potential same infrastructure)
    local unique_ouis
    local unique_ouis=$(echo "$networks_json" | run_tool jq -r '.[].bssid' | cut -d: -f1-3 | sort | uniq -c | sort -rn | head -5)
    result_details+="\\nTop BSSID OUI prefixes (potential shared infrastructure):\\n${unique_ouis}\n"

    # Build result JSON
    local result_json
    evidence_register_file "$csv_file"
    evidence_register_file "$cap_file"
    evidence_register_file "$summary_file"

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "$(echo -e "$result_details")" \
        --arg target_ssid "${GUEST_SSID:-}" \
        --arg target_bssid "${GUEST_BSSID:-}" \
        --arg target_channel "${GUEST_CHANNEL:-}" \
        --arg internal_ssid "${INTERNAL_SSID:-}" \
        --arg internal_bssid "${INTERNAL_BSSID:-}" \
        --argjson networks "$networks_json" \
        --argjson network_count "$network_count" \
        --argjson hidden_count "$hidden_count" \
        --argjson open_count "${open_networks:-0}" \
        --arg target_found "$target_found" \
        --arg scan_duration "${AIRODUMP_SCAN_TIME}s" \
        --arg csv_file "$(basename "$csv_file")" \
        --arg cap_file "$(basename "${cap_file:-}")" \
        --arg summary_file "$(basename "$summary_file")" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            network_count: $network_count,
            hidden_count: $hidden_count,
            open_count: $open_count,
            target_ssid: $target_ssid,
            target_bssid: $target_bssid,
            target_channel: $target_channel,
            internal_ssid: $internal_ssid,
            internal_bssid: $internal_bssid,
            target_identified: ($target_found == "true"),
            scan_duration: $scan_duration,
            networks: $networks,
                        recommendations: (
                if $open_count > 0 then "Open networks detected. Ensure no corporate data traverses unencrypted WiFi."
                else "All networks use encryption."
                end
            )
        }')

    local has_tool_output=0
    [[ -n "$csv_file" && -f "$csv_file" ]] && has_tool_output=1

    local has_primary=0
    [[ -n "$cap_file" && -f "$cap_file" ]] && has_primary=1

    save_tc_result "A1" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0
    save_session_state

    # Display summary
    echo ""
    if [[ "$result_status" == "FINDING" ]]; then
        log_result "FINDING" "${open_networks} open (unencrypted) network(s) detected"
    else
        log_result "SECURE" "No open (unencrypted) networks detected"
    fi
    log_result "INFO" "${network_count} total networks found, ${hidden_count} hidden"
    log_result "INFO" "Target: ${GUEST_SSID} (${GUEST_BSSID}) on CH ${GUEST_CHANNEL}"
    if [[ -n "${INTERNAL_SSID:-}" ]]; then
        log_result "INFO" "Internal Reference: ${INTERNAL_SSID} (${INTERNAL_BSSID})"
    fi

    return 0
    }