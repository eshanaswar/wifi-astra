#!/usr/bin/env bash
#===============================================================================
#  lib/session.sh — Session Management
#  
#  Handles: Creating new sessions, detecting previous sessions,
#           saving/loading state, session resume
#===============================================================================

#--- Initialize a new session ---
init_new_session() {
    # Ask for a session name
    echo ""
    read -rep "  Enter a name for this session (or Enter for default): " session_name
    session_name=$(echo "$session_name" | tr -cs '[:alnum:]-_' '_' | sed 's/^_//;s/_$//')
    
    if [[ -n "$session_name" ]]; then
        SESSION_ID="${session_name}_$(date '+%Y%m%d_%H%M%S')"
    else
        SESSION_ID="session_$(date '+%Y%m%d_%H%M%S')"
    fi
    
    export SESSION_NAME="${session_name:-Unnamed}"
    SESSION_DIR="${EVIDENCE_BASE}/${SESSION_ID}"
    SESSION_STATE_FILE="${SESSION_DIR}/session.state"
    SESSION_LOG_DIR="${SESSION_DIR}/logs"
    SESSION_EVIDENCE_DIR="${SESSION_DIR}/evidence"
    SESSION_REPORT_DIR="${SESSION_DIR}/reports"
    SESSION_RESULTS_DIR="${SESSION_DIR}/results"
    
    # Create all directories
    mkdir -p "$SESSION_DIR" "$SESSION_LOG_DIR" "$SESSION_EVIDENCE_DIR" "$SESSION_REPORT_DIR" "$SESSION_RESULTS_DIR"
    mkdir -p "${SESSION_DIR}/.pids"
    
    # Initialize all TC statuses
    for _tc in "${TC_ORDER[@]}"; do
        TC_STATUS["$_tc"]="not_run"
    done
    
    # Save initial state
    save_session_state
    
    log_info "Session initialized: ${SESSION_ID}"
    log_info "Session directory: ${SESSION_DIR}"
}

#--- Detect previous sessions ---
detect_previous_session() {
    local sessions=()
    
    # Find session directories with state files
    while IFS= read -r -d '' state_file; do
        sessions+=("$(dirname "$state_file")")
    done < <(find "$EVIDENCE_BASE" -maxdepth 2 -name "session.state" -print0 2>/dev/null | sort -z -r)
    
    if [[ ${#sessions[@]} -eq 0 ]]; then
        echo "new"
        return
    fi
    
    # Show last 5 sessions (all UI goes to stderr so stdout is clean for return value)
    echo "" >&2
    echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}" >&2
    echo -e "${C_CYAN}│  ${ICON_INFO}  Previous sessions detected                                  │${C_RESET}" >&2
    echo -e "${C_CYAN}│                                                                 │${C_RESET}" >&2
    
    local count=0
    local max_show=5
    declare -a session_paths
    
    for session_dir in "${sessions[@]}"; do
        [[ $count -ge $max_show ]] && break
        
        local sid
        sid=$(basename "$session_dir")
        local state_file="${session_dir}/session.state"
        
        # Read session name and count completed TCs
        local done_count=0
        local total_count=0
        local sname=""
        if [[ -f "$state_file" ]]; then
            if ${TOOL_PATHS[jq]} -e . "$state_file" >/dev/null 2>&1; then
                total_count=$(${TOOL_PATHS[jq]} '.tc_status | length' "$state_file" 2>/dev/null || echo "0")
                done_count=$(${TOOL_PATHS[jq]} '[.tc_status[] | select(. == "done")] | length' "$state_file" 2>/dev/null || echo "0")
                sname=$(${TOOL_PATHS[jq]} -r '.session_name // ""' "$state_file" 2>/dev/null)
            else
                # Legacy fallback just in case
                while IFS='=' read -r key value; do
                    if [[ "$key" =~ ^[A-H][0-9]+$ ]]; then
                        ((total_count++))
                        if [[ "$value" == "done" ]]; then
                            ((done_count++))
                        fi
                    elif [[ "$key" == "SESSION_NAME" ]]; then
                        sname="$value"
                    fi
                done < "$state_file"
            fi
        fi
        
        local display_name="${sname:-$sid}"
        
        ((count++))
        session_paths+=("$session_dir")
        printf "${C_CYAN}│   [%d] %-30s  │  %d/%d tests  ${C_RESET}\n" "$count" "$display_name" "$done_count" "$total_count" >&2
    done
    
    echo -e "${C_CYAN}│                                                                 │${C_RESET}" >&2
    echo -e "${C_CYAN}│   [N] Start NEW session                                         │${C_RESET}" >&2
    echo -e "${C_CYAN}│   [D] Delete a session                                           │${C_RESET}" >&2
    echo -e "${C_CYAN}│                                                                 │${C_RESET}" >&2
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}" >&2
    echo "" >&2
    
    while true; do
        read -rep "  Select session [1-${count}, N, D]: " choice
        
        if [[ "${choice^^}" == "N" ]]; then
            echo "new"
            return
        fi
        
        if [[ "${choice^^}" == "D" ]]; then
            # Delete session sub-menu
            read -rep "  Enter session number to delete [1-${count}]: " del_num
            if [[ "$del_num" =~ ^[0-9]+$ ]] && [[ $del_num -ge 1 ]] && [[ $del_num -le $count ]]; then
                local del_idx=$((del_num - 1))
                local del_dir="${session_paths[$del_idx]}"
                local del_sid
                del_sid=$(basename "$del_dir")
                read -rep "  Delete session '${del_sid}' and all its data? [y/N]: " confirm_del
                if [[ "${confirm_del,,}" == "y" ]]; then
                    rm -rf "$del_dir"
                    echo -e "${C_GREEN}  Session deleted: ${del_sid}${C_RESET}" >&2
                fi
            fi
            # Re-run detection
            detect_previous_session
            return
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le $count ]]; then
            local idx=$((choice - 1))
            # Write the resume path to a temp file since we're in a $() subshell
            echo "${session_paths[$idx]}" > /tmp/.wifi_resume_path
            echo "resume"
            return
        fi
        
        echo -e "${C_RED}Invalid choice. Enter 1-${count}, N, or D.${C_RESET}" >&2
    done
}

#--- Load a previous session ---
# Uses _resume_session_path set by detect_previous_session
_resume_session_path=""

load_session() {
    # Read resume path from temp file (written by detect_previous_session in subshell)
    local session_dir="${_resume_session_path}"
    if [[ -z "$session_dir" ]] && [[ -f /tmp/.wifi_resume_path ]]; then
        session_dir=$(cat /tmp/.wifi_resume_path)
        rm -f /tmp/.wifi_resume_path
    fi
    
    if [[ -z "$session_dir" || ! -d "$session_dir" ]]; then
        log_error "Session directory not found: ${session_dir}"
        init_new_session
        return
    fi
    
    SESSION_ID=$(basename "$session_dir")
    SESSION_DIR="$session_dir"
    SESSION_STATE_FILE="${SESSION_DIR}/session.state"
    SESSION_LOG_DIR="${SESSION_DIR}/logs"
    SESSION_EVIDENCE_DIR="${SESSION_DIR}/evidence"
    SESSION_REPORT_DIR="${SESSION_DIR}/reports"
    SESSION_RESULTS_DIR="${SESSION_DIR}/results"
    
    # Ensure directories exist (in case of partial cleanup)
    mkdir -p "$SESSION_DIR" "$SESSION_LOG_DIR" "$SESSION_EVIDENCE_DIR" "$SESSION_REPORT_DIR" "$SESSION_RESULTS_DIR"
    
    # Null out variables to prevent bleed
    for _tc in "${TC_ORDER[@]}"; do
        TC_STATUS["$_tc"]="not_run"
    done
    
    if [[ ! -f "$SESSION_STATE_FILE" ]]; then
        return
    fi
    
    local state_json
    state_json=$(cat "$SESSION_STATE_FILE")
    
    # Check if it's JSON or legacy format
    if ! echo "$state_json" | ${TOOL_PATHS[jq]} . &>/dev/null; then
        log_warn "Legacy session state detected. Converting..."
        # Minimal legacy loader logic could go here if migration is critical
        return
    fi
    
    # Load TC Statuses
    for _tc in "${TC_ORDER[@]}"; do
        TC_STATUS["$_tc"]=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r ".tc_status[\"$_tc\"] // \"not_run\"")
    done
    
    # Load Config
    export SESSION_NAME=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.session_name // "Unnamed"')
    export WIFI_INTERFACE=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.wifi_interface // ""')
    export MONITOR_INTERFACE=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.monitor_interface // ""')
    export GUEST_SSID=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.guest_ssid // ""')
    export GUEST_BSSID=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.guest_bssid // ""')
    export GUEST_CHANNEL=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.guest_channel // ""')
    export INTERNAL_SSID=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.internal_ssid // ""')
    export INTERNAL_BSSID=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.internal_bssid // ""')
    export GATEWAY_IP=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.gateway_ip // ""')
    export MY_IP=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.my_ip // ""')
    export MY_MAC=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.my_mac // ""')
    export DNS_SERVER=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.dns_server // ""')
    export VPS_IP=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.vps_ip // ""')
    export VPS_DOMAIN=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.vps_domain // ""')
    export VPS_CONFIGURED=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.vps_configured // 0')
    export CAPTIVE_PORTAL=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.captive_portal // ""')
    export C2_SCOPE=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.c2_scope // ""')
    export PREFLIGHT_DONE=$(echo "$state_json" | ${TOOL_PATHS[jq]} -r '.config.preflight_done // 0')
    
    # Reset any stale 'running' status
    for _tc in "${TC_ORDER[@]}"; do
        if [[ "${TC_STATUS[$_tc]}" == "running" ]]; then
            TC_STATUS["$_tc"]="not_run"
        fi
    done
    
    local done_count=$(get_completed_count)
    local total=${#TC_ORDER[@]}
    log_success "Session loaded: ${SESSION_ID} (${done_count}/${total} completed)"
    
    if [[ -n "$GUEST_SSID" ]]; then
        log_info "Restored network config: SSID=${GUEST_SSID}, Gateway=${GATEWAY_IP:-unknown}"
    fi
}

#--- Save session state to disk (JSON) ---
save_session_state() {
    [[ -z "${SESSION_STATE_FILE:-}" ]] && return
    
    local state_json="{}"
    
    # Add TC Statuses
    local tc_status_obj="{}"
    for _tc in "${TC_ORDER[@]}"; do
        tc_status_obj=$(echo "$tc_status_obj" | ${TOOL_PATHS[jq]} --arg tc "$_tc" --arg st "${TC_STATUS[$_tc]:-not_run}" '.[$tc] = $st')
    done
    
    state_json=$(echo "$state_json" | ${TOOL_PATHS[jq]} \
        --argjson tc_status "$tc_status_obj" \
        --arg session_id "${SESSION_ID:-}" \
        --arg session_name "${SESSION_NAME:-}" \
        --arg wifi_iface "${WIFI_INTERFACE:-}" \
        --arg mon_iface "${MONITOR_INTERFACE:-}" \
        --arg g_ssid "${GUEST_SSID:-}" \
        --arg g_bssid "${GUEST_BSSID:-}" \
        --arg g_chan "${GUEST_CHANNEL:-}" \
        --arg i_ssid "${INTERNAL_SSID:-}" \
        --arg i_bssid "${INTERNAL_BSSID:-}" \
        --arg gw_ip "${GATEWAY_IP:-}" \
        --arg my_ip "${MY_IP:-}" \
        --arg my_mac "${MY_MAC:-}" \
        --arg dns "${DNS_SERVER:-}" \
        --arg v_ip "${VPS_IP:-}" \
        --arg v_dom "${VPS_DOMAIN:-}" \
        --argjson v_conf "${VPS_CONFIGURED:-0}" \
        --arg cp "${CAPTIVE_PORTAL:-}" \
        --arg c2 "${C2_SCOPE:-}" \
        --argjson preflight "${PREFLIGHT_DONE:-0}" \
        '. + {
            session_id: $session_id,
            session_name: $session_name,
            tc_status: $tc_status,
            config: {
                wifi_interface: $wifi_iface,
                monitor_interface: $mon_iface,
                guest_ssid: $g_ssid,
                guest_bssid: $g_bssid,
                guest_channel: $g_chan,
                internal_ssid: $i_ssid,
                internal_bssid: $i_bssid,
                gateway_ip: $gw_ip,
                my_ip: $my_ip,
                my_mac: $my_mac,
                dns_server: $dns,
                vps_ip: $v_ip,
                vps_domain: $v_dom,
                vps_configured: $v_conf,
                captive_portal: $cp,
                c2_scope: $c2,
                preflight_done: $preflight
            },
            updated_at: (now | strflocaltime("%Y-%m-%d %H:%M:%S"))
        }')
    
    echo "$state_json" > "$SESSION_STATE_FILE"
}

#--- Get completed TC count ---
get_completed_count() {
    local count=0
    for _tc in "${TC_ORDER[@]}"; do
        if [[ "${TC_STATUS[$_tc]}" == "done" ]]; then
            ((count++))
        fi
    done
    echo "$count"
}

#--- Get TC result file path ---
get_tc_result_file() {
    local tc_id="$1"
    echo "${SESSION_RESULTS_DIR}/${tc_id,,}_results.json"
}

#--- Save TC results as JSON ---
save_tc_result() {
    local tc_id="$1"
    local json_data="$2"
    local result_file
    result_file=$(get_tc_result_file "$tc_id")
    
    echo "$json_data" > "$result_file"
    TC_RESULTS_FILE["$tc_id"]="$result_file"
    _log_to_file "RESULT-SAVE" "Saved results for ${tc_id} to ${result_file}"
}

#--- Enrich a TC result file with standard metadata/evidence/confidence ---
enrich_tc_result_file() {
    local tc_id="$1"
    local exit_code="${2:-0}"
    local started_at_iso="${3:-}"
    local ended_at_iso="${4:-}"
    local duration_sec="${5:-0}"

    local result_file
    result_file=$(get_tc_result_file "$tc_id")
    [[ -f "$result_file" ]] || return 0
    command -v jq &>/dev/null || return 0

    local evidence_json="[]"
    if declare -f evidence_list_json_array &>/dev/null; then
        evidence_json=$(evidence_list_json_array)
    fi

    local confidence="${TC_CONFIDENCE:-}"
    local tc_name category
    tc_name=$(get_tc_field "$tc_id" "name" 2>/dev/null || echo "")
    category=$(get_tc_field "$tc_id" "category" 2>/dev/null || echo "")

    ${TOOL_PATHS[jq]} \
      --arg tc_id "$tc_id" \
      --arg name "$tc_name" \
      --arg category "$category" \
      --arg started_at "$started_at_iso" \
      --arg ended_at "$ended_at_iso" \
      --argjson duration_sec "${duration_sec:-0}" \
      --argjson exit_code "${exit_code:-0}" \
      --arg wifi_iface "${WIFI_INTERFACE:-}" \
      --arg mon_iface "${MONITOR_INTERFACE:-}" \
      --arg my_ip "${MY_IP:-}" \
      --arg gw "${GATEWAY_IP:-}" \
      --arg dns "${DNS_SERVER:-}" \
      --arg conf "$confidence" \
      --argjson ev "$evidence_json" \
      '.
       + {tc_id: $tc_id}
       + (if ($name|length)>0 then {name:$name} else {} end)
       + (if ($category|length)>0 then {category:$category} else {} end)
       + (if ($started_at|length)>0 then {started_at:$started_at} else {} end)
       + (if ($ended_at|length)>0 then {ended_at:$ended_at} else {} end)
       + {duration_sec:$duration_sec, exit_code:$exit_code}
       + {environment: {
            wifi_interface: $wifi_iface,
            monitor_interface: $mon_iface,
            my_ip: $my_ip,
            gateway_ip: $gw,
            dns_server: $dns
         } | with_entries(select(.value | length > 0))}
       + (if ($conf|length)>0 then {confidence:$conf} else {} end)
       + (if (.evidence_files? and (.evidence_files|type) == "array") then {evidence_files:(.evidence_files + $ev | unique)} else {evidence_files:$ev} end)' "$result_file" >"${result_file}.tmp" && mv "${result_file}.tmp" "$result_file"

       # Ensure all evidence files generated in this TC have correct permissions
       finalize_evidence_permissions
       }

#--- Check if TC has results ---
has_tc_results() {
    local tc_id="$1"
    local result_file
    result_file=$(get_tc_result_file "$tc_id")
    [[ -f "$result_file" ]] && return 0
    return 1
}

#--- Load TC results ---
load_tc_result() {
    local tc_id="$1"
    local result_file
    result_file=$(get_tc_result_file "$tc_id")
    
    if [[ -f "$result_file" ]]; then
        local data=$(cat "$result_file")
        if validate_json "$data"; then
            echo "$data"
        else
            echo "{}"
        fi
    else
        echo "{}"
    fi
}

#--- Select target network from A1 results ---
# Returns 0 on success, 1 if no data or cancelled.
# Sets GUEST_SSID, GUEST_BSSID, GUEST_CHANNEL if successful.
select_target_network() {
    if ! has_tc_results "A1"; then
        log_warn "A1 (Network Identification) results not found. Run A1 first to use this feature."
        return 1
    fi

    local a1_data
    a1_data=$(load_tc_result "A1")
    local network_count
    network_count=$(echo "$a1_data" | ${TOOL_PATHS[jq]} '.networks | length' 2>/dev/null || echo "0")

    if [[ "$network_count" -eq 0 ]]; then
        log_warn "A1 results contain no networks. Run A1 again."
        return 1
    fi

    echo ""
    echo -e "${C_CYAN}┌── SELECT TARGET NETWORK ────────────────────────────────────────┐${C_RESET}"
    echo -e "  ${C_BOLD}Available networks from A1 scan:${C_RESET}"
    echo ""

    local -a bssid_list=()
    local -a ssid_list=()
    local -a chan_list=()
    
    # Extract networks and present a clean list
    local i=0
    while IFS=$'\t' read -r ssid bssid channel encryption signal; do
        ((i++))
        local display_ssid="$ssid"
        [[ "$ssid" == "<HIDDEN>" ]] && display_ssid="${C_YELLOW}<HIDDEN>${C_RESET}"
        printf "    [${C_BOLD}%2d${C_RESET}]  %-30s  %-18s  CH %-3s  %-8s\n" "$i" "$display_ssid" "$bssid" "$channel" "$signal"
        ssid_list+=("$ssid")
        bssid_list+=("$bssid")
        chan_list+=("$channel")
    done < <(echo "$a1_data" | ${TOOL_PATHS[jq]} -r '.networks[] | "\(.ssid)\t\(.bssid)\t\(.channel)\t\(.encryption)\t\(.signal)"')

    echo ""
    echo -e "    [${C_BOLD} M${C_RESET}]  Manual Entry"
    echo -e "    [${C_BOLD} Q${C_RESET}]  Cancel"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""

    local choice
    read -rep "  Selection: " choice

    if [[ "${choice,,}" == "q" ]]; then
        return 1
    fi

    if [[ "${choice,,}" == "m" ]]; then
        read -rep "  Enter SSID: " GUEST_SSID
        read -rep "  Enter BSSID (optional): " GUEST_BSSID
        read -rep "  Enter Channel (optional): " GUEST_CHANNEL
        export GUEST_SSID GUEST_BSSID GUEST_CHANNEL
        save_session_state
        return 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#ssid_list[@]} ]]; then
        local idx=$((choice - 1))
        GUEST_SSID="${ssid_list[$idx]}"
        GUEST_BSSID="${bssid_list[$idx]}"
        GUEST_CHANNEL="${chan_list[$idx]}"
        
        # Clean up <HIDDEN> SSIDs
        if [[ "$GUEST_SSID" == "<HIDDEN>" ]]; then
            log_warn "Target SSID is hidden. Attempting to use BSSID: ${GUEST_BSSID}"
            read -rep "  Do you know the real SSID? (optional): " real_ssid
            [[ -n "$real_ssid" ]] && GUEST_SSID="$real_ssid"
        fi

        export GUEST_SSID GUEST_BSSID GUEST_CHANNEL
        log_success "Target set: ${GUEST_SSID} (${GUEST_BSSID}) CH ${GUEST_CHANNEL}"
        save_session_state
        return 0
    fi

    log_error "Invalid selection."
    return 1
}

#--- Manage Sessions (List / Load / Delete / New) ---
manage_sessions() {
    while true; do
        echo ""
        echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_CYAN}║  SESSION MANAGER                                                ║${C_RESET}"
        echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""

        # Discover all sessions
        local -a session_dirs=()
        while IFS= read -r -d '' state_file; do
            session_dirs+=("$(dirname "$state_file")")
        done < <(find "$EVIDENCE_BASE" -maxdepth 2 -name "session.state" -print0 2>/dev/null | sort -z -r)

        if [[ ${#session_dirs[@]} -eq 0 ]]; then
            echo -e "  ${C_GRAY}No saved sessions found.${C_RESET}"
        else
            printf "  ${C_BOLD}%-4s %-30s %-12s %-20s${C_RESET}\n" "#" "SESSION ID" "PROGRESS" "DATE"
            echo -e "  ${C_GRAY}$(printf '─%.0s' {1..66})${C_RESET}"

            local idx=1
            for session_dir in "${session_dirs[@]}"; do
                local sid
                sid=$(basename "$session_dir")
                local state_file="${session_dir}/session.state"
                local done_count=0 total_count=0
                local sname=""

                if [[ -f "$state_file" ]]; then
                    if ${TOOL_PATHS[jq]} -e . "$state_file" >/dev/null 2>&1; then
                        total_count=$(${TOOL_PATHS[jq]} '.tc_status | length' "$state_file" 2>/dev/null || echo "0")
                        done_count=$(${TOOL_PATHS[jq]} '[.tc_status[] | select(. == "done")] | length' "$state_file" 2>/dev/null || echo "0")
                        sname=$(${TOOL_PATHS[jq]} -r '.session_name // ""' "$state_file" 2>/dev/null)
                    else
                        while IFS='=' read -r key value; do
                            if [[ "$key" =~ ^[A-H][0-9]+$ ]]; then
                                ((total_count++))
                                [[ "$value" == "done" ]] && ((done_count++))
                            fi
                        done < "$state_file"
                    fi
                fi

                local session_date
                session_date=$(echo "$sid" | sed 's/session_//' | sed 's/_/ /' | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3/' | sed 's/ \([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/ \1:\2:\3/')

                local marker=""
                [[ "$sid" == "$SESSION_ID" ]] && marker=" ${C_GREEN}◀ current${C_RESET}"

                printf "  [${C_BOLD}%2d${C_RESET}]  %-30s %d/%-10d %s%s\n" "$idx" "$sid" "$done_count" "$total_count" "$session_date" "$marker"
                ((idx++))
            done
        fi

        echo ""
        echo -e "  ${C_BOLD}Actions:${C_RESET}"
        echo -e "    [${C_BOLD}L${C_RESET}] Load a session        [${C_BOLD}D${C_RESET}] Delete a session"
        echo -e "    [${C_BOLD}N${C_RESET}] Create new session    [${C_BOLD}B${C_RESET}] Back to main menu"
        echo ""

        local action
        read -rep "  Select action [L/D/N/B]: " action

        case "${action^^}" in
            "L")
                if [[ ${#session_dirs[@]} -eq 0 ]]; then
                    log_warn "No sessions to load."
                    continue
                fi
                read -rep "  Enter session number to load: " load_num
                if [[ "$load_num" =~ ^[0-9]+$ ]] && [[ $load_num -ge 1 ]] && [[ $load_num -le ${#session_dirs[@]} ]]; then
                    local target_dir="${session_dirs[$((load_num - 1))]}"
                    local target_sid
                    target_sid=$(basename "$target_dir")

                    if [[ "$target_sid" == "$SESSION_ID" ]]; then
                        log_info "That is already the current session."
                        continue
                    fi

                    # Save current session before switching
                    save_session_state

                    # Clear environment to prevent bleed
                    _resume_session_path="$target_dir"
                    load_session
                    log_success "Switched to session: ${SESSION_ID}"
                    return 0
                else
                    log_error "Invalid selection."
                fi
                ;;
            "D")
                if [[ ${#session_dirs[@]} -eq 0 ]]; then
                    log_warn "No sessions to delete."
                    continue
                fi
                read -rep "  Enter session number to delete: " del_num
                if [[ "$del_num" =~ ^[0-9]+$ ]] && [[ $del_num -ge 1 ]] && [[ $del_num -le ${#session_dirs[@]} ]]; then
                    local del_dir="${session_dirs[$((del_num - 1))]}"
                    local del_sid
                    del_sid=$(basename "$del_dir")

                    if [[ "$del_sid" == "$SESSION_ID" ]]; then
                        log_error "Cannot delete the currently active session."
                        continue
                    fi

                    read -rep "  Delete session ${del_sid} and all its data? [y/N]: " confirm
                    if [[ "${confirm,,}" == "y" ]]; then
                        rm -rf "$del_dir"
                        log_success "Session ${del_sid} deleted."
                    else
                        log_info "Deletion cancelled."
                    fi
                else
                    log_error "Invalid selection."
                fi
                ;;
            "N")
                save_session_state
                init_new_session
                log_success "Created and switched to new session: ${SESSION_ID}"
                return 0
                ;;
            "B")
                return 0
                ;;
            *)
                log_error "Invalid action. Enter L, D, N, or B."
                ;;
        esac
    done
}

#--- JSON Validation Helper ---
# Validates if a string is a valid JSON object or array.
# Usage: validate_json "$string" || return 1
validate_json() {
    local json_str="$1"
    [[ -z "$json_str" ]] && return 1
    if echo "$json_str" | ${TOOL_PATHS[jq]} -e . >/dev/null 2>&1; then
        return 0
    else
        log_error "Invalid JSON detected."
        return 1
    fi
}