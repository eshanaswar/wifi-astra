#!/usr/bin/env bash
#===============================================================================
#  lib/session.sh — Session Management
#  
#  Handles: Creating new sessions, detecting previous sessions,
#           saving/loading state, session resume
#===============================================================================

set -uo pipefail

#--- Initialize a new session ---
init_new_session() {
    # Ask for a session name
    echo ""
    safe_read "Enter a name for this session (or Enter for default): " session_name
    session_name=$(echo "$session_name" | tr -cs '[:alnum:]-_' '_' | sed 's/^_//;s/_$//')
    
    if [[ -n "$session_name" ]]; then
        SESSION_ID="${session_name}_$(date '+%Y%m%d_%H%M%S')"
    else
        SESSION_ID="session_$(date '+%Y%m%d_%H%M%S')"
    fi
    
    export SESSION_NAME="${session_name:-Unnamed}"
    SESSION_DIR="${EVIDENCE_BASE}/${SESSION_ID}"
    SESSION_STATE_FILE="${SESSION_DIR}/session.state" # Keep for compatibility/migration if needed
    SESSION_DB_FILE="${SESSION_DIR}/session.db"
    SESSION_LOG_DIR="${SESSION_DIR}/logs"
    SESSION_EVIDENCE_DIR="${SESSION_DIR}/evidence"
    SESSION_REPORT_DIR="${SESSION_DIR}/reports"
    SESSION_RESULTS_DIR="${SESSION_DIR}/results"
    
    # Create all directories
    mkdir -p "$SESSION_DIR" "$SESSION_LOG_DIR" "$SESSION_EVIDENCE_DIR" "$SESSION_REPORT_DIR" "$SESSION_RESULTS_DIR"
    mkdir -p "${SESSION_DIR}/.pids"
    
    # Initialize SQLite database via Go engine
    log_info "Initializing session database..."
    ./astra-engine --db "$SESSION_DB_FILE" state set-config --key "session_id" --value "$SESSION_ID"
    ./astra-engine --db "$SESSION_DB_FILE" state set-config --key "session_name" --value "$SESSION_NAME"
    ./astra-engine --db "$SESSION_DB_FILE" state set-config --key "created_at" --value "$(date -Iseconds)"

    # Initialize all TC statuses in DB
    for _tc in "${TC_ORDER[@]}"; do
        TC_STATUS["$_tc"]="not_run"
        ./astra-engine --db "$SESSION_DB_FILE" state update-status --tc "$_tc" --status "not_run"
    done
    
    # Save initial state (also updates DB)
    save_session_state
    
    # Ensure all session directories have correct permissions
    if declare -f finalize_evidence_permissions &>/dev/null; then
        finalize_evidence_permissions
    fi

    log_info "Session initialized: ${SESSION_ID}"
    log_info "Session directory: ${SESSION_DIR}"
}

#--- Detect previous sessions ---
detect_previous_session() {
    local sessions=()
    
    # Find session directories with database files
    while IFS= read -r -d '' db_file; do
        sessions+=("$(dirname "$db_file")")
    done < <(find "$EVIDENCE_BASE" -maxdepth 2 -name "session.db" -print0 2>/dev/null | sort -z -r)
    
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
        local db_file="${session_dir}/session.db"
        
        # Read session name and count completed TCs from SQLite via Go Engine
        local done_count=0
        local total_count=${#TC_ORDER[@]}
        local sname=""
        
        if [[ -f "$db_file" ]]; then
            sname=$(./astra-engine --db "$db_file" state get-config --key "session_name" 2>/dev/null)
            # Count statuses that are 'done'
            # For simplicity in this shell loop, we'll just use astra-engine to get all statuses and count
            done_count=$(./astra-engine --db "$db_file" state get-dashboard | grep -c ":done" || echo "0")
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
        safe_read "Select session [1-${count}, N, D]: " choice
        
        if [[ "${choice^^}" == "N" ]]; then
            echo "new"
            return
        fi
        
        if [[ "${choice^^}" == "D" ]]; then
            safe_read "Enter session number to delete [1-${count}]: " del_num
            if [[ "$del_num" =~ ^[0-9]+$ ]] && [[ $del_num -ge 1 ]] && [[ $del_num -le $count ]]; then
                local del_idx=$((del_num - 1))
                local del_dir="${session_paths[$del_idx]}"
                local del_sid
                del_sid=$(basename "$del_dir")
                safe_read "Delete session '${del_sid}' and all its data? [y/N]: " confirm_del
                if [[ "${confirm_del,,}" == "y" ]]; then
                    # Safety check: Ensure we are only deleting within SESSION_BASE_DIR
                    if [[ -n "$del_dir" && "$del_dir" == "$SESSION_BASE_DIR"/* ]]; then
                        rm -rf "$del_dir"
                        echo -e "${C_GREEN}  Session deleted: ${del_sid}${C_RESET}" >&2
                    else
                        log_error "Safety abort: Attempted to delete invalid path: $del_dir"
                    fi
                fi
            fi
            # Re-run detection
            detect_previous_session
            return
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le $count ]]; then
            local idx=$((choice - 1))
            # Write the resume path to a temp file since we're in a $() subshell
            echo "${session_paths[$idx]}" > $TMP_DIR/.wifi_resume_path
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
    if [[ -z "$session_dir" ]] && [[ -f $TMP_DIR/.wifi_resume_path ]]; then
        session_dir=$(cat $TMP_DIR/.wifi_resume_path)
        rm -f $TMP_DIR/.wifi_resume_path
    fi
    
    if [[ -z "$session_dir" || ! -d "$session_dir" ]]; then
        log_error "Session directory not found: ${session_dir}. Falling back to new session initialization."
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
    
    # --- PRIMARY: Load from SQLite via Go Engine ---
    if [[ -n "${SESSION_DB_FILE:-}" && -f "$SESSION_DB_FILE" ]]; then
        log_info "Loading state from database..."
        
        # Load TC Statuses
        for _tc in "${TC_ORDER[@]}"; do
            TC_STATUS["$_tc"]=$(./astra-engine --db "$SESSION_DB_FILE" state get-status --tc "$_tc" 2>/dev/null || echo "not_run")
        done
        
        # Load Config variables
        for var_name in "${SESSION_VARS[@]}"; do
            local key=$(echo "$var_name" | tr '[:upper:]' '[:lower:]')
            local val=$(./astra-engine --db "$SESSION_DB_FILE" state get-config --key "$key" 2>/dev/null)
            
            # Handle default values
            if [[ "$var_name" == "SESSION_NAME" && -z "$val" ]]; then
                val="Unnamed"
            elif [[ "$var_name" == "VPS_CONFIGURED" || "$var_name" == "PREFLIGHT_DONE" ]]; then
                [[ -z "$val" ]] && val=0
            fi
            
            export "$var_name"="$val"
        done
    else
        # --- SECONDARY: Fallback to JSON (Migration/Legacy) ---
        log_warn "Session database missing. Falling back to JSON state..."
        
        if [[ ! -f "$SESSION_STATE_FILE" ]] || ! validate_json "$(cat "$SESSION_STATE_FILE" 2>/dev/null || echo "")"; then
            local is_corrupt=false
            [[ -f "$SESSION_STATE_FILE" ]] && is_corrupt=true
            
            if [[ -f "${SESSION_STATE_FILE}.bak" ]] && validate_json "$(cat "${SESSION_STATE_FILE}.bak" 2>/dev/null || echo "")"; then
                log_warn "Session state file missing or corrupt for ${SESSION_ID}, but valid backup exists."
                safe_read "Session state is corrupt. Recover from backup? [y/N]: " recover
                if [[ "${recover,,}" == "y" ]]; then
                    cp "${SESSION_STATE_FILE}.bak" "$SESSION_STATE_FILE"
                    log_success "Restored session state from backup."
                else
                    log_warn "Initializing empty state for ${SESSION_ID}."
                    state_json="{}"
                    echo "$state_json" > "$SESSION_STATE_FILE"
                fi
            else
                if [[ "$is_corrupt" == "true" ]]; then
                    log_error "Session state is corrupt or invalid JSON and no backup exists."
                    return 1
                else
                    log_warn "Session state file missing. Initializing fresh state."
                    state_json="{}"
                    echo "$state_json" > "$SESSION_STATE_FILE"
                fi
            fi
        fi
        
        if [[ -z "${state_json:-}" ]]; then
            state_json=$(cat "$SESSION_STATE_FILE" 2>/dev/null || echo "{}")
        fi
        
        if validate_json "$state_json"; then
            for _tc in "${TC_ORDER[@]}"; do
                TC_STATUS["$_tc"]=$(echo "$state_json" | run_tool jq -r ".tc_status[\"$_tc\"] // \"not_run\"")
            done
            for var_name in "${SESSION_VARS[@]}"; do
                local key=$(echo "$var_name" | tr '[:upper:]' '[:lower:]')
                local val=$(echo "$state_json" | run_tool jq -r ".config[\"$key\"] // .[\"$key\"] // \"\"")
                
                # Handle default values
                if [[ "$var_name" == "SESSION_NAME" && -z "$val" ]]; then
                    val="Unnamed"
                elif [[ "$var_name" == "VPS_CONFIGURED" || "$var_name" == "PREFLIGHT_DONE" ]]; then
                    [[ -z "$val" ]] && val=0
                fi
                
                export "$var_name"="$val"
            done
        fi
    fi
    
    # Reset any stale 'running' status
    for _tc in "${TC_ORDER[@]}"; do
        if [[ "${TC_STATUS[$_tc]}" == "running" ]]; then
            TC_STATUS["$_tc"]="not_run"
        fi
    done
    
    local done_count
    done_count=$(get_completed_count)
    local total=${#TC_ORDER[@]}
    log_success "Session loaded: ${SESSION_ID} (${done_count}/${total} completed)"
    
    if [[ -n "${GUEST_SSID:-}" ]]; then
        log_info "Restored network config: SSID=${GUEST_SSID}, Gateway=${GATEWAY_IP:-unknown}"
    fi
}

#--- Save session state to disk (SQLite + JSON fallback) ---
save_session_state() {
    [[ -z "${SESSION_STATE_FILE:-}" ]] && return
    
    # 1. Prepare data for batch update
    local config_map="{}"
    for var_name in "${SESSION_VARS[@]}"; do
        local val="${!var_name:-}"
        # Apply defaults if empty
        if [[ "$var_name" == "SESSION_NAME" && -z "$val" ]]; then val="Unnamed"; fi
        if [[ "$var_name" == "VPS_CONFIGURED" || "$var_name" == "PREFLIGHT_DONE" ]]; then
            [[ -z "$val" ]] && val=0
        fi
        local key=$(echo "$var_name" | tr '[:upper:]' '[:lower:]')
        config_map=$(echo "$config_map" | run_tool jq --arg k "$key" --arg v "$val" '.[$k] = $v')
    done
    
    local status_map="{}"
    for _tc in "${TC_ORDER[@]}"; do
        status_map=$(echo "$status_map" | run_tool jq --arg tc "$_tc" --arg st "${TC_STATUS[$_tc]:-not_run}" '.[$tc] = $st')
    done
    
    # 2. Sync to SQLite via Go Engine
    if [[ -n "${SESSION_DB_FILE:-}" && -f "${TOOL_PATHS[astra-engine]}" ]]; then
        run_tool astra-engine --db "$SESSION_DB_FILE" state batch-set-config --json "$config_map" >/dev/null 2>&1
        run_tool astra-engine --db "$SESSION_DB_FILE" state batch-update-status --json "$status_map" >/dev/null 2>&1
        run_tool astra-engine --db "$SESSION_DB_FILE" state set-config --key "updated_at" --value "$(date '+%Y-%m-%d %H:%M:%S')" >/dev/null 2>&1
    fi

    # 3. JSON Fallback (for existing report generator logic)
    local state_json
    state_json=$(run_tool jq -n \
        --arg session_id "${SESSION_ID:-}" \
        --argjson tc_status "$status_map" \
        --argjson config "$config_map" \
        '{
            session_id: $session_id,
            tc_status: $tc_status,
            config: $config,
            updated_at: (now | strflocaltime("%Y-%m-%d %H:%M:%S"))
        }')
    
    # Atomic write
    if echo "$state_json" > "${SESSION_STATE_FILE}.tmp"; then
        if validate_json "$(cat "${SESSION_STATE_FILE}.tmp")"; then
            if [[ -f "$SESSION_STATE_FILE" ]]; then
                cp "$SESSION_STATE_FILE" "${SESSION_STATE_FILE}.bak"
            fi
            mv "${SESSION_STATE_FILE}.tmp" "$SESSION_STATE_FILE"
        else
            log_error "Generated state JSON is invalid. Not saving."
            rm -f "${SESSION_STATE_FILE}.tmp"
        fi
    fi
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
    shift 2 || true
    
    local result_file
    result_file=$(get_tc_result_file "$tc_id")
    
    # 1. Resolve Confidence
    local confidence_obj="{\"label\": \"LOW\", \"score\": 0}"
    if [[ $# -gt 0 ]]; then
        local flags_array=()
        local raw_input="$*"
        # Standardize: replace commas with spaces
        raw_input="${raw_input//,/ }"
        
        for part in $raw_input; do
            if [[ "$part" == *:* ]]; then
                # Extract value after colon: "key:1" -> "1"
                flags_array+=("${part#*:}")
            else
                flags_array+=("$part")
            fi
        done
        
        if declare -f confidence_from_flags &>/dev/null; then
            local conf_res
            conf_res=$(confidence_from_flags "${flags_array[@]}")
            local score="${conf_res%|*}"
            local label="${conf_res#*|}"
            confidence_obj="{\"label\": \"$label\", \"score\": $score}"
            export TC_CONFIDENCE="$confidence_obj"
        fi
    fi

    # 2. Build/Repair the JSON object to meet schema
    # We do this FIRST to avoid the "Repairing" warning for standard flows
    if ! validate_json "$json_data"; then
        json_data="{}"
    fi

    # Extract or default required fields
    local status=$(echo "$json_data" | run_tool jq -r '.status // "INFO"')
    [[ "$status" == "null" ]] && status="INFO"
    
    # Assemble finalized JSON
    local finalized_json
    finalized_json=$(echo "$json_data" | run_tool jq \
        --arg s "$status" \
        --argjson c "$confidence_obj" \
        '.status = ($s | ascii_upcase) |
         .summary |= (. // "Assessment completed.") |
         .details |= (. // "No additional details provided.") |
         .confidence = $c |
         .recommendations |= (. // "No specific recommendations.") |
         if (.evidence_files | type != "array") then .evidence_files = [] else . end')

    # 3. Final Validation (Silent unless truly broken)
    if ! validate_tc_result "$finalized_json"; then
        log_debug "Final JSON for ${tc_id} failed schema validation. Check lib/session.sh logic."
    fi
    
    echo "$finalized_json" > "$result_file"
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

    run_tool jq \
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
       + (if ($conf|length)>0 then 
            if ($conf == "HIGH") then {confidence: {label: "HIGH", score: 90}}
            elif ($conf == "MEDIUM") then {confidence: {label: "MEDIUM", score: 50}}
            elif ($conf == "LOW") then {confidence: {label: "LOW", score: 20}}
            elif ($conf | startswith("{")) then {confidence: ($conf | fromjson)}
            else {confidence: {label: "LOW", score: 0}}
            end
          else {} end)
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
        local data
        data=$(cat "$result_file")
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
    network_count=$(echo "$a1_data" | run_tool jq '.networks | length' 2>/dev/null || echo "0")

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
    done < <(echo "$a1_data" | run_tool jq -r '.networks[] | "\(.ssid)\t\(.bssid)\t\(.channel)\t\(.encryption)\t\(.signal)"')

    echo ""
    echo -e "    [${C_BOLD} M${C_RESET}]  Manual Entry"
    echo -e "    [${C_BOLD} Q${C_RESET}]  Cancel"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""

    local choice
    safe_read "Selection: " choice

    if [[ "${choice,,}" == "q" ]]; then
        return 1
    fi

    if [[ "${choice,,}" == "m" ]]; then
        safe_read "Enter SSID: " GUEST_SSID
        safe_read "Enter BSSID (optional): " GUEST_BSSID
        safe_read "Enter Channel (optional): " GUEST_CHANNEL
        export GUEST_SSID GUEST_BSSID GUEST_CHANNEL
        save_session_state
        return 0
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#ssid_list[@]} ]]; then
        local idx=$((choice - 1))
        GUEST_SSID="${ssid_list[$idx]}"
        GUEST_BSSID="${bssid_list[$idx]}"
        GUEST_CHANNEL="${chan_list[$idx]}"
        
        if [[ "$GUEST_SSID" == "<HIDDEN>" ]]; then
            log_warn "Target SSID is hidden. Attempting to use BSSID: ${GUEST_BSSID}"
            safe_read "Do you know the real SSID? (optional): " real_ssid
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
        while IFS= read -r -d '' db_file; do
            session_dirs+=("$(dirname "$db_file")")
        done < <(find "$EVIDENCE_BASE" -maxdepth 2 -name "session.db" -print0 2>/dev/null | sort -z -r)

        if [[ ${#session_dirs[@]} -eq 0 ]]; then
            echo -e "  ${C_GRAY}No saved sessions found.${C_RESET}"
        else
            printf "  ${C_BOLD}%-4s %-30s %-12s %-20s${C_RESET}\n" "#" "SESSION ID" "PROGRESS" "DATE"
            echo -e "  ${C_GRAY}$(printf '─%.0s' {1..66})${C_RESET}"

            local idx=1
            for session_dir in "${session_dirs[@]}"; do
                local sid
                sid=$(basename "$session_dir")
                local db_file="${session_dir}/session.db"
                local done_count=0 total_count=${#TC_ORDER[@]}
                local sname=""

                if [[ -f "$db_file" ]]; then
                    sname=$(./astra-engine --db "$db_file" state get-config --key "session_name" 2>/dev/null)
                    done_count=$(./astra-engine --db "$db_file" state get-dashboard | grep -c ":done" || echo "0")
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
        safe_read "Select action [L/D/N/B]: " action

        case "${action^^}" in
            "L")
                if [[ ${#session_dirs[@]} -eq 0 ]]; then
                    log_warn "No sessions to load."
                    continue
                fi
                safe_read "Enter session number to load: " load_num
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
                safe_read "Enter session number to delete: " del_num
                if [[ "$del_num" =~ ^[0-9]+$ ]] && [[ $del_num -ge 1 ]] && [[ $del_num -le ${#session_dirs[@]} ]]; then
                    local del_dir="${session_dirs[$((del_num - 1))]}"
                    local del_sid
                    del_sid=$(basename "$del_dir")

                    if [[ "$del_sid" == "$SESSION_ID" ]]; then
                        log_error "Cannot delete the currently active session."
                        continue
                    fi

                    safe_read "Delete session ${del_sid} and all its data? [y/N]: " confirm
                    if [[ "${confirm,,}" == "y" ]]; then
                        # Safety check: Ensure we are only deleting within SESSION_BASE_DIR
                        if [[ -n "$del_dir" && "$del_dir" == "$SESSION_BASE_DIR"/* ]]; then
                            rm -rf "$del_dir"
                            log_success "Session ${del_sid} deleted."
                        else
                            log_error "Safety abort: Attempted to delete invalid path: $del_dir"
                        fi
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
    
    # Use run_tool jq for safer execution
    if echo "$json_str" | run_tool jq -e . >/dev/null 2>&1; then
        return 0
    else
        log_error "Invalid JSON detected."
        return 1
    fi
}

#--- TC Result Validation ---
# Validates if a JSON string follows the unified result schema.
# Usage: validate_tc_result "$json_str" || return 1
validate_tc_result() {
    local json_str="$1"
    
    # Must be valid JSON
    validate_json "$json_str" || return 1
    
    # Combined JQ call for all validations
    echo "$json_str" | run_tool jq -e '
        . as $in |
        all(("status", "summary", "details", "confidence", "evidence_files", "recommendations"); . as $f | $in | has($f)) and
        ($in.status | ascii_upcase | . == "CRITICAL" or . == "FINDING" or . == "SECURE" or . == "INFO" or . == "FAIL") and
        ($in.evidence_files | type == "array") and
        ($in.confidence | type == "object") and
        ($in.confidence | has("label") and has("score"))
    ' >/dev/null 2>&1
}