#!/usr/bin/env bash
#===============================================================================
#  lib/menu.sh — Text User Interface & Menu System
#===============================================================================

main_menu_loop() {
    while true; do
        render_menu
        
        local choice
        read -rep "  Select module [A1-H1, ALL, R, M, S, P, V, W, Q]: " choice
        
        handle_menu_choice "$choice"
    done
}

#--- Render the full menu ---
render_menu() {
    clear
    
    local completed
    completed=$(get_completed_count)
    local total=${#TC_ORDER[@]}
    
    echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_BOLD}WiFi-Astra${C_RESET} ${C_DIM}v${TOOLKIT_VERSION}${C_RESET} ${C_CYAN}— Wireless Security Assessment Framework${C_RESET}"
    echo -e "  Session: ${C_WHITE}${SESSION_ID}${C_RESET} │ Progress: ${C_WHITE}${completed}/${total}${C_RESET} │ ${C_DIM}Ctrl+\\ Abort${C_RESET}"
    echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════════════${C_RESET}"
    
    local current_cat=""
    
    for _tc in "${TC_ORDER[@]}"; do
        local cat
        cat=$(get_tc_field "$_tc" "category")
        local tc_name
        tc_name=$(get_tc_field "$_tc" "name")
        local tc_status="${TC_STATUS[$_tc]:-not_run}"
        local deps
        deps=$(get_tc_field "$_tc" "deps")
        local is_critical
        is_critical=$(get_tc_field "$_tc" "critical")
        
        # Category header
        if [[ "$cat" != "$current_cat" ]]; then
            current_cat="$cat"
            local cat_label="${CATEGORY_LABELS[$cat]:-UNKNOWN}"
            echo ""
            echo -e "  ${C_WHITE}${C_BOLD}${cat_label}${C_RESET}"
            echo -e "  ${C_GRAY}$(printf '─%.0s' {1..76})${C_RESET}"
        fi
        
        # Status icon
        local icon="${ICON_PENDING}"
        local color="${C_GRAY}"
        local ready_to_run=false
        
        case "$tc_status" in
            "done")    icon="${ICON_DONE}"    ; color="${C_GREEN}" ;;
            "failed")  icon="${ICON_FAIL}"    ; color="${C_RED}"   ;;
            "aborted") icon="${ICON_WARN}"    ; color="${C_YELLOW}" ;;
            "running") icon="${ICON_RUNNING}" ; color="${C_CYAN}"  ;;
            "not_run")
                if check_dependencies "$_tc"; then
                    ready_to_run=true
                    color="${C_WHITE}"
                fi
                ;;
        esac
        
        # Status icon colorization
        local icon_display=""
        local line_color="${color}${C_BOLD}"
        [[ "$ready_to_run" == "true" ]] && line_color="${C_WHITE}${C_BOLD}"
        
        case "$tc_status" in
            "done")
                icon_display="${C_GRAY}[${C_GREEN}✓${C_RESET}${C_GRAY}]${C_RESET}"
                ;;
            "failed")
                icon_display="${C_GRAY}[${C_RED}x${C_RESET}${C_GRAY}]${C_RESET}"
                ;;
            "aborted")
                icon_display="${C_GRAY}[${C_YELLOW}!${C_RESET}${C_GRAY}]${C_RESET}"
                ;;
            "running")
                icon_display="${C_GRAY}[${C_CYAN}>${C_RESET}${C_GRAY}]${C_RESET}"
                ;;
            *)
                icon_display="${C_GRAY}[ ]${C_RESET}"
                ;;
        esac
        
        # 1. Print Status Icon
        # Note: icon_display visible width is exactly 3.
        printf "   %b  " "${icon_display}"
        
        # 2. Print TC ID (Always Bold, fixed 4 chars width)
        printf "${C_BOLD}%-4s${C_RESET} " "${_tc}"
        
        # 3. Print TC Name + Critical Star (Fixed 45 chars)
        local full_name="${tc_name}"
        [[ "$is_critical" == "yes" ]] && full_name="${full_name} *"
        
        # Manually calculate padding to ensure perfect alignment
        # visible width of full_name
        local name_len=${#full_name}
        local pad_len=$(( 45 - name_len ))
        [[ $pad_len -lt 0 ]] && pad_len=0
        local padding=$(printf '%*s' "$pad_len" "")
        
        # Force all names to be BOLD as requested
        printf "${line_color}%s${C_RESET}%s  " "${full_name}" "${padding}"
        
        # 4. Dependency hint (Starts at fixed column)
        if [[ "$tc_status" == "not_run" && "$deps" != "none" ]]; then
            local formatted_deps=""
            local old_ifs="$IFS"
            IFS=','
            for d in $deps; do
                d=$(echo "$d" | xargs)
                [[ -n "$formatted_deps" ]] && formatted_deps+=", "
                
                # Each dependency ID + optional tick takes fixed space
                # Pad ID to 3 chars
                local d_id=$(printf "%-3s" "$d")
                if [[ "${TC_STATUS[$d]:-not_run}" == "done" ]]; then
                    formatted_deps+="${d_id}${C_GREEN}✓${C_RESET}${C_DIM}"
                else
                    formatted_deps+="${d_id} " # Space placeholder for alignment
                fi
            done
            IFS="$old_ifs"
            printf "${C_DIM}(req: %s)${C_RESET}\n" "${formatted_deps}"
        else
            echo ""
        fi
    done
    
    echo ""
    echo -e "  ${C_BOLD}Assessment Controls:${C_RESET}"
    echo -e "   [${C_BOLD}ALL${C_RESET}]  Run all pending test cases"
    echo -e "   [${C_BOLD}R${C_RESET}]    Generate Report (from completed tests)"
    echo -e "   [${C_BOLD}M${C_RESET}]    Manage Sessions (List/Load/Delete)"
    echo -e "   [${C_BOLD}S${C_RESET}]    Session Info (Target configuration)"
    echo -e "   [${C_BOLD}P${C_RESET}]    Tool Prerequisite Check"
    echo -e "   [${C_BOLD}V${C_RESET}]    View Results (completed test summaries)"
    echo -e "   [${C_BOLD}T${C_RESET}]    Run Automated Tests (framework internal logic)"
    echo -e "   [${C_BOLD}W${C_RESET}]    Preflight Wizard (interfaces, target, DNS, safety)"
    echo -e "   [${C_BOLD}Q${C_RESET}]    Quit & Save Session"
    echo ""
    echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  💡 Type module ID (e.g. A1, D3, G2)  │  ${ICON_DONE}=Done  ${ICON_PENDING}=Pending  ${ICON_FAIL}=Failed"
    echo ""
}

#--- Handle menu input ---
handle_menu_choice() {
    local choice="${1^^}"  # Uppercase
    
    case "$choice" in
        "ALL")
            run_all_tests
            ;;
        "R")
            generate_report
            ;;
        "M")
            manage_sessions
            ;;
        "S")
            show_session_info
            ;;
        "P")
            full_prereq_check
            ;;
        "V")
            view_results_menu
            ;;
        "T")
            run_automated_tests
            ;;
        "W")
            preflight_wizard
            ;;
        "Q")
            save_session_state
            echo -e "${C_GREEN}Session saved: ${SESSION_ID}${C_RESET}"
            exit 0
            ;;
        *)
            # Check if it's a valid module ID
            if [[ -n "${TC_REGISTRY[$choice]:-}" ]]; then
                execute_test_case "$choice"
            else
                log_error "Invalid selection: ${choice}"
                sleep 1
            fi
            ;;
    esac
}

#--- Execute a single test case ---
execute_test_case() {
    local tc_id="$1"
    local tc_name
    tc_name=$(get_tc_field "$tc_id" "name")
    
    # 1) Dependency Check
    if ! handle_dependencies "$tc_id"; then
        return 1
    fi
    
    # 2) Interface/Network Prep
    local reqs
    reqs=$(get_tc_field "$tc_id" "reqs")
    
    if [[ "$reqs" == *"monitor_iface"* ]]; then
        enable_monitor_mode || return 1
    fi
    
    if [[ "$reqs" == *"managed_iface"* ]]; then
        ensure_connected_wifi || return 1
    fi
    
    if [[ "$reqs" == *"target_ssid"* ]] && [[ -z "${GUEST_SSID:-}" ]]; then
        if ! select_target_network; then
            log_error "This test requires a target network. Select one first."
            return 1
        fi
    fi
    
    if [[ "$reqs" == *"gateway_ip"* ]] && [[ -z "${GATEWAY_IP:-}" ]]; then
        log_error "No gateway IP detected. Connect to WiFi first."
        return 1
    fi

    # 3) Setup Evidence Registry
    evidence_tc_start "$tc_id"
    
    # 4) Launch Module
    local func_name="run_${tc_id,,}"
    
    # Mark as running for menu status
    TC_STATUS["$tc_id"]="running"
    save_session_state
    
    echo ""
    echo -e "${C_BLUE}┌── EXECUTING: ${C_BOLD}${tc_id} — ${tc_name}${C_RESET}${C_BLUE} ──────────────────────┐${C_RESET}"
    echo ""
    
    # Record metadata
    local _tc_started_iso=$(date -Iseconds)
    local _tc_start_time=$(date +%s)
    CURRENT_TC="$tc_id"
    TC_ABORT_REQUESTED=0
    
    # Source and Run
    local mod_file="${MOD_DIR}/${tc_id,,}_*.sh"
    # Find the actual file (glob)
    for f in $mod_file; do
        if [[ -f "$f" ]]; then
            source "$f"
            break
        fi
    done
    
    # Run the function
    if declare -f "$func_name" &>/dev/null; then
        $func_name
        local exit_code=$?
        
        # Record end time
        local _tc_ended_iso=$(date -Iseconds)
        local _tc_end_time=$(date +%s)
        local _duration_sec=$(( _tc_end_time - _tc_start_time ))
        
        # Enrich the JSON with standard metadata and evidence
        if declare -f enrich_tc_result_file &>/dev/null; then
            enrich_tc_result_file "$tc_id" "$exit_code" "$_tc_started_iso" "$_tc_ended_iso" "$_duration_sec" || true
        fi
        
        if [[ "$exit_code" -eq 0 ]]; then
            TC_STATUS["$tc_id"]="done"
            log_success "Module ${tc_id} completed successfully."
        else
            TC_STATUS["$tc_id"]="failed"
            log_error "Module ${tc_id} exited with error code ${exit_code}."
        fi
    else
        log_error "Function ${func_name} not found in ${mod_file}"
        TC_STATUS["$tc_id"]="failed"
    fi
    
    CURRENT_TC=""
    save_session_state
    
    echo ""
    echo -e "${C_BLUE}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""
    read -rep "  Press Enter to return to menu..." _
}

#--- Run all pending tests ---
run_all_tests() {
    log_info "Starting batch execution of all pending tests..."
    
    for tc_id in "${TC_ORDER[@]}"; do
        # Skip if already done or failed
        [[ "${TC_STATUS[$tc_id]:-not_run}" == "done" ]] && continue
        
        execute_test_case "$tc_id"
        
        # Check if user aborted
        if [[ ${TC_ABORT_REQUESTED:-0} -eq 1 ]]; then
            break
        fi
    done
    
    log_success "Batch execution complete."
}

#--- Preflight Wizard ---
preflight_wizard() {
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  PREFLIGHT WIZARD — Session Setup                               ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    # 1) Managed interface
    echo -e "  ${C_BOLD}Step 1:${C_RESET} Select managed WiFi interface"
    echo ""
    if [[ -n "${WIFI_INTERFACE:-}" ]]; then
        echo -e "    Current interface: ${C_BOLD}${WIFI_INTERFACE}${C_RESET}"
        read -rep "  Keep this interface? [Y/n]: " _keep_iface
        if [[ "${_keep_iface,,}" == "n" ]]; then
            configure_network || return 1
        fi
    else
        configure_network || return 1
    fi

    # Derive details
    MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    GATEWAY_IP=$(${TOOL_PATHS[ip]} route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
    MY_MAC=$(${TOOL_PATHS[ip]} link show "$WIFI_INTERFACE" 2>/dev/null | awk '/ether/{print $2}')
    export MY_IP GATEWAY_IP MY_MAC

    echo ""
    echo -e "    WiFi Interface: ${C_BOLD}${WIFI_INTERFACE}${C_RESET}"
    echo -e "    Our IP:         ${C_BOLD}${MY_IP:-unknown}${C_RESET}"
    echo -e "    Our MAC:        ${C_BOLD}${MY_MAC:-unknown}${C_RESET}"
    echo ""

    # Verify hardware capabilities immediately after selection
    if declare -f check_hardware_capabilities &>/dev/null; then
        check_hardware_capabilities
    fi

    PREFLIGHT_DONE=1
    export PREFLIGHT_DONE
    save_session_state

    echo ""
    echo -e "${C_GREEN}Preflight wizard complete. Settings saved.${C_RESET}"
    echo ""
    read -rep "  Press Enter to return to menu..." _
}

#--- View results menu ---
view_results_menu() {
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  VIEW RESULTS — Completed Test Cases                            ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    local -a done_tcs=()
    for _tc in "${TC_ORDER[@]}"; do
        [[ "${TC_STATUS[$_tc]:-not_run}" == "done" ]] && done_tcs+=("$_tc")
    done

    if [[ ${#done_tcs[@]} -eq 0 ]]; then
        echo -e "  ${C_GRAY}No completed test cases yet.${C_RESET}"
        echo ""
        read -rep "  Press Enter to return to menu..." _
        return 0
    fi

    local i=1
    for _tc in "${done_tcs[@]}"; do
        local tc_name result_file status
        tc_name=$(get_tc_field "$_tc" "name")
        result_file=$(get_tc_result_file "$_tc")
        status=$(${TOOL_PATHS[jq]} -r '.status // "—"' "$result_file" 2>/dev/null || echo "—")
        printf "    [%2d]  %-4s  %-35s  [%s]\n" "$i" "$_tc" "$tc_name" "$status"
        ((i++))
    done

    echo ""
    local choice
    read -rep "  Select Module ID to view summary (or Enter to return): " choice
    [[ -z "$choice" ]] && return 0
    choice="${choice^^}"

    if [[ -n "${TC_REGISTRY[$choice]:-}" ]]; then
        local result_file
        result_file=$(get_tc_result_file "$choice")
        if [[ -f "$result_file" ]]; then
            echo ""
            echo -e "${C_CYAN}─ RESULTS SUMMARY: ${choice} ───────────────────────────────────────${C_RESET}"
            ${TOOL_PATHS[jq]} -r '"Summary: " + .summary, "Status:  " + .status, "Details: " + .details' "$result_file"
            echo ""
            read -rep "  Press Enter to continue..." _
        else
            log_error "Result file not found for ${choice}"
        fi
    fi
}

#--- VPS Config Wizard ---
configure_vps() {
    echo ""
    echo -e "${C_CYAN}───────────────────────────────────────────────────────────────────${C_RESET}"
    echo -e "  ${C_BOLD}VPS CONFIGURATION (Egress Testing)${C_RESET}"
    echo -e "${C_CYAN}───────────────────────────────────────────────────────────────────${C_RESET}"
    echo ""
    
    read -rep "  VPS Public IP Address: " VPS_IP
    [[ -z "$VPS_IP" ]] && { log_error "VPS IP is required."; return 1; }
    
    read -rep "  VPS Domain (optional): " VPS_DOMAIN
    
    VPS_CONFIGURED=1
    save_session_state
    log_success "VPS configuration updated."
    return 0
}

#--- Run Automated Framework Tests ---
run_automated_tests() {
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  AUTOMATED FRAMEWORK TESTS — Verifying Internal Logic           ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    
    local test_script="${SCRIPT_DIR}/tests/test_parsers.py"
    if [[ ! -f "$test_script" ]]; then
        log_error "Test script not found: $test_script"
        read -rep "  Press Enter to return..." _
        return 1
    fi
    
    log_info "Running parser unit tests..."
    if python3 "$test_script"; then
        echo ""
        log_success "All framework internal tests PASSED."
    else
        echo ""
        log_error "Some framework tests FAILED."
    fi
    
    echo ""
    read -rep "  Press Enter to return to menu..." _
}
