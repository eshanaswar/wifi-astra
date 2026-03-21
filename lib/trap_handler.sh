#!/usr/bin/env bash
#===============================================================================
#  lib/trap_handler.sh — Signal Handling
#  
#  Ctrl+\  (SIGQUIT) = Abort current test case only
#  Ctrl+C  (SIGINT)  = Exit entire script gracefully
#===============================================================================

declare -ga CLEANUP_HOOKS=()

register_cleanup() {
    CLEANUP_HOOKS+=("$1")
}

_execute_cleanups() {
    if [[ ${#CLEANUP_HOOKS[@]} -eq 0 ]]; then
        return
    fi
    log_info "Executing cleanup hooks..."
    # LIFO execution
    for (( i=${#CLEANUP_HOOKS[@]}-1; i>=0; i-- )); do
        local cmd="${CLEANUP_HOOKS[$i]}"
        log_debug "Cleanup: $cmd"
        eval "$cmd" 2>/dev/null || true
    done
    CLEANUP_HOOKS=()
}

register_traps() {
    trap '_handle_sigquit' SIGQUIT    # Ctrl+\
    trap '_handle_sigint'  SIGINT     # Ctrl+C
    trap '_handle_exit'    EXIT       # Script exit (cleanup)
}

#--- Ctrl+\ Handler: Abort current test ---
_handle_sigquit() {
    echo ""
    
    if [[ -n "${CURRENT_TC:-}" ]]; then
        TC_ABORT_REQUESTED=1
        log_warn "Abort requested for ${CURRENT_TC}"
        
        # Stop any active PCAP capture for this TC (best effort)
        if declare -f pcap_stop &>/dev/null; then
            pcap_stop "$CURRENT_TC" || true
        fi

        # Kill any running background processes from this TC
        _kill_tc_processes
        
        # Stop any progress indicators
        stop_spinner 2>/dev/null
        stop_countdown 2>/dev/null
        
        # Execute cleanups for the current test
        _execute_cleanups

        # Mark as aborted
        TC_STATUS["$CURRENT_TC"]="aborted"
        save_session_state
        
        # Calculate duration
        local end_time
        end_time=$(date +%s)
        local duration
        duration=$(format_duration $(( end_time - ${_TC_START_TIME:-$end_time} )))
        
        log_tc_end "$CURRENT_TC" "aborted" "$duration"

        if declare -f log_event &>/dev/null; then
            log_event "tc_abort" "$CURRENT_TC" "duration=${duration}"
        fi
        
        # Show abort menu
        _show_abort_menu
    else
        log_warn "No test running. Use Ctrl+C to exit or 'Q' from the menu."
    fi
    
    # Re-register the trap (one-shot on some systems)
    trap '_handle_sigquit' SIGQUIT
}

#--- Ctrl+C Handler: Exit script ---
_handle_sigint() {
    echo ""
    log_warn "Script exit requested (Ctrl+C)"
    
    # Kill any running test
    if [[ -n "${CURRENT_TC:-}" ]]; then
        TC_ABORT_REQUESTED=1
        if declare -f pcap_stop &>/dev/null; then
            pcap_stop "$CURRENT_TC" || true
        fi
        _kill_tc_processes
        stop_spinner 2>/dev/null
        stop_countdown 2>/dev/null
        TC_STATUS["$CURRENT_TC"]="aborted"
    fi
    
    # Execute any pending cleanups
    _execute_cleanups

    # Save state before exit
    save_session_state 2>/dev/null
    
    echo -e "${C_YELLOW}Session saved. Run the script again to resume.${C_RESET}"
    echo -e "${C_YELLOW}Session ID: ${SESSION_ID}${C_RESET}"
    
    # Cleanup monitor mode if active
    ensure_managed_mode
    
    exit 0
}

#--- EXIT Handler: Final cleanup ---
_handle_exit() {
    # Stop any lingering progress indicators
    stop_spinner 2>/dev/null
    stop_countdown 2>/dev/null

    # Stop any lingering capture
    if [[ -n "${CURRENT_TC:-}" ]] && declare -f pcap_stop &>/dev/null; then
        pcap_stop "$CURRENT_TC" || true
    fi
    
    # Execute cleanups (just in case)
    _execute_cleanups

    # Finalize permissions for all evidence files
    if declare -f finalize_evidence_permissions &>/dev/null; then
        finalize_evidence_permissions
    fi

    # Save session one final time
    save_session_state 2>/dev/null
    
    # Restore terminal
    stty sane 2>/dev/null
    tput cnorm 2>/dev/null  # Show cursor
}

#--- Kill processes spawned by current TC ---
_kill_tc_processes() {
    # Kill specific tracked PID
    if [[ -n "${CURRENT_TC_PID:-}" ]] && kill -0 "$CURRENT_TC_PID" 2>/dev/null; then
        kill -TERM "$CURRENT_TC_PID" 2>/dev/null
        sleep 1
        kill -9 "$CURRENT_TC_PID" 2>/dev/null
        wait "$CURRENT_TC_PID" 2>/dev/null
        CURRENT_TC_PID=""
    fi
    
    # Kill any ${TOOL_PATHS[airodump-ng]}, ${TOOL_PATHS[masscan]} etc that we spawned
    # (tracked via PID files in session dir)
    local pid_dir="${SESSION_DIR:-/tmp}/.pids"
    if [[ -d "$pid_dir" ]]; then
        for pid_file in "$pid_dir"/*.pid; do
            [[ -f "$pid_file" ]] || continue
            local pid
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null
                sleep 0.5
                kill -9 "$pid" 2>/dev/null
            fi
            rm -f "$pid_file"
        done
    fi
}

# Also stop the runner-level PCAP capture (stored in pcap.sh registry).
_kill_runner_pcap() {
    if [[ -n "${CURRENT_TC:-}" ]] && declare -f pcap_stop &>/dev/null; then
        pcap_stop "$CURRENT_TC" || true
    fi
}

#--- Cleanup monitor mode ---
# Supported by global ensure_managed_mode

#--- Abort Menu ---
_show_abort_menu() {
    local tc_id="${CURRENT_TC}"
    CURRENT_TC=""
    TC_ABORT_REQUESTED=0
    
    echo ""
    echo -e "${C_YELLOW}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_YELLOW}│  ${ICON_WARN}  TEST ABORTED — ${tc_id}${C_RESET}"
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    echo -e "${C_YELLOW}│  Partial results saved to evidence directory.                   │${C_RESET}"
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    echo -e "${C_YELLOW}│  What would you like to do?                                     │${C_RESET}"
    echo -e "${C_YELLOW}│   [M] Return to Main Menu                                       │${C_RESET}"
    echo -e "${C_YELLOW}│   [R] Rerun this test case from the beginning                    │${C_RESET}"
    echo -e "${C_YELLOW}│   [Q] Quit script                                               │${C_RESET}"
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    echo -e "${C_YELLOW}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""
    
    while true; do
        read -rep "  Select [M/R/Q]: " abort_choice
        case "${abort_choice^^}" in
            "M")
                return 0  # Will return to menu loop
                ;;
            "R")
                # Reset status and re-run
                TC_STATUS["$tc_id"]="not_run"
                execute_test_case "$tc_id"
                return 0
                ;;
            "Q")
                save_session_state
                echo -e "${C_GREEN}Session saved: ${SESSION_ID}${C_RESET}"
                exit 0
                ;;
            *)
                echo -e "${C_RED}Invalid choice. Enter M, R, or Q.${C_RESET}"
                ;;
        esac
    done
}

#--- Helper: Track a background PID ---
track_pid() {
    local name="$1"
    local pid="$2"
    local pid_dir="${SESSION_DIR}/.pids"
    mkdir -p "$pid_dir"
    echo "$pid" > "${pid_dir}/${name}.pid"
}

#--- Helper: Check if abort was requested ---
check_abort() {
    if [[ ${TC_ABORT_REQUESTED:-0} -eq 1 ]]; then
        return 1
    fi
    return 0
}