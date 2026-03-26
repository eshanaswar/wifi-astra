#!/usr/bin/env bash
#===============================================================================
#  lib/progress.sh — Progress Indicators
#  
#  Provides three types:
#    1. Step-based progress bar  (e.g., Step 3/6 — 50%)
#    2. Time-based countdown     (e.g., Capturing CDP... 45s / 120s)
#    3. Spinner                  (e.g., Waiting for DNS response...)
#===============================================================================

# PID tracker for background spinners/countdowns
export _PROGRESS_PID=""

#--- 1. STEP-BASED PROGRESS BAR ---
# Usage: show_progress_bar 3 6 "Scanning 10.0.0.0/16"
show_progress_bar() {
    local current="$1"
    local total="$2"
    local label="${3:-Processing}"
    local bar_width=40
    
    local percent=$(( (current * 100) / total ))
    local filled=$(( (current * bar_width) / total ))
    local empty=$(( bar_width - filled ))
    
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++));  do bar+="░"; done
    
    # Color based on progress
    local color="$C_YELLOW"
    if [[ $percent -ge 100 ]]; then
        color="$C_GREEN"
    elif [[ $percent -ge 60 ]]; then
        color="$C_CYAN"
    fi
    
    printf "\r  ${color}  [${bar}] ${percent}%% — Step ${current}/${total}: ${label}${C_RESET}  "
    echo ""  # Always newline after progress update
}

# Update the progress for a running TC
# Usage: update_tc_progress 3 6 "Scanning 10.0.0.0/16"
update_tc_progress() {
    show_progress_bar "$@"
}


#--- 2. TIME-BASED COUNTDOWN ---
# Runs in background, updates every second
# Usage: start_countdown 120 "Capturing CDP/LLDP frames"
#        ... (your actual command runs here) ...
#        stop_countdown
start_countdown() {
    local total_seconds="$1"
    local label="${2:-Working}"
    
    # Kill any existing countdown
    stop_countdown 2>/dev/null
    
    disable_echo
    
    (
        local start_time=$(date +%s)
        local elapsed=0
        local bar_width=40
        
        while [[ $elapsed -le $total_seconds ]]; do
            local percent=$(( (elapsed * 100) / total_seconds ))
            local filled=$(( (elapsed * bar_width) / total_seconds ))
            local empty=$(( bar_width - filled ))
            local remaining=$(( total_seconds - elapsed ))
            
            local bar=""
            for ((i=0; i<filled; i++)); do bar+="█"; done
            for ((i=0; i<empty; i++));  do bar+="░"; done
            
            local color="$C_YELLOW"
            if [[ $percent -ge 100 ]]; then color="$C_GREEN"
            elif [[ $percent -ge 60 ]]; then color="$C_CYAN"
            fi
            
            local min_r=$(( remaining / 60 ))
            local sec_r=$(( remaining % 60 ))
            local min_e=$(( elapsed / 60 ))
            local sec_e=$(( elapsed % 60 ))
            
            printf "\r  ${color}  [${bar}] ${percent}%% — ${label} (${min_e}m${sec_e}s / ${min_r}m${sec_r}s remaining)${C_RESET}  "
            
            sleep 1
            local now=$(date +%s)
            elapsed=$(( now - start_time ))
        done
        echo ""
    ) &
    _PROGRESS_PID=$!
    export _PROGRESS_PID
}

stop_countdown() {
    if [[ -n "${_PROGRESS_PID:-}" ]] && kill -0 "$_PROGRESS_PID" 2>/dev/null; then
        kill "$_PROGRESS_PID" 2>/dev/null
        wait "$_PROGRESS_PID" 2>/dev/null
        _PROGRESS_PID=""
        echo ""  # Clean newline
    fi
    
    # Flush stdin queue and restore terminal sanity
    clear_stdin
    # We DO NOT re-enable echo here; the framework remains in -echo mode
    tput cnorm 2>/dev/null # Show cursor
}


#--- 3. SPINNER ---
# Usage: start_spinner "Waiting for DNS response"
#        ... (your command) ...
#        stop_spinner
start_spinner() {
    local label="${1:-Working}"
    
    stop_spinner 2>/dev/null
    
    disable_echo
    
    (
        local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
        local i=0
        local elapsed=0
        local frame_count=0
        
        while true; do
            local min_e=$(( elapsed / 60 ))
            local sec_e=$(( elapsed % 60 ))
            printf "\r  ${C_CYAN}  ${frames[$i]} ${label} (${min_e}m${sec_e}s elapsed)${C_RESET}  "
            i=$(( (i + 1) % ${#frames[@]} ))
            sleep 0.2
            # Increment elapsed every 5 frames (1 second)
            ((frame_count++))
            if (( frame_count % 5 == 0 )); then
                ((elapsed++))
            fi
        done
    ) &
    _PROGRESS_PID=$!
    export _PROGRESS_PID
}

stop_spinner() {
    if [[ -n "${_PROGRESS_PID:-}" ]] && kill -0 "$_PROGRESS_PID" 2>/dev/null; then
        kill "$_PROGRESS_PID" 2>/dev/null
        wait "$_PROGRESS_PID" 2>/dev/null
        _PROGRESS_PID=""
        printf "\r%80s\r" ""  # Clear the line
    fi
    
    # Flush stdin queue and restore terminal sanity
    clear_stdin
    # We DO NOT re-enable echo here; the framework remains in -echo mode
    tput cnorm 2>/dev/null # Show cursor
}


#--- 4. COMBINED: Run command with spinner ---
# Usage: run_with_spinner "Scanning target" "${TOOL_PATHS[nmap]}" "-sV" "target"
# Returns: command exit code. Output captured in $CMD_OUTPUT
CMD_OUTPUT=""
run_with_spinner() {
    local label="$1"
    shift
    local cmd_array=("$@")
    
    # We still log a string representation
    local cmd_str="${cmd_array[*]}"
    log_cmd "$cmd_str"
    
    start_spinner "$label"
    
    CMD_OUTPUT=$("${cmd_array[@]}" 2>&1)
    local exit_code=$?
    
    stop_spinner

    # Persist raw tool output as evidence (best-effort)
    if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
        {
            echo "============================================================"
            echo "ts: $(date -Iseconds)"
            echo "cmd: $cmd_str"
            echo "exit_code: $exit_code"
            echo "------------------------------------------------------------"
            echo "$CMD_OUTPUT"
            echo ""
        } >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
    fi
    
    return ${exit_code:-0}
}

#--- 5. COMBINED: Run command with countdown ---
# Usage: run_with_countdown "${TOOL_PATHS[tcpdump]} -i eth0 -w out.pcap" 120 "Capturing traffic"
# Note: This runs the command with a timeout
run_with_countdown() {
    local cmd="$1"
    local seconds="$2"
    local label="${3:-Running command}"
    
    log_cmd "$cmd (timeout: ${seconds}s)"
    start_countdown "$seconds" "$label"
    
    # Run the command with timeout
    CMD_OUTPUT=$(timeout "$seconds" bash -c "$cmd" 2>&1) || true
    local exit_code=$?
    
    stop_countdown

    if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
        {
            echo "============================================================"
            echo "ts: $(date -Iseconds)"
            echo "cmd: $cmd (timeout: ${seconds}s)"
            echo "exit_code: $exit_code"
            echo "------------------------------------------------------------"
            echo "$CMD_OUTPUT"
            echo ""
        } >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
    fi
    
    # Exit code 124 means timeout killed it (expected)
    if [[ $exit_code -eq 124 ]]; then
        return 0
    fi
    return ${exit_code:-0}
}

#--- 6. FORMAT DURATION ---
format_duration() {
    local seconds="$1"
    local hours=$(( seconds / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$(( seconds % 60 ))
    
    if [[ $hours -gt 0 ]]; then
        printf "%dh %dm %ds" "$hours" "$minutes" "$secs"
    elif [[ $minutes -gt 0 ]]; then
        printf "%dm %ds" "$minutes" "$secs"
    else
        printf "%ds" "$secs"
    fi
}