#!/usr/bin/env bash
#===============================================================================
#  lib/headless.sh — Automated / Headless Audit Engine
#===============================================================================

# Run a fully automated audit based on a JSON config file
run_headless_audit() {
    export HEADLESS_MODE=1
    local config_file="$1"
    
    log_info "Starting headless audit with config: ${config_file}"
    
    if ! command -v jq &>/dev/null; then
        log_error "${TOOL_PATHS[jq]} is required for headless mode."
        exit 1
    fi
    
    #--- Load Config ---
    local session_name
    session_name=$(${TOOL_PATHS[jq]} -r '.session_name // "headless"' "$config_file")
    
    # Initialize session (non-interactively)
    SESSION_ID="${session_name}_$(date '+%Y%m%d_%H%M%S')"
    export SESSION_NAME="$session_name"
    SESSION_DIR="${EVIDENCE_BASE}/${SESSION_ID}"
    SESSION_STATE_FILE="${SESSION_DIR}/session.state"
    SESSION_LOG_DIR="${SESSION_DIR}/logs"
    SESSION_EVIDENCE_DIR="${SESSION_DIR}/evidence"
    SESSION_REPORT_DIR="${SESSION_DIR}/reports"
    SESSION_RESULTS_DIR="${SESSION_DIR}/results"
    
    mkdir -p "$SESSION_DIR" "$SESSION_LOG_DIR" "$SESSION_EVIDENCE_DIR" "$SESSION_REPORT_DIR" "$SESSION_RESULTS_DIR"
    
    # Initialize TC statuses
    for _tc in "${TC_ORDER[@]}"; do
        TC_STATUS["$_tc"]="not_run"
    done
    
    #--- Inject Global Parameters from Config ---
    # Example config: { "params": { "GUEST_SSID": "TargetWiFi", "GATEWAY_IP": "192.168.1.1" } }
    local params
    params=$(${TOOL_PATHS[jq]} -r '.params | to_entries | .[] | "\(.key)=\(.value)"' "$config_file" 2>/dev/null)
    while IFS='=' read -r key value; do
        if [[ -n "$key" ]]; then
            export "$key"="$value"
            log_info "Config injected: ${key}=${value}"
        fi
    done <<< "$params"
    
    save_session_state
    log_success "Headless session initialized: ${SESSION_ID}"

    #--- Execute Modules ---
    local modules_to_run
    modules_to_run=$(${TOOL_PATHS[jq]} -r '.run_modules[]' "$config_file" 2>/dev/null)
    
    if [[ -z "$modules_to_run" ]]; then
        log_warn "No modules specified in run_modules array. Running default discovery (A1)."
        modules_to_run="A1"
    fi
    
    register_traps
    
    for tc_id in $modules_to_run; do
        log_step_header "HEADLESS EXECUTION: ${tc_id}"
        execute_test_case "$tc_id" || log_error "Module ${tc_id} failed."
        
        # Check for abort
        if [[ ${TC_ABORT_REQUESTED:-0} -eq 1 ]]; then
            log_warn "Headless audit aborted by user/signal."
            break
        fi
    done
    
    #--- Finalize ---
    log_info "Generating final reports..."
    generate_report
    
    log_success "Headless audit complete. Results in: ${SESSION_DIR}"
}

# Helper to log step headers in headless mode
log_step_header() {
    echo ""
    echo -e "${C_BLUE}${C_BOLD}================================================================${C_RESET}"
    echo -e "${C_BLUE}${C_BOLD}  $1 ${C_RESET}"
    echo -e "${C_BLUE}${C_BOLD}================================================================${C_RESET}"
    echo ""
}
