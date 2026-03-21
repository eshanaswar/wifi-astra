#!/usr/bin/env bash
#===============================================================================
#  lib/ui_helpers.sh — Adaptive Scoping & Annotations
#===============================================================================

# Dynamically request a parameter if it's missing from the session state.
# Usage: get_or_request_param "VAR_NAME" "Prompt for the user:" "default_value"
get_or_request_param() {
    local var_name="$1"
    local prompt_msg="$2"
    local default_val="${3:-}"
    
    local current_val="${!var_name:-}"
    
    if [[ -n "$current_val" ]]; then
        # Already set, just return
        return 0
    fi
    
    echo ""
    echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_CYAN}│  MISSING CONTEXT REQUIREMENT                                    │${C_RESET}"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    
    local user_input
    if [[ -n "$default_val" ]]; then
        read -rep "  ${prompt_msg} [${default_val}]: " user_input
        if [[ -z "$user_input" ]]; then
            user_input="$default_val"
        fi
    else
        read -rep "  ${prompt_msg}: " user_input
    fi
    
    export "$var_name"="$user_input"
    save_session_state
}

# Add a manual observation to the session's evidence manifest/report
# Usage: add_manual_annotation "Observation text"
add_manual_annotation() {
    local note="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local notes_file="${SESSION_REPORT_DIR}/manual_annotations.txt"
    echo "[${timestamp}] [${CURRENT_TC:-SYSTEM}] ${note}" >> "$notes_file"
    
    log_info "Annotation recorded: ${note}"
}
