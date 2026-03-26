#!/usr/bin/env bash
#===============================================================================
#  lib/ui_helpers.sh — Adaptive Scoping & Annotations
#===============================================================================

# Safely read user input with Readline support and TTY cleanup
# Usage: safe_read "Prompt" "var_name" ["default_value"]
safe_read() {
    local prompt_msg="$1"
    local target_var="$2"
    local default_val="${3:-}"
    
    # Non-interactive / Headless mode handling
    if [[ "${HEADLESS_MODE:-0}" == "1" ]] || [[ ! -t 0 ]]; then
        # Just use the default if available, otherwise empty
        printf -v "$target_var" "%s" "$default_val"
        return 0
    fi

    # Ensure Readline is enabled
    set -o emacs 2>/dev/null || true
    
    # Defensive: restore terminal state and enable echo
    stty sane 2>/dev/null
    enable_echo
    # Ensure backspace is handled correctly (^? or ^H depending on terminal)
    stty erase '^?' 2>/dev/null || stty erase '^H' 2>/dev/null
    
    # Clear any pending characters in stdin
    clear_stdin
    
    # Strip all trailing colons and spaces from prompt_msg to avoid doubling
    local clean_prompt="${prompt_msg}"
    while [[ "$clean_prompt" == *":" || "$clean_prompt" == *" " ]]; do
        clean_prompt="${clean_prompt%:}"
        clean_prompt="${clean_prompt% }"
    done
    
    local _input=""
    if [[ -n "$default_val" ]]; then
        read -rep "  ${clean_prompt} [${default_val}]: " _input
        [[ -z "$_input" ]] && _input="$default_val"
    else
        read -rep "  ${clean_prompt}: " _input
    fi
    
    # Use printf -v for safe dynamic variable assignment (removes eval RCE vulnerability)
    printf -v "$target_var" "%s" "$_input"
}

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
    
    local user_input=""
    safe_read "$prompt_msg" user_input "$default_val"
    
    export "$var_name"="$user_input"
    save_session_state
}

#--- Standardized UI Rendering ---

# Print a module banner
# Usage: ui_banner "TITLE" ["Description line 1" "Description line 2" ...]
ui_banner() {
    local title="${1^^}"
    shift
    local desc=("$@")
    
    echo ""
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  ${C_BOLD}${title}${C_RESET}${C_CYAN}$(printf '%*s' $((64 - ${#title})) '')║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    
    for line in "${desc[@]}"; do
        printf "${C_CYAN}║  %-66s  ║${C_RESET}\n" "$line"
    done
    
    [[ ${#desc[@]} -gt 0 ]] && echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# Print a section header
# Usage: ui_section "SECTION NAME"
ui_section() {
    local name="${1^^}"
    echo ""
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "  ${C_BOLD}${name}${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo ""
}

# Print an info box
# Usage: ui_info_box "TITLE" "Content line 1" "Content line 2" ...
ui_info_box() {
    local title="${1^^}"
    shift
    local lines=("$@")
    
    echo ""
    echo -e "${C_CYAN}┌── ${C_BOLD}${title}${C_RESET}${C_CYAN} ──────────────────────────────────────────────────┐${C_RESET}"
    for line in "${lines[@]}"; do
        printf "${C_CYAN}│  ${C_RESET}%-63s ${C_CYAN}│${C_RESET}\n" "$line"
    done
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
}

# Print a critical warning banner
# Usage: ui_warning_banner "WARNING TITLE" "Warning detail line 1" ...
ui_warning_banner() {
    local title="${1^^}"
    shift
    local lines=("$@")
    
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    printf "  ║  ★ %-64s ★  ║\n" "$title"
    echo "  ║                                                                    ║"
    for line in "$@"; do
        printf "  ║  • %-64s  ║\n" "$line"
    done
    echo "  ║                                                                    ║"
    echo "  ║  THIS MAY DISRUPT CLIENTS OR INFRASTRUCTURE. PROCEED WITH CARE.    ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
}

# Print a standardized module sub-menu
# Usage: ui_menu "TITLE" "Option1|Description1" "Option2|Description2" ...
ui_menu() {
    local title="${1^^}"
    shift
    local options=("$@")
    
    echo ""
    echo -e "${C_CYAN}${C_BOLD}  ┌── ${title} ──────────────────────────────────┐${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}"
    
    for opt in "${options[@]}"; do
        if [[ "$opt" == "---"* ]]; then
            echo -e "  ${C_CYAN}├──────────────────────────────────────────────────────────────────┤${C_RESET}"
        else
            local key=$(echo "$opt" | cut -d'|' -f1)
            local desc=$(echo "$opt" | cut -d'|' -f2)
            printf "  ${C_CYAN}│${C_RESET}    ${C_YELLOW}[%s]${C_RESET} %-52s\n" "$key" "$desc"
        fi
    done
    
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}  └──────────────────────────────────────────────────────────────────┘${C_RESET}"
}
