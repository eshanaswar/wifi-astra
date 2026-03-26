#!/usr/bin/env bash
#===============================================================================
#  WiFi-Astra — Wireless Security Assessment Framework
#  Main Launcher Script
#
#  Usage: sudo ./wifi-astra.sh
#  
#  Requires: Kali Linux with root privileges
#===============================================================================

set -uo pipefail

# Ensure Readline is enabled for interactive input
set -o emacs 2>/dev/null || true

# Initialize terminal state
stty sane 2>/dev/null
stty erase '^?' 2>/dev/null || stty erase '^H' 2>/dev/null

#--- Resolve script root directory safely across all subshells/symlinks ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
export SCRIPT_DIR

#--- Pre-flight: Must be root ---
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[✗] This toolkit requires root privileges.\033[0m"
    echo -e "    Run: sudo $0"
    exit 1
fi

#--- Pre-flight: Must be bash 4+ ---
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo -e "\033[1;31m[✗] Bash 4.0+ required. Current: ${BASH_VERSION}\033[0m"
    exit 1
fi

#--- Load core libraries in order ---
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/logger.sh"
source "${SCRIPT_DIR}/lib/process_manager.sh"
source "${SCRIPT_DIR}/lib/ui_helpers.sh"
source "${SCRIPT_DIR}/lib/progress.sh"
source "${SCRIPT_DIR}/lib/events.sh"
source "${SCRIPT_DIR}/lib/evidence.sh"
source "${SCRIPT_DIR}/lib/pcap.sh"
source "${SCRIPT_DIR}/lib/confidence.sh"
source "${SCRIPT_DIR}/lib/hardware.sh"
source "${SCRIPT_DIR}/lib/network_stack.sh"
source "${SCRIPT_DIR}/lib/trap_handler.sh"
source "${SCRIPT_DIR}/lib/session.sh"
source "${SCRIPT_DIR}/lib/migration.sh"
source "${SCRIPT_DIR}/lib/dependency.sh"
source "${SCRIPT_DIR}/lib/discovery.sh"
source "${SCRIPT_DIR}/lib/prereq_check.sh"
source "${SCRIPT_DIR}/lib/report.sh"
source "${SCRIPT_DIR}/lib/headless.sh"
source "${SCRIPT_DIR}/lib/menu.sh"

#--- Initialize framework ---
disable_echo

usage() {
    echo "Usage: sudo ./wifi-astra.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config <file.json>   Run in headless mode with specified config"
    echo "  --check-only           Check prerequisites and exit (0 if OK, 1 if missing)"
    echo "  --verbose, -v          Enable verbose output"
    echo "  --help, -h             Show this help message"
    echo ""
}

main() {
    #--- Secure Temporary Workspace ---
    # Create a restricted directory within the project root to keep the tool self-contained
    mkdir -p "${SCRIPT_DIR}/.tmp"
    export TMP_DIR=$(mktemp -d "${SCRIPT_DIR}/.tmp/work.XXXXXX")
    
    # Ensure human user has access for dropped-privilege parsing
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        local user_group
        user_group=$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")
        chown "${SUDO_USER}:${user_group}" "$TMP_DIR" 2>/dev/null || true
    fi
    chmod 700 "$TMP_DIR"

    #--- Discover Assessment Modules ---
    if declare -f discover_modules &>/dev/null; then
        discover_modules
    fi

    #--- Handle arguments ---

    local config_file=""
    local check_only=false
    export VERBOSE_MODE=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config) config_file="$2"; shift 2 ;;
            --check-only) check_only=true; shift ;;
            --verbose|-v) export VERBOSE_MODE=1; shift ;;
            --help|-h)
                usage
                exit 0
                ;;
            *) shift ;;
        esac
    done

    #--- Handle non-interactive check ---
    if [[ "$check_only" == "true" ]]; then
        echo -e "\033[1;34m[*] Verifying core environment...\033[0m"
        if ! quick_prereq_check; then
            echo -e "\033[1;31m[✗] Prerequisite check FAILED.\033[0m"
            exit 1
        fi
        echo -e "\033[1;32m[✓] Prerequisites OK.\033[0m"

        echo -e "\033[1;34m[*] Validating framework syntax...\033[0m"
        local failed=0
        for file in "${SCRIPT_DIR}/lib/"*.sh "${SCRIPT_DIR}/wifi-astra.sh"; do
            if ! bash -n "$file"; then
                echo -e "\033[1;31m[✗] Syntax error in: $file\033[0m"
                failed=1
            fi
        done
        
        if [[ $failed -eq 1 ]]; then
            echo -e "\033[1;31m[✗] Framework validation FAILED.\033[0m"
            exit 1
        fi
        
        echo -e "\033[1;32m[✓] Framework validation PASSED.\033[0m"
        exit 0
    fi

    clear
    print_banner

    #--- Populate Tool Paths and verify core environment ---
    quick_prereq_check

    #--- Migrate legacy sessions ---
    migrate_legacy_sessions

    #--- Handle headless mode ---
    if [[ -n "$config_file" ]]; then
        if [[ ! -f "$config_file" ]]; then
            log_error "Config file not found: $config_file"
            exit 1
        fi
        if declare -f run_headless_audit &>/dev/null; then
            run_headless_audit "$config_file"
            exit 0
        else
            log_error "Headless mode engine not loaded."
            exit 1
        fi
    fi

    #--- Check for previous sessions ---
    local session_action
    session_action=$(detect_previous_session)

    case "$session_action" in
        "resume")
            load_session
            log_info "Resumed session: ${SESSION_ID}"
            check_hardware_capabilities
            safe_read "Press Enter to continue to Main Menu..." _
            ;;
        "new"|"")
            init_new_session
            log_info "New session started: ${SESSION_ID}"
            # Run preflight wizard once for new sessions
            if declare -f preflight_wizard &>/dev/null; then
                preflight_wizard
            fi
            ;;
    esac

    #--- Register signal handlers ---
    register_traps

    #--- Quick pre-req check (non-blocking) ---
    quick_prereq_check

    #--- Ensure terminal settings are sane ---
    enable_echo

    #--- Enter main menu loop ---
    main_menu_loop
}

print_banner() {
    echo -e "${C_CYAN}"
    cat << 'BANNER'

     ██╗    ██╗██╗███████╗██╗       █████╗ ███████╗████████╗██████╗  █████╗
     ██║    ██║██║██╔════╝██║      ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
     ██║ █╗ ██║██║█████╗  ██║█████╗███████║███████╗   ██║   ██████╔╝███████║
     ██║███╗██║██║██╔══╝  ██║╚════╝██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
     ╚███╔███╔╝██║██║     ██║      ██║  ██║███████║   ██║   ██║  ██║██║  ██║
      ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝      ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝

BANNER
    echo -e "${C_RESET}"
    echo -e "  ${C_WHITE}${C_BOLD}Wireless Security Assessment Framework${C_RESET}  ${C_DIM}v${TOOLKIT_VERSION}${C_RESET}"
    echo ""
}

#--- Launch ---
main "$@"
