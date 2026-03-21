#!/usr/bin/env bash
#===============================================================================
#  lib/dependency.sh — Dependency Checker & Auto-Run Logic
#  
#  Resolves the full dependency chain for a test case.
#  If dependencies haven't been run, shows them and auto-runs.
#===============================================================================

#--- Get direct dependencies for a TC ---
get_dependencies() {
    local tc_id="$1"
    local deps
    deps=$(get_tc_field "$tc_id" "deps")
    
    if [[ "$deps" == "none" || -z "$deps" ]]; then
        echo ""
        return
    fi
    
    echo "$deps"
}

#--- Recursively resolve full dependency chain ---
# Returns: ordered list of TCs that need to run (deepest deps first)
# Uses global scratch arrays to avoid bash nameref circular reference bugs.
declare -ga _DEP_CHAIN=()
declare -gA _DEP_VISITED=()

resolve_dependency_chain() {
    local tc_id="$1"
    _DEP_CHAIN=()
    _DEP_VISITED=()
    
    _resolve_deps_recursive "$tc_id"
    
    # Remove the original TC from the chain (we only want deps)
    local result=()
    for item in "${_DEP_CHAIN[@]}"; do
        if [[ "$item" != "$tc_id" ]]; then
            result+=("$item")
        fi
    done
    
    echo "${result[*]}"
}

_resolve_deps_recursive() {
    local tc_id="$1"
    
    # Prevent cycles
    if [[ -n "${_DEP_VISITED[$tc_id]:-}" ]]; then
        return
    fi
    _DEP_VISITED["$tc_id"]=1
    
    local deps
    deps=$(get_dependencies "$tc_id")
    
    if [[ -n "$deps" ]]; then
        IFS=',' read -ra dep_array <<< "$deps"
        for dep in "${dep_array[@]}"; do
            dep=$(echo "$dep" | xargs)  # Trim whitespace
            _resolve_deps_recursive "$dep"
        done
    fi
    
    _DEP_CHAIN+=("$tc_id")
}

#--- Check if all dependencies are satisfied ---
check_dependencies() {
    local tc_id="$1"
    local deps
    deps=$(get_dependencies "$tc_id")
    
    if [[ -z "$deps" ]]; then
        return 0  # No dependencies
    fi
    
    IFS=',' read -ra dep_array <<< "$deps"
    for dep in "${dep_array[@]}"; do
        dep=$(echo "$dep" | xargs)
        if [[ "${TC_STATUS[$dep]:-not_run}" != "done" ]]; then
            return 1  # Dependency not met
        fi
    done
    
    return 0  # All deps satisfied
}

#--- Get list of unmet dependencies ---
get_unmet_dependencies() {
    local tc_id="$1"
    local -a unmet=()
    
    # Get full chain
    local chain
    chain=$(resolve_dependency_chain "$tc_id")
    
    if [[ -z "$chain" ]]; then
        echo ""
        return
    fi
    
    read -ra chain_array <<< "$chain"
    for dep in "${chain_array[@]}"; do
        if [[ "${TC_STATUS[$dep]:-not_run}" != "done" ]]; then
            unmet+=("$dep")
        fi
    done
    
    echo "${unmet[*]}"
}

#--- Show dependency resolution dialog & auto-run ---
# Returns 0 if user proceeds, 1 if user cancels
handle_dependencies() {
    local tc_id="$1"
    local tc_name
    tc_name=$(get_tc_field "$tc_id" "name")
    
    # Check if deps are already met
    if check_dependencies "$tc_id"; then
        return 0
    fi
    
    # Get unmet dependencies
    local unmet
    unmet=$(get_unmet_dependencies "$tc_id")
    read -ra unmet_array <<< "$unmet"
    
    # Get full dependency chain for display
    local full_chain
    full_chain=$(resolve_dependency_chain "$tc_id")
    read -ra full_chain_array <<< "$full_chain"
    
    # Display dependency resolution dialog
    echo ""
    echo -e "${C_YELLOW}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_YELLOW}│  ${ICON_WARN}  DEPENDENCY CHECK — ${tc_id} (${tc_name})${C_RESET}"
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    echo -e "${C_YELLOW}│  ${tc_id} requires the following tests to be completed:          ${C_RESET}"
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    
    for dep in "${full_chain_array[@]}"; do
        local dep_name
        dep_name=$(get_tc_field "$dep" "name")
        local dep_status="${TC_STATUS[$dep]:-not_run}"
        local status_icon
        
        case "$dep_status" in
            "done")    status_icon="${ICON_DONE} DONE" ;;
            "not_run") status_icon="${ICON_PENDING} NOT RUN" ;;
            "failed")  status_icon="${ICON_FAIL} FAILED" ;;
            "aborted") status_icon="${ICON_WARN} ABORTED" ;;
            *)         status_icon="${ICON_PENDING} ${dep_status^^}" ;;
        esac
        
        echo -e "${C_YELLOW}│    → ${dep} (${dep_name}) ... ${status_icon}${C_RESET}"
    done
    
    echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    
    if [[ ${#unmet_array[@]} -gt 0 ]]; then
        echo -e "${C_YELLOW}│  The following will auto-run first:                             │${C_RESET}"
        local step=1
        for dep in "${unmet_array[@]}"; do
            local dep_name
            dep_name=$(get_tc_field "$dep" "name")
            echo -e "${C_YELLOW}│    ${step}. ${dep} → ${dep_name}${C_RESET}"
            ((step++))
        done
        echo -e "${C_YELLOW}│    ${step}. ${tc_id} → ${tc_name}${C_RESET}"
        echo -e "${C_YELLOW}│                                                                 │${C_RESET}"
    fi
    
    echo -e "${C_YELLOW}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""
    
    read -rep "  Proceed? [Y/n]: " proceed
    if [[ "${proceed,,}" == "n" ]]; then
        log_info "User cancelled dependency auto-run for ${tc_id}"
        return 1
    fi
    
    # Auto-run unmet dependencies
    for dep in "${unmet_array[@]}"; do
        log_info "Auto-running dependency: ${dep}"
        execute_test_case "$dep"
        
        # Check if dependency succeeded
        if [[ "${TC_STATUS[$dep]}" != "done" ]]; then
            log_error "Dependency ${dep} did not complete successfully. Cannot proceed with ${tc_id}."
            return 1
        fi
    done
    
    return 0
}