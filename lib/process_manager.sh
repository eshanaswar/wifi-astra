#!/usr/bin/env bash
#===============================================================================
#  lib/process_manager.sh — Safe Process Execution & Job Control
#  
#  Provides robust tool execution, timeout handling, and prevents race conditions.
#===============================================================================

# Run an attack tool safely with a timeout, logging, and error handling.
# Usage: run_attack_tool --timeout <secs> --log <file> --cmd "<command>"
run_attack_tool() {
    local timeout_secs=""
    local log_file=""
    local cmd=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout) timeout_secs="$2"; shift 2 ;;
            --log) log_file="$2"; shift 2 ;;
            --cmd) cmd="$2"; shift 2 ;;
            *) log_error "Unknown argument to run_attack_tool: $1"; return 1 ;;
        esac
    done
    
    if [[ -z "$cmd" ]]; then
        log_error "run_attack_tool requires --cmd"
        return 1
    fi
    
    log_cmd "$cmd"
    
    if [[ -n "$log_file" ]]; then
        if [[ -n "$timeout_secs" ]]; then
            timeout "$timeout_secs" bash -c "$cmd" >> "$log_file" 2>&1
        else
            bash -c "$cmd" >> "$log_file" 2>&1
        fi
    else
        if [[ -n "$timeout_secs" ]]; then
            timeout "$timeout_secs" bash -c "$cmd"
        else
            bash -c "$cmd"
        fi
    fi
    
    local exit_code=$?
    
    # 124 is the standard exit code for GNU timeout
    if [[ $exit_code -eq 124 ]]; then
        log_info "Command completed (timeout reached: ${timeout_secs}s)"
        return 0
    fi
    
    return $exit_code
}
