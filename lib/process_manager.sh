#!/usr/bin/env bash
#===============================================================================
#  lib/process_manager.sh — Safe Process Execution & Job Control
#  
#  Provides robust tool execution, timeout handling, and prevents race conditions.
#===============================================================================

set -uo pipefail

# Run a tool in the foreground
# Usage: run_fg [--quiet] <tool_name> [args...]
run_fg() {
    local quiet=0
    if [[ "$1" == "--quiet" ]]; then
        quiet=1
        shift
    fi

    local tool_name="$1"
    shift
    
    local path="${TOOL_PATHS[$tool_name]:-}"
    
    if [[ -z "$path" ]]; then
        log_error "Tool '$tool_name' not found in TOOL_PATHS."
        return 127
    fi

    if [[ ! -x "$path" ]]; then
        log_error "Tool path '$path' for '$tool_name' is not executable."
        return 127
    fi

    if [[ $quiet -eq 0 ]]; then
        log_cmd "$path $*"
    fi
    "$path" "$@"
    return $?
}

# Spawn a tool in the background
# Usage: spawn_bg <name> <tool_name> [--log <file>] [args...]
spawn_bg() {
    local name="$1"
    local tool_name="$2"
    shift 2
    
    local log_file=""
    if [[ $# -ge 2 && "$1" == "--log" ]]; then
        log_file="$2"
        shift 2
    fi
    
    local path="${TOOL_PATHS[$tool_name]:-}"

    if [[ -z "$path" ]]; then
        log_error "Tool '$tool_name' not found in TOOL_PATHS."
        return 127
    fi

    if [[ ! -x "$path" ]]; then
        log_error "Tool path '$path' for '$tool_name' is not executable."
        return 127
    fi

    log_info "Requesting background job '$name' ($tool_name) from assessment engine..."
    
    # Build JSON request
    # Note: we need to handle arguments as a JSON array
    local args_json="[]"
    if [[ $# -gt 0 ]]; then
        args_json=$(printf '%s\n' "$@" | run_tool jq -R . | run_tool jq -s . -c)
    fi

    local req_json=$(run_tool jq -n \
        --arg id "$name" \
        --arg cmd "$path" \
        --argjson args "$args_json" \
        --arg log "$log_file" \
        '{id: $id, command: $cmd, args: $args, log_file: $log}')

    if run_engine_api POST "/v1/process/start" "$req_json" >/dev/null; then
        log_debug "Background job '$name' started by assessment engine."
        return 0
    else
        log_error "Failed to start background job '$name' via assessment engine."
        return 1
    fi
}

# Systematic cleanup of background processes
# Now handled by engine daemon, but keeping as a no-op for compatibility
cleanup_processes() {
    log_debug "Cleanup requested (handled by engine daemon)"
    return 0
}

# Stop a specific background process by name
# Usage: stop_process <name> [signal]
stop_process() {
    local name="$1"
    # Note: engine API currently doesn't support specific signals via stop endpoint
    # it always tries TERM then KILL.
    
    log_debug "Stopping background process '$name' via assessment engine"
    if run_engine_api POST "/v1/process/stop?id=${name}" >/dev/null; then
        return 0
    else
        log_debug "No process found with ID '$name' in assessment engine."
        return 1
    fi
}
