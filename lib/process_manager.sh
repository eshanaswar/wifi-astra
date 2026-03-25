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

    # Ensure SESSION_DIR is set; fallback to $TMP_DIR/wifi-astra/default if not
    local base_dir="${SESSION_DIR:-$TMP_DIR/wifi-astra/default}"
    local pid_dir="${base_dir}/.pids"
    mkdir -p "$pid_dir"
    local pid_file="${pid_dir}/${name}.pid"

    log_info "Spawning background job '$name' ($tool_name): $path $*"
    
    if [[ -n "$log_file" ]]; then
        mkdir -p "$(dirname "$log_file")"
        "$path" "$@" >> "$log_file" 2>&1 &
    else
        "$path" "$@" > /dev/null 2>&1 &
    fi
    
    local pid=$!
    echo "$pid" > "$pid_file"
    log_debug "Background job '$name' started with PID $pid. PID file: $pid_file"
    
    return 0
}

# Run a command as the non-root human user (drops privileges)
# Usage: run_as_user <command> [args...]
run_as_user() {
    local cmd="$1"
    shift
    
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        sudo -u "$SUDO_USER" "$cmd" "$@"
    else
        "$cmd" "$@"
    fi
}

# Systematic cleanup of background processes
# Iterates through .pid files in SESSION_DIR/.pids
cleanup_processes() {
    local base_dir="${SESSION_DIR:-$TMP_DIR/wifi-astra/default}"
    local pid_dir="${base_dir}/.pids"
    
    if [[ ! -d "$pid_dir" ]]; then
        return 0
    fi

    log_debug "Cleaning up background processes in $pid_dir"
    
    # Use nullglob to avoid literal *.pid if no files match
    shopt -s nullglob
    local pid_files=("$pid_dir"/*.pid)
    shopt -u nullglob

    if [[ ${#pid_files[@]} -eq 0 ]]; then
        return 0
    fi

    for pid_file in "${pid_files[@]}"; do
        if [[ ! -f "$pid_file" ]]; then continue; fi
        
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        local name
        name=$(basename "$pid_file" .pid)

        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_debug "Sending SIGTERM to $name (PID: $pid)"
            kill -TERM "$pid" 2>/dev/null
            
            # Wait for process to exit (max 5s)
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 50 ]]; do
                sleep 0.1
                ((count++))
            done

            if kill -0 "$pid" 2>/dev/null; then
                log_warn "$name (PID: $pid) did not exit after SIGTERM, sending SIGKILL"
                kill -9 "$pid" 2>/dev/null
            fi
        fi
        rm -f "$pid_file"
    done
}

# Stop a specific background process by name
# Usage: stop_process <name> [signal]
stop_process() {
    local name="$1"
    local signal="${2:-TERM}"
    local base_dir="${SESSION_DIR:-$TMP_DIR/wifi-astra/default}"
    local pid_file="${base_dir}/.pids/${name}.pid"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_debug "Stopping background process '$name' (PID: $pid) with SIG$signal"
            kill -"$signal" "$pid" 2>/dev/null
            
            # Wait up to 5s for process to exit
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 50 ]]; do
                sleep 0.1
                ((count++))
            done
            
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "Process '$name' (PID: $pid) did not exit after SIG$signal, sending SIGKILL"
                kill -9 "$pid" 2>/dev/null
            fi
        fi
        rm -f "$pid_file"
    else
        log_debug "No PID file found for background process '$name' at $pid_file"
    fi
}
