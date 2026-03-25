#!/usr/bin/env bash
#===============================================================================
#  lib/migration.sh — Legacy Session Migration
#===============================================================================

set -uo pipefail

migrate_legacy_sessions() {
    # Legacy sessions were stored in ${SCRIPT_DIR}/evidence
    local legacy_dir="${SCRIPT_DIR}/evidence"
    local target_dir="${SESSION_BASE_DIR}"

    # If legacy dir doesn't exist, nothing to do
    [[ -d "$legacy_dir" ]] || return 0

    log_info "Checking for legacy sessions in ${legacy_dir}..."

    # Ensure target dir exists
    if [[ ! -d "$target_dir" ]]; then
        mkdir -p "$target_dir"
        if [[ -n "${SUDO_USER:-}" ]]; then
            # Ensure the parent .wifi-astra is also owned by the user
            local astra_home
            astra_home=$(dirname "$target_dir")
            chown "$SUDO_USER:$SUDO_USER" "$astra_home" "$target_dir" 2>/dev/null || true
        fi
    fi

    local migrated_count=0
    
    # Find all session.state files in legacy directory
    # We look for legacy_dir/*/session.state
    # find -maxdepth 2 because legacy sessions were in evidence/SESSION_ID/session.state
    while IFS= read -r -d '' state_file; do
        local session_path
        session_path=$(dirname "$state_file")
        local session_id
        session_id=$(basename "$session_path")

        # Skip if it's the legacy directory itself (shouldn't happen with maxdepth 2)
        [[ "$session_path" == "$legacy_dir" ]] && continue

        if [[ -d "${target_dir}/${session_id}" ]]; then
            log_warn "Session collision: ${session_id} already exists in ${target_dir}. Skipping migration for this session."
            continue
        fi

        log_info "Migrating legacy session: ${session_id} -> ${target_dir}/${session_id}"
        
        # Move the entire session directory
        mv "$session_path" "$target_dir/"
        
        # Fix ownership if needed
        if [[ -n "${SUDO_USER:-}" ]]; then
            chown -R "$SUDO_USER:$SUDO_USER" "${target_dir}/${session_id}" 2>/dev/null || true
        fi
        
        ((migrated_count++))
    done < <(find "$legacy_dir" -maxdepth 2 -name "session.state" -print0 2>/dev/null)

    if [[ $migrated_count -gt 0 ]]; then
        log_success "Successfully migrated ${migrated_count} legacy sessions to ${target_dir}."
        
        # Optionally remove the legacy evidence directory if empty
        if [[ -d "$legacy_dir" ]] && [[ -z "$(ls -A "$legacy_dir")" ]]; then
            rmdir "$legacy_dir"
        fi
    fi
}
