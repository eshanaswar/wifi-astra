#!/usr/bin/env bash
#===============================================================================
#  lib/discovery.sh — Dynamic Module Discovery Engine
#
#  Replaces the hardcoded registries in config.sh by scanning the modules/
#  directory and parsing the MODULE_META headers.
#===============================================================================

set -uo pipefail

#--- Global Discovery State ---
declare -gA TC_REGISTRY
declare -gA TC_REQUIREMENTS
declare -gA TC_PCAP_REQUIRED
declare -gA TC_DECODE_PROFILE
declare -gA TOOL_TC_MAP
declare -ga TC_ORDER=()

#--- Internal: Extract a field from a module's meta header ---
_get_meta_field() {
    local file="$1"
    local field="$2"
    grep "^# ${field}=" "$file" | cut -d'"' -f2
}

#--- Discover all modules in the modules/ directory ---
discover_modules() {
    local mod_dir="${MOD_DIR:-${SCRIPT_DIR}/modules}"
    local -a found_tcs=()
    
    # Reset state
    TC_REGISTRY=()
    TC_REQUIREMENTS=()
    TC_PCAP_REQUIRED=()
    TC_DECODE_PROFILE=()
    TC_ORDER=()

    # Find all .sh files that have MODULE_META
    local mod_file
    for mod_file in "${mod_dir}"/[a-h][0-9]*_*.sh; do
        [[ -f "$mod_file" ]] || continue
        
        # Verify it has metadata
        if ! grep -q "# MODULE_META" "$mod_file"; then
            log_debug "Skipping module without metadata: $(basename "$mod_file")"
            continue
        fi

        # Extract TC_ID from filename (e.g. a1_xxx.sh -> A1)
        local tc_id=$(basename "$mod_file" | cut -d'_' -f1 | tr '[:lower:]' '[:upper:]')
        
        # Parse fields
        local name=$(_get_meta_field "$mod_file" "NAME")
        local cat=$(_get_meta_field "$mod_file" "CATEGORY")
        local deps=$(_get_meta_field "$mod_file" "DEPS")
        local crit=$(_get_meta_field "$mod_file" "CRITICAL")
        local desc=$(_get_meta_field "$mod_file" "DESC")
        local reqs=$(_get_meta_field "$mod_file" "REQS")
        local pcap=$(_get_meta_field "$mod_file" "PCAP")
        local decode=$(_get_meta_field "$mod_file" "DECODE")
        local tools=$(_get_meta_field "$mod_file" "TOOLS")

        # Populate global registries
        TC_REGISTRY["$tc_id"]="${name}|${cat}|${deps}|${crit}|${desc}"
        TC_REQUIREMENTS["$tc_id"]="$reqs"
        TC_PCAP_REQUIRED["$tc_id"]="$pcap"
        TC_DECODE_PROFILE["$tc_id"]="$decode"
        
        # Populate TOOL_TC_MAP
        if [[ -n "$tools" ]]; then
            # Split comma-separated tools
            local t_list=$(echo "$tools" | tr ',' ' ')
            for t in $t_list; do
                if [[ -z "${TOOL_TC_MAP[$t]:-}" ]]; then
                    TOOL_TC_MAP["$t"]="$tc_id"
                else
                    # Append if not already there
                    if [[ ",${TOOL_TC_MAP[$t]}," != *",${tc_id},"* ]]; then
                        TOOL_TC_MAP["$t"]="${TOOL_TC_MAP[$t]},$tc_id"
                    fi
                fi
            done
        fi
        
        found_tcs+=("$tc_id")
    done

    # Sort TC_ORDER (A1, A2, B1...)
    # Custom sort to handle alphanumeric IDs correctly
    IFS=$'\n' TC_ORDER=($(sort <<<"${found_tcs[*]}"))
    unset IFS
    
    log_debug "Discovered ${#TC_ORDER[@]} assessment modules."
}

#--- Helper: Get a field from TC_REGISTRY ---
get_tc_field() {
    local tc_id="$1"
    local field_idx="$2" # name=1, category=2, deps=3, critical=4, desc=5
    local entry="${TC_REGISTRY[$tc_id]:-}"
    [[ -n "$entry" ]] || return 1
    
    case "$field_idx" in
        "name") echo "$entry" | cut -d'|' -f1 ;;
        "category") echo "$entry" | cut -d'|' -f2 ;;
        "deps") echo "$entry" | cut -d'|' -f3 ;;
        "critical") echo "$entry" | cut -d'|' -f4 ;;
        "desc") echo "$entry" | cut -d'|' -f5 ;;
    esac
}
