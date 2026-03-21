#!/usr/bin/env bash
#===============================================================================
#  lib/evidence.sh — Evidence registration + session manifest
#
#  Maintains a per-TC list of evidence files and writes/updates a session-level
#  evidence manifest JSON:
#    ${SESSION_DIR}/evidence_manifest.json
#===============================================================================

declare -ga TC_EVIDENCE_FILES=()
declare -g  TC_EVIDENCE_TC_ID=""

evidence_tc_start() {
    TC_EVIDENCE_FILES=()
    TC_EVIDENCE_TC_ID="$1"
}

evidence_register_file() {
    local file_path="$1"
    local label="${2:-evidence}"

    [[ -n "${TC_EVIDENCE_TC_ID:-}" ]] || return 0
    [[ -n "$file_path" ]] || return 0

    # Store relative file names when inside session evidence dir
    local rel="$file_path"
    if [[ -n "${SESSION_DIR:-}" ]] && [[ "$file_path" == "${SESSION_DIR}/"* ]]; then
        rel="${file_path#${SESSION_DIR}/}"
    fi
    # Avoid duplicates
    local existing
    for existing in "${TC_EVIDENCE_FILES[@]}"; do
        [[ "$existing" == "$rel" ]] && return 0
    done
    TC_EVIDENCE_FILES+=("$rel")

    # Generate sidecar hash file
    evidence_generate_hash "$file_path" || true

    # Best-effort: append to manifest now
    evidence_manifest_add "$TC_EVIDENCE_TC_ID" "$file_path" "$label" || true
}

evidence_generate_hash() {
    local file_path="$1"
    [[ -f "$file_path" ]] || return 1
    
    # Don't hash already hashed files or sidecar files
    [[ "$file_path" == *.sha256 ]] && return 0
    
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file_path" > "${file_path}.sha256" 2>/dev/null
        return 0
    fi
    return 1
}

evidence_autoregister_by_prefix() {
    # Register evidence files written by modules that follow the convention:
    #   ${SESSION_EVIDENCE_DIR}/${tc_id,,}*
    local tc_id="$1"
    [[ -n "${SESSION_EVIDENCE_DIR:-}" ]] || return 0
    local prefix="${SESSION_EVIDENCE_DIR}/${tc_id,,}"
    local f
    shopt -s nullglob
    for f in "${prefix}"*; do
        [[ -f "$f" ]] || continue
        evidence_register_file "$f" "module_output"
    done
    shopt -u nullglob
}

evidence_list_json_array() {
    # Print JSON array of evidence file names (relative)
    if command -v jq &>/dev/null; then
        printf '%s\n' "${TC_EVIDENCE_FILES[@]}" | ${TOOL_PATHS[jq]} -R . | ${TOOL_PATHS[jq]} -s .
    else
        # Minimal JSON without ${TOOL_PATHS[jq]} (best effort)
        printf '['
        local first=1
        local f
        for f in "${TC_EVIDENCE_FILES[@]}"; do
            [[ $first -eq 1 ]] || printf ','
            first=0
            printf '"%s"' "${f//\"/\\\"}"
        done
        printf ']'
    fi
}

evidence_manifest_add() {
    local tc_id="$1"
    local file_path="$2"
    local label="${3:-evidence}"

    [[ -n "${SESSION_DIR:-}" ]] || return 1
    mkdir -p "$SESSION_DIR" 2>/dev/null || true

    local manifest="${SESSION_DIR}/evidence_manifest.json"
    local ts size sha
    ts=$(date -Iseconds)
    size=0
    sha=""
    if [[ -f "$file_path" ]]; then
        size=$(stat -c '%s' "$file_path" 2>/dev/null || echo 0)
        if command -v sha256sum &>/dev/null; then
            sha=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}' || true)
        fi
    fi

    if ! command -v jq &>/dev/null; then
        # If ${TOOL_PATHS[jq]} is missing, skip manifest JSON (events/tool output still exist)
        return 0
    fi

    # Ensure manifest exists and is valid JSON array
    if [[ ! -f "$manifest" ]] || ! ${TOOL_PATHS[jq]} -e . "$manifest" &>/dev/null; then
        echo "[]" >"$manifest"
    fi

    ${TOOL_PATHS[jq]} \
      --arg ts "$ts" \
      --arg tc "$tc_id" \
      --arg file "$file_path" \
      --arg label "$label" \
      --arg sha "$sha" \
      --argjson size "${size:-0}" \
      '. + [{
        ts: $ts,
        tc_id: $tc,
        file: $file,
        label: $label,
        size: $size,
        sha256: ($sha | select(length>0))
      }]' "$manifest" >"${manifest}.tmp" && mv "${manifest}.tmp" "$manifest"
}

#--- Finalize evidence permissions ---
# Ensures all generated evidence files are readable by the user who invoked sudo.
finalize_evidence_permissions() {
    [[ -n "${SESSION_DIR:-}" && -d "${SESSION_DIR}" ]] || return 0
    
    # If SUDO_USER is set, chown the session directory to that user
    if [[ -n "${SUDO_USER:-}" ]]; then
        local user_group
        user_group=$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")
        chown -R "${SUDO_USER}:${user_group}" "$SESSION_DIR" 2>/dev/null || true
    fi
    
    # Ensure readable permissions
    chmod -R 755 "$SESSION_DIR" 2>/dev/null || true
    find "$SESSION_DIR" -type f -exec chmod 644 {} + 2>/dev/null || true
}

