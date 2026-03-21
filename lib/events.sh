#!/usr/bin/env bash
#===============================================================================
#  lib/events.sh — Structured event logging (JSONL)
#
#  Writes an append-only events log per session:
#    ${SESSION_RESULTS_DIR}/events.jsonl
#===============================================================================

declare -g EVENTS_FILE=""

_events_init() {
    [[ -n "${SESSION_RESULTS_DIR:-}" ]] || return 1
    mkdir -p "$SESSION_RESULTS_DIR" 2>/dev/null || true
    EVENTS_FILE="${SESSION_RESULTS_DIR}/events.jsonl"
    return 0
}

log_event() {
    local event_type="$1"
    local tc_id="${2:-}"
    local message="${3:-}"

    _events_init || return 0

    local ts
    ts=$(date -Iseconds)

    if command -v jq &>/dev/null; then
        ${TOOL_PATHS[jq]} -cn \
            --arg ts "$ts" \
            --arg event "$event_type" \
            --arg tc "$tc_id" \
            --arg msg "$message" \
            --arg session "${SESSION_ID:-}" \
            --arg iface "${WIFI_INTERFACE:-}" \
            --arg mon "${MONITOR_INTERFACE:-}" \
            '{
              ts: $ts,
              event: $event,
              session_id: $session,
              tc_id: ($tc | select(length>0)),
              message: ($msg | select(length>0)),
              wifi_interface: ($iface | select(length>0)),
              monitor_interface: ($mon | select(length>0))
            }' >>"$EVENTS_FILE" 2>/dev/null || true
    else
        # Fallback: simple text line (still append-only)
        printf '%s\t%s\t%s\t%s\n' "$ts" "$event_type" "$tc_id" "$message" >>"$EVENTS_FILE" 2>/dev/null || true
    fi
}

