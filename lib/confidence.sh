#!/usr/bin/env bash
#===============================================================================
#  lib/confidence.sh — Confidence scoring helpers (0-100)
#===============================================================================

set -uo pipefail

# Compute confidence from checklist booleans (0/1) and a few caps.
# Usage:
#   confidence_from_flags <pcap_required> <has_tool_output> <has_primary_artifact> \
#                         <has_commands> <has_versions> <has_environment> \
#                         <has_independent_confirm> <has_known_good_target> \
#                         <adequate_runtime> <clean_run> <is_secure_claim>
#
# Returns: "score|LABEL" (e.g., "85|HIGH")
confidence_from_flags() {
    local pcap_required="${1:-0}"
    local has_tool_output="${2:-0}"
    local has_primary="${3:-0}"
    local has_cmds="${4:-0}"
    local has_versions="${5:-0}"
    local has_env="${6:-0}"
    local has_confirm="${7:-0}"
    local has_known_target="${8:-0}"
    local adequate_runtime="${9:-0}"
    local clean_run="${10:-0}"
    local is_secure_claim="${11:-0}"

    local score=0

    # Weighted scoring (Total: 100)
    (( has_primary ))      && (( score += 25 )) # Essential artifact (PCAP, Handshake, etc.)
    (( has_tool_output ))  && (( score += 15 )) # Raw tool logs/output
    (( has_confirm ))      && (( score += 15 )) # Independent verification
    (( has_env ))          && (( score += 10 )) # System context (IPs, Ifaces)
    (( has_known_target )) && (( score += 10 )) # Target verification (BSSID/ESSID confirmed)
    (( adequate_runtime )) && (( score += 10 )) # Enough time for reliable results
    (( has_cmds ))         && (( score += 5 ))  # Reproducibility (CLI commands logged)
    (( has_versions ))     && (( score += 5 ))  # Versioning of tools
    (( clean_run ))        && (( score += 5 ))  # No errors or warnings

    # Caps / Penalties
    # 1. PCAP Required but missing
    if (( pcap_required )) && (( ! has_primary )); then
        (( score > 30 )) && score=30
        echo "${score}|LOW"
        return 0
    fi

    # 2. Secure claim without known-good target (e.g. "We are secure" but we didn't даже find the AP)
    if (( is_secure_claim )) && (( ! has_known_target )); then
        (( score > 60 )) && score=60
    fi

    # 3. Unclean run (errors occurred)
    if (( ! clean_run )); then
        (( score > 40 )) && score=40
    fi

    # Determine Label
    local label="LOW"
    if (( score >= 80 )); then
        label="HIGH"
    elif (( score >= 40 )); then
        label="MEDIUM"
    fi

    echo "${score}|${label}"
}
