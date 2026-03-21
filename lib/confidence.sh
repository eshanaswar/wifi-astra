#!/usr/bin/env bash
#===============================================================================
#  lib/confidence.sh — Confidence scoring helpers (LOW/MEDIUM/HIGH)
#===============================================================================

# Compute confidence from checklist booleans (0/1) and a few caps.
# Usage:
#   confidence_from_flags <pcap_required> <has_tool_output> <has_primary_artifact> \
#                         <has_commands> <has_versions> <has_environment> \
#                         <has_independent_confirm> <has_known_good_target> \
#                         <adequate_runtime> <clean_run> <is_secure_claim>
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

    (( has_tool_output )) && (( score+=20 ))
    (( has_cmds ))        && (( score+=10 ))
    (( has_versions ))    && (( score+=10 ))
    (( has_env ))         && (( score+=20 ))
    (( has_primary ))     && (( score+=20 ))
    (( has_confirm ))     && (( score+=20 ))
    (( adequate_runtime ))&& (( score+=10 ))
    (( clean_run ))       && (( score+=10 ))
    (( has_known_target ))&& (( score+=15 ))

    # Caps / penalties
    if (( pcap_required )) && (( ! has_primary )); then
        echo "LOW"
        return 0
    fi
    if (( is_secure_claim )) && (( ! has_known_target )); then
        # Can't exceed MEDIUM for SECURE without known-good target
        if (( score >= 75 )); then
            echo "MEDIUM"
            return 0
        fi
    fi
    if (( ! clean_run )); then
        # Errors/aborts cap confidence
        if (( score >= 40 )); then
            echo "LOW"
            return 0
        fi
    fi

    if (( score >= 75 )); then
        echo "HIGH"
    elif (( score >= 40 )); then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

