#!/usr/bin/env bash
#===============================================================================
#  lib/network_stack.sh — Interface & Connection Management
#===============================================================================

configure_network() {
    echo ""
    echo -e "${C_CYAN}───────────────────────────────────────────────────────────────────${C_RESET}"
    echo -e "  ${C_BOLD}NETWORK CONFIGURATION${C_RESET}"
    echo -e "${C_CYAN}───────────────────────────────────────────────────────────────────${C_RESET}"
    echo ""
    
    # Detect wireless interfaces
    echo -e "  ${C_BOLD}Available wireless interfaces:${C_RESET}"
    local ifaces
    ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')
    
    if [[ -z "$ifaces" ]]; then
        log_error "No wireless interfaces detected."
        log_info "Ensure your WiFi adapter is connected and recognized."
        return 1
    fi
    
    local idx=1
    local -a iface_list=()
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        local driver
        driver=$(ethtool -i "$iface" 2>/dev/null | awk '/driver/{print $2}' || echo "unknown")
        local mac
        mac=$(${TOOL_PATHS[ip]} link show "$iface" 2>/dev/null | awk '/ether/{print $2}')
        echo -e "    [${idx}] ${iface}  (Driver: ${driver}, MAC: ${mac})"
        iface_list+=("$iface")
        ((idx++))
    done <<< "$ifaces"
    
    echo ""
    local iface_choice
    read -rep "  Select interface [1-$((idx-1))]: " iface_choice
    
    if [[ "$iface_choice" =~ ^[0-9]+$ ]] && [[ $iface_choice -ge 1 ]] && [[ $iface_choice -le ${#iface_list[@]} ]]; then
        WIFI_INTERFACE="${iface_list[$((iface_choice-1))]}"
        MY_MAC=$(${TOOL_PATHS[ip]} link show "$WIFI_INTERFACE" 2>/dev/null | awk '/ether/{print $2}')
        log_success "Selected interface: ${WIFI_INTERFACE} (${MY_MAC})"
    else
        log_error "Invalid selection."
        return 1
    fi
    
    # Auto-detect gateway and IP if connected
    MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    GATEWAY_IP=$(${TOOL_PATHS[ip]} route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
    DNS_SERVER=$(resolvectl dns "$WIFI_INTERFACE" 2>/dev/null | awk '{print $NF}' | head -1 || grep "nameserver" /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
    
    if [[ -n "$MY_IP" ]]; then
        log_info "Current IP:  ${MY_IP}"
        log_info "Gateway:     ${GATEWAY_IP:-unknown}"
        log_info "DNS Server:  ${DNS_SERVER:-unknown}"
    else
        log_info "Interface is not currently connected. IP will be detected during tests."
    fi
    
    save_session_state
    return 0
}

enable_monitor_mode() {
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        if iw dev "$MONITOR_INTERFACE" info &>/dev/null; then
            return 0
        fi
    fi
    
    [[ -z "${WIFI_INTERFACE:-}" ]] && { configure_network || return 1; }
    
    log_info "Enabling monitor mode on ${WIFI_INTERFACE}..."
    
    # Preferred: Virtual interface
    local mon_iface="mon0"
    local idx=0
    while iw dev "$mon_iface" info &>/dev/null; do ((idx++)); mon_iface="mon${idx}"; done

    if iw dev "${WIFI_INTERFACE}" interface add "${mon_iface}" type monitor 2>/dev/null; then
        ip link set "$mon_iface" up 2>/dev/null
        MONITOR_INTERFACE="$mon_iface"
        register_cleanup "iw dev $mon_iface del 2>/dev/null || true"
        log_success "Monitor interface created: ${MONITOR_INTERFACE}"
        save_session_state
        return 0
    fi

    # Fallback: airmon-ng
    log_warn "Virtual interface failed. Falling back to airmon-ng check kill..."
    ${TOOL_PATHS[airmon-ng]} check kill &>/dev/null
    ${TOOL_PATHS[airmon-ng]} start "$WIFI_INTERFACE" &>/dev/null
    
    MONITOR_INTERFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E "mon|wlan[0-9]+mon" | head -1)
    [[ -z "$MONITOR_INTERFACE" ]] && MONITOR_INTERFACE="$WIFI_INTERFACE"
    
    log_success "Monitor mode enabled: ${MONITOR_INTERFACE}"
    save_session_state
    return 0
}

disable_monitor_mode() {
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        log_info "Disabling monitor mode on ${MONITOR_INTERFACE}..."
        ${TOOL_PATHS[airmon-ng]} stop "$MONITOR_INTERFACE" &>/dev/null
        
        # If it was a virtual mon0, delete it
        if [[ "$MONITOR_INTERFACE" == mon* ]]; then
            iw dev "$MONITOR_INTERFACE" del 2>/dev/null
        fi
        
        MONITOR_INTERFACE=""
        systemctl start NetworkManager 2>/dev/null || service network-manager start 2>/dev/null
        save_session_state
    fi
}

ensure_managed_mode() {
    local mode=$(iw dev "${WIFI_INTERFACE:-wlan0}" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$mode" == "monitor" || -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 2
    fi
}

ensure_connected_wifi() {
    [[ -n "${WIFI_INTERFACE:-}" ]] || { configure_network || return 1; }
    ensure_managed_mode || return 1

    local ip_addr=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    local link=$(iw dev "$WIFI_INTERFACE" link 2>/dev/null || true)

    if [[ -z "$ip_addr" ]] || echo "$link" | grep -q "Not connected"; then
        log_warn "Not connected to WiFi on ${WIFI_INTERFACE}."
        read -rep "  Connect to ${GUEST_SSID:-target} and press Enter: " _
    fi

    # Refresh
    MY_IP=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    GATEWAY_IP=$(${TOOL_PATHS[ip]} route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
    export MY_IP GATEWAY_IP
    return 0
}
