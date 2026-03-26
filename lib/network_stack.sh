#!/usr/bin/env bash
#===============================================================================
#  lib/network_stack.sh — Interface & Connection Management
#===============================================================================

set -uo pipefail

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
    safe_read "Select interface [1-$((idx-1))]: " iface_choice
    
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
    # 1. If we already have a valid monitor interface, just verify it's UP
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        if iw dev "$MONITOR_INTERFACE" info &>/dev/null; then
            local type=$(iw dev "$MONITOR_INTERFACE" info | awk '/type/{print $2}')
            if [[ "$type" == "monitor" ]]; then
                ip link set "$MONITOR_INTERFACE" up 2>/dev/null || true
                return 0
            fi
        fi
    fi
    
    [[ -z "${WIFI_INTERFACE:-}" ]] && { configure_network || return 1; }
    
    log_info "Enabling monitor mode on ${WIFI_INTERFACE}..."
    
    # 2. Kill interfering processes (Essential for in-place mode switching)
    log_info "Stopping interfering processes (airmon-ng check kill)..."
    ${TOOL_PATHS[airmon-ng]} check kill &>/dev/null
    
    # 3. Perform in-place mode switch using airmon-ng (industry standard)
    # airmon-ng is the most robust tool for handling the variety of driver naming conventions
    if ! ${TOOL_PATHS[airmon-ng]} start "$WIFI_INTERFACE" > $TMP_DIR/airmon_start.log 2>&1; then
        # If airmon-ng fails, try raw iw fallback
        log_warn "airmon-ng failed. Attempting raw kernel mode switch..."
        ip link set "$WIFI_INTERFACE" down 2>/dev/null || true
        if ! iw dev "$WIFI_INTERFACE" set type monitor 2>/dev/null; then
            log_error "Kernel rejected monitor mode request for ${WIFI_INTERFACE}."
            return 1
        fi
        ip link set "$WIFI_INTERFACE" up 2>/dev/null || true
    fi
    
    # 4. Detect the resulting interface name
    # airmon-ng often renames 'wlan0' to 'wlan0mon'
    local detected_mon=""
    
    # Check for the expected airmon-ng suffix
    if iw dev "${WIFI_INTERFACE}mon" info &>/dev/null; then
        detected_mon="${WIFI_INTERFACE}mon"
    # Check if the name stayed the same but mode changed
    elif [[ "$(iw dev "$WIFI_INTERFACE" info 2>/dev/null | awk '/type/{print $2}')" == "monitor" ]]; then
        detected_mon="$WIFI_INTERFACE"
    # Scrape all interfaces for any monitor mode device
    else
        detected_mon=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | while read -r iface; do
            if [[ "$(iw dev "$iface" info | awk '/type/{print $2}')" == "monitor" ]]; then
                echo "$iface"
                break
            fi
        done | head -1)
    fi

    if [[ -n "$detected_mon" ]]; then
        MONITOR_INTERFACE="$detected_mon"
        
        # Ensure the interface is UP
        ip link set "$MONITOR_INTERFACE" up 2>/dev/null || true
        
        log_success "Monitor mode active: ${MONITOR_INTERFACE}"
        
        # Lock to target channel
        if [[ -n "${GUEST_CHANNEL:-}" ]]; then
            log_info "Tuning ${MONITOR_INTERFACE} to CH ${GUEST_CHANNEL}..."
            iw dev "$MONITOR_INTERFACE" set channel "$GUEST_CHANNEL" 2>/dev/null || true
        fi
        
        save_session_state
        return 0
    else
        log_error "Could not identify monitor interface after setup."
        return 1
    fi
}

#--- Restore NetworkManager service if it was stopped ---
restore_network_manager() {
    log_info "Ensuring NetworkManager is running..."
    # Check if NetworkManager is inactive
    if ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        log_info "Restarting NetworkManager..."
        systemctl restart NetworkManager 2>/dev/null || service network-manager restart 2>/dev/null || true
        # Wait a bit for it to initialize
        sleep 2
    fi
}

#--- Comprehensive cleanup of all wireless interfaces ---
scrub_interfaces() {
    log_debug "Scrubbing wireless interfaces to a clean state..."

    # Detect all virtual monitor interfaces (mon0, wlan0mon, etc.)
    local virtual_ifaces
    virtual_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E "mon[0-9]+|wlan[0-9]+mon|[a-z0-9]+mon")

    for iface in $virtual_ifaces; do
        log_debug "Stopping virtual interface: $iface"
        # Use airmon-ng if available
        if [[ -n "${TOOL_PATHS[airmon-ng]:-}" ]]; then
            ${TOOL_PATHS[airmon-ng]} stop "$iface" &>/dev/null || true
        fi
        
        # If it still exists and is not our primary interface, delete it via iw
        if iw dev "$iface" info &>/dev/null; then
            if [[ "$iface" != "${WIFI_INTERFACE:-}" ]]; then
                log_debug "Deleting remaining virtual device: $iface"
                iw dev "$iface" del 2>/dev/null || true
            fi
        fi
    done

    # Ensure the physical device is in managed mode and up
    if [[ -n "${WIFI_INTERFACE:-}" ]]; then
        local type
        type=$(iw dev "$WIFI_INTERFACE" info 2>/dev/null | awk '/type/{print $2}')
        if [[ "$type" != "managed" ]]; then
            log_info "Restoring ${WIFI_INTERFACE} to managed mode..."
            ip link set "$WIFI_INTERFACE" down 2>/dev/null || true
            iw dev "$WIFI_INTERFACE" set type managed 2>/dev/null || true
            ip link set "$WIFI_INTERFACE" up 2>/dev/null || true
        fi
    fi

    # Reliable NetworkManager restoration
    restore_network_manager

    MONITOR_INTERFACE=""
    save_session_state 2>/dev/null || true
}

disable_monitor_mode() {
    scrub_interfaces
}

ensure_managed_mode() {
    # Only scrub if we actually have virtual monitor interfaces
    local virtual_ifaces
    virtual_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -E "mon[0-9]+|wlan[0-9]+mon|[a-z0-9]+mon")
    
    if [[ -n "$virtual_ifaces" ]]; then
        scrub_interfaces
    else
        # Even if no virtual ifaces, ensure physical iface is managed
        if [[ -n "${WIFI_INTERFACE:-}" ]]; then
            local type
            type=$(iw dev "$WIFI_INTERFACE" info 2>/dev/null | awk '/type/{print $2}')
            if [[ "$type" != "managed" ]]; then
                scrub_interfaces
            fi
        fi
    fi
    return 0
}

ensure_connected_wifi() {
    [[ -n "${WIFI_INTERFACE:-}" ]] || { configure_network || return 1; }
    ensure_managed_mode || return 1

    # Get current IP and link status
    local ip_addr link
    ip_addr=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    link=$(iw dev "$WIFI_INTERFACE" link 2>/dev/null || true)

    if [[ -z "$ip_addr" ]] || echo "$link" | grep -q "Not connected"; then
        if [[ "${HEADLESS_MODE:-0}" == "1" ]]; then
            log_error "Headless mode: Interface ${WIFI_INTERFACE} is not connected to WiFi."
            return 1
        fi
        
        log_warn "Not connected to WiFi on ${WIFI_INTERFACE}."
        echo -e "${C_YELLOW}  Please connect to '${GUEST_SSID:-the target network}' first.${C_RESET}"
        safe_read "Press Enter after connecting (or Q to skip)" _
        [[ "${_,,}" == "q" ]] && return 1
        
        # Refresh after wait
        ip_addr=$(${TOOL_PATHS[ip]} -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    fi

    if [[ -z "$ip_addr" ]]; then
        log_error "Still no IP address on ${WIFI_INTERFACE}."
        return 1
    fi

    # Final refresh of globals
    MY_IP="$ip_addr"
    GATEWAY_IP=$(${TOOL_PATHS[ip]} route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)
    export MY_IP GATEWAY_IP
    return 0
}
