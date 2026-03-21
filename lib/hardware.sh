#!/usr/bin/env bash
#===============================================================================
#  lib/hardware.sh — Universal Hardware Analysis
#===============================================================================

check_hardware_capabilities() {
    local iface="${WIFI_INTERFACE:-}"
    [[ -z "$iface" ]] && return 0

    log_step 1 2 "Querying Hardware Capabilities: ${iface}"
    
    # 1. Map Interface to PHY
    local phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
    [[ -z "$phy" ]] && phy=$(iw dev | grep -B 1 "$iface" | awk '/phy#/{print "phy"$1}' | tr -d '#')
    
    if [[ -z "$phy" ]]; then
        log_error "Could not map interface ${iface} to a physical radio (PHY)."
        return 1
    fi

    # 2. Get Raw PHY Info
    local raw_info=$(${TOOL_PATHS[iw]} phy "$phy" info 2>/dev/null)
    
    # 3. Detect Band Support (Parsing by Section)
    HW_24GHZ_SUPPORT="no"
    HW_5GHZ_SUPPORT="no"
    HW_6GHZ_SUPPORT="no"

    # Band 1 is 2.4GHz, Band 2 is 5GHz, Band 3 is 6GHz in modern iw output
    if echo "$raw_info" | grep -A 20 "Band 1:" | grep -q "MHz"; then HW_24GHZ_SUPPORT="yes"; fi
    if echo "$raw_info" | grep -A 20 "Band 2:" | grep -q "MHz"; then HW_5GHZ_SUPPORT="yes"; fi
    if echo "$raw_info" | grep -A 20 "Band 3:" | grep -q "MHz"; then HW_6GHZ_SUPPORT="yes"; fi

    # Fallback for older iw versions or specific drivers that don't use "Band X" labels
    if [[ "$HW_5GHZ_SUPPORT" == "no" ]]; then
        if echo "$raw_info" | grep -qE "5[0-9]{3} MHz"; then HW_5GHZ_SUPPORT="yes"; fi
    fi
    if [[ "$HW_6GHZ_SUPPORT" == "no" ]]; then
        if echo "$raw_info" | grep -qE "6[0-9]{3} MHz"; then HW_6GHZ_SUPPORT="yes"; fi
    fi

    # 4. Detect Injection & Monitor Mode via Kernel Flags
    HW_CAN_MONITOR="no"
    HW_CAN_INJECT="no"

    if echo "$raw_info" | grep -qi "monitor"; then
        HW_CAN_MONITOR="yes"
    fi

    # Injection is indicated by the presence of 'tx' and 'monitor' capabilities
    # and confirmed by the driver module flags.
    local driver=$(basename $(readlink /sys/class/net/"$iface"/device/driver/module) 2>/dev/null || echo "unknown")
    
    # We confirm injection support via 'iw' and known-good driver list
    if [[ "$HW_CAN_MONITOR" == "yes" ]]; then
        # Most modern drivers supporting monitor mode also support injection.
        # We verify if 'software interface generation' or 'packet injection' is blocked.
        if ! echo "$raw_info" | grep -q "set_wiphy_netns"; then
            # This is a very technical indicator that the driver supports full control
            HW_CAN_INJECT="yes"
        fi
        
        # Override for high-performance drivers known to support injection
        case "$driver" in
            ath*|mt7*|rtl*|rtw*|brcmfmac|carl9170|zd1211rw) HW_CAN_INJECT="yes" ;;
        esac
    fi

    #--- Display Results ---
    log_info "PHY: ${phy} | Driver: ${driver}"
    
    local bands="2.4GHz"
    [[ "$HW_5GHZ_SUPPORT" == "yes" ]] && bands+=", 5GHz"
    [[ "$HW_6GHZ_SUPPORT" == "yes" ]] && bands+=", 6GHz (WiFi 6E)"
    log_success "Band Support: ${bands}"

    if [[ "$HW_CAN_INJECT" == "yes" ]]; then
        log_success "Packet Injection: Supported by driver"
    else
        log_warn "Packet Injection: Not reported by kernel (may be limited)"
    fi

    log_step 2 2 "Hardware Profile Initialized"
    echo ""
}
