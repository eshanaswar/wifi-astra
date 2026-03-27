#!/usr/bin/env bash
#===============================================================================
#  lib/hardware.sh — Universal Hardware Analysis
#===============================================================================

set -uo pipefail

validate_injection() {
    local iface="$1"
    [[ -z "$iface" ]] && return 1

    log_step 1 1 "Testing Packet Injection on ${iface}"
    
    # 1. Verify Mode First
    local type=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$type" != "monitor" ]]; then
        log_error "Interface ${iface} is not in monitor mode (current: ${type})."
        log_info "Attempting to force monitor mode..."
        if ! enable_monitor_mode; then
            log_error "Failed to switch to monitor mode. Injection test aborted."
            return 1
        fi
        # Re-check iface name as it might have changed (e.g. wlan0 -> wlan0mon)
        iface="${MONITOR_INTERFACE:-$iface}"
    fi

    echo -e "  ${C_GRAY}Tuning to various channels and sending probe requests...${C_RESET}"
    echo -e "  ${C_GRAY}This may take up to 30 seconds.${C_RESET}"
    echo ""
    
    # Resolve tool path
    local aireplay_path="${TOOL_PATHS[aireplay-ng]:-}"
    if [[ -z "$aireplay_path" ]]; then
        aireplay_path=$(command -v aireplay-ng)
    fi

    if [[ -z "$aireplay_path" ]] || [[ ! -x "$aireplay_path" ]]; then
        log_error "aireplay-ng not found or not executable."
        return 1
    fi

    # Create a temporary file to capture output for parsing while still showing it to the user
    local tmp_out
    tmp_out=$(mktemp)

    # Disable echo to prevent keystroke leakage during the long-running test
    disable_echo

    # Run aireplay-ng --test and pipe to both console and temp file
    # We use a 45s timeout to give the driver enough time to cycle channels
    ( timeout 45s "$aireplay_path" --test "$iface" 2>&1 | tee "$tmp_out" ) || true
    
    # Restore echo and clear buffer
    clear_stdin
    enable_echo

    local output
    output=$(cat "$tmp_out")
    rm -f "$tmp_out"
    echo ""

    # Parse for "Injection is working!"
    if echo "$output" | grep -q "Injection is working!"; then
        local percentage
        percentage=$(echo "$output" | grep -oP "[0-9]+(?=%)" | head -1)
        
        log_success "Packet Injection is working on ${iface}!"
        [[ -n "$percentage" ]] && log_info "Success Rate: ${percentage}%"
        
        # Threshold check
        if [[ -n "$percentage" ]] && [[ "$percentage" -lt 50 ]]; then
            log_warn "Injection success rate is low (${percentage}%)."
            local force_choice="n"
            safe_read "Minimum 50% recommended. Proceed anyway? [y/N]" force_choice "n"
            [[ "${force_choice,,}" == "y" ]] || return 1
        fi
        return 0
    else
        log_critical "Packet Injection test FAILED on ${iface}."
        echo -e "${C_YELLOW}  Possible causes:${C_RESET}"
        echo -e "  1. No active Access Points nearby to respond to probes."
        echo -e "  2. Wireless card driver does not support packet injection."
        echo -e "  3. Interface is not properly in monitor mode."
        echo ""
        
        local force_fail="n"
        safe_read "Do you want to ignore this failure and FORCE active testing? [y/N]" force_fail "n"
        if [[ "${force_fail,,}" == "y" ]]; then
            log_warn "User forced injection mode. Expect potential tool failures."
            HW_CAN_INJECT="yes"
            return 0
        fi
        return 1
    fi
}
check_hardware_capabilities() {
    local iface="${1:-${WIFI_INTERFACE:-}}"
    [[ -z "$iface" ]] && return 0

    log_step 1 2 "Querying Hardware Capabilities: ${iface}"

    # 1. Map Interface to PHY
    # Method A: Direct lookup via 'iw dev <iface> info'
    local phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')

    # Method B: Search the full 'iw dev' output for the interface block
    if [[ -z "$phy" ]]; then
        # Use awk to find the PHY associated with the interface name
        phy=$(iw dev 2>/dev/null | awk -v iface="$iface" '
            /^phy#/ { current_phy = "phy" substr($1, 5) }
            /Interface/ { 
                if ($2 == iface) { 
                    print current_phy
                    exit 
                }
            }
        ')
    fi

    # Method C: Virtual Interface Parent Resolution (Check if it's a monitor child)
    if [[ -z "$phy" ]] && [[ "$iface" == *mon ]]; then
        local base_iface="${iface%mon}"
        log_debug "Detected potential monitor interface. Checking parent: ${base_iface}"
        phy=$(iw dev "$base_iface" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
    fi

    # Method D: Look up by sysfs (works even if iw is weird)
    if [[ -z "$phy" ]]; then
        if [[ -d "/sys/class/net/$iface/phy80211" ]]; then
            phy=$(basename "$(readlink "/sys/class/net/$iface/phy80211" 2>/dev/null || echo "")")
        fi
    fi
    
    if [[ -z "$phy" ]]; then
        log_error "Could not map interface ${iface} to a physical radio (PHY)."
        log_debug "Dumping raw interface state for diagnosis:"
        log_debug "iw dev output:\n$(iw dev 2>&1)"
        log_debug "sysfs check: $(ls -l /sys/class/net/"$iface"/phy80211 2>&1)"
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

    # Resolve actual driver using ethtool (most reliable)
    # If it's a monitor interface, try the base name first
    local check_iface="$iface"
    [[ "$iface" == *mon ]] && check_iface="${iface%mon}"
    
    local driver
    driver=$(ethtool -i "$check_iface" 2>/dev/null | awk '/driver/{print $2}')
    [[ -z "$driver" ]] && driver=$(basename $(readlink /sys/class/net/"$iface"/device/driver/module) 2>/dev/null || echo "unknown")
    
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
