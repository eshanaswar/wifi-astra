#!/usr/bin/env bash
#===============================================================================
#  modules/g4_nac_bypass.sh
#  G4: NAC / 802.1X Port Bypass
#
#  PURPOSE:
#    Test Network Access Control bypass techniques from the wireless side.
#    Attempts MAC whitelist bypass, wired-to-wireless pivoting assessment,
#    and checks for NAC exceptions or misconfigurations.
#
#  TOOLS: ${TOOL_PATHS[nmap]}, ${TOOL_PATHS[macchanger]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[ip]}
#  PHASE: 2B — Policy Validation
#  DEPENDENCIES: C2 (needs network scan data)
#
#  EVIDENCE PRODUCED:
#    - g4_mac_bypass.txt             (MAC spoofing test results)
#    - g4_port_scan.txt              (port accessibility results)
#    - g4_nac_analysis.txt           (NAC posture analysis)
#    - g4_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - nac_detected: bool — is NAC/802.1X enforced?
#    - mac_bypass_possible: bool
#    - restricted_ports_accessible: int
#    - vlan_assignment_changed: bool
#===============================================================================

run_g4() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/g4"
#--- Step 1: Verify tools ---
log_step 1 $total_steps "Verifying tools"
update_tc_progress 1 $total_steps "Checking"

local has_nmap=false
    ensure_managed_mode || return 1

    local iface="${WIFI_INTERFACE:-wlan0}"

    if [[ -z "${GATEWAY_IP:-}" || -z "${MY_IP:-}" ]]; then
        log_error "Network info not set. Ensure you are connected to the target network."
        return 1
    fi

    log_success "Interface: ${iface}, IP: ${MY_IP}, Gateway: ${GATEWAY_IP}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_YELLOW}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  NAC / 802.1X BYPASS TESTING                                     ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • Check for NAC enforcement (802.1X, MAB)                      ║"
    echo "  ║    • Test MAC address spoofing to bypass whitelist                ║"
    echo "  ║    • Scan for restricted ports accessible via target WiFi          ║"
    echo "  ║    • Test if VLAN assignment changes with different MACs          ║"
    echo "  ║                                                                    ║"
    echo "  ║  This will temporarily change your MAC address.                   ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with NAC bypass testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local nac_detected="false"
    local mac_bypass_possible="false"
    local restricted_ports_accessible=0
    local vlan_assignment_changed="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local mac_bypass_file="${evidence_prefix}_mac_bypass.txt"
    local port_scan_file="${evidence_prefix}_port_scan.txt"
    local nac_analysis_file="${evidence_prefix}_nac_analysis.txt"

    {
        echo "============================================================"
        echo "  G4: NAC / 802.1X Bypass Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${iface}, IP: ${MY_IP}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 2: Baseline — Current NAC posture ---
    log_step 2 $total_steps "Analyzing current NAC posture"
    update_tc_progress 2 $total_steps "NAC analysis"

    local orig_mac
    local orig_mac=$(${TOOL_PATHS[ip]} link show "$iface" | awk '/ether/{print $2}')
    local orig_ip="$MY_IP"
    local orig_dns="$DNS_SERVER"

    {
        echo "============================================================"
        echo "  NAC Posture Analysis"
        echo "============================================================"
        echo ""
        echo "Current state:"
        echo "  MAC: ${orig_mac}"
        echo "  IP:  ${MY_IP}"
        echo "  GW:  ${GATEWAY_IP}"
        echo "  DNS: ${DNS_SERVER:-unknown}"
        echo ""
    } > "$nac_analysis_file"

    # Check for 802.1X authentication prompts (EAP presence)
    local eap_check
    local eap_check=$(timeout 10 ${TOOL_PATHS[tcpdump]} -i "$iface" -c 5 \
        "ether proto 0x888e" 2>/dev/null | wc -l) || true
    local eap_check=${eap_check:-0}

    if [[ $eap_check -gt 0 ]]; then
        local nac_detected="true"
        echo "802.1X EAP frames detected — NAC is enforced" >> "$nac_analysis_file"
        log_result "INFO" "802.1X EAP frames detected — NAC is active"
    fi

    # Scan restricted ports from current position
    log_info "Scanning restricted enterprise ports..."
    local restricted_ports="88,135,389,445,636,1433,1521,3306,3389,5985,5986,8443"

    {
        echo "============================================================"
        echo "  Restricted Port Accessibility (Baseline)"
        echo "============================================================"
        echo ""
    } > "$port_scan_file"

    local baseline_scan
    local baseline_scan=$(${TOOL_PATHS[nmap]} -Pn -sT -p "$restricted_ports" "$GATEWAY_IP" \
        --max-retries 1 --host-timeout 30s -oG - 2>/dev/null || true)

    echo "$baseline_scan" >> "$port_scan_file"

    local baseline_open
    local baseline_open=$(echo "$baseline_scan" | grep -oP '\d+/open' | wc -l) || true
    local baseline_open=${baseline_open:-0}

    log_info "Baseline: ${baseline_open} restricted port(s) open from current position"
    echo "Baseline open restricted ports: ${baseline_open}" >> "$findings_file"

    check_abort || return 1

    #--- Step 3: MAC spoofing test ---
    log_step 3 $total_steps "Testing MAC address spoofing"
    update_tc_progress 3 $total_steps "MAC spoof test"

    {
        echo "============================================================"
        echo "  MAC Spoofing Test Results"
        echo "============================================================"
        echo ""
        echo "Original MAC: ${orig_mac}"
        echo ""
    } > "$mac_bypass_file"

    local has_macchanger=false
    command -v macchanger &>/dev/null && has_macchanger=true

    if [[ "$has_macchanger" == "true" ]]; then
        # Test 1: Random MAC
        log_info "Test: Connecting with random MAC address..."

        ${TOOL_PATHS[ip]} link set "$iface" down 2>/dev/null
        ${TOOL_PATHS[macchanger]} -r "$iface" &>/dev/null || true
        ${TOOL_PATHS[ip]} link set "$iface" up 2>/dev/null
        register_cleanup "${TOOL_PATHS[ip]} link set $iface down 2>/dev/null; ${TOOL_PATHS[macchanger]} -p $iface &>/dev/null || ${TOOL_PATHS[ip]} link set $iface address $orig_mac 2>/dev/null || true; ${TOOL_PATHS[ip]} link set $iface up 2>/dev/null; dhclient $iface &>/dev/null || true"

        local new_mac
        local new_mac=$(${TOOL_PATHS[ip]} link show "$iface" | awk '/ether/{print $2}')
        echo "Random MAC: ${new_mac}" >> "$mac_bypass_file"

        # Wait for DHCP
        sleep 5
        dhclient -r "$iface" &>/dev/null || true
        dhclient "$iface" &>/dev/null || true
        sleep 5

        local new_ip
        local new_ip=$(${TOOL_PATHS[ip]} -4 addr show "$iface" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

        if [[ -n "$new_ip" ]]; then
            echo "Got IP with random MAC: ${new_ip}" >> "$mac_bypass_file"
            log_info "Got IP ${new_ip} with random MAC ${new_mac}"

            # Check if we got a different VLAN/subnet
            local orig_subnet new_subnet
            local orig_subnet=$(echo "$orig_ip" | cut -d. -f1-3)
            local new_subnet=$(echo "$new_ip" | cut -d. -f1-3)

            if [[ "$orig_subnet" != "$new_subnet" ]]; then
                local vlan_assignment_changed="true"
                log_result "FINDING" "VLAN assignment changed with different MAC! ${orig_subnet}.x → ${new_subnet}.x"
                echo "FINDING: VLAN changed — ${orig_subnet}.x → ${new_subnet}.x" >> "$findings_file"
            fi

            # Can we still reach the gateway?
            if ping -c 2 -W 3 "$GATEWAY_IP" &>/dev/null; then
                local mac_bypass_possible="true"
                log_result "FINDING" "Network accessible with spoofed MAC — no MAC-based NAC"
                echo "FINDING: Network accessible with random MAC" >> "$mac_bypass_file"
            else
                log_info "Gateway unreachable with spoofed MAC — MAC filtering may be active"
                echo "INFO: Gateway unreachable with random MAC" >> "$mac_bypass_file"
            fi

            # Scan restricted ports with new MAC
            local spoof_scan
            local spoof_scan=$(${TOOL_PATHS[nmap]} -Pn -sT -p "$restricted_ports" "$GATEWAY_IP" \
                --max-retries 1 --host-timeout 30s -oG - 2>/dev/null || true)

            local spoof_open
            local spoof_open=$(echo "$spoof_scan" | grep -oP '\d+/open' | wc -l) || true
            local spoof_open=${spoof_open:-0}

            if [[ $spoof_open -gt $baseline_open ]]; then
                local restricted_ports_accessible=$((spoof_open - baseline_open))
                log_result "FINDING" "Additional ${restricted_ports_accessible} restricted port(s) accessible with spoofed MAC!"
                echo "FINDING: ${restricted_ports_accessible} more ports accessible with MAC spoof" >> "$findings_file"
            fi
        else
            log_info "No IP assigned with random MAC — MAC filtering may be active"
            echo "INFO: No IP with random MAC" >> "$mac_bypass_file"
        fi
    else
        log_info "${TOOL_PATHS[macchanger]} not available — skipping MAC spoof test"
        echo "SKIPPED: ${TOOL_PATHS[macchanger]} not available" >> "$mac_bypass_file"
    fi

    check_abort || return 1

    #--- Step 4: Test with known vendor OUIs ---
    log_step 4 $total_steps "Testing with known device vendor MACs"
    update_tc_progress 4 $total_steps "Vendor OUI test"

    # Try MACs with common enterprise device OUIs
    local -a vendor_macs=(
        "00:50:56"  # VMware — often whitelisted for VDI
        "F8:75:A4"  # Dell/HP — often whitelisted corporate endpoints
        "3C:22:FB"  # Apple — often whitelisted for BYOD
    )
    local -a vendor_names=("VMware" "Dell/HP" "Apple")

    if [[ "$has_macchanger" == "true" ]]; then
        for idx in "${!vendor_macs[@]}"; do
            local oui="${vendor_macs[$idx]}"
            local vendor="${vendor_names[$idx]}"

            ${TOOL_PATHS[ip]} link set "$iface" down 2>/dev/null
            local random_suffix
            local random_suffix=$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
            ${TOOL_PATHS[ip]} link set "$iface" address "${oui}:${random_suffix}" 2>/dev/null || continue
            ${TOOL_PATHS[ip]} link set "$iface" up 2>/dev/null

            sleep 3
            dhclient -r "$iface" &>/dev/null || true
            dhclient "$iface" &>/dev/null || true
            sleep 3

            local vendor_ip
            local vendor_ip=$(${TOOL_PATHS[ip]} -4 addr show "$iface" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

            if [[ -n "$vendor_ip" ]]; then
                echo "Vendor ${vendor} (${oui}:${random_suffix}): Got IP ${vendor_ip}" >> "$mac_bypass_file"

                local vendor_subnet
                local vendor_subnet=$(echo "$vendor_ip" | cut -d. -f1-3)
                if [[ "$vendor_subnet" != "$orig_subnet" ]]; then
                    log_result "FINDING" "${vendor} OUI → different VLAN: ${vendor_subnet}.x"
                    echo "FINDING: ${vendor} OUI assigned different VLAN" >> "$findings_file"
                fi
            else
                echo "Vendor ${vendor} (${oui}:${random_suffix}): No IP assigned" >> "$mac_bypass_file"
            fi

            check_abort || break
        done
    fi

    # Restore original MAC handled by register_cleanup
    #--- Step 6: RADIUS/NAC server detection ---
    log_step 6 $total_steps "Detecting RADIUS/NAC servers"
    update_tc_progress 6 $total_steps "RADIUS detection"

    # Scan for RADIUS ports (1812/1813) and NAC portals
    local radius_scan
    local radius_scan=$(${TOOL_PATHS[nmap]} -Pn -sU -p 1812,1813 "$GATEWAY_IP" \
        --max-retries 1 --host-timeout 15s -oG - 2>/dev/null || true)

    if echo "$radius_scan" | grep -q "open"; then
        local nac_detected="true"
        log_info "RADIUS port open on gateway — 802.1X infrastructure present"
        echo "INFO: RADIUS ports detected on gateway" >> "$nac_analysis_file"
    fi

    echo "" >> "$nac_analysis_file"
    echo "RADIUS scan:" >> "$nac_analysis_file"
    echo "$radius_scan" >> "$nac_analysis_file"

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$mac_bypass_possible" == "true" || "$vlan_assignment_changed" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="NAC bypass is possible. "
        [[ "$mac_bypass_possible" == "true" ]] && result_summary+="Network is accessible with spoofed MAC addresses — no MAC-based authentication. "
        [[ "$vlan_assignment_changed" == "true" ]] && result_summary+="VLAN assignment changes with different MAC OUIs — policy based on MAC vendor."
        [[ $restricted_ports_accessible -gt 0 ]] && result_summary+=" ${restricted_ports_accessible} additional restricted ports became accessible."
        local recommendations="1) Implement proper 802.1X authentication (not MAB alone). "
        recommendations+="2) Do not rely on MAC addresses for access decisions. "
        recommendations+="3) Use RADIUS-based dynamic VLAN assignment with certificate validation. "
        recommendations+="4) Enable sticky MAC or port security features. "
        recommendations+="5) Deploy a proper NAC solution (Cisco ISE, Aruba ClearPass, FortiNAC)."
    elif [[ "$nac_detected" == "true" ]]; then
        local result_summary="NAC/802.1X infrastructure detected and appears to be enforcing access control. MAC spoofing did not bypass controls."
        local recommendations="NAC appears properly configured. Periodically re-test and monitor for exceptions."
    else
        local result_summary="No MAC-based access control bypass detected. Network may not use NAC or uses alternative controls."
        local recommendations="Consider implementing 802.1X for all network access."
    fi

    local result_json
    evidence_register_file "g4_mac_bypass.txt"
    evidence_register_file "g4_port_scan.txt"
    evidence_register_file "g4_nac_analysis.txt"
    evidence_register_file "g4_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "NAC detected: ${nac_detected}, MAC bypass: ${mac_bypass_possible}, VLAN changed: ${vlan_assignment_changed}, Extra ports: ${restricted_ports_accessible}" \
        --arg recommendations "$recommendations" \
        --arg nac_detected "$nac_detected" \
        --arg mac_bypass_possible "$mac_bypass_possible" \
        --argjson restricted_ports_accessible "$restricted_ports_accessible" \
        --arg vlan_assignment_changed "$vlan_assignment_changed" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            nac_detected: ($nac_detected == "true"),
            mac_bypass_possible: ($mac_bypass_possible == "true"),
            restricted_ports_accessible: $restricted_ports_accessible,
            vlan_assignment_changed: ($vlan_assignment_changed == "true"),
                    }')

    save_tc_result "G4" "$result_json"

    echo ""
    if [[ "$mac_bypass_possible" == "true" ]]; then
        log_result "FINDING" "NAC bypass possible — network accessible with spoofed MAC"
    elif [[ "$vlan_assignment_changed" == "true" ]]; then
        log_result "FINDING" "VLAN assignment changes based on MAC OUI — policy bypass risk"
    else
        log_result "SECURE" "MAC-based bypass not successful — NAC appears enforced"
    fi

    return 0
}
