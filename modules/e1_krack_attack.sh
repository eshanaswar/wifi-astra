#!/usr/bin/env bash
# MODULE_META
# NAME="KRACK Attack Testing"
# CATEGORY="E"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="tshark,krack-test"
# DESC="Test WPA2 key reinstallation (CVE-2017-13077), nonce reuse, GTK reinstall"
# REQS="monitor_iface,target_ssid,target_bssid,target_channel"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/e1_krack_attack.sh
#  E1: KRACK (Key Reinstallation Attack) Testing
#
#  PURPOSE:
#    Test if the target network's clients and APs are vulnerable to KRACK
#    (CVE-2017-13077 through CVE-2017-13088). KRACK exploits the WPA2
#    4-way handshake by forcing nonce reuse, allowing traffic decryption.
#    Many IoT devices and older clients remain unpatched.
#
#  TOOLS: krack-test (python), ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[aireplay-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - e1_krack_results.txt          (KRACK test results)
#    - e1_client_analysis.txt        (per-client vulnerability assessment)
#    - e1_nonce_capture.pcap         (captured handshake nonce data)
#    - e1_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - ap_vulnerable: bool
#    - clients_tested: int
#    - clients_vulnerable: int
#    - nonce_reuse_detected: bool
#    - gtk_reinstall_vulnerable: bool
#===============================================================================

set -uo pipefail

run_e1() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/e1"

    #--- Step 1: Verify tools & dependencies ---
    log_step 1 $total_steps "Verifying tools & dependencies"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "E1" || return 1
    
    local has_krack_test=false
    local has_tshark=false
    local has_aireplay=false
    local has_scapy=false

    # Check for krackattacks test scripts
    local krack_script=""
    for kpath in \
        "/opt/krackattacks-scripts/krackattack/krack_all_zero_tk.py" \
        "/usr/share/krackattacks/krack_all_zero_tk.py" \
        "${SCRIPT_DIR}/tools/krackattacks/krack_all_zero_tk.py" \
        "/opt/krackattacks/krack-ft-test.py"; do
        if [[ -f "$kpath" ]]; then
            krack_script="$kpath"
            has_krack_test=true
            break
        fi
    done

    command -v tshark &>/dev/null && has_tshark=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true
    python3 -c "from scapy.all import *" &>/dev/null 2>&1 && has_scapy=true

    if [[ "$has_krack_test" == "false" && "$has_scapy" == "false" ]]; then
        log_warn "krackattacks-scripts not found. Will perform passive nonce analysis only."
        log_info "For full KRACK testing, install: git clone https://github.com/vanhoefm/krackattacks-scripts /opt/krackattacks-scripts"
    fi

    if [[ "$has_tshark" == "false" ]]; then
        log_error "tshark is required for nonce analysis."
        return 1
    fi

    if [[ -z "${GUEST_SSID:-}" || -z "${GUEST_BSSID:-}" ]]; then
        log_warn "Target SSID/BSSID not set."
        if ! select_target_network; then
            log_error "No target selected. Run A1 first or enter manually."
            return 1
        fi
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID}) CH ${GUEST_CHANNEL:-auto}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ KRACK — KEY REINSTALLATION ATTACK TEST ★                     ║"
    echo "  ║                                                                    ║"
    echo "  ║  Tests for CVE-2017-13077 through CVE-2017-13088:                 ║"
    echo "  ║    • 4-way handshake nonce reuse (client-side)                    ║"
    echo "  ║    • Group key reinstallation (GTK)                               ║"
    echo "  ║    • FT (Fast BSS Transition) key reinstallation                  ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will capture handshakes and analyze nonce patterns.    ║"
    echo "  ║  Deauth frames will be sent to trigger handshake replays.        ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with KRACK testing? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local ap_vulnerable="false"
    local clients_tested=0
    local clients_vulnerable=0
    local nonce_reuse_detected="false"
    local gtk_reinstall_vulnerable="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local results_file="${evidence_prefix}_krack_results.txt"
    local client_analysis="${evidence_prefix}_client_analysis.txt"
    local nonce_pcap="${evidence_prefix}_nonce_capture.pcap"

    {
        echo "============================================================"
        echo "  E1: KRACK Attack Testing"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target: ${GUEST_SSID} (${GUEST_BSSID})"
        echo "  CVEs: CVE-2017-13077 to CVE-2017-13088"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  KRACK Test Results"
        echo "============================================================"
        echo ""
    } > "$results_file"

    #--- Step 2: Enable monitor mode ---
    log_step 2 $total_steps "Enabling monitor mode"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        run_fg "iw" dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Capture EAPOL handshakes with nonce tracking ---
    log_step 3 $total_steps "Capturing EAPOL handshakes for nonce analysis (90s)"
    update_tc_progress 3 $total_steps "Nonce capture"

    # Capture all EAPOL traffic
    spawn_bg "e1_tcpdump" "tcpdump" -i "$mon_iface" -w "$nonce_pcap" \
        "ether proto 0x888e or (type mgt subtype deauth) or (type mgt subtype auth)" \
        &>/dev/null

    # Send periodic deauths to trigger handshake re-negotiations
    if [[ "$has_aireplay" == "true" ]]; then
        log_info "Sending deauth bursts to trigger handshake retransmissions..."
        (
            for burst in $(seq 1 6); do
                sleep 10
                check_abort || break
                run_fg "aireplay-ng" --deauth 3 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
                sleep 5
            done
        ) &
        local deauth_pid=$!
        register_cleanup "kill -TERM $deauth_pid 2>/dev/null || true; wait $deauth_pid 2>/dev/null || true"
    fi

    start_countdown 90 "Capturing handshakes — analyzing nonce patterns"
    sleep 90
    stop_countdown

    # Stop deauth
    if [[ -n "${deauth_pid:-}" ]]; then
        kill -TERM "$deauth_pid" 2>/dev/null || true
        wait "$deauth_pid" 2>/dev/null || true
    fi

    # Stop capture
    stop_process "e1_tcpdump"
    
    validate_pcap "$nonce_pcap" "EAPOL nonce capture"

    check_abort || return 1

    #--- Step 4: Analyze nonces for reuse ---
    log_step 4 $total_steps "Analyzing handshake nonces for reuse patterns"
    update_tc_progress 4 $total_steps "Nonce analysis"

    {
        echo "============================================================"
        echo "  Per-Client Nonce Analysis"
        echo "============================================================"
        echo ""
    } > "$client_analysis"

    if [[ -f "$nonce_pcap" && -s "$nonce_pcap" ]]; then
        ensure_user_ownership "$nonce_pcap"
        # Extract EAPOL message 3 (from AP) — contains ANonce
        # If nonce repeats in msg3 retransmissions, client may not be patched
        local eapol_data
        eapol_data=$(run_as_user tshark -r "$nonce_pcap" \
            -Y "eapol && wlan.bssid == ${GUEST_BSSID}" \
            -T fields \
            -e wlan.sa \
            -e wlan.da \
            -e eapol.keydes.key_info \
            -e eapol.keydes.nonce \
            -e eapol.keydes.replay_counter \
            2>/dev/null || true)

        if [[ -n "$eapol_data" ]]; then
            echo "$eapol_data" >> "$results_file"

            # Count unique client MACs involved in EAPOL
            local client_macs
            client_macs=$(echo "$eapol_data" | awk '{print $2}' | sort -u | \
                grep -v "$GUEST_BSSID" | grep -v "ff:ff:ff:ff:ff:ff" || true)

            if [[ -n "$client_macs" ]]; then
                clients_tested=$(echo "$client_macs" | wc -l)
                log_info "Analyzing ${clients_tested} client(s) for nonce reuse..."

                while IFS= read -r client_mac; do
                    [[ -z "$client_mac" ]] && continue

                    # Extract nonces for this client's handshakes
                    local client_nonces
                    client_nonces=$(run_as_user tshark -r "$nonce_pcap" \
                        -Y "eapol && (wlan.da == ${client_mac} || wlan.sa == ${client_mac})" \
                        -T fields \
                        -e eapol.keydes.nonce \
                        2>/dev/null | grep -v "^$" | sort || true)

                    local total_nonces unique_nonces
                    total_nonces=$(echo "$client_nonces" | wc -l) || true
                    unique_nonces=$(echo "$client_nonces" | sort -u | wc -l) || true

                    echo "Client: ${client_mac}" >> "$client_analysis"
                    echo "  Total nonces: ${total_nonces:-0}" >> "$client_analysis"
                    echo "  Unique nonces: ${unique_nonces:-0}" >> "$client_analysis"

                    if [[ ${total_nonces:-0} -gt ${unique_nonces:-0} && ${total_nonces:-0} -gt 1 ]]; then
                        local reused=$((total_nonces - unique_nonces))
                        nonce_reuse_detected="true"
                        ((clients_vulnerable++))
                        echo "  STATUS: ★ NONCE REUSE DETECTED (${reused} reuses) — POTENTIALLY VULNERABLE" >> "$client_analysis"
                        log_result "FINDING" "Client ${client_mac}: nonce reuse detected (${reused} reuses) — potentially KRACK vulnerable"
                        echo "FINDING: Client ${client_mac} shows nonce reuse" >> "$findings_file"
                    else
                        echo "  STATUS: No nonce reuse detected — likely patched" >> "$client_analysis"
                    fi
                    echo "" >> "$client_analysis"
                done <<< "$client_macs"
            fi

            # Check for GTK reinstallation (group key message replays)
            local gtk_msgs
            gtk_msgs=$(run_as_user tshark -r "$nonce_pcap" \
                -Y "eapol && eapol.keydes.key_info == 0x1381" \
                -T fields \
                -e eapol.keydes.replay_counter \
                2>/dev/null | sort || true)

            if [[ -n "$gtk_msgs" ]]; then
                local gtk_total gtk_unique
                gtk_total=$(echo "$gtk_msgs" | wc -l) || true
                gtk_unique=$(echo "$gtk_msgs" | sort -u | wc -l) || true

                if [[ ${gtk_total:-0} -gt ${gtk_unique:-0} ]]; then
                    gtk_reinstall_vulnerable="true"
                    ap_vulnerable="true"
                    log_result "FINDING" "GTK reinstallation detected — AP may be vulnerable to group key attack"
                    echo "FINDING: GTK message replay detected — AP potentially vulnerable" >> "$findings_file"
                fi
                echo "GTK messages: total=${gtk_total:-0}, unique=${gtk_unique:-0}" >> "$results_file"
            fi
        else
            log_info "No EAPOL frames captured — try with more active clients on the network"
            echo "INFO: No EAPOL data captured in 90s window" >> "$findings_file"
        fi
    fi

    #--- Step 5: Run krackattacks-scripts (if available) ---
    log_step 5 $total_steps "Running KRACK test scripts (if available)"
    update_tc_progress 5 $total_steps "KRACK scripts"

    check_abort || return 1

    if [[ "$has_krack_test" == "true" && -n "$krack_script" ]]; then
        log_info "Running krackattacks test script: $(basename "$krack_script")"
        log_cmd "python3 ${krack_script} --interface ${mon_iface} --bssid ${GUEST_BSSID}"

        local krack_output
        krack_output=$(timeout 120 python3 "$krack_script" \
            --interface "$mon_iface" \
            --bssid "$GUEST_BSSID" \
            2>&1 || true)

        echo "" >> "$results_file"
        echo "=== krackattacks-scripts Output ===" >> "$results_file"
        echo "$krack_output" >> "$results_file"

        if echo "$krack_output" | grep -qi "vulnerable"; then
            ap_vulnerable="true"
            log_result "CRITICAL" "★ KRACK vulnerability confirmed by test scripts!"
            echo "CRITICAL: KRACK vulnerability confirmed" >> "$findings_file"
        elif echo "$krack_output" | grep -qi "not vulnerable\|patched"; then
            log_success "KRACK test scripts report: NOT vulnerable / patched"
        fi
    else
        log_info "krackattacks-scripts not installed — using passive nonce analysis only"
        echo "" >> "$results_file"
        echo "NOTE: Install krackattacks-scripts for active KRACK testing:" >> "$results_file"
        echo "  git clone https://github.com/vanhoefm/krackattacks-scripts /opt/krackattacks-scripts" >> "$results_file"
    fi

    #--- Step 6: Restore managed mode ---
    log_step 6 $total_steps "Restoring managed mode"
    update_tc_progress 6 $total_steps "Cleanup"

    disable_monitor_mode
    sleep 3

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$ap_vulnerable" == "true" || $clients_vulnerable -gt 0 ]]; then
        result_status="FINDING"
        result_summary="KRACK vulnerability indicators detected. "
        [[ "$nonce_reuse_detected" == "true" ]] && result_summary+="${clients_vulnerable}/${clients_tested} client(s) show nonce reuse patterns. "
        [[ "$gtk_reinstall_vulnerable" == "true" ]] && result_summary+="GTK reinstallation vulnerability detected on AP. "
        [[ "$ap_vulnerable" == "true" ]] && result_summary+="AP may be vulnerable to key reinstallation."
        recommendations="1) Update ALL client device firmware/drivers — KRACK patches available since late 2017. "
        recommendations+="2) Update AP firmware to include KRACK countermeasures. "
        recommendations+="3) Prioritize IoT devices which are often unpatched. "
        recommendations+="4) Enable 802.11w (MFP) to reduce deauth-based handshake triggering. "
        recommendations+="5) Consider WPA3-SAE which is not vulnerable to KRACK. "
        recommendations+="6) Deploy WIDS to detect repeated handshake retransmissions."
    elif [[ $clients_tested -gt 0 ]]; then
        result_summary="Tested ${clients_tested} client(s) for KRACK vulnerability — no nonce reuse patterns detected. Devices appear to be patched."
        recommendations="Continue monitoring for unpatched devices connecting to the network."
    else
        result_summary="No EAPOL handshakes captured for KRACK analysis. Network may have low client activity or uses WPA3."
        recommendations="Re-test during peak usage hours or with known test clients."
    fi

    local result_json
    evidence_register_file "$results_file"
    evidence_register_file "$client_analysis"
    evidence_register_file "$nonce_pcap"
    evidence_register_file "$findings_file"

    result_json=$(run_fg "jq" -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "AP vulnerable: ${ap_vulnerable}, Clients tested: ${clients_tested}, Vulnerable: ${clients_vulnerable}, Nonce reuse: ${nonce_reuse_detected}, GTK reinstall: ${gtk_reinstall_vulnerable}" \
        --arg recommendations "$recommendations" \
        --arg ap_vulnerable "$ap_vulnerable" \
        --argjson clients_tested "$clients_tested" \
        --argjson clients_vulnerable "$clients_vulnerable" \
        --arg nonce_reuse_detected "$nonce_reuse_detected" \
        --arg gtk_reinstall_vulnerable "$gtk_reinstall_vulnerable" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            ap_vulnerable: ($ap_vulnerable == "true"),
            clients_tested: $clients_tested,
            clients_vulnerable: $clients_vulnerable,
            nonce_reuse_detected: ($nonce_reuse_detected == "true"),
            gtk_reinstall_vulnerable: ($gtk_reinstall_vulnerable == "true")
        }')

    local has_tool_output=1
    local has_primary=0
    [[ -f "$nonce_pcap" && -s "$nonce_pcap" ]] && has_primary=1
    
    save_tc_result "E1" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0
    save_session_state

    echo ""
    if [[ "$ap_vulnerable" == "true" || $clients_vulnerable -gt 0 ]]; then
        log_result "FINDING" "★ KRACK indicators: ${clients_vulnerable} vulnerable client(s), AP: $(if [[ "$ap_vulnerable" == "true" ]]; then echo "VULNERABLE"; else echo "unclear"; fi)"
    elif [[ $clients_tested -gt 0 ]]; then
        log_result "SECURE" "KRACK: ${clients_tested} client(s) tested — no nonce reuse detected"
    else
        log_result "INFO" "KRACK: No EAPOL handshakes captured for analysis"
    fi

    return 0
}
