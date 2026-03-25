#!/usr/bin/env bash
# MODULE_META
# NAME="Egress Filtering Assessment"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap"
# DESC="Test which outbound ports and protocols are allowed from target WiFi"
# REQS="managed_iface"
# PCAP="no"
# DECODE="none"

#===============================================================================
#  modules/c5_egress_filtering.sh
#  C5: Egress Filtering Assessment
#
#  PURPOSE:
#    Systematically test which outbound ports and protocols are allowed
#    from the target WiFi network. Identifies overly permissive egress
#    rules that could enable data exfiltration or tunneling.
#
#  TOOLS: ${TOOL_PATHS[nmap]}, ${TOOL_PATHS[curl]}, nc (netcat)
#  PHASE: 1C — Segmentation Testing (Core Tests)
#  DEPENDENCIES: None
#
#  EVIDENCE PRODUCED:
#    - c5_egress_scan.txt          (port-by-port egress results)
#    - c5_protocol_tests.txt       (protocol-specific test results)
#    - c5_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - open_ports[]: list of allowed outbound ports
#    - blocked_ports[]: list of blocked outbound ports
#    - high_risk_open[]: dangerous ports that are open (e.g., SSH, RDP)
#    - total_open: int
#    - total_tested: int
#    - egress_policy: string (permissive/moderate/restrictive)
#===============================================================================

set -uo pipefail

run_c5() {
    set -uo pipefail

    local interface=""
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks to globals if not provided
    interface="${interface:-${WIFI_INTERFACE:-wlan0}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-.}}"

    local total_steps=6
    local evidence_prefix="${evidence_dir}/c5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools and connectivity"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "C5" || return 1
    
    WIFI_INTERFACE="$interface"
    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi
    ensure_managed_mode || return 1

    # Verify we have internet connectivity
    if ! run_fg ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
        log_error "No outbound connectivity. Connect to target WiFi first."
        return 1
    fi
    log_success "Outbound connectivity confirmed"

    local findings_file="${evidence_prefix}_findings.txt"
    local egress_file="${evidence_prefix}_egress_scan.txt"
    local protocol_file="${evidence_prefix}_protocol_tests.txt"

    {
        echo "============================================================"
        echo "  C5: Egress Filtering Assessment"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${interface}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "============================================================"
        echo "  Port-by-Port Egress Test Results"
        echo "  External target: scanme.nmap.org (45.33.32.156)"
        echo "============================================================"
        echo ""
    } > "$egress_file"

    #--- Step 2: Test common ports ---
    log_step 2 $total_steps "Testing common egress ports"
    update_tc_progress 2 $total_steps "Port scanning"

    check_abort || return 1

    # Target: scanme.nmap.org is explicitly for scanning
    local scan_target="scanme.nmap.org"

    # Key ports to test — categorized by risk
    # Format: port:protocol:service:risk_level
    local -a test_ports=(
        "21:tcp:FTP:high"
        "22:tcp:SSH:high"
        "23:tcp:Telnet:high"
        "25:tcp:SMTP:high"
        "53:tcp:DNS-TCP:medium"
        "53:udp:DNS-UDP:low"
        "80:tcp:HTTP:low"
        "110:tcp:POP3:medium"
        "143:tcp:IMAP:medium"
        "443:tcp:HTTPS:low"
        "445:tcp:SMB:high"
        "465:tcp:SMTPS:medium"
        "587:tcp:SMTP-Submit:medium"
        "993:tcp:IMAPS:low"
        "995:tcp:POP3S:low"
        "1080:tcp:SOCKS:high"
        "1194:udp:OpenVPN:high"
        "1433:tcp:MSSQL:high"
        "1723:tcp:PPTP:medium"
        "3306:tcp:MySQL:high"
        "3389:tcp:RDP:high"
        "5432:tcp:PostgreSQL:high"
        "5900:tcp:VNC:high"
        "8080:tcp:HTTP-Proxy:medium"
        "8443:tcp:HTTPS-Alt:low"
        "8888:tcp:HTTP-Alt:medium"
        "9001:tcp:Tor:high"
    )

    local open_ports="[]"
    local blocked_ports="[]"
    local high_risk_open="[]"
    local total_open=0
    local total_tested=0

    printf "  ${C_BOLD}%-8s %-6s %-15s %-10s %-12s${C_RESET}\n" "PORT" "PROTO" "SERVICE" "STATUS" "RISK"
    echo -e "  ${C_GRAY}$(printf '─%.0s' {1..55})${C_RESET}"

    for port_entry in "${test_ports[@]}"; do
        local IFS=':' read -r port proto service risk <<< "$port_entry"
        ((total_tested++))

        check_abort || return 1

        local port_status="blocked"
        local status_color="${C_GREEN}"

        if [[ "$proto" == "tcp" ]]; then
            # Quick TCP connect scan
            if timeout 5 bash -c "echo >/dev/tcp/${scan_target}/${port}" 2>/dev/null; then
                port_status="open"
            else
                # Fallback: nmap single port
                local nmap_result
                nmap_result=$(timeout 10 run_fg nmap -Pn -p "$port" --max-retries 1 -T4 "$scan_target" 2>&1 | grep "^${port}/" || true)
                if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
                    {
                        echo "============================================================"
                        echo "ts: $(date -Iseconds)"
                        echo "cmd: timeout 10 nmap -Pn -p ${port} --max-retries 1 -T4 ${scan_target}"
                        echo "exit_code: $?"
                        echo "------------------------------------------------------------"
                        echo "$nmap_result"
                        echo ""
                    } >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
                fi
                if echo "$nmap_result" | grep -q "open"; then
                    port_status="open"
                fi
            fi
        elif [[ "$proto" == "udp" ]]; then
            # UDP test
            if [[ "$port" == "53" ]]; then
                # Special DNS test
                if timeout 5 run_fg dig +short +timeout=3 @"$scan_target" example.com A &>/dev/null; then
                    port_status="open"
                fi
            else
                local nmap_result
                nmap_result=$(timeout 15 run_fg nmap -Pn -sU -p "$port" --max-retries 1 "$scan_target" 2>&1 | grep "^${port}/" || true)
                if [[ -n "${TC_TOOL_OUTPUT_FILE:-}" ]]; then
                    {
                        echo "============================================================"
                        echo "ts: $(date -Iseconds)"
                        echo "cmd: timeout 15 nmap -Pn -sU -p ${port} --max-retries 1 ${scan_target}"
                        echo "exit_code: $?"
                        echo "------------------------------------------------------------"
                        echo "$nmap_result"
                        echo ""
                    } >>"$TC_TOOL_OUTPUT_FILE" 2>/dev/null || true
                fi
                if echo "$nmap_result" | grep -qE "open|open\|filtered"; then
                    port_status="open"
                fi
            fi
        fi

        if [[ "$port_status" == "open" ]]; then
            ((total_open++))
            status_color="${C_RED}"
            open_ports=$(echo "$open_ports" | run_fg jq --arg p "${port}/${proto}" '. += [$p]')

            if [[ "$risk" == "high" ]]; then
                high_risk_open=$(echo "$high_risk_open" | run_fg jq --arg p "${port}/${proto} (${service})" '. += [$p]')
            fi
        else
            blocked_ports=$(echo "$blocked_ports" | run_fg jq --arg p "${port}/${proto}" '. += [$p]')
        fi

        local risk_color="${C_GRAY}"
        [[ "$risk" == "high" ]] && risk_color="${C_RED}"
        [[ "$risk" == "medium" ]] && risk_color="${C_YELLOW}"

        printf "  %-8s %-6s %-15s ${status_color}%-10s${C_RESET} ${risk_color}%-12s${C_RESET}\n" \
            "$port" "$proto" "$service" "${port_status^^}" "${risk^^}"

        echo "${port}/${proto} (${service}): ${port_status} [${risk}]" >> "$egress_file"
    done

    echo "" >> "$egress_file"
    echo "Open ports: ${total_open}/${total_tested}" >> "$egress_file"

    log_info "Egress scan complete: ${total_open}/${total_tested} ports open"

    #--- Step 3: Protocol-specific tests ---
    log_step 3 $total_steps "Testing protocol-specific filtering"
    update_tc_progress 3 $total_steps "Protocol tests"

    check_abort || return 1

    {
        echo "============================================================"
        echo "  Protocol-Specific Egress Tests"
        echo "============================================================"
        echo ""
    } > "$protocol_file"

    # Test ICMP
    local icmp_allowed="false"
    if run_fg ping -c 2 -W 3 8.8.8.8 &>/dev/null; then
        icmp_allowed="true"
    fi
    echo "ICMP Echo: $(if [[ "$icmp_allowed" == "true" ]]; then echo "ALLOWED"; else echo "BLOCKED"; fi)" >> "$protocol_file"

    # Test DNS over HTTPS (DoH)
    local doh_allowed="false"
    local doh_response
    doh_response=$(timeout 10 run_fg curl -s -o /dev/null -w "%{http_code}" \
        "https://dns.google/resolve?name=example.com&type=A" 2>/dev/null) || true
    if [[ "$doh_response" == "200" ]]; then
        doh_allowed="true"
    fi
    echo "DNS over HTTPS (DoH): $(if [[ "$doh_allowed" == "true" ]]; then echo "ALLOWED"; else echo "BLOCKED"; fi)" >> "$protocol_file"

    # Test common VPN protocols
    local vpn_tests=""

    # Test SSH tunnel capability
    local ssh_tunnel="false"
    if timeout 5 bash -c "echo >/dev/tcp/github.com/22" 2>/dev/null; then
        ssh_tunnel="true"
    fi
    echo "SSH (port 22): $(if [[ "$ssh_tunnel" == "true" ]]; then echo "ALLOWED — SSH tunneling possible"; else echo "BLOCKED"; fi)" >> "$protocol_file"

    # Test HTTPS on non-standard port (tunnel indicator)
    local https_alt="false"
    if timeout 5 run_fg curl -s -o /dev/null -w "%{http_code}" "https://www.google.com:443" &>/dev/null; then
        https_alt="true"
    fi
    echo "HTTPS (443): $(if [[ "$https_alt" == "true" ]]; then echo "ALLOWED"; else echo "BLOCKED"; fi)" >> "$protocol_file"

    # Test if we can use alternate DNS
    local alt_dns="false"
    if timeout 5 run_fg dig +short +timeout=3 @1.1.1.1 example.com A &>/dev/null; then
        alt_dns="true"
    fi
    echo "Alternate DNS (1.1.1.1): $(if [[ "$alt_dns" == "true" ]]; then echo "ALLOWED"; else echo "BLOCKED"; fi)" >> "$protocol_file"

    #--- Step 4: Expanded port range scan ---
    log_step 4 $total_steps "Quick scan of top 100 ports"
    update_tc_progress 4 $total_steps "Broad scan"

    check_abort || return 1

    run_fg nmap -Pn --top-ports 100 -T4 --max-retries 1 -oA "${evidence_prefix}_top100" "${scan_target}"

    # Parse additional open ports from nmap
    if [[ -f "${evidence_prefix}_top100.nmap" ]]; then
        local nmap_open
        nmap_open=$(grep "^[0-9].*open" "${evidence_prefix}_top100.nmap" 2>/dev/null || true)
        if [[ -n "$nmap_open" ]]; then
            echo "" >> "$egress_file"
            echo "=== Extended Scan (top-100) ===" >> "$egress_file"
            echo "$nmap_open" >> "$egress_file"

            # Count additional opens not in our targeted scan
            local extended_open
            extended_open=$(echo "$nmap_open" | wc -l)
            log_info "Extended scan found ${extended_open} open ports in top-100"
        fi
    fi

    #--- Step 5: Risk assessment ---
    log_step 5 $total_steps "Assessing egress policy"
    update_tc_progress 5 $total_steps "Assessment"

    local high_risk_count
    high_risk_count=$(echo "$high_risk_open" | run_fg jq 'length')

    local egress_policy="unknown"
    if [[ $total_open -le 3 ]]; then
        egress_policy="restrictive"
    elif [[ $total_open -le 8 ]]; then
        egress_policy="moderate"
    else
        egress_policy="permissive"
    fi

    echo "" >> "$findings_file"
    echo "Egress Policy Assessment: ${egress_policy^^}" >> "$findings_file"
    echo "Open ports: ${total_open}/${total_tested}" >> "$findings_file"
    echo "High-risk open ports: ${high_risk_count}" >> "$findings_file"

    if [[ $high_risk_count -gt 0 ]]; then
        echo "" >> "$findings_file"
        echo "High-risk open ports:" >> "$findings_file"
        echo "$high_risk_open" | run_fg jq -r '.[]' | sed 's/^/  FINDING: /' >> "$findings_file"
    fi

    if [[ "$ssh_tunnel" == "true" ]]; then
        echo "FINDING: SSH tunneling possible — full network bypass via SSH" >> "$findings_file"
    fi
    if [[ "$doh_allowed" == "true" ]]; then
        echo "INFO: DNS over HTTPS allowed — DNS-based filtering can be bypassed" >> "$findings_file"
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ "$egress_policy" == "permissive" || $high_risk_count -gt 0 ]]; then
        result_status="FINDING"
        result_summary="Egress filtering is ${egress_policy}. ${total_open}/${total_tested} tested ports are open outbound. "
        result_summary+="${high_risk_count} high-risk port(s) open: $(echo "$high_risk_open" | run_fg jq -r 'join(", ")')."
        recommendations="1) Implement restrictive egress firewall — allow only ports 80/443 for target WiFi. "
        recommendations+="2) Block SSH (22), RDP (3389), SMB (445), and database ports from target network. "
        recommendations+="3) Force DNS through a filtering proxy (block direct DNS to external servers). "
        recommendations+="4) Consider deploying a web proxy for target traffic with URL filtering. "
        recommendations+="5) Block VPN protocols (OpenVPN/1194, PPTP/1723, IPSec/500,4500) to prevent tunnel bypass."
    elif [[ "$egress_policy" == "moderate" ]]; then
        result_summary="Egress filtering is moderate. ${total_open}/${total_tested} ports open. Some non-essential ports are allowed but high-risk ports are mostly blocked."
        recommendations="Review remaining open ports and close any not required for target use."
    else
        result_summary="Egress filtering is restrictive. Only ${total_open}/${total_tested} tested ports are open outbound. Good security posture."
        recommendations="No immediate action needed. Continue monitoring egress rules."
    fi

    local result_json
    evidence_register_file "$egress_file"
    evidence_register_file "$protocol_file"
    evidence_register_file "$findings_file"

    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Policy: ${egress_policy}, Open: ${total_open}/${total_tested}, High-risk: ${high_risk_count}" \
        --arg recommendations "$recommendations" \
        --argjson open_ports "$open_ports" \
        --argjson blocked_ports "$blocked_ports" \
        --argjson high_risk_open "$high_risk_open" \
        --argjson total_open "$total_open" \
        --argjson total_tested "$total_tested" \
        --arg egress_policy "$egress_policy" \
        --arg icmp_allowed "$icmp_allowed" \
        --arg doh_allowed "$doh_allowed" \
        --arg ssh_tunnel "$ssh_tunnel" \
        --arg alt_dns_allowed "$alt_dns" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            open_ports: $open_ports,
            blocked_ports: $blocked_ports,
            high_risk_open: $high_risk_open,
            total_open: $total_open,
            total_tested: $total_tested,
            egress_policy: $egress_policy,
            icmp_allowed: ($icmp_allowed == "true"),
            doh_allowed: ($doh_allowed == "true"),
            ssh_tunnel_possible: ($ssh_tunnel == "true"),
            alt_dns_allowed: ($alt_dns_allowed == "true"),
                    }')

    save_tc_result "C5" "$result_json" 0 1 0 1 1 1 0 1 1 1 1
    save_session_state
    return 0
}
