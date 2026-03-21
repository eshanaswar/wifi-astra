#!/usr/bin/env bash
#===============================================================================
#  lib/report.sh — Report Generator
#  
#  Generates both TXT and HTML assessment reports from completed test results.
#===============================================================================

generate_report() {
    local completed
    completed=$(get_completed_count)
    local total=${#TC_ORDER[@]}
    
    if [[ $completed -eq 0 ]]; then
        log_warn "No tests completed yet. Run some tests first."
        [[ ${HEADLESS_MODE:-0} -eq 0 ]] && read -rep "  Press Enter to return to menu..." _
        return
    fi
    
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  REPORT GENERATION — ${completed}/${total} tests completed                      ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    
    local txt_report="${SESSION_REPORT_DIR}/assessment_report.txt"
    local html_report="${SESSION_REPORT_DIR}/assessment_report.html"
    
    # Generate TXT report
    _generate_txt_report "$txt_report"
    
    # Generate HTML report
    _generate_html_report "$html_report"
    
    echo ""
    log_success "Reports generated:"
    log_info "  TXT:  ${txt_report}"
    log_info "  HTML: ${html_report}"
    log_info "  Evidence: ${SESSION_EVIDENCE_DIR}/"
    echo ""
    [[ ${HEADLESS_MODE:-0} -eq 0 ]] && read -rep "  Press Enter to return to menu..." _
}

#--- TXT Report ---
_generate_txt_report() {
    local output="$1"
    
    {
        echo "==============================================================================="
        echo "  WIFI SEGREGATION ASSESSMENT REPORT"
        echo "==============================================================================="
        echo ""
        echo "  Session ID:     ${SESSION_ID}"
        echo "  Generated:      $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target SSID:    ${GUEST_SSID:-Not recorded}"
        echo "  Target BSSID:   ${GUEST_BSSID:-Not recorded}"
        echo "  Gateway:        ${GATEWAY_IP:-Not recorded}"
        echo "  Assigned IP:    ${MY_IP:-Not recorded}"
        echo ""
        echo "==============================================================================="
        echo "  EXECUTIVE SUMMARY"
        echo "==============================================================================="
        echo ""
        
        # Count findings
        local findings=0
        local secure=0
        local critical=0
        
        for _tc in "${TC_ORDER[@]}"; do
            if [[ "${TC_STATUS[$_tc]}" == "done" ]]; then
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                if [[ -f "$result_file" ]]; then
                    local status
                    status=$(${TOOL_PATHS[jq]} -r '.status // "unknown"' "$result_file" 2>/dev/null || echo "unknown")
                    case "$status" in
                        "FINDING"|"FAIL"|"VULNERABLE")
                            ((findings++))
                            local is_crit
                            is_crit=$(get_tc_field "$_tc" "critical")
                            if [[ "$is_crit" == "yes" ]]; then
                                ((critical++))
                            fi
                            ;;
                        "SECURE"|"PASS")
                            ((secure++))
                            ;;
                    esac
                fi
            fi
        done
        
        local completed
        completed=$(get_completed_count)
        
        echo "  Tests Completed:       ${completed}/${#TC_ORDER[@]}"
        echo "  Findings (Issues):     ${findings}"
        echo "  Critical Findings:     ${critical}"
        echo "  Secure (Passed):       ${secure}"
        echo ""
        
        if [[ $critical -gt 0 ]]; then
            echo "  *** CRITICAL: Segmentation bypass detected. Immediate remediation required. ***"
        elif [[ $findings -gt 0 ]]; then
            echo "  WARNING: Issues detected that may weaken target WiFi isolation."
        else
            echo "  Target WiFi segregation appears properly configured."
        fi
        
        echo ""
        echo "==============================================================================="
        echo "  DETAILED RESULTS"
        echo "==============================================================================="
        
        for _tc in "${TC_ORDER[@]}"; do
            local tc_name
            tc_name=$(get_tc_field "$_tc" "name")
            local tc_status="${TC_STATUS[$_tc]:-not_run}"
            
            echo ""
            echo "-------------------------------------------------------------------------------"
            echo "  ${_tc}: ${tc_name}"
            echo "  Status: ${tc_status^^}"
            echo "-------------------------------------------------------------------------------"
            
            if [[ "$tc_status" == "done" ]]; then
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                if [[ -f "$result_file" ]]; then
                    echo ""
                    # Pretty-print the JSON results
                    ${TOOL_PATHS[jq]} -r '
                        if .status then "  Result: \(.status)" else empty end,
                        if .summary then "  Summary: \(.summary)" else empty end,
                        if .details then "\n  Details:\n\(.details)" else empty end,
                        if .evidence_files then "  Evidence: \(.evidence_files | join(", "))" else empty end,
                        if .recommendations then "\n  Recommendations:\n\(.recommendations)" else empty end
                    ' "$result_file" 2>/dev/null || echo "  [Results file exists but could not be parsed]"
                fi
            else
                echo "  [Not executed]"
            fi
        done
        
        echo ""
        echo "==============================================================================="
        echo "  EVIDENCE FILES"
        echo "==============================================================================="
        echo ""
        echo "  Directory: ${SESSION_EVIDENCE_DIR}/"
        echo ""
        
        if [[ -d "$SESSION_EVIDENCE_DIR" ]]; then
            find "$SESSION_EVIDENCE_DIR" -type f -printf "  %f (%s bytes)\n" 2>/dev/null | sort
        fi
        
        echo ""
        echo "==============================================================================="
        
    } > "$output"
    
    # Strip ANSI colors from TXT report
    sed -i -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$output" 2>/dev/null || sed -i 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$output" 2>/dev/null
    
    log_success "TXT report: ${output}"
}

#--- HTML Report ---
_generate_html_report() {
    local output="$1"
    local completed
    completed=$(get_completed_count)
    
    # Count findings for summary
    local findings=0 secure=0 critical=0 not_run=0
    for _tc in "${TC_ORDER[@]}"; do
        case "${TC_STATUS[$_tc]}" in
            "done")
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                if [[ -f "$result_file" ]]; then
                    local status
                    status=$(${TOOL_PATHS[jq]} -r '.status // "unknown"' "$result_file" 2>/dev/null || echo "unknown")
                    case "$status" in
                        "FINDING"|"FAIL"|"VULNERABLE") ((findings++)) ;;
                        "SECURE"|"PASS") ((secure++)) ;;
                    esac
                fi
                ;;
            "not_run") ((not_run++)) ;;
        esac
    done
    
    cat > "$output" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi-Astra Report</title>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
    h2 { color: #00d4ff; margin-top: 30px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
    .summary-card { background: #16213e; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #555; }
    .summary-card.critical { border-left-color: #ff4444; }
    .summary-card.finding { border-left-color: #ffaa00; }
    .summary-card.secure { border-left-color: #00ff88; }
    .summary-card.info { border-left-color: #00d4ff; }
    .summary-card .number { font-size: 36px; font-weight: bold; }
    .summary-card .label { font-size: 14px; color: #aaa; margin-top: 5px; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #16213e; color: #00d4ff; padding: 12px; text-align: left; }
    td { padding: 10px 12px; border-bottom: 1px solid #2a2a4a; }
    tr:hover { background: #16213e44; }
    .status-done { color: #00ff88; font-weight: bold; }
    .status-finding { color: #ff4444; font-weight: bold; }
    .status-secure { color: #00ff88; }
    .status-notrun { color: #666; }
    .status-failed { color: #ff4444; }
    .tc-detail { background: #16213e; border-radius: 8px; padding: 20px; margin: 15px 0; }
    .tc-detail h3 { color: #00d4ff; margin-top: 0; }
    .evidence { background: #0d1117; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 13px; overflow-x: auto; }
    .meta { color: #888; font-size: 14px; }
    .tag-critical { background: #ff4444; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
    .tag-finding { background: #ffaa00; color: black; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
    .tag-secure { background: #00ff88; color: black; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
HTMLHEAD

    # Dynamic content
    {
        echo "<h1>🛜 WiFi-Astra — Wireless Security Assessment Framework</h1>"
        echo "<p class='meta'>Session: ${SESSION_ID} | Generated: $(date '+%Y-%m-%d %H:%M:%S') | Target: ${GUEST_SSID:-N/A}</p>"
        
        echo "<div class='summary-grid'>"
        echo "  <div class='summary-card info'><div class='number'>${completed}</div><div class='label'>Tests Completed</div></div>"
        echo "  <div class='summary-card finding'><div class='number'>${findings}</div><div class='label'>Findings</div></div>"
        echo "  <div class='summary-card secure'><div class='number'>${secure}</div><div class='label'>Secure</div></div>"
        echo "  <div class='summary-card info'><div class='number'>${not_run}</div><div class='label'>Not Run</div></div>"
        echo "</div>"
        
        echo "<h2>Test Case Results</h2>"
        echo "<table>"
        echo "<tr><th>#</th><th>Test Case</th><th>Name</th><th>Status</th><th>Result</th><th>Confidence</th></tr>"
        
        local num=1
        for _tc in "${TC_ORDER[@]}"; do
            local tc_name
            tc_name=$(get_tc_field "$_tc" "name")
            local tc_status="${TC_STATUS[$_tc]:-not_run}"
            local result_status="—"
            local confidence="—"
            local status_class="status-notrun"
            
            case "$tc_status" in
                "done")
                    status_class="status-done"
                    local result_file
                    result_file=$(get_tc_result_file "$_tc")
                    if [[ -f "$result_file" ]]; then
                        result_status=$(${TOOL_PATHS[jq]} -r '.status // "—"' "$result_file" 2>/dev/null || echo "—")
                        confidence=$(${TOOL_PATHS[jq]} -r '.confidence // "—"' "$result_file" 2>/dev/null || echo "—")
                    fi
                    ;;
                "failed") status_class="status-failed" ;;
            esac
            
            local result_class="status-notrun"
            case "$result_status" in
                "FINDING"|"FAIL"|"VULNERABLE") result_class="status-finding" ;;
                "SECURE"|"PASS") result_class="status-secure" ;;
            esac
            
            echo "<tr><td>${num}</td><td>${_tc}</td><td>${tc_name}</td><td class='${status_class}'>${tc_status^^}</td><td class='${result_class}'>${result_status}</td><td>${confidence}</td></tr>"
            ((num++))
        done
        
        echo "</table>"
        
        # Detailed results per TC
        echo "<h2>Detailed Findings</h2>"
        
        for _tc in "${TC_ORDER[@]}"; do
            if [[ "${TC_STATUS[$_tc]}" == "done" ]]; then
                local tc_name
                tc_name=$(get_tc_field "$_tc" "name")
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                
                echo "<div class='tc-detail'>"
                echo "<h3>${_tc}: ${tc_name}</h3>"
                
                if [[ -f "$result_file" ]]; then
                    local summary
                    summary=$(${TOOL_PATHS[jq]} -r '.summary // "No summary"' "$result_file" 2>/dev/null)
                    local details
                    details=$(${TOOL_PATHS[jq]} -r '.details // "No details"' "$result_file" 2>/dev/null)
                    local status
                    status=$(${TOOL_PATHS[jq]} -r '.status // "unknown"' "$result_file" 2>/dev/null)
                    local confidence
                    confidence=$(${TOOL_PATHS[jq]} -r '.confidence // ""' "$result_file" 2>/dev/null)
                    
                    local tag_class="tag-secure"
                    case "$status" in
                        "FINDING"|"FAIL"|"VULNERABLE") tag_class="tag-finding" ;;
                        "SECURE"|"PASS") tag_class="tag-secure" ;;
                    esac
                    
                    local reqs
                    reqs=$(${TOOL_PATHS[jq]} -r '.recommendations // ""' "$result_file" 2>/dev/null)
                    local ev
                    ev=$(${TOOL_PATHS[jq]} -r 'if .evidence_files and (.evidence_files | type) == "array" then .evidence_files | join(", ") else "" end' "$result_file" 2>/dev/null)
                    
                    if [[ -n "$confidence" && "$confidence" != "null" ]]; then
                        echo "<p><span class='${tag_class}'>${status}</span> <span class='tag-info'>Confidence: ${confidence}</span></p>"
                    else
                        echo "<p><span class='${tag_class}'>${status}</span></p>"
                    fi
                    echo "<p><strong>Summary:</strong> ${summary}</p>"
                    if [[ -n "$reqs" && "$reqs" != "null" ]]; then
                        echo "<p><strong>Recommendations:</strong> ${reqs}</p>"
                    fi
                    if [[ -n "$ev" && "$ev" != "null" ]]; then
                        echo "<p><strong>Evidence Files:</strong> ${ev}</p>"
                    fi
                    echo "<div class='evidence'><pre>${details}</pre></div>"
                fi
                
                echo "</div>"
            fi
        done
        
        echo "</div></body></html>"
        
    } >> "$output"
    
    log_success "HTML report: ${output}"
}

#--- Session info display ---
show_session_info() {
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  SESSION INFORMATION                                            ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    echo -e "  ${C_BOLD}Session ID:${C_RESET}       ${SESSION_ID}"
    echo -e "  ${C_BOLD}Session Dir:${C_RESET}      ${SESSION_DIR}"
    echo -e "  ${C_BOLD}Evidence Dir:${C_RESET}     ${SESSION_EVIDENCE_DIR}"
    echo -e "  ${C_BOLD}Log Dir:${C_RESET}          ${SESSION_LOG_DIR}"
    echo -e "  ${C_BOLD}Report Dir:${C_RESET}       ${SESSION_REPORT_DIR}"
    echo ""
    echo -e "  ${C_BOLD}Network Configuration:${C_RESET}"
    echo -e "    WiFi Interface:   ${WIFI_INTERFACE:-Not set}"
    echo -e "    Monitor Mode:     ${MONITOR_INTERFACE:-Not active}"
    echo -e "    Target SSID:      ${GUEST_SSID:-Not set}"
    echo -e "    Target BSSID:     ${GUEST_BSSID:-Not set}"
    echo -e "    Gateway IP:       ${GATEWAY_IP:-Not set}"
    echo -e "    Our IP:           ${MY_IP:-Not set}"
    echo -e "    DNS Server:       ${DNS_SERVER:-Not set}"
    echo ""
    echo -e "  ${C_BOLD}VPS Configuration:${C_RESET}"
    echo -e "    VPS IP:           ${VPS_IP:-Not configured}"
    echo -e "    VPS Domain:       ${VPS_DOMAIN:-Not configured}"
    echo ""
    echo -e "  ${C_BOLD}Test Case Status:${C_RESET}"
    
    for _tc in "${TC_ORDER[@]}"; do
        local tc_name
        tc_name=$(get_tc_field "$_tc" "name")
        local tc_status="${TC_STATUS[$_tc]:-not_run}"
        local icon
        
        case "$tc_status" in
            "done")    icon="${ICON_DONE}" ;;
            "not_run") icon="${ICON_PENDING}" ;;
            "failed")  icon="${ICON_FAIL}" ;;
            "aborted") icon="${ICON_WARN}" ;;
            "running") icon="${ICON_RUNNING}" ;;
        esac
        
        echo -e "    ${icon}  ${_tc}  ${tc_name}"
    done
    
    echo ""
    
    # Calculate evidence size
    local evidence_size="0"
    if [[ -d "$SESSION_EVIDENCE_DIR" ]]; then
        evidence_size=$(du -sh "$SESSION_EVIDENCE_DIR" 2>/dev/null | awk '{print $1}')
    fi
    echo -e "  ${C_BOLD}Evidence Size:${C_RESET} ${evidence_size}"
    echo ""
    [[ ${HEADLESS_MODE:-0} -eq 0 ]] && read -rep "  Press Enter to return to menu..." _
}