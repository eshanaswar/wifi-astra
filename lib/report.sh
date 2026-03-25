#!/usr/bin/env bash
#===============================================================================
#  lib/report.sh — Report Generator
#  
#  Generates both TXT and HTML assessment reports from completed test results.
#===============================================================================

set -uo pipefail

generate_report() {
    local completed
    completed=$(get_completed_count)
    local total=${#TC_ORDER[@]}
    
    if [[ $completed -eq 0 ]]; then
        log_warn "No tests completed yet. Run some tests first."
        [[ ${HEADLESS_MODE:-0} -eq 0 ]] && safe_read "Press Enter to return to menu..." _
        return
    fi
    
    echo ""
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║  REPORT GENERATION — ${completed}/${total} tests completed                      ║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    
    local txt_report="${SESSION_REPORT_DIR}/assessment_report.txt"
    local html_report="${SESSION_REPORT_DIR}/assessment_report.html"
    local pdf_report="${SESSION_REPORT_DIR}/assessment_report.pdf"
    
    # Generate TXT report
    _generate_txt_report "$txt_report"
    
    # Generate HTML report
    _generate_html_report "$html_report"

    # Generate PDF report
    _generate_pdf_report "$html_report" "$pdf_report"
    
    echo ""
    log_success "Reports generated:"
    log_info "  TXT:  ${txt_report}"
    log_info "  HTML: ${html_report}"
    [[ -f "$pdf_report" ]] && log_info "  PDF:  ${pdf_report}"
    log_info "  Evidence: ${SESSION_EVIDENCE_DIR}/"
    echo ""
    [[ ${HEADLESS_MODE:-0} -eq 0 ]] && safe_read "Press Enter to return to menu..." _
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
            if [[ "${TC_STATUS[$_tc]:-}" == "done" ]]; then
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                if [[ -f "$result_file" ]]; then
                    local status
                    status=$(run_tool jq -r '.status // "INFO"' "$result_file" 2>/dev/null || echo "INFO")
                    case "${status^^}" in
                        "CRITICAL")
                            ((findings++)) || true
                            ((critical++)) || true
                            ;;
                        "FINDING"|"FAIL")
                            ((findings++)) || true
                            ;;
                        "SECURE")
                            ((secure++)) || true
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
            echo "  *** CRITICAL: Segmentation bypass or severe vulnerability detected. ***"
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
                    # Pretty-print the JSON results with defensive parsing
                    run_tool jq -r '
                        "  Result:         " + (.status // "N/A"),
                        "  Confidence:     " + (.confidence // "N/A"),
                        "  Summary:        " + (.summary // "N/A"),
                        "\n  Details:",
                        "  " + (.details // "No details provided"),
                        "\n  Recommendations:",
                        "  " + (.recommendations // "No recommendations provided"),
                        (if .evidence_files and (.evidence_files | length > 0) then 
                            "\n  Evidence Files: " + (.evidence_files | join(", "))
                         else empty end)
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
    
    # Group results and count for summary
    local critical_tcs=() finding_tcs=() secure_tcs=() info_tcs=() failed_tcs=() not_run_tcs=()
    local critical=0 findings=0 secure=0 info=0
    
    for _tc in "${TC_ORDER[@]}"; do
        case "${TC_STATUS[$_tc]:-not_run}" in
            "done")
                local result_file
                result_file=$(get_tc_result_file "$_tc")
                if [[ -f "$result_file" ]]; then
                    local status
                    status=$(run_tool jq -r '.status // "INFO"' "$result_file" 2>/dev/null || echo "INFO")
                    case "${status^^}" in
                        "CRITICAL")
                            ((critical++)) || true
                            critical_tcs+=("$_tc")
                            ;;
                        "FINDING"|"FAIL")
                            ((findings++)) || true
                            finding_tcs+=("$_tc")
                            ;;
                        "SECURE")
                            ((secure++)) || true
                            secure_tcs+=("$_tc")
                            ;;
                        *)
                            ((info++)) || true
                            info_tcs+=("$_tc")
                            ;;
                    esac
                else
                    info_tcs+=("$_tc")
                fi
                ;;
            "failed")
                failed_tcs+=("$_tc")
                ;;
            "not_run")
                not_run_tcs+=("$_tc")
                ;;
        esac
    done
    
    # Start HTML generation
    cat > "$output" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi-Astra Assessment Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --header-bg: #1e293b;
            --accent: #38bdf8;
            --text-main: #f1f5f9;
            --text-dim: #94a3b8;
            --critical: #ef4444;
            --finding: #f59e0b;
            --secure: #10b981;
            --info: #38bdf8;
            --border: #334155;
        }
        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem 1rem;
        }
        header {
            background-color: var(--header-bg);
            border-bottom: 1px solid var(--border);
            padding: 2rem 0;
            margin-bottom: 2rem;
        }
        .header-content {
            max-width: 1000px;
            margin: 0 auto;
            padding: 0 1rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .brand h1 {
            margin: 0;
            color: var(--accent);
            font-size: 1.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .brand p {
            margin: 0.25rem 0 0;
            color: var(--text-dim);
        }
        .session-meta {
            text-align: right;
            font-size: 0.875rem;
            color: var(--text-dim);
        }
        .session-meta div span {
            color: var(--text-main);
            font-weight: 600;
        }
        
        /* Dashboard */
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 3rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            text-align: center;
        }
        .stat-card .value {
            font-size: 2.25rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.25rem;
        }
        .stat-card .label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
        }
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.finding .value { color: var(--finding); }
        .stat-card.secure .value { color: var(--secure); }
        .stat-card.info .value { color: var(--info); }
        
        /* Sections */
        section { margin-bottom: 3rem; }
        h2 {
            font-size: 1.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        /* Finding Cards */
        .finding-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border-left-width: 6px;
        }
        .finding-card.critical { border-left-color: var(--critical); }
        .finding-card.finding { border-left-color: var(--finding); }
        .finding-card.secure { border-left-color: var(--secure); }
        .finding-card.info { border-left-color: var(--info); }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
            gap: 1rem;
        }
        .finding-title h3 {
            margin: 0;
            font-size: 1.25rem;
        }
        .finding-id {
            font-family: monospace;
            font-size: 0.875rem;
            color: var(--text-dim);
        }
        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.625rem;
            border-radius: 9999px;
            text-transform: uppercase;
        }
        .badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--critical); }
        .badge.finding { background: rgba(245, 158, 11, 0.15); color: var(--finding); }
        .badge.secure { background: rgba(16, 185, 129, 0.15); color: var(--secure); }
        .badge.info { background: rgba(56, 189, 248, 0.15); color: var(--info); }
        
        .finding-body {
            display: grid;
            grid-template-columns: 1fr;
            gap: 1.25rem;
        }
        .finding-summary {
            font-weight: 600;
            color: var(--text-main);
        }
        .finding-details, .finding-recs {
            font-size: 0.9375rem;
        }
        .finding-details h4, .finding-recs h4 {
            margin: 0 0 0.5rem;
            font-size: 0.8125rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
        }
        .evidence-list {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
        .evidence-list h4 {
            margin: 0 0 0.5rem;
            font-size: 0.8125rem;
            color: var(--text-dim);
            text-transform: uppercase;
        }
        .evidence-links {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .ev-link {
            background: rgba(255,255,255,0.05);
            padding: 0.375rem 0.75rem;
            border-radius: 0.375rem;
            text-decoration: none;
            color: var(--accent);
            font-size: 0.8125rem;
            border: 1px solid var(--border);
            transition: all 0.2s;
        }
        .ev-link:hover {
            background: rgba(255,255,255,0.1);
            border-color: var(--accent);
        }
        
        footer {
            text-align: center;
            padding: 3rem 0;
            color: var(--text-dim);
            font-size: 0.875rem;
        }
        
        @media (max-width: 640px) {
            .header-content { flex-direction: column; text-align: center; align-items: center; }
            .session-meta { text-align: center; }
            .finding-header { flex-direction: column; }
        }
        
        /* PDF/Print Tweaks */
        @media print {
            body { background-color: #0f172a !important; color: #f1f5f9 !important; -webkit-print-color-adjust: exact; }
            .finding-card { page-break-inside: avoid; border: 1px solid #334155 !important; }
            .stat-card { border: 1px solid #334155 !important; }
            /* wkhtmltopdf sometimes struggles with CSS variables, provide fallbacks */
            :root {
                --bg: #0f172a;
                --card-bg: #1e293b;
                --text-main: #f1f5f9;
            }
        }
    </style>
</head>
<body>
HTMLHEAD

    # Dynamic Header content
    {
        local esc_sid esc_ssid esc_bssid esc_date
        esc_sid=$(echo -n "${SESSION_ID}" | run_tool jq -Rr '@html')
        esc_ssid=$(echo -n "${GUEST_SSID:-N/A}" | run_tool jq -Rr '@html')
        esc_bssid=$(echo -n "${GUEST_BSSID:-N/A}" | run_tool jq -Rr '@html')
        esc_date=$(date '+%Y-%m-%d %H:%M:%S' | run_tool jq -Rr '@html')

        echo "<header>"
        echo "    <div class='header-content'>"
        echo "        <div class='brand'>"
        echo "            <h1>🛜 WiFi-Astra</h1>"
        echo "            <p>Wireless Security Assessment Report</p>"
        echo "        </div>"
        echo "        <div class='session-meta'>"
        echo "            <div>Session ID: <span>${esc_sid}</span></div>"
        echo "            <div>Target SSID: <span>${esc_ssid}</span></div>"
        echo "            <div>Target BSSID: <span>${esc_bssid}</span></div>"
        echo "            <div>Date: <span>${esc_date}</span></div>"
        echo "        </div>"
        echo "    </div>"
        echo "</header>"
        
        echo "<div class='container'>"
        
        # Dashboard
        echo "    <div class='dashboard'>"
        echo "        <div class='stat-card critical'><div class='value'>${critical}</div><div class='label'>Critical</div></div>"
        echo "        <div class='stat-card finding'><div class='value'>${findings}</div><div class='label'>Findings</div></div>"
        echo "        <div class='stat-card secure'><div class='value'>${secure}</div><div class='label'>Secure</div></div>"
        echo "        <div class='stat-card info'><div class='value'>${info}</div><div class='label'>Info/Fail</div></div>"
        echo "    </div>"
        
        # Render Function
        render_tc_card() {
            local tc_id="$1"
            local tc_name esc_tc_name result_file
            tc_name=$(get_tc_field "$tc_id" "name")
            esc_tc_name=$(echo -n "$tc_name" | run_tool jq -Rr '@html')
            result_file=$(get_tc_result_file "$tc_id")
            
            if [[ ! -f "$result_file" ]]; then
                # Handle cases where result file is missing but status is done
                echo "<div class='finding-card info'>"
                echo "  <div class='finding-header'><h3>${tc_id}: ${esc_tc_name}</h3></div>"
                echo "  <div class='finding-body'>Result data missing.</div>"
                echo "</div>"
                return
            fi
            
            local status confidence summary details recommendations
            status=$(run_tool jq -r '.status // "INFO" | @html' "$result_file" 2>/dev/null)
            confidence=$(run_tool jq -r '.confidence // "N/A" | @html' "$result_file" 2>/dev/null)
            summary=$(run_tool jq -r '.summary // "No summary provided" | @html' "$result_file" 2>/dev/null)
            details=$(run_tool jq -r '.details // "No details provided" | @html' "$result_file" 2>/dev/null)
            recommendations=$(run_tool jq -r '.recommendations // "" | @html' "$result_file" 2>/dev/null)
            
            local lower_status="${status,,}"
            [[ "$lower_status" == "fail" ]] && lower_status="finding"
            [[ "$lower_status" != "critical" && "$lower_status" != "finding" && "$lower_status" != "secure" ]] && lower_status="info"
            
            echo "<div class='finding-card ${lower_status}'>"
            echo "    <div class='finding-header'>"
            echo "        <div class='finding-title'>"
            echo "            <div class='finding-id'>${tc_id}</div>"
            echo "            <h3>${esc_tc_name}</h3>"
            echo "        </div>"
            echo "        <div class='badge ${lower_status}'>${status}</div>"
            echo "    </div>"
            echo "    <div class='finding-body'>"
            echo "        <div class='finding-summary'>${summary}</div>"
            echo "        <div class='finding-meta'><small>Confidence: ${confidence}</small></div>"
            echo "        <div class='finding-details'><h4>Details</h4>${details}</div>"
            
            if [[ -n "$recommendations" && "$recommendations" != "" && "$recommendations" != "null" ]]; then
                echo "        <div class='finding-recs'><h4>Recommendations</h4>${recommendations}</div>"
            fi
            
            # Evidence Links
            local ev_files
            ev_files=$(run_tool jq -r 'if .evidence_files and (.evidence_files | type) == "array" then .evidence_files[] else empty end' "$result_file" 2>/dev/null)
            if [[ -n "$ev_files" ]]; then
                echo "        <div class='evidence-list'>"
                echo "            <h4>Evidence Files</h4>"
                echo "            <div class='evidence-links'>"
                for ev in $ev_files; do
                    local esc_ev
                    esc_ev=$(echo -n "$ev" | run_tool jq -Rr '@html')
                    # Relative link to evidence dir from report dir
                    # Report is in $SESSION_REPORT_DIR/assessment_report.html
                    # Evidence is in $SESSION_EVIDENCE_DIR/
                    # Assuming they are both subdirs of $SESSION_DIR
                    echo "                <a href='../evidence/${esc_ev}' class='ev-link' target='_blank'>${esc_ev}</a>"
                done
                echo "            </div>"
                echo "        </div>"
            fi
            
            echo "    </div>"
            echo "</div>"
        }
        
        # CRITICAL
        if [[ ${#critical_tcs[@]} -gt 0 ]]; then
            echo "<section>"
            echo "    <h2>🔴 Critical Findings</h2>"
            for tc in "${critical_tcs[@]}"; do render_tc_card "$tc"; done
            echo "</section>"
        fi
        
        # FINDINGS
        if [[ ${#finding_tcs[@]} -gt 0 ]]; then
            echo "<section>"
            echo "    <h2>🟠 Security Findings</h2>"
            for tc in "${finding_tcs[@]}"; do render_tc_card "$tc"; done
            echo "</section>"
        fi
        
        # SECURE
        if [[ ${#secure_tcs[@]} -gt 0 ]]; then
            echo "<section>"
            echo "    <h2>🟢 Secure Checks</h2>"
            for tc in "${secure_tcs[@]}"; do render_tc_card "$tc"; done
            echo "</section>"
        fi
        
        # INFO / OTHERS
        if [[ ${#info_tcs[@]} -gt 0 || ${#failed_tcs[@]} -gt 0 ]]; then
            echo "<section>"
            echo "    <h2>🔵 Information & Other Results</h2>"
            for tc in "${info_tcs[@]}"; do render_tc_card "$tc"; done
            for tc in "${failed_tcs[@]}"; do
                echo "<div class='finding-card info'>"
                echo "  <div class='finding-header'><h3>${tc}: $(get_tc_field "$tc" "name" | run_tool jq -Rr '@html')</h3><div class='badge info'>FAILED</div></div>"
                echo "  <div class='finding-body'>Test case failed during execution.</div>"
                echo "</div>"
            done
            echo "</section>"
        fi
        
        echo "</div>" # end container
        echo "<footer>Generated by WiFi-Astra Assessment Framework — $(date '+%Y')</footer>"
        echo "</body></html>"
        
    } >> "$output"
    
    log_success "HTML report: ${output}"
}

#--- PDF Report ---
_generate_pdf_report() {
    local html_input="$1"
    local pdf_output="$2"
    
    local wk_path="${TOOL_PATHS[wkhtmltopdf]:-}"
    
    # Re-check if not set
    if [[ -z "$wk_path" ]]; then
        wk_path=$(command -v wkhtmltopdf 2>/dev/null || echo "")
    fi
    
    if [[ -z "$wk_path" ]] || [[ ! -x "$wk_path" ]]; then
        log_warn "wkhtmltopdf not found. Skipping PDF generation."
        return 0
    fi
    
    log_info "Generating PDF report..."
    
    # wkhtmltopdf can be finicky with some CSS, so we use some safe flags
    # We use --enable-local-file-access as requested
    local cmd=(
        "$wk_path"
        "--quiet"
        "--page-size" "Letter"
        "--margin-top" "20mm"
        "--margin-bottom" "20mm"
        "--header-center" "WiFi-Astra Security Assessment"
        "--footer-right" "Page [page] of [topage]"
        "--enable-local-file-access"
        "$html_input"
        "$pdf_output"
    )

    # Log command if VERBOSE_MODE is enabled
    if [[ "${VERBOSE_MODE:-0}" -eq 1 ]]; then
        log_info "PDF generation command: ${cmd[*]}"
    fi
    
    if "${cmd[@]}" 2>/dev/null; then
        log_success "PDF report: ${pdf_output}"
    else
        log_warn "Failed to generate PDF report (wkhtmltopdf error)."
    fi
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
    [[ ${HEADLESS_MODE:-0} -eq 0 ]] && safe_read "Press Enter to return to menu..." _
}
