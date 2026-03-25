#!/usr/bin/env bash
# MODULE_META
# NAME="AirSnitch — Client Isolation Bypass"
# CATEGORY="B"
# DEPS="B1"
# CRITICAL="no"
# TOOLS="airsnitch"
# DESC="Test client isolation bypass via GTK abuse, gateway bouncing, port stealing (airsnitch)"
# REQS="managed_iface,gateway_ip,monitor_iface"
# PCAP="yes"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/b10_airsnitch.sh
#  B10: AirSnitch — Client Isolation Bypass Test
#
#  PURPOSE:
#    Test whether client isolation can be bypassed using techniques from the
#    AirSnitch tool (NDSS 2026): GTK group key abuse, gateway bouncing,
#    and switching-layer attacks (port stealing, broadcast reflection).
#
#  TOOLS: ${TOOL_PATHS[airsnitch]} (optional — clone https://github.com/vanhoefm/airsnitch, make)
#  PHASE: B — Network & Service Recon (connected to target WiFi + monitor capable)
#  DEPENDENCIES: B1 (Client-to-Client Isolation — run first for context)
#
#  METHODOLOGY:
#    1. Verify ${TOOL_PATHS[airsnitch]} is available; if not, show install instructions.
#    2. Ensure managed interface (connected) and monitor interface for injection.
#    3. Run ${TOOL_PATHS[airsnitch]} with target interface/BSSID; capture output.
#    4. Record findings and produce result JSON.
#
#  EVIDENCE PRODUCED:
#    - b10_airsnitch_output.txt   (stdout/stderr from ${TOOL_PATHS[airsnitch]})
#    - b10_airsnitch_summary.txt  (summary and recommendations)
#
#  RESULT JSON FIELDS:
#    - tool_available: bool
#    - bypass_detected: bool (if tool ran and reported bypass)
#    - evidence_files: list
#===============================================================================

run_b10() {
    local total_steps=5
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/b10"

    #--- Step 1: Locate ${TOOL_PATHS[airsnitch]} and verify environment ---
    log_step 1 $total_steps "Checking for AirSnitch and network setup"
    update_tc_progress 1 $total_steps "Checking"

    
    # Resolve ${TOOL_PATHS[airsnitch]} binary: PATH, AIRSNITCH_PATH, or common build locations
    local AIRSNITCH_CMD=""
    if command -v airsnitch &>/dev/null; then
        AIRSNITCH_CMD="${TOOL_PATHS[airsnitch]}"
    elif [[ -n "${AIRSNITCH_PATH:-}" && -x "${AIRSNITCH_PATH}" ]]; then
        AIRSNITCH_CMD="$AIRSNITCH_PATH"
    elif [[ -x "${SCRIPT_DIR:-.}/airsnitch/airsnitch" ]]; then
        AIRSNITCH_CMD="${SCRIPT_DIR}/airsnitch/airsnitch"
    elif [[ -x "${HOME:-/root}/airsnitch/airsnitch" ]]; then
        AIRSNITCH_CMD="${HOME}/airsnitch/airsnitch"
    fi

    if [[ -z "$AIRSNITCH_CMD" ]]; then
        log_warn "AirSnitch not found. This test will record 'tool not installed' and skip execution."
        echo ""
        echo -e "${C_CYAN}┌─────────────────────────────────────────────────────────────────┐${C_RESET}"
        echo -e "${C_CYAN}│  AirSnitch not found — optional B10 test                        │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}│  To install:                                                     │${C_RESET}"
        echo -e "${C_CYAN}│    git clone https://github.com/vanhoefm/airsnitch.git           │${C_RESET}"
        echo -e "${C_CYAN}│    cd ${TOOL_PATHS[airsnitch]} && make                                          │${C_RESET}"
        echo -e "${C_CYAN}│  Then either add the build directory to PATH or set:             │${C_RESET}"
        echo -e "${C_CYAN}│    export AIRSNITCH_PATH=/path/to/airsnitch/airsnitch           │${C_RESET}"
        echo -e "${C_CYAN}│                                                                 │${C_RESET}"
        echo -e "${C_CYAN}│  B10 will save a result indicating the tool was not run.         │${C_RESET}"
        echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────────┘${C_RESET}"
        echo ""

        mkdir -p "${SESSION_EVIDENCE_DIR}"
        local out_file="${evidence_prefix}_airsnitch_output.txt"
        {
            echo "============================================================"
            echo "  B10: AirSnitch — Client Isolation Bypass"
            echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "  Status: SKIPPED — AirSnitch not installed"
            echo "============================================================"
            echo ""
            echo "Install: git clone https://github.com/vanhoefm/airsnitch.git && cd ${TOOL_PATHS[airsnitch]} && make"
            echo "Optional: export AIRSNITCH_PATH=/path/to/airsnitch/airsnitch"
        } > "$out_file"

        local result_json
        evidence_register_file "b10_airsnitch_output.txt"
        evidence_register_file "b10_airsnitch_summary.txt"

        local result_json=$(run_tool jq -n \
            --arg status "INFO" \
            --arg summary "B10 skipped: AirSnitch not installed. Install from https://github.com/vanhoefm/airsnitch to test client isolation bypass (GTK abuse, gateway bouncing, port stealing)." \
            --arg details "Tool not found in PATH or AIRSNITCH_PATH. No bypass test performed." \
            --arg recommendations "To run B10: clone and build AirSnitch, then re-run this test case." \
            --argjson tool_available false \
            --argjson bypass_detected false \
            '{
                status: $status,
                summary: $summary,
                details: $details,
                recommendations: $recommendations,
                tool_available: $tool_available,
                bypass_detected: $bypass_detected,
                            }')
        save_tc_result "B10" "$result_json" "has_tool_output:1,clean_run:1"
        log_result "INFO" "B10 skipped — install AirSnitch to test client isolation bypass"
        return 0
    fi

    log_success "Found AirSnitch: ${AIRSNITCH_CMD}"

    # Need managed interface (connected) and monitor interface
    if [[ -z "${WIFI_INTERFACE:-}" ]]; then
        configure_network || return 1
    fi

    local mon_iface="${MONITOR_INTERFACE:-}"
    if [[ -z "$mon_iface" ]]; then
        log_info "Monitor interface not set. AirSnitch may require a monitor-mode interface for injection."
        get_or_request_param "mon_iface" "  Enter monitor interface (e.g. wlan0mon), or Enter to try with managed only"
    fi

    #--- Step 2: Ensure we're connected (managed) and optionally have monitor ---
    log_step 2 $total_steps "Verifying interfaces"
    update_tc_progress 2 $total_steps "Interfaces"

    ensure_managed_mode || return 1

    local my_ip gateway_ip
    local my_ip=$(run_tool ip -4 addr show "$WIFI_INTERFACE" 2>/dev/null | awk '/inet/{print $2}' | cut -d'/' -f1 | head -1)
    local gateway_ip="${GATEWAY_IP:-$(run_tool ip route show dev "$WIFI_INTERFACE" 2>/dev/null | awk '/default/{print $3}' | head -1)}"

    if [[ -z "$my_ip" ]]; then
        log_error "No IP on ${WIFI_INTERFACE}. Connect to the target WiFi first."
        return 1
    fi
    log_success "Connected: ${WIFI_INTERFACE} IP=${my_ip}, Gateway=${gateway_ip}"

    #--- Step 3: Run AirSnitch ---
    log_step 3 $total_steps "Running AirSnitch"
    update_tc_progress 3 $total_steps "Running"

    check_abort || return 1

    mkdir -p "${SESSION_EVIDENCE_DIR}"
    local out_file="${evidence_prefix}_airsnitch_output.txt"
    local run_iface="${mon_iface:-$WIFI_INTERFACE}"

    {
        echo "============================================================"
        echo "  B10: AirSnitch — Client Isolation Bypass"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Managed interface: ${WIFI_INTERFACE}"
        echo "  Monitor/attack interface: ${run_iface}"
        echo "  Gateway: ${gateway_ip}"
        echo "============================================================"
        echo ""
    } > "$out_file"

    log_cmd "${AIRSNITCH_CMD} -i ${run_iface} (or see tool usage)"
    # Common patterns: -i interface, -b bssid; run and capture. If tool has different CLI, output will show usage.
    local airsnitch_exit=0
    if ! "$AIRSNITCH_CMD" -i "$run_iface" >> "$out_file" 2>&1; then
        local airsnitch_exit=$?
        echo "[Exit code: ${airsnitch_exit}]" >> "$out_file"
    fi

    #--- Step 4: Summarize and detect bypass in output ---
    log_step 4 $total_steps "Analyzing AirSnitch output"
    update_tc_progress 4 $total_steps "Analyzing"

    local bypass_detected="false"
    local result_status="INFO"
    local result_summary="AirSnitch run completed. Review evidence for client isolation bypass findings."
    local result_details=""
    if [[ -f "$out_file" ]]; then
        if grep -qiE "bypass|vulnerable|success|inject|GTK|gateway bounce|port steal" "$out_file" 2>/dev/null; then
            local bypass_detected="true"
            local result_status="FINDING"
            local result_summary="AirSnitch indicated a possible client isolation bypass. Review b10_airsnitch_output.txt."
            local result_details="Tool output contained keywords suggesting bypass (GTK abuse, gateway bouncing, or port stealing)."
        fi
        if [[ $airsnitch_exit -ne 0 ]]; then
            local result_details="${result_details} Exit code: ${airsnitch_exit}. Tool may need different arguments or environment."
        fi
    fi

    # Summary file for report
    local summary_file="${evidence_prefix}_airsnitch_summary.txt"
    {
        echo "============================================================"
        echo "  B10: AirSnitch Summary"
        echo "============================================================"
        echo "  Tool: ${AIRSNITCH_CMD}"
        echo "  Interface: ${run_iface}"
        echo "  Bypass indicated: ${bypass_detected}"
        echo "  Status: ${result_status}"
        echo ""
        echo "  Recommendations:"
        if [[ "$bypass_detected" == "true" ]]; then
            echo "  - Client isolation can be bypassed; consider AP/controller hardening."
            echo "  - Review NDSS 2026 AirSnitch paper for mitigations (key separation, gateway filtering)."
        else
            echo "  - Review raw output in b10_airsnitch_output.txt for details."
            echo "  - If AirSnitch usage differs, run manually and attach output to evidence."
        fi
    } > "$summary_file"

    #--- Step 5: Save result ---
    log_step 5 $total_steps "Saving results"
    update_tc_progress 5 $total_steps "Saving"

    local recommendations="Review b10_airsnitch_output.txt. If a bypass was found, harden AP/client isolation and gateway forwarding."
    if [[ "$bypass_detected" == "true" ]]; then
        local recommendations="Client isolation bypass detected. Harden wireless controller: enforce key separation, disable gateway bouncing where possible, and review port/VLAN mapping."
    fi

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "${result_details:-AirSnitch executed. See evidence.}" \
        --arg recommendations "$recommendations" \
        --argjson tool_available true \
        --argjson bypass_detected "$bypass_detected" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            tool_available: $tool_available,
            bypass_detected: $bypass_detected,
        }')
    save_tc_result "B10" "$result_json" "has_tool_output:1,clean_run:1"

    if [[ "$bypass_detected" == "true" ]]; then
        log_result "FINDING" "Client isolation bypass indicated by AirSnitch"
    else
        log_result "INFO" "B10 AirSnitch run complete — review evidence"
    fi
    return 0
}
