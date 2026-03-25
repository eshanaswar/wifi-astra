#!/usr/bin/env bash
# MODULE_META
# NAME="BSSID Correlation Analysis"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="airmon-ng,airodump-ng"
# DESC="Map BSSIDs to same controller, detect infra overlap"
# REQS="monitor_iface,target_ssid"
# PCAP="no"
# DECODE="wifi_mgmt"

#===============================================================================
#  modules/a2_bssid_correlation.sh
#  A2: BSSID Correlation Analysis
#
#  PURPOSE:
#    Analyze the A1 scan data to correlate BSSIDs belonging to the same
#    wireless controller/infrastructure. Maps OUI prefixes to identify which
#    APs are managed by the same controller. Identifies if Target and internal
#    networks share the same physical APs (indicating virtual SSID separation
#    vs physical separation).
#
#  TOOLS: run_tool jq (analysis of A1 JSON data)
#  PHASE: 1A — Passive Recon
#  DEPENDENCIES: A1
#
#  EVIDENCE PRODUCED:
#    - a2_bssid_correlation.txt     (correlation analysis)
#    - a2_ap_infrastructure_map.txt (AP-to-SSID mapping)
#
#  RESULT JSON FIELDS:
#    - shared_aps: count of APs hosting both target and internal SSIDs
#    - unique_ouis: list of OUI prefixes
#    - ap_map[]: grouped by physical AP
#    - same_infrastructure: bool — guest/corp on same APs?
#===============================================================================

run_a2() {
    local total_steps=5
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/a2"

    #--- Step 1: Load scan data from assessment engine ---
    log_step 1 $total_steps "Loading scan data from assessment engine"
    update_tc_progress 1 $total_steps "Loading data"

    if [[ ! -f "${SESSION_DB_FILE:-}" ]]; then
        log_error "Session database not found. Run A1 first."
        return 1
    fi

    local networks_json
    networks_json=$(run_tool astra-engine --db "$SESSION_DB_FILE" ingest list 2>/dev/null)

    if [[ -z "$networks_json" || "$networks_json" == "null" || "$networks_json" == "[]" ]]; then
        log_error "No network data found in database. Run A1 first."
        return 1
    fi

    local network_count
    network_count=$(echo "$networks_json" | run_tool jq length)

    # Use internal variables if available, otherwise fallback to config in DB
    local target_ssid="${GUEST_SSID:-}"
    if [[ -z "$target_ssid" ]]; then
        target_ssid=$(run_tool astra-engine --db "$SESSION_DB_FILE" state get-config --key guest_ssid 2>/dev/null)
    fi

    log_success "Loaded ${network_count} networks from assessment engine"
    log_info "Target SSID: ${target_ssid:-NOT SET}"

    #--- Step 2: Extract and group by OUI prefix ---
    log_step 2 $total_steps "Analyzing OUI prefixes"
    update_tc_progress 2 $total_steps "OUI analysis"

    check_abort || return 1

    local correlation_file="${evidence_prefix}_bssid_correlation.txt"
    local ap_map_file="${evidence_prefix}_ap_infrastructure_map.txt"

    # Header
    {
        echo "============================================================"
        echo "  A2: BSSID Correlation Analysis"
        echo "  Analysis Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Source: Assessment Engine (${network_count} networks)"
        echo "============================================================"
        echo ""
    } > "$correlation_file"

    # Group BSSIDs by OUI (first 3 octets)
    local oui_groups
    local oui_groups=$(echo "$networks_json" | run_tool jq -r '.[].bssid' | cut -d: -f1-3 | sort | uniq -c | sort -rn)

    echo "--- OUI Prefix Distribution ---" >> "$correlation_file"
    echo "$oui_groups" >> "$correlation_file"
    echo "" >> "$correlation_file"

    local unique_oui_count
    local unique_oui_count=$(echo "$oui_groups" | wc -l)
    log_info "${unique_oui_count} unique OUI prefixes found"

    # Show OUI groups
    echo ""
    echo -e "  ${C_BOLD}OUI Prefix Distribution:${C_RESET}"
    echo "$oui_groups" | head -10 | while IFS= read -r line; do
        echo -e "  ${C_GRAY}  ${line}${C_RESET}"
    done

    #--- Step 3: Correlate BSSIDs on same physical AP ---
    log_step 3 $total_steps "Correlating physical APs (virtual SSID detection)"
    update_tc_progress 3 $total_steps "AP correlation"

    check_abort || return 1

    # When multiple SSIDs are on the same AP, their BSSIDs typically differ
    # by only the last octet (or second-to-last octet).
    # Group BSSIDs by their first 5 octets to find co-located SSIDs.

    {
        echo "--- Physical AP Correlation ---"
        echo "(BSSIDs sharing first 5 octets are likely on the same physical AP)"
        echo ""
    } >> "$correlation_file"

    # Build AP groups: key = first 5 octets of BSSID
    local ap_groups_json="{}"
    local shared_ap_count=0
    local same_infrastructure="false"

    while IFS= read -r network_line; do
        local bssid ssid
        local bssid=$(echo "$network_line" | run_tool jq -r '.bssid')
        local ssid=$(echo "$network_line" | run_tool jq -r '.ssid')
        local channel
        local channel=$(echo "$network_line" | run_tool jq -r '.channel')
        local encryption
        local encryption=$(echo "$network_line" | run_tool jq -r '.encryption')

        # AP group key: first 5 octets
        local ap_key
        local ap_key=$(echo "$bssid" | cut -d: -f1-5)

        # Add to groups
        ap_groups_json=$(echo "$ap_groups_json" | run_tool jq \
            --arg key "$ap_key" \
            --arg ssid "$ssid" \
            --arg bssid "$bssid" \
            --arg channel "$channel" \
            --arg encryption "$encryption" \
            '.[$key] = (.[$key] // []) + [{ssid: $ssid, bssid: $bssid, channel: $channel, encryption: $encryption}]')

    done < <(echo "$a1_data" | run_tool jq -c '.networks[]')

    # Analyze AP groups
    {
        echo "--- Co-located SSIDs (Same Physical AP) ---"
        echo ""
    } >> "$ap_map_file"

    local co_located_aps=0
    local target_internal_shared=0
    local ap_map_json="[]"

    while IFS= read -r ap_key; do
        local group
        local group=$(echo "$ap_groups_json" | run_tool jq --arg key "$ap_key" '.[$key]')
        local group_size
        group_size=$(echo "$group" | run_tool jq 'length')

        if [[ $group_size -gt 1 ]]; then
            ((co_located_aps++))

            # Write to AP map file
            {
                echo "Physical AP: ${ap_key}:XX"
                echo "  SSIDs on this AP:"
                echo "$group" | run_tool jq -r '.[] | "    - \(.ssid) (\(.bssid)) CH:\(.channel) \(.encryption)"'
                echo ""
            } >> "$ap_map_file"

            # Check if target SSID shares AP with other SSIDs (especially the reference internal SSID)
            local has_target
            local has_target=$(echo "$group" | run_tool jq --arg target "$target_ssid" '[.[] | select(.ssid == $target)] | length')

            if [[ $has_target -gt 0 && $group_size -gt 1 ]]; then
                ((target_internal_shared++))
                local same_infrastructure="true"

                local other_ssids
                local other_ssids=$(echo "$group" | run_tool jq -r --arg target "$target_ssid" '[.[] | select(.ssid != $target) | .ssid] | unique | join(", ")')

                # Specifically highlight if it shares with the selected INTERNAL_SSID
                if [[ -n "${INTERNAL_SSID:-}" ]]; then
                    if echo "$other_ssids" | grep -q "${INTERNAL_SSID}"; then
                        echo "  *** CRITICAL FINDING: Target SSID '${target_ssid}' SHARES physical AP with Internal SSID '${INTERNAL_SSID}'" >> "$ap_map_file"
                    fi
                fi

                echo "  *** FINDING: Target SSID '${target_ssid}' shares this AP with: ${other_ssids}" >> "$ap_map_file"
                echo "" >> "$ap_map_file"

                log_result "FINDING" "Target '${target_ssid}' shares AP ${ap_key}:XX with: ${other_ssids}"
            fi

            # Add to AP map JSON
            ap_map_json=$(echo "$ap_map_json" | run_tool jq \
                --arg ap_key "$ap_key" \
                --argjson ssids "$group" \
                --argjson has_target "$has_target" \
                '. += [{ap_prefix: $ap_key, ssids: $ssids, has_target: ($has_target > 0)}]')
        fi

    done < <(echo "$ap_groups_json" | run_tool jq -r 'keys[]')

    #--- Step 4: OUI Vendor Lookup ---
    log_step 4 $total_steps "Performing OUI vendor identification"
    update_tc_progress 4 $total_steps "OUI lookup"

    check_abort || return 1

    # Use local OUI database if available, otherwise note for manual lookup
    local oui_results=""
    local oui_db="/usr/share/ieee-data/oui.txt"
    local alt_oui_db="/usr/share/nmap/nmap-mac-prefixes"

    {
        echo ""
        echo "--- OUI Vendor Identification ---"
        echo ""
    } >> "$correlation_file"

    while IFS= read -r oui; do
        oui=$(echo "$oui" | xargs)
        [[ -z "$oui" ]] && continue

        local oui_normalized
        local oui_normalized=$(echo "$oui" | tr -d ':' | tr 'a-f' 'A-F')
        local oui_search
        local oui_search=$(echo "$oui" | tr ':' '-' | tr 'a-f' 'A-F')

        local vendor="Unknown"

        # Try ${TOOL_PATHS[nmap]} MAC prefix DB first
        if [[ -f "$alt_oui_db" ]]; then
            local vendor=$(grep -i "^${oui_normalized:0:6}" "$alt_oui_db" 2>/dev/null | head -1 | awk '{$1=""; print $0}' | xargs)
        fi

        # Try IEEE OUI DB
        if [[ "$vendor" == "Unknown" || -z "$vendor" ]] && [[ -f "$oui_db" ]]; then
            local vendor=$(grep -i "${oui_search}" "$oui_db" 2>/dev/null | head -1 | sed 's/.*)\s*//')
            local vendor=$(echo "$vendor" | xargs)
        fi

        [[ -z "$vendor" ]] && vendor="Unknown (manual lookup needed)"

        local ap_count_for_oui
        local ap_count_for_oui=$(echo "$a1_data" | run_tool jq -r '.networks[].bssid' | grep -ic "^${oui}" || true)

        echo "  ${oui} → ${vendor} (${ap_count_for_oui} APs)" >> "$correlation_file"
        oui_results+="${oui}=${vendor}\n"

    done < <(echo "$a1_data" | run_tool jq -r '.networks[].bssid' | cut -d: -f1-3 | sort -u)

    log_info "OUI vendor lookup complete"

    #--- Step 5: Save results ---
    log_step 5 $total_steps "Saving correlation results"
    update_tc_progress 5 $total_steps "Saving"

    # Determine overall result
    local result_status="INFO"
    local result_summary=""
    local recommendations=""

    if [[ "$same_infrastructure" == "true" ]]; then
        local result_status="FINDING"
        local int_msg=""
        [[ -n "${INTERNAL_SSID:-}" ]] && int_msg=" (including '${INTERNAL_SSID}')"
        local result_summary="Target WiFi '${target_ssid}' shares physical APs with ${target_internal_shared} other network(s)${int_msg}. This indicates virtual SSID separation (not physical)."
        local recommendations="Virtual SSID separation detected. Verify: (1) VLANs are correctly assigned per SSID, (2) Inter-VLAN routing is restricted, (3) ACLs prevent target→internal traffic. Physical AP separation would provide stronger isolation."
    else
        local result_status="SECURE"
        local result_summary="No evidence that target WiFi shares physical APs with internal/corporate networks."
        local recommendations="Continue testing with connectivity-based modules to verify logical segregation is effective."
    fi

    local details=""
    details+="Physical APs hosting multiple SSIDs: ${co_located_aps}\n"
    details+="Target SSID on shared APs: ${target_internal_shared}\n"
    details+="Unique OUI prefixes: ${unique_oui_count}\n"
    details+="\nVendor identification:\n$(echo -e "$oui_results")"

    local result_json
    evidence_register_file "a2_bssid_correlation.txt"
    evidence_register_file "a2_ap_infrastructure_map.txt"

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "$(echo -e "$details")" \
        --arg recommendations "$recommendations" \
        --argjson co_located_aps "$co_located_aps" \
        --argjson target_internal_shared "$target_internal_shared" \
        --arg same_infrastructure "$same_infrastructure" \
        --argjson ap_map "$ap_map_json" \
        --argjson unique_oui_count "$unique_oui_count" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            co_located_aps: $co_located_aps,
            target_internal_shared: $target_internal_shared,
            same_infrastructure: ($same_infrastructure == "true"),
            ap_map: $ap_map,
            unique_oui_count: $unique_oui_count,
                    }')

    save_tc_result "A2" "$result_json" "has_tool_output:1,clean_run:1"

    # Display summary
    echo ""
    if [[ "$same_infrastructure" == "true" ]]; then
        log_result "FINDING" "Target and internal SSIDs share ${target_internal_shared} physical AP(s)"
        log_result "INFO" "Virtual SSID separation detected — segregation relies on VLAN/ACLs"
    else
        log_result "SECURE" "No shared physical APs between Target and internal networks"
    fi
    log_result "INFO" "${co_located_aps} APs host multiple SSIDs total"

    return 0
}