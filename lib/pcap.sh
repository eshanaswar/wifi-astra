#!/usr/bin/env bash
#===============================================================================
#  lib/pcap.sh — Unified ${TOOL_PATHS[tcpdump]} capture + optional ${TOOL_PATHS[tshark]} decode
#===============================================================================

declare -gA _PCAP_PID=()
declare -gA _PCAP_FILE=()
declare -gA _PCAP_META=()

pcap_file_for_tc() {
    local tc_id="$1"
    echo "${SESSION_EVIDENCE_DIR}/${tc_id,,}_capture.pcap"
}

pcap_meta_for_tc() {
    local tc_id="$1"
    echo "${SESSION_EVIDENCE_DIR}/${tc_id,,}_capture.meta.txt"
}

pcap_decode_out_for_tc() {
    local tc_id="$1"
    echo "${SESSION_EVIDENCE_DIR}/${tc_id,,}_tshark_summary.txt"
}

pcap_start() {
    local tc_id="$1"
    local iface="$2"
    local bpf_filter="${3:-}"

    [[ -n "${SESSION_EVIDENCE_DIR:-}" ]] || return 1
    mkdir -p "$SESSION_EVIDENCE_DIR" 2>/dev/null || true

    if ! command -v tcpdump &>/dev/null; then
        return 1
    fi

    local pcap meta
    pcap=$(pcap_file_for_tc "$tc_id")
    meta=$(pcap_meta_for_tc "$tc_id")

    {
        echo "=== PCAP CAPTURE META ==="
        echo "tc_id: ${tc_id}"
        echo "started_at: $(date -Iseconds)"
        echo "iface: ${iface}"
        echo "bpf_filter: ${bpf_filter:-<none>}"
        ${TOOL_PATHS[tcpdump]} --version 2>/dev/null | head -1 || true
        echo "command: ${TOOL_PATHS[tcpdump]} -i ${iface} -U -w ${pcap} ${bpf_filter}"
        echo ""
    } >"$meta"

    if [[ -n "$bpf_filter" ]]; then
        ${TOOL_PATHS[tcpdump]} -i "$iface" -U -w "$pcap" $bpf_filter >/dev/null 2>&1 &
    else
        ${TOOL_PATHS[tcpdump]} -i "$iface" -U -w "$pcap" >/dev/null 2>&1 &
    fi
    local pid=$!

    _PCAP_PID["$tc_id"]="$pid"
    _PCAP_FILE["$tc_id"]="$pcap"
    _PCAP_META["$tc_id"]="$meta"

    # Track for abort cleanup if trap_handler uses PID tracking
    if declare -f track_pid &>/dev/null; then
        track_pid "${tc_id,,}_pcap" "$pid"
    fi

    return 0
}

pcap_stop() {
    local tc_id="$1"
    local pid="${_PCAP_PID[$tc_id]:-}"
    local pcap="${_PCAP_FILE[$tc_id]:-}"
    local meta="${_PCAP_META[$tc_id]:-}"

    [[ -n "$pid" ]] || return 0

    if kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        
        # Give it up to 3 seconds to exit gracefully
        local wait_secs=0
        while kill -0 "$pid" 2>/dev/null && (( wait_secs < 3 )); do
            sleep 1
            ((wait_secs++))
        done
        
        # If it's still alive (e.g. kernel locked due to interface cycling), murder it
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    fi

    {
        echo "stopped_at: $(date -Iseconds)"
        if [[ -f "$pcap" ]]; then
            echo "pcap_size: $(stat -c '%s' "$pcap" 2>/dev/null || echo 0)"
        else
            echo "pcap_size: 0"
        fi
    } >>"$meta" 2>/dev/null || true

    _PCAP_PID["$tc_id"]=""
    return 0
}

pcap_decode_if_available() {
    local tc_id="$1"
    local profile="${2:-none}"
    local pcap="${_PCAP_FILE[$tc_id]:-$(pcap_file_for_tc "$tc_id")}"

    command -v tshark &>/dev/null || return 1
    [[ -f "$pcap" ]] || return 1

    local out
    out=$(pcap_decode_out_for_tc "$tc_id")
    : >"$out"

    if declare -f start_spinner &>/dev/null; then
        start_spinner "Decoding PCAP to text summary"
    fi

    local pcap_size=0
    if [[ -f "$pcap" ]]; then
        pcap_size=$(stat -c '%s' "$pcap" 2>/dev/null || echo 0)
    fi

    local tshark_opts="-n -q"  # Disable name resolution and be quiet
    local large_file_limit="-c 10000" # Safety cap for all summary decodes
    local skip_io_stat="false"

    # Throttle if file is > 50MB
    if [[ $pcap_size -gt 52428800 ]]; then
        large_file_limit="-c 5000"
        skip_io_stat="true"
        {
            echo "!!! PCAP file is large ($(numfmt --to=iec $pcap_size)). Optimizing decode pass."
            echo "Summary limited to first 5000 packets."
            echo ""
        } >>"$out"
    fi

    {
        echo "=== TSHARK DECODE SUMMARY ==="
        ${TOOL_PATHS[tshark]} --version 2>/dev/null | head -1 || true
        echo "PCAP: $pcap"
        echo "profile: $profile"
        echo ""
        if [[ "$skip_io_stat" == "false" ]]; then
            echo "--- IO STAT (count + time) ---"
            ${TOOL_PATHS[tshark]} $tshark_opts -r "$pcap" -q -z io,stat,0 2>/dev/null || true
            echo ""
        fi
    } >>"$out"

    case "$profile" in
        dns)
            {
                echo "--- DNS QUERIES/RESPONSES (fields) ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "dns" -T fields \
                    -e frame.time -e ip.src -e ip.dst \
                    -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport \
                    -e dns.flags.response -e dns.flags.rcode \
                    -e dns.qry.name -e dns.qry.type -e dns.a -e dns.aaaa -e dns.cname \
                    2>/dev/null | head -n 200 || true
                echo ""
                echo "--- mDNS (udp/5353) ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "udp.port==5353 && dns" -T fields \
                    -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.ptr.domain_name -e dns.resp.name \
                    2>/dev/null | head -n 200 || true
                echo ""
            } >>"$out"
            ;;
        l2_discovery)
            {
                echo "--- LAYER 2 DISCOVERY (LLDP/CDP/LLMNR/NBNS/SSDP) ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "lldp || cdp || llmnr || nbns || ssdp" -T fields \
                    -e frame.time -e eth.src -e ip.src -e ip.dst \
                    -e lldp.chassis.id -e lldp.system.name -e cdp.deviceid -e cdp.ip_address \
                    -e dns.qry.name -e http.request.method -e http.host \
                    2>/dev/null | head -n 400 || true
                echo ""
            } >>"$out"
            ;;
        wifi_mgmt)
            {
                echo "--- WIFI MANAGEMENT & CONTROL ---"
                # Combine beacons, probes, deauths, and eapol into one pass
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" \
                    -Y "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || wlan.fc.type_subtype==0x04 || wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a || eapol" \
                    -T fields \
                    -e frame.time -e wlan.fc.type_subtype -e wlan.sa -e wlan.da -e wlan.bssid -e wlan.ssid \
                    -e wlan_radio.channel -e radiotap.dbm_antsignal -e wlan.fixed.reason_code -e eapol.type \
                    2>/dev/null | head -n 500 || true
                echo ""
            } >>"$out"
            ;;
        dhcp)
            {
                echo "--- DHCP (BOOTP) ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "bootp" -T fields \
                    -e frame.time -e eth.src -e ip.src -e ip.dst \
                    -e bootp.option.dhcp -e bootp.option.dhcp_server_id -e bootp.yiaddr \
                    -e bootp.option.router -e bootp.option.dns_server -e bootp.option.hostname \
                    2>/dev/null | head -n 200 || true
                echo ""
            } >>"$out"
            ;;
        mitm_arp_tls)
            {
                echo "--- ARP ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "arp" -T fields \
                    -e frame.time -e eth.src \
                    -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
                    2>/dev/null | head -n 200 || true
                echo ""
                echo "--- HTTP/TLS METADATA ---"
                ${TOOL_PATHS[tshark]} $tshark_opts $large_file_limit -r "$pcap" -Y "tcp.port==80 || tcp.port==443" -T fields \
                    -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
                    -e http.host -e http.request.uri -e tls.handshake.extensions_server_name \
                    2>/dev/null | head -n 400 || true
                echo ""
            } >>"$out"
            ;;
        *)
            # No-op profile; header still provides count/time.
            ;;
    esac

    if declare -f stop_spinner &>/dev/null; then
        stop_spinner
    fi

    return 0
}

