import os
import glob

# Task 4: Update all timed modules with metadata and indefinite execution logic.
# This script automates the update of 35+ modules to support Astra's Indefinite mode.

modules = [
    "a1_identify_networks.sh", "a3_hidden_ssid.sh", "a4_client_fingerprinting.sh",
    "b3_cdp_lldp_leaks.sh", "b4_mdns_leaks.sh", "b5_snmp_exposure.sh",
    "b6_dhcp_analysis.sh", "b7_ipv6_leaks.sh", "b8_broadcast_leaks.sh",
    "b9_ap_vulnerability.sh", "c3_vlan_hopping.sh", "d1_wpa_handshake.sh",
    "d2_wep_cracking.sh", "d3_wps_testing.sh", "d4_wpa3_dragonblood.sh",
    "d5_eap_attack.sh", "d6_owe_downgrade.sh", "d7_wpa3_downgrade_active.sh",
    "e1_krack_attack.sh", "e2_fragattacks.sh", "e3_deauth_resilience.sh",
    "e4_wireless_fuzzing.sh", "e5_kr00k_test.sh", "f1_rogue_ap.sh",
    "f2_pineap_karma.sh", "f3_captive_portal.sh", "f4_portal_bypass.sh",
    "f5_dns_tunnel.sh", "g1_arp_spoofing.sh", "g2_ssl_interception.sh",
    "g3_dns_spoofing.sh", "g4_nac_bypass.sh", "g6_responder_pivot.sh",
    "h1_wids_detection.sh", "h2_pmf_check.sh"
]

updated_count = 0
for m in modules:
    path = f"modules/{m}"
    if not os.path.exists(path):
        print(f"Skipping {path} (not found)")
        continue
    
    with open(path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # 1. Add TIMED="yes" metadata if missing
    if 'TIMED=' not in content:
        # We insert it before # DECODE= to maintain standard order
        if '# DECODE=' in content:
            content = content.replace('# DECODE=', '# TIMED="yes"\n# DECODE=')
        else:
            # Fallback: insert before the first empty line after MODULE_META
            content = content.replace('# MODULE_META', '# MODULE_META\n# TIMED="yes"')
    
    # 2. Update while loops to respect ASTRA_INDEFINITE
    # We use multiple replace calls to cover common variable names
    content = content.replace('while [[ $ELAPSED -lt $SCAN_TIME ]]', 
                              'while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $SCAN_TIME ]]')
    content = content.replace('while [[ $ELAPSED -lt $CAPTURE_TIME ]]', 
                              'while [[ "${ASTRA_INDEFINITE:-}" == "true" || $ELAPSED -lt $CAPTURE_TIME ]]')
    content = content.replace('while [[ $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]', 
                              'while [[ "${ASTRA_INDEFINITE:-}" == "true" || $HEARTBEAT_ELAPSED -lt $SCAN_TIME ]]')
    
    if content != original_content:
        with open(path, 'w') as f:
            f.write(content)
        print(f"Updated {path}")
        updated_count += 1
    else:
        print(f"No changes needed for {path}")

print(f"\nTask Complete. Updated {updated_count} files.")
