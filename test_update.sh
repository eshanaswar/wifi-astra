#!/usr/bin/env bash
set -uo pipefail

# Mock environment
export SESSION_ID="test_session"
export SESSION_DIR="/tmp/wifi_astra_test"
export SESSION_RESULTS_DIR="${SESSION_DIR}/results"
export SESSION_EVIDENCE_DIR="${SESSION_DIR}/evidence"
export SESSION_LOG_DIR="${SESSION_DIR}/logs"
mkdir -p "$SESSION_RESULTS_DIR" "$SESSION_EVIDENCE_DIR" "$SESSION_LOG_DIR"

# Global arrays needed by lib/session.sh
declare -gA TC_STATUS
declare -gA TC_RESULTS_FILE
declare -ga TC_ORDER=("A1" "B1" "D1")
for _tc in "${TC_ORDER[@]}"; do
    TC_STATUS["$_tc"]="not_run"
done

# Mock colors
export C_CYAN=""
export C_RESET=""
export C_BOLD=""
export C_YELLOW=""
export C_GRAY=""
export C_WHITE=""
export C_BG_RED=""

# Mock logging
log_step() { echo "[STEP] $*"; }
log_success() { echo "[OK] $*"; }
log_error() { echo "[ERROR] $*"; }
log_warn() { echo "[WARN] $*"; }
log_info() { echo "[INFO] $*"; }
log_result() { echo "[RESULT] $*"; }
_log_to_file() { :; }
update_tc_progress() { :; }
run_tool() { "$@"; }
run_fg() { "$@"; }

# Source libraries
SCRIPT_DIR=$(pwd)
source lib/confidence.sh
source lib/session.sh

# Mock validate_tc_result (just return 0)
validate_tc_result() { return 0; }
validate_json() { jq . >/dev/null 2>&1 <<< "$1"; }
save_session_state() { :; }

echo "--- Testing A1 Schema and Confidence ---"
# Mock A1 variables
csv_file="${SESSION_EVIDENCE_DIR}/a1_test.csv"
cap_file="${SESSION_EVIDENCE_DIR}/a1_test.cap"
summary_file="${SESSION_EVIDENCE_DIR}/a1_networks_summary.txt"
touch "$csv_file" "$cap_file" "$summary_file"
GUEST_SSID="TestNet"
GUEST_BSSID="00:11:22:33:44:55"
GUEST_CHANNEL="6"
INTERNAL_SSID="CorpNet"
INTERNAL_BSSID="AA:BB:CC:DD:EE:FF"
AIRODUMP_SCAN_TIME="30"
networks_json='[{"ssid":"TestNet","bssid":"00:11:22:33:44:55","channel":"6","encryption":"WPA2","signal":"-50","beacons":"100"}]'
network_count=1
hidden_count=0
open_networks=0
target_found="true"
result_status="SECURE"
result_summary="1 wireless networks discovered. 0 hidden SSIDs."
result_details="INFO: Top BSSID OUI prefixes..."

# The actual code from A1
has_tool_output=0
[[ -f "$csv_file" ]] && has_tool_output=1
has_primary=0
[[ -f "$cap_file" ]] && has_primary=1
adequate_runtime=1
clean_run=1

result_json=$(jq -n \
    --arg status "$result_status" \
    --arg summary "$result_summary" \
    --arg details "$result_details" \
    --arg target_ssid "$GUEST_SSID" \
    --arg target_bssid "$GUEST_BSSID" \
    --arg target_channel "$GUEST_CHANNEL" \
    --arg internal_ssid "$INTERNAL_SSID" \
    --arg internal_bssid "$INTERNAL_BSSID" \
    --argjson networks "$networks_json" \
    --argjson network_count "$network_count" \
    --argjson hidden_count "$hidden_count" \
    --argjson open_count "$open_networks" \
    --arg target_found "$target_found" \
    --arg scan_duration "${AIRODUMP_SCAN_TIME}s" \
    --arg csv_file "$(basename "$csv_file")" \
    --arg cap_file "$(basename "$cap_file")" \
    --arg summary_file "$(basename "$summary_file")" \
    '{
        status: $status,
        summary: $summary,
        details: $details,
        network_count: $network_count,
        hidden_count: $hidden_count,
        open_count: $open_count,
        target_ssid: $target_ssid,
        target_bssid: $target_bssid,
        target_channel: $target_channel,
        internal_ssid: $internal_ssid,
        internal_bssid: $internal_bssid,
        target_identified: ($target_found == "true"),
        scan_duration: $scan_duration,
        networks: $networks,
        recommendations: (
            if $open_count > 0 then "Open networks detected. Ensure no corporate data traverses unencrypted WiFi."
            else "All networks use encryption."
            end
        ),
        evidence_files: [$csv_file, $cap_file, $summary_file]
    }')

save_tc_result "A1" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0

echo "Verifying A1 Results File..."
cat "$SESSION_RESULTS_DIR/a1_results.json" | jq .
if grep -q "confidence" "$SESSION_RESULTS_DIR/a1_results.json"; then
    echo "SUCCESS: Confidence object present in A1"
else
    echo "FAIL: Confidence object missing in A1"
    exit 1
fi

echo "--- Testing B1 Schema and Confidence ---"
# Mock B1 variables
reachable_count=1
client_count=2
second_device_ip="192.168.1.10"
result_status="FINDING"
isolation_enforced="false"
summary="Client isolation NOT enforced. 1 client(s) are reachable."
reachable_json='[{"ip":"192.168.1.10","methods":"icmp arp"}]'
arp_scan_file="${SESSION_EVIDENCE_DIR}/b1_test_arp_scan"
touch "${arp_scan_file}.nmap"
reach_file="${SESSION_EVIDENCE_DIR}/b1_test_reach.txt"
touch "$reach_file"
declare -A TOOL_PATHS
TOOL_PATHS[jq]="jq"

# The actual code from B1
has_tool_output=1
has_primary=0
[[ $client_count -gt 0 ]] && has_primary=1
has_known_target=0
[[ -n "${second_device_ip:-}" ]] && has_known_target=1
is_secure_claim=0
[[ "$result_status" == "SECURE" ]] && is_secure_claim=1

result_json=$(jq -n \
    --arg status "$result_status" \
    --arg summary "$summary" \
    --arg details "Tested against $client_count client(s). $reachable_count responded." \
    --arg recommendations "Enable AP/Client isolation..." \
    --argjson clients_found "$client_count" \
    --argjson clients_reachable "$reachable_count" \
    --arg isolation_enforced "$isolation_enforced" \
    --argjson reachable_clients "$reachable_json" \
    --arg arp_scan "$(basename "${arp_scan_file}.nmap")" \
    --arg reach_test "$(basename "$reach_file")" \
    '{
        status: $status,
        summary: $summary,
        details: $details,
        recommendations: $recommendations,
        clients_discovered: $clients_found,
        clients_reachable: $clients_reachable,
        isolation_enforced: ($isolation_enforced == "true"),
        reachable_data: $reachable_clients,
        evidence_files: [$arp_scan, $reach_test]
    }')

save_tc_result "B1" "$result_json" 0 $has_tool_output $has_primary 1 1 1 0 $has_known_target 1 1 $is_secure_claim

echo "Verifying B1 Results File..."
cat "$SESSION_RESULTS_DIR/b1_results.json" | jq .
if grep -q "confidence" "$SESSION_RESULTS_DIR/b1_results.json"; then
    echo "SUCCESS: Confidence object present in B1"
else
    echo "FAIL: Confidence object missing in B1"
    exit 1
fi

echo "--- Testing D1 Schema and Confidence ---"
# Mock D1 variables
psk_cracked="true"
cracked_psk="password123"
pmkid_captured="true"
handshake_captured="true"
hash_file="${SESSION_EVIDENCE_DIR}/d1_test.hc22000"
touch "$hash_file"
hcx_pcapng="${SESSION_EVIDENCE_DIR}/d1_test.pcapng"
touch "$hcx_pcapng"
handshake_cap="${SESSION_EVIDENCE_DIR}/d1_test_handshake"
touch "${handshake_cap}-01.cap"

# The actual code from D1
result_status="CRITICAL"
result_summary="CRITICAL: WPA PSK was cracked..."
recommendations="Use strong passphrase..."

has_primary=0
[[ "$pmkid_captured" == "true" || "$handshake_captured" == "true" ]] && has_primary=1
clean_run=1

evidence_array=()
evidence_array+=("d1_findings.txt")
[[ -f "$hcx_pcapng" ]] && evidence_array+=("$(basename "$hcx_pcapng")")
[[ -f "$hash_file" && -s "$hash_file" ]] && evidence_array+=("$(basename "$hash_file")")
cap_file_final=$(ls "${handshake_cap}"*.cap 2>/dev/null | head -1)
[[ -n "$cap_file_final" ]] && evidence_array+=("$(basename "$cap_file_final")")

result_json=$(jq -n \
    --arg status "$result_status" \
    --arg summary "$result_summary" \
    --arg details "PMKID Captured: $pmkid_captured, Handshake Captured: $handshake_captured, PSK Cracked: $psk_cracked" \
    --arg recommendations "$recommendations" \
    --arg pmkid_captured "$pmkid_captured" \
    --arg handshake_captured "$handshake_captured" \
    --arg psk_cracked "$psk_cracked" \
    --arg cracked_psk "$cracked_psk" \
    --arg hash_file "$(basename "$hash_file")" \
    --argjson evidence_files "$(printf '%s\n' "${evidence_array[@]}" | jq -R . | jq -s .)" \
    '{
        status: $status,
        summary: $summary,
        details: $details,
        recommendations: $recommendations,
        pmkid_captured: ($pmkid_captured == "true"),
        handshake_captured: ($handshake_captured == "true"),
        psk_cracked: ($psk_cracked == "true"),
        cracked_psk: $cracked_psk,
        hash_file: $hash_file,
        evidence_files: $evidence_files
    }')

save_tc_result "D1" "$result_json" 1 1 $has_primary 1 1 1 0 1 1 $clean_run 0

echo "Verifying D1 Results File..."
cat "$SESSION_RESULTS_DIR/d1_results.json" | jq .
if grep -q "confidence" "$SESSION_RESULTS_DIR/d1_results.json"; then
    echo "SUCCESS: Confidence object present in D1"
else
    echo "FAIL: Confidence object missing in D1"
    exit 1
fi

echo "CLEANUP"
rm -rf "$SESSION_DIR"
