#!/usr/bin/env bash
# Verification script for Task 03-01-01 fixes

# Mock run_tool
run_tool() {
    if [[ "$1" == "jq" ]]; then
        shift
        jq "$@"
    else
        "$@"
    fi
}
export -f run_tool

# Mock logging
log_warn() { echo "WARN: $1"; }
log_error() { echo "ERROR: $1"; }
log_info() { echo "INFO: $1"; }
log_success() { echo "SUCCESS: $1"; }
export -f log_warn log_error log_info log_success

# Mock TC_REGISTRY and get_tc_field
declare -gA TC_REGISTRY
TC_REGISTRY=( ["A1"]="Identify Networks|A|none|no|Desc" )
get_tc_field() {
    local tc_id="$1"
    local field="$2"
    local entry="${TC_REGISTRY[$tc_id]}"
    case "$field" in
        name) echo "${entry%%|*}" ;;
    esac
}
export -f get_tc_field

# Load the files
# Note: we might need to mock more things because of set -uo pipefail
source ./lib/session.sh
source ./lib/report.sh

# Mock required variables
TC_ORDER=("A1")
declare -gA TC_STATUS
TC_STATUS["A1"]="done"
declare -gA TC_RESULTS_FILE
SESSION_RESULTS_DIR="/tmp/wifi_astra_test_results"
SESSION_REPORT_DIR="/tmp/wifi_astra_test_reports"
mkdir -p "$SESSION_RESULTS_DIR" "$SESSION_REPORT_DIR"

echo "=== 1. Testing bash -n ==="
bash -n lib/session.sh lib/report.sh && echo "Syntax OK" || echo "Syntax ERROR"

echo "=== 2. Testing save_tc_result repair ==="
# Input with missing fields and lowercase status
json_input='{"status":"vulnerable", "summary":null}'
# save_tc_result will repair status to FINDING and fill defaults
save_tc_result "A1" "$json_input"
result_file=$(get_tc_result_file "A1")
echo "Repaired JSON:"
cat "$result_file"
# Verify status is FINDING and summary is "No summary provided"
status=$(jq -r .status "$result_file")
summary=$(jq -r .summary "$result_file")
if [[ "$status" == "FINDING" && "$summary" == "No summary provided" ]]; then
    echo "save_tc_result repair: PASS"
else
    echo "save_tc_result repair: FAIL (Status: $status, Summary: $summary)"
fi

echo "=== 3. Testing validate_tc_result optimization ==="
valid_json='{"status":"FINDING","summary":"test","details":"test","confidence":"low","evidence_files":[],"recommendations":"test"}'
if validate_tc_result "$valid_json"; then
    echo "validate_tc_result (valid): PASS"
else
    echo "validate_tc_result (valid): FAIL"
fi

invalid_json='{"status":"FINDING"}' # Missing fields
if ! validate_tc_result "$invalid_json"; then
    echo "validate_tc_result (invalid): PASS"
else
    echo "validate_tc_result (invalid): FAIL"
fi

echo "=== 4. Testing HTML escaping ==="
# Create a result with special characters
malicious_json='{
    "status":"FINDING",
    "summary":"<script>alert(1)</script>",
    "details":"\"quotes\" & &amp;",
    "confidence":"high",
    "evidence_files":["file<1>.txt"],
    "recommendations":"Don' "'" 't do this"
}'
save_tc_result "A1" "$malicious_json"
generate_report >/dev/null 2>&1

html_report="${SESSION_REPORT_DIR}/assessment_report.html"
echo "Checking HTML report for escaping..."
if grep -F "&lt;script&gt;" "$html_report" >/dev/null; then
    echo "HTML escaping (summary): PASS"
else
    echo "HTML escaping (summary): FAIL"
fi

if grep -F "&quot;quotes&quot; &amp; &amp;amp;" "$html_report" >/dev/null; then
    echo "HTML escaping (details): PASS"
else
    echo "HTML escaping (details): FAIL"
fi

if grep -F "file&lt;1&gt;.txt" "$html_report" >/dev/null; then
    echo "HTML escaping (evidence): PASS"
else
    echo "HTML escaping (evidence): FAIL"
fi
