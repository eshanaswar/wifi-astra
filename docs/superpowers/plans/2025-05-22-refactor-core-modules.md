# Update A1, B1, D1 to New Result Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor A1, B1, and D1 modules to use the new `save_tc_result` signature and standardized result schema with confidence scoring.

**Architecture:** Update `save_tc_result` calls in each module to pass confidence flags and ensure JSON output matches the expected schema.

**Tech Stack:** Bash, JQ, WiFi-Astra Framework

---

### Task 1: Refactor A1 (modules/a1_identify_networks.sh)

**Files:**
- Modify: `modules/a1_identify_networks.sh`

- [ ] **Step 1: Calculate confidence flags**
Determine values for `has_tool_output` (CSV exists), `has_primary` (CAP exists), `adequate_runtime` (scan completed), and `clean_run`.

- [ ] **Step 2: Update save_tc_result call**
Update the call to: `save_tc_result "A1" "$result_json" 1 $has_tool_output $has_primary 1 1 1 0 1 1 1 0` (adjusting flags as needed).
Wait, the signature is 11 flags:
1. pcap_required
2. has_tool_output
3. has_primary_artifact
4. has_commands
5. has_versions
6. has_environment
7. has_independent_confirm
8. has_known_good_target
9. adequate_runtime
10. clean_run
11. is_secure_claim

- [ ] **Step 3: Ensure schema population**
Verify `summary`, `details`, and `recommendations` are correctly set in the JSON.

- [ ] **Step 4: Verify with bash -n**
Run: `bash -n modules/a1_identify_networks.sh`

---

### Task 2: Refactor B1 (modules/b1_client_isolation.sh)

**Files:**
- Modify: `modules/b1_client_isolation.sh`

- [ ] **Step 1: Calculate confidence flags**
Determine `has_tool_output`, `has_primary` (reachability tests ran), `has_known_target` (if `second_device_ip` provided), `is_secure_claim` (if status is SECURE).

- [ ] **Step 2: Update save_tc_result call**
Update the call to: `save_tc_result "B1" "$result_json" 0 $has_tool_output $has_primary 1 1 1 0 $has_known_target 1 1 $is_secure_claim`

- [ ] **Step 3: Verify with bash -n**
Run: `bash -n modules/b1_client_isolation.sh`

---

### Task 3: Refactor D1 (modules/d1_wpa_handshake.sh)

**Files:**
- Modify: `modules/d1_wpa_handshake.sh`

- [ ] **Step 1: Calculate confidence flags**
Determine `has_primary` (if handshake/PMKID captured), `clean_run`.

- [ ] **Step 2: Update save_tc_result call**
Update the call to: `save_tc_result "D1" "$result_json" 1 1 $has_primary 1 1 1 0 1 1 $clean_run 0`

- [ ] **Step 3: Ensure evidence_files array**
Verify `evidence_files` is correctly populated as a JSON array.

- [ ] **Step 4: Verify with bash -n**
Run: `bash -n modules/d1_wpa_handshake.sh`

---

### Task 4: End-to-End Verification

- [ ] **Step 1: Run verification script**
Create or run a script that mocks the dependencies and executes the modules (or parts of them) to verify the `_results.json` files.
- [ ] **Step 2: Check JSON files**
Verify `_results.json` files contain the correct schema and structured confidence objects.
