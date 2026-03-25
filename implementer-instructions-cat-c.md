# Implementer Task: Refactor Category C Modules (C3-C5)

## Goal
Refactor `modules/c3_vlan_hopping.sh`, `modules/c4_radius_reachability.sh`, and `modules/c5_egress_filtering.sh` to follow the project's new standards.

## Standards Checklist
1. **Hardening**: Add `set -uo pipefail` at the top (after header).
2. **Dependencies**: Use `check_module_dependencies "C3"` (or C4, C5) in Step 1.
3. **Process Management**: 
   - Use `run_fg "tool" args...` for synchronous tools.
   - Use `spawn_bg "label" "tool" args...` and `stop_process "label"` for background tasks.
   - Use `run_fg "jq"` for all JSON operations.
4. **Logging & Progress**:
   - Use `log_step`, `update_tc_progress`, `log_success`, `log_info`, etc.
   - Ensure `total_steps` is accurate.
5. **Reporting**:
   - Use `evidence_register_file` for all output files.
   - Construct result JSON using `run_fg "jq" -n`.
   - Use `save_tc_result "C3" "$result_json" <11_FLAGS>` with appropriate flags.
   - Flags: `pcap_required has_tool_output has_primary has_cmds has_versions has_env has_confirm has_known_target adequate_runtime clean_run is_secure_claim` (all 0 or 1).
   - Call `save_session_state`.
6. **Safety**: Ensure `check_abort || return 1` is used between steps and in long loops.

## Specific Module Notes
- **C3**: Uses `yersinia`, `tcpdump`, `scapy`, `tshark`. Ensure `evidence_register_file` is used for pcap and text results.
- **C4**: Uses `radius-test` (custom script or tool). Ensure it uses `run_fg`.
- **C5**: Uses `egress-tester` or similar. Ensure proper reporting of reachable ports.

## Files to Modify
- `/home/kali/Documents/Antigravity/WiFi_PT/modules/c3_vlan_hopping.sh`
- `/home/kali/Documents/Antigravity/WiFi_PT/modules/c4_radius_reachability.sh`
- `/home/kali/Documents/Antigravity/WiFi_PT/modules/c5_egress_filtering.sh`

## Reference
See `modules/a1_identify_networks.sh` for the ideal implementation pattern.
