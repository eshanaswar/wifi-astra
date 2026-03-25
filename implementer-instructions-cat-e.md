# Implementer Task: Refactor Category E Modules (E1-E5)

## Goal
Refactor Category E modules (`modules/e1_krack_attack.sh`, `modules/e2_fragattacks.sh`, `modules/e3_deauth_resilience.sh`, `modules/e4_wireless_fuzzing.sh`, `modules/e5_kr00k_test.sh`) to follow the project's new standards.

## Standards Checklist
1. **Hardening**: Add `set -uo pipefail` at the top (after header).
2. **Dependencies**: Use `check_module_dependencies "<ID>"` (e.g., "E1").
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
   - Use `save_tc_result "<ID>" "$result_json" <11_FLAGS>`.
   - Call `save_session_state`.
6. **Safety**: Ensure `check_abort || return 1` is used between steps and in long loops.

## Specific Module Notes
- **E1**: KRACK attack. Uses `krack-test`, `tcpdump`, `tshark`.
- **E2**: FragAttacks. Uses `fragattacks` toolset.
- **E3**: Deauth resilience. Uses `aireplay-ng`.
- **E4**: Wireless fuzzing. Uses `scapy` or custom fuzzers.
- **E5**: KR00k test. Uses `kr00k-test` tool.

## Files to Modify
- `modules/e1_krack_attack.sh`
- `modules/e2_fragattacks.sh`
- `modules/e3_deauth_resilience.sh`
- `modules/e4_wireless_fuzzing.sh`
- `modules/e5_kr00k_test.sh`

## Reference
See `modules/a1_identify_networks.sh` for the ideal implementation pattern.
