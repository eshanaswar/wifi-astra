# Implementer Task: Refactor Category D Modules (D2-D4, D6, D7)

## Goal
Refactor Category D modules (`modules/d2_wep_cracking.sh`, `modules/d3_wps_testing.sh`, `modules/d4_wpa3_dragonblood.sh`, `modules/d6_owe_downgrade.sh`, `modules/d7_wpa3_downgrade_active.sh`) to follow the project's new standards.

## Standards Checklist
1. **Hardening**: Add `set -uo pipefail` at the top (after header).
2. **Dependencies**: Use `check_module_dependencies "<ID>"` (e.g., "D2").
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
- **D2**: WEP cracking. Uses `airodump-ng`, `aireplay-ng`, `aircrack-ng`.
- **D3**: WPS testing. Uses `reaver` or `bully`.
- **D4**: WPA3 Dragonblood. Uses `dragonblood` toolset.
- **D6/D7**: Downgrade attacks. Ensure proper capture and analysis.

## Files to Modify
- `modules/d2_wep_cracking.sh`
- `modules/d3_wps_testing.sh`
- `modules/d4_wpa3_dragonblood.sh`
- `modules/d6_owe_downgrade.sh`
- `modules/d7_wpa3_downgrade_active.sh`

## Reference
See `modules/a1_identify_networks.sh` for the ideal implementation pattern.
