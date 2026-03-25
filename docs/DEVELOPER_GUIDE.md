# WiFi-Astra: Developer Guide

This guide is for developers who want to extend the **WiFi-Astra** framework, add new assessment modules, or contribute to the core library.

## 🏗️ Architecture Overview
WiFi-Astra is built on a modular, library-driven Bash architecture.
- `wifi-astra.sh`: The main orchestrator.
- `lib/`: Core libraries (logging, process management, session state, etc.).
- `modules/`: Individual test cases (TCs).
- `utils/`: External helpers (Python parsers, etc.).

## 🛠️ Core Library API

### Process Management (`lib/process_manager.sh`)
Never use raw `&` or `bash -c`. Use the following helpers to ensure PID tracking and cleanup:
- `run_fg <tool_name> [args...]`: Run a tool in the foreground.
- `spawn_bg <name> <tool_name> [--log <file>] [args...]`: Run a tool in the background and track its PID.
- `stop_process <name> [signal]`: Stop a tracked background process.

### Logging (`lib/logger.sh`)
- `log_step <current> <total> <desc>`: Print a step header.
- `log_info / log_success / log_warn / log_error`: Standard console output.
- `log_result <type> <msg>`: Log a formal finding (`FINDING`, `SECURE`, `INFO`).

### Session & Reporting (`lib/session.sh`)
- `save_tc_result <tc_id> <json_data> <conf_flags>`: Save module results using the unified schema.
- `evidence_register_file <path> <label>`: Register a file in the session manifest and generate a SHA256 hash.

## 🚀 Creating a New Module

### 1. Register the Module
Add your new Test Case to `lib/config.sh` in the `TC_REGISTRY` and `TC_ORDER` arrays.
```bash
["X1"]="My New Attack|X|A1|no|Description of the attack"
```

### 2. Create the Script
Create `modules/x1_my_attack.sh`. It must implement a function named `run_x1()`.

```bash
#!/usr/bin/env bash
run_x1() {
    local total_steps=3
    
    # Step 1: Check tools
    log_step 1 $total_steps "Verifying tools"
    check_module_dependencies "X1" || return 1
    
    # Step 2: Run attack
    log_step 2 $total_steps "Executing attack"
    run_fg "my-tool" --target "$GUEST_BSSID"
    
    # Step 3: Save results
    log_step 3 $total_steps "Finalizing"
    local result_json=$(run_fg --quiet "jq" -n --arg msg "Vulnerable" '{$msg}')
    save_tc_result "X1" "$result_json" "has_tool_output:1,clean_run:1"
    
    return 0
}
```

## 🧪 Testing
- **Unit Tests**: Add Python-based tests to `tests/`.
- **E2E Tests**: Run `bash tests/e2e_simulated_audit.sh` to verify the full lifecycle using mocks.

## 🛡️ Coding Standards
- **Strict Mode**: Always use `set -uo pipefail`.
- **Paths**: Use `${TOOL_PATHS[tool_name]}` for all binary execution.
- **Cleanup**: Register cleanup commands for any temporary files or interface changes.
- **Reporting**: Ensure all findings use the standard `status`, `summary`, `details`, `confidence` fields.
