# Design Spec: Indefinite Execution Mode for Red Team Audits

## Overview
Astra currently uses hardcoded timeouts (e.g., 60s, 120s) for most assessment modules. While sufficient for quick surgical audits, Red Team scenarios often require running a capture (like A1 or D1) until a specific event occurs (e.g., a target client connects) or for an extended period. This spec introduces a "Run Until Stopped" mode activated per-module.

## Goals
1. **Flexibility**: Allow users to bypass default timeouts for any module that performs a time-based scan or capture.
2. **Standardization**: Use metadata to identify timed modules instead of hardcoding a list in the Go controller.
3. **Graceful Termination**: Ensure that stopping a module via Ctrl+C results in proper data ingestion and report generation, rather than just "killing" the process.

## Architecture

### 1. Module Metadata Update
All 30+ timed modules will receive a new metadata tag:
```bash
# MODULE_META
# ...
# TIMED="yes"
```

### 2. Go Module Discovery
- Update `internal/module/Module` struct to include `Timed bool`.
- Update `internal/module/parseModuleMeta` to detect `TIMED="yes"`.

### 3. Controller Logic (Execution Flow)
In `internal/controller/AssessmentController.ExecuteModule`:
- If `Module.Timed` is true, prompt the user:
  - Option 1: **Timed (Default: [N]s)**
  - Option 2: **Indefinite (Until Ctrl+C)**
- If Option 2 is chosen:
  - Set environment variable `ASTRA_INDEFINITE=true`.
  - Disable the "Stuck?" watchdog for this run.

### 4. Signal Handling & Process Management
- Astra will catch `SIGINT` (Ctrl+C) during module execution.
- Instead of immediately exiting Astra, it will send `SIGTERM` to the module process group.
- The module scripts will be updated to trap `SIGTERM` and perform their standard cleanup/reporting logic before exiting.

### 5. Bash Wrapper Updates
Modules will be updated to respect `ASTRA_INDEFINITE`:
- If `ASTRA_INDEFINITE="true"`, the internal `while` loops (e.g., `while [[ $ELAPSED -lt $SCAN_TIME ]]`) will run indefinitely.
- The telemetry heartbeat will continue to report progress (e.g., sticking at 95% or showing an "∞" symbol).

## Components Affected

### Go Core
- `internal/module/discovery.go`: Parse the `TIMED` metadata.
- `internal/controller/assessment.go`: Add the duration prompt and environment injection.
- `pkg/executor/executor.go`: Ensure `SIGTERM` is used for graceful stop before `SIGKILL`.

### Bash Modules
- All 30+ scripts identified as having `SCAN_TIME` or `CAPTURE_TIME`.

## Verification Plan
1. **Unit Test**: Verify `parseModuleMeta` correctly identifies `Timed: true` for a mock module.
2. **Integration Test**: Run `A1` in Indefinite mode, wait 10 seconds, press Ctrl+C, and verify that results are still recorded in the database and the HTML report.
3. **Regression Test**: Ensure standard Timed mode still works and exits automatically when the timer expires.
