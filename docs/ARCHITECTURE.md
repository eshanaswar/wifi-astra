# WiFi-Astra Architecture

This document describes the internal design of the WiFi-Astra framework — how the Go core, Bash modules, and evidence system work together.

---

## 1. High-Level Design

WiFi-Astra uses a **Controller-Module** architecture:

```
┌─────────────────────────────────────────────┐
│              Go Core (wifi-astra)           │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Session │  │ Hardware │  │  Scope   │  │
│  │  Manager │  │  Layer   │  │ Enforcer │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       └──────────────┴─────────────┘        │
│                     │                       │
│          ┌──────────▼──────────┐            │
│          │ AssessmentController│            │
│          └──────────┬──────────┘            │
│                     │  injects env vars     │
└─────────────────────┼─────────────────────-─┘
                      │
          ┌───────────▼──────────┐
          │  Bash Module (*.sh)  │
          │  aircrack-ng         │
          │  aireplay-ng         │
          │  tshark / tcpdump    │
          │  ...                 │
          └───────────┬──────────┘
                      │  $ASTRA_BIN record-finding
                      ▼
          ┌───────────────────────┐
          │   Evidence Store      │
          │  sessions/<id>/       │
          │  evidence/            │
          └───────────────────────┘
```

The Go core never touches the radio. All 802.11 operations happen inside isolated Bash scripts. The core handles state, scope, evidence, and the TUI.

---

## 2. Package Structure

```
wifi-astra/
├── bin/                    # Compiled binary
├── cmd/
│   └── astra/              # main.go entry point
├── cmd/
│   ├── root.go             # Execute(), signal handling, panic recovery
│   ├── start.go            # sessionWizard, ensureAdapterSetup, launchMainMenu
│   └── lookup_oui.go       # OUI vendor lookup subcommand
├── internal/
│   ├── config/             # Viper-based configuration management
│   ├── controller/         # AssessmentController: module execution, post-run dispatch,
│   │                       #   inline cracking, scope enforcement, cleanup checklist
│   ├── db/                 # SQLite schema and query layer
│   ├── evidence/           # Manifest writer, replay log, evidence index
│   ├── headless/           # RunAutonomousAudit() — JSON plan execution
│   ├── ingest/             # airodump-ng CSV parsing, OUI DB updates, result ingestion
│   ├── module/             # DiscoverModules() — parses MODULE_META headers at runtime
│   ├── report/             # GenerateReport() — structured report from session findings
│   ├── session/            # Session struct, SQLite (module_state, config tables)
│   └── ui/                 # PromptString, PromptConfirm, Menu, singleton Readline manager
├── modules/                # 46 assessment scripts (Golden Wrappers)
├── pkg/
│   ├── constants/          # Status codes, config keys, color codes
│   ├── executor/           # Process lifecycle, SanitizeEnv, KillAll
│   ├── hw/                 # Interface enumeration, monitor mode, Recover(), RoleRegistry
│   └── prereq/             # VerifyEnvironment, DropPrivileges, PreflightModules
├── tests/                  # Integration tests
└── sessions/               # Runtime data (gitignored)
```

---

## 3. Session Lifecycle

```
Start
  │
  ▼
Session Manager ──── Create / Resume / Delete
  │
  ▼
Adapter Wizard ───── Assign MONITOR role (monitor mode, injection)
  │                  Assign MANAGEMENT role (managed, operator connectivity)
  │                  Roles locked via InterfaceRoleRegistry for session duration
  ▼
A1 Discovery ──────── Mandatory; populates network table
  │
  ▼
Scope Selection ───── Operator selects authorized BSSIDs
  │                   No manual entry — scope built from discovered data only
  ▼
Module Execution ───── Controller validates every target against scope
  │                    SCOPE_VIOLATION events logged to session_replay.log
  │                    Post-run dispatcher: inline cracking for D1/D2/D3/D5
  ▼
Report Generation ──── Structured report from all session findings
  │
  ▼
Cleanup Checklist ──── Verify interfaces restored, processes killed,
                       evidence indexed and hashed
```

---

## 4. Dual-Adapter Design

WiFi-Astra enforces strict separation between two wireless roles:

| Role | Interface | Purpose |
|------|-----------|---------|
| **MONITOR** | e.g., `wlan1mon` | Monitor mode; packet injection, sniffing, attack execution |
| **MANAGEMENT** | e.g., `wlan0` | Managed mode; operator network connectivity |

The `InterfaceRoleRegistry` in `pkg/hw` tracks this assignment. The management interface is explicitly excluded from the pool available to attack modules — no module can request it, preventing accidental operator disconnection mid-engagement.

---

## 5. Module Communication Contract

The controller injects these environment variables before each module launch. All values are sanitized by `pkg/executor.SanitizeEnv` (strips newlines, null bytes, and shell metacharacters) before being set.

| Variable | Description |
|----------|-------------|
| `MONITOR_INTERFACE` | Monitor mode adapter (e.g., `wlan1mon`) |
| `WIFI_INTERFACE` | Managed mode adapter for modules that associate (F, G categories) |
| `GUEST_BSSID` | Target AP BSSID (`AA:BB:CC:DD:EE:FF`) |
| `GUEST_SSID` | Target AP SSID |
| `GUEST_CHANNEL` | Target AP channel |
| `SESSION_DIR` | Session root directory (absolute path) |
| `SESSION_EVIDENCE_DIR` | Evidence subdirectory for this module |
| `SCAN_TIME` | Scan duration in seconds |
| `CAPTURE_TIME` | Capture duration in seconds |
| `ASTRA_BIN` | Path to the wifi-astra binary (for callbacks) |
| `ASTRA_IN_WINDOW` | `true` when running inside a tmux/terminal window |
| `ASTRA_INDEFINITE` | `true` for indefinite-mode scans |

Modules report findings back to the core via the binary callback:

```bash
"$ASTRA_BIN" record-finding \
    --session-dir "$SESSION_DIR" \
    --tc "D1" \
    --type vulnerability \
    --name "WPA2 Handshake Captured" \
    --severity HIGH \
    --desc "4-way handshake captured for SSID: Corp-WiFi" \
    --target "$GUEST_BSSID" \
    --evidence "$PCAP_FILE" \
    --rationale "Handshake enables offline PSK cracking with hashcat."
```

Progress is reported via:

```bash
"$ASTRA_BIN" record-progress \
    --session-dir "$SESSION_DIR" \
    --tc "D1" \
    --percent 65 \
    --status "Sending deauth, waiting for handshake..."
```

---

## 6. Evidence System

All artifacts are written to `sessions/<session-id>/evidence/` — treated as an append-only forensic store.

### Per-Module Artifacts

| File | Contents |
|------|----------|
| `<TC_ID>_run_<timestamp>.json` | Structured run log: module ID, target, tools invoked, files written, exit code, duration |
| `<TC_ID>_result.json` | Security finding record (used for report generation) |
| `<TC_ID>_failure.log` | Full stderr + last 50 lines stdout — written only on non-zero exit |
| `<TC_ID>_run_context.json` | Pre-run snapshot: adapter assignments, target params, engagement metadata |

### Session-Level Artifacts

| File | Contents |
|------|----------|
| `session_replay.log` | Chronological event stream: SESSION_START, SCOPE_SET, MODULE_START, MODULE_END, SCOPE_VIOLATION, SESSION_END |
| `EVIDENCE_INDEX.txt` | Human-readable listing of all artifacts with hash, module, and size |
| `manifest.sha256` | SHA256 hash of every file in `evidence/`, append-only for chain of custody |

---

## 7. Module Discovery

At session start, `internal/module.DiscoverModules()` scans `modules/*.sh` and parses the `MODULE_META` header block from each file to build the module registry without recompiling the binary.

### MODULE_META Format

```bash
# MODULE_META
# NAME="Hidden SSID Discovery"
# CATEGORY="A"
# DEPS="A1"
# CRITICAL="no"
# TOOLS="aireplay-ng,airodump-ng"
# DESC="Identify and reveal SSIDs of hidden networks"
# REQS="monitor_iface,target_bssid"
# PCAP="yes"
# TIMED="yes"
# DECODE="wifi_mgmt"
```

`pkg/prereq.PreflightModules()` checks each module's `TOOLS` list against installed binaries at session launch. Modules with missing tools are flagged `[tools missing]` in the menu but do not block other modules from running.

---

## 8. Privilege Model

WiFi-Astra starts as root (required for hardware operations) and drops to the invoking user immediately after adapter setup via `prereq.DropPrivileges()`. Hardware operations inside modules temporarily re-acquire root through the executor's process launch mechanism, then drop again on exit.

Signal handling: `SIGINT`/`SIGTERM` triggers `ExecMgr.Cleanup()` then `hw.Recover(false)` before exit. A global `defer` in `Execute()` calls `hw.Recover(false)` on panic to ensure interfaces are always restored.

---

## 9. Inline Cracking

After successful captures, the controller dispatches cracking automatically:

| Module | Capture | Cracking Path |
|--------|---------|---------------|
| D1 | WPA2 PMKID / 4-way handshake | `hashcat -m 22000` (PMKID) or `-m 2500` (EAPOL) |
| D2 | WEP IVs | `aircrack-ng` inline key recovery |
| D3 | WPS | `oneshot`/`bully --pixie` (Pixie Dust primary), PIN brute-force fallback |
| D5 | MSCHAPv2 pairs | `asleap` auto-run; `hashcat -m 5500/-m 5600` offered as fallback |

Recovered credentials are recorded as `CRITICAL` findings in the evidence store.
