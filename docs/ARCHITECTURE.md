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
  │                  Assign AP role (managed mode, hostapd / Evil Twin)
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
  │                    HMAC scope token injected as ASTRA_SCOPE_TOKEN env var.
  │                    Active attack modules verify token via 'verify-scope' callback.
  │                    ⚠ Guardrail: deters direct script invocation; does not prevent
  │                      bypass by operators with direct filesystem/SQLite access.
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

| Role | Constant | Env Var | Purpose |
|------|----------|---------|---------|
| **MONITOR** | `hw.RoleMonitor` | `MONITOR_INTERFACE` (e.g. `wlan0mon`) | Monitor mode — injection, sniffing, capture, active attacks |
| **AP** | `hw.RoleAP` | `AP_INTERFACE` (e.g. `wlan1`) | Managed mode — hostapd for Evil Twin, KARMA, Captive Portal, rogue RADIUS |

The `InterfaceRoleRegistry` (`pkg/hw/roles.go`) assigns and locks these roles at session start. No attack module can place the AP interface into monitor mode — `AssertMonitor()` enforces this at the Go layer before any script launches.

When only one adapter is available, Evil Twin modules (F1, F2, F3, D5) temporarily toggle the monitor card to managed mode and restore it via `airmon-ng start` on cleanup. The operator is warned via `PromptAPAdapterGuard` before the module launches.

### NAT Routing (F1, F2, F3)

Modules with `REQS="nat"` in their `MODULE_META` receive automatic NAT management from the controller:

1. `hw.DetectUplinkInterface()` — finds the default-route interface via `ip route get 8.8.8.8` (run live before each launch, not cached from session creation)
2. `hw.SetupNAT(iface)` — enables `net.ipv4.ip_forward` and installs an idempotent `iptables MASQUERADE` rule
3. Bash module assigns `192.168.44.1/24` to the AP interface so dnsmasq can bind
4. `hw.TeardownNAT(iface)` — deferred; removes the masquerade rule when the module exits

---

## 5. Module Communication Contract

The controller injects the **complete process environment** before each module launch — both DB-persisted config keys and all `os.Setenv` calls made by tactical prompts. All values pass through `pkg/executor.SanitizeEnv` (strips newlines, null bytes, and shell metacharacters) before being set.

In tactical window mode (separate X11 terminal), the wrapper script explicitly exports the full `envMap` so every variable — including `AP_INTERFACE`, tactical prompt results, and scout intelligence — reaches the module regardless of how the terminal emulator handles environment inheritance.

**Core variables injected by the controller:**

| Variable | Description |
|----------|-------------|
| `MONITOR_INTERFACE` | Monitor mode adapter name (e.g. `wlan0mon`) |
| `WIFI_INTERFACE` | Physical interface name before monitor mode was enabled (e.g. `wlan0`) |
| `AP_INTERFACE` | Dedicated AP adapter for Evil Twin modules (empty in single-adapter mode) |
| `UPLINK_INTERFACE` | Internet-facing interface for NAT masquerade (F1, F2, F3) |
| `GUEST_BSSID` | Target AP BSSID (`AA:BB:CC:DD:EE:FF`) |
| `GUEST_SSID` | Target AP SSID |
| `GUEST_CHANNEL` | Target AP channel |
| `SESSION_DIR` | Session root directory (absolute path) |
| `SESSION_EVIDENCE_DIR` | Evidence subdirectory for this module |
| `SCAN_TIME` | Scan duration in seconds |
| `CAPTURE_TIME` | Capture duration in seconds |
| `ASTRA_BIN` | Path to the wifi-astra binary (for `record-finding` / `record-progress` callbacks) |
| `ASTRA_IN_WINDOW` | `true` when module runs inside a separate X11 terminal window |
| `ASTRA_INDEFINITE` | `true` when the operator selected indefinite (Ctrl+C to stop) mode |
| `ASTRA_HEADLESS` | `true` when running from a JSON audit plan |
| `ASTRA_TARGET_RSSI` | Signal strength to target AP (populated by `hw.ScoutTarget` if BSSID is known) |
| `ASTRA_TARGET_PMF` | PMF enforcement status: `Required`, `Capable`, or `None` |
| `ASTRA_SCOPE_TOKEN` | HMAC-SHA256 scope token encoding `moduleID\|bssid\|expiry`, verified by modules before executing against a target |

**Tactical prompt results** (set before `runModuleWithCode` via `os.Setenv`):

| Variable | Set by | Values |
|----------|--------|--------|
| `AP_MODE` | F1 rogue_ap_mode prompt | `ssid` / `clone` |
| `CATALYST` | F1 roaming_catalyst prompt | `0` (none) / `1` (deauth) / `2` (CSA) |
| `KARMA_MODE` | F2 karma_vector prompt | `mana` / `loud` |
| `PHISH_TEMPLATE` | F3 phishing_template prompt | `generic` / `m365` / `cisco_ise` / `aruba` / `meraki` |
| `WPS_ATTACK` | D3 wps_vector prompt | `pixie` / `online` |
| `TARGET_CLIENT` | D1/A4 target_client prompt | MAC address or `FF:FF:FF:FF:FF:FF` (broadcast) |

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
| D1 | WPA2 PMKID / 4-way handshake | Three-stage: (1) SSID mutations, 30 s timeout; (2) rockyou.txt + best64.rule (prompted); (3) custom wordlist (prompted). `hashcat -m 22000` (PMKID) or `-m 2500` (EAPOL). PSK recorded as CRITICAL credential on success. |
| D2 | WEP IVs | `aircrack-ng` inline key recovery |
| D3 | WPS | `oneshot`/`bully --pixie` (Pixie Dust primary), PIN brute-force fallback |
| D5 | MSCHAPv2 pairs | `asleap` auto-run; `hashcat -m 5500/-m 5600` offered as fallback |

Recovered credentials are recorded as `CRITICAL` findings in the evidence store.

---

## 10. Scope Guardrail Mechanism

WiFi-Astra includes an **operational scope guardrail** — not a cryptographic enforcement barrier. The distinction matters:

**What it does:**
- The AssessmentController generates a per-launch HMAC-SHA256 token encoding `moduleID|bssid|expiry`.
- The token is signed with a 32-byte random secret generated fresh for each session and persisted in the session SQLite database.
- Active attack modules (D1–D3, D5–D7, E3, F1, G5) call `$ASTRA_BIN verify-scope` before executing radio operations.
- If the token is absent, wrong, or expired, the module prints an error and exits before touching the radio.

**What it does NOT do:**
- An operator with read access to the session SQLite database (`sessions/<id>/session.db`) can extract the scope secret and forge a valid token using standard HMAC tooling.
- Removing the guard check from a script copy trivially bypasses it.
- This mechanism targets: accidental invocation without authorization context, runbook copy-paste errors, and automated tooling invoking scripts without a proper session.

**Token format:**
```
<moduleID>|<bssid>|<unix_expiry>|<hmac_sha256_hex>
```

Token TTL is 5 minutes. The controller regenerates it on every `ExecuteModule()` call.
