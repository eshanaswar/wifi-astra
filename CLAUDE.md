# wifi-astra

WiFi penetration testing framework for authorized engagements. Go CLI frontend + modular Bash attack modules.

> AUTHORIZED USE ONLY — this tool is designed exclusively for engagements where written permission has been obtained.

---

## 1. Tool Overview

- What it is: A professional WiFi penetration testing framework covering the full 802.11 attack lifecycle, from initial discovery to advanced exploitation and reporting.
- Architecture: A Go CLI (built with cobra) acts as the central orchestrator, managing state, hardware, and session logic, while modular Bash scripts perform the actual radio-frequency operations and attacks.
- Dual adapter design: The framework enforces a strict separation of concerns using two wireless interfaces:
  - MONITOR Role: This interface is placed into monitor mode and used for packet injection, sniffing, and all attack-related operations.
  - MANAGEMENT Role: This interface remains in managed mode, maintains a connection to the control network (if applicable), and is never touched by attack modules to ensure operator connectivity is not disrupted.
- Coverage: 2.4GHz and 5GHz bands are fully supported on any monitor-mode adapter. 6GHz (WiFi 6E, 5925–7125 MHz) scanning is attempted when `iw phy` reports 6GHz frequencies — requires a Wi-Fi 6E capable adapter with Linux monitor mode support (e.g., Intel AX210, MediaTek MT7921AX). Encryption handled: WPA2-PSK, WPA3-SAE, OWE, and WPA3-Enterprise (802.1X).
- Hardware Safety: The InterfaceRoleRegistry (pkg/hw) tracks and enforces interface roles. The management interface is explicitly excluded from available attack interfaces to prevent accidental disruption.
- Key binary: `bin/wifi-astra`

---

## 2. Build and Run

```bash
# Build
go build -o bin/wifi-astra ./cmd/astra/

# Run interactive session
sudo bin/wifi-astra start

# Run with verbose/debug logging (writes to console and session log file)
sudo bin/wifi-astra start -v

# Run headless with a JSON audit plan (unattended autonomous mode)
sudo bin/wifi-astra start --config plan.json

# Override modules directory (default: ./modules)
sudo bin/wifi-astra start --mod-dir ./modules

# Test suite
go test ./...

# Lint all module scripts
shellcheck -S warning modules/*.sh
```

### CLI Reference

| Command | Description |
|---------|-------------|
| `astra start` | Start or resume an interactive assessment session |
| `astra run <MODULE_ID>` | Run a single module directly (no TUI wizard); useful for automation and CI |
| `astra clean` | Remove stale session directories older than a threshold (default 30 days) |
| `astra setup` | Install all required system dependencies via apt (requires root) |
| `astra update-oui` | Force-refresh the local IEEE OUI database used for vendor lookups |
| `astra lookup-oui [MAC/OUI]` | Look up hardware vendor for a MAC address or OUI prefix |

**Global flags** (available on all commands):

| Flag | Description |
|------|-------------|
| `--config <path>` | YAML config file (settings) or JSON audit plan (headless mode) |
| `--mod-dir <path>` | Path to directory containing assessment module scripts (`*.sh`); default `./modules` |
| `-v, --verbose` | Enable debug-level logging to console and session log file |

**`astra clean` flags:**

| Flag | Description |
|------|-------------|
| `-t, --older-than <N>` | Delete sessions whose last modification time exceeds N days (default 30) |
| `--dry-run` | List sessions that would be removed without deleting them |

**`astra run <MODULE_ID>` flags:**

| Flag | Description |
|------|-------------|
| `--iface <name>` | Monitor-mode interface (required) |
| `--bssid <AA:BB:CC:DD:EE:FF>` | Target BSSID |
| `--ssid <name>` | Target SSID |
| `--channel <N>` | Target channel (1–196) |
| `--session-dir <path>` | Session directory (auto-generated under `./sessions/` if omitted) |
| `--capture-time <N>` | Capture duration in seconds (default: 60) |
| `--scan-time <N>` | Scan duration in seconds (default: 30) |
| `--ap-iface <name>` | AP interface for Evil Twin modules (F1, F2, F3, D5) |

**Headless audit plan format** (`--config plan.json`):

```json
{
  "session_name": "corp-wifi-2026",
  "monitor_interface": "wlan1",
  "ap_interface": "wlan2",
  "modules": ["A1", "D1", "D3"],
  "capture_time": 60,
  "scan_time": 30
}
```

### Operational Notes

- Root required: Hardware ops (monitor mode, interface control) require root. The process runs as root throughout; `SUDO_UID`/`SUDO_GID` are captured via `prereq.GetSudoUser()` only for `chown` operations on session directories.
- Signal handling: SIGINT/SIGTERM triggers `ExecMgr.Cleanup()` then `hw.Recover(false)` before exit.
- Panic recovery: A global `defer` in `Execute()` calls `hw.Recover(false)` on crash to restore interfaces.
- OUI refresh: `astra start` automatically refreshes the OUI database in the background if missing or older than 30 days.

---

## 3. Module System

### Discovery

Modules are discovered at runtime. `DiscoverModules()` (internal/module) scans `modules/*.sh` and parses MODULE_META headers to populate module ID, name, description, and category without recompiling the binary.

### MODULE_META Header Format

```bash
# MODULE_META
# ID: A1
# NAME: Identify Networks
# DESC: Passive/active WiFi network discovery across 2.4, 5, and 6GHz bands
# CATEGORY: A
# TOOLS: airodump-ng,hcxdumptool,iw
```

### Categories

| Category | Name |
|----------|------|
| A | Discovery & Recon (Passive/Active) |
| B | Internal Network Recon (Connected) |
| C | Segmentation & Egress Testing |
| D | Encryption & Authentication Attacks |
| E | Implementation & Design Flaws |
| F | Rogue AP & Evil Twin Attacks |
| G | Man-in-the-Middle (MitM) & Pivoting |
| H | Policy & WIDS Validation |

### Complete Module List

| ID | File | Description |
|----|------|-------------|
| A1 | a1_identify_networks.sh | Passive/active WiFi network discovery (2.4/5/6GHz) |
| A2 | a2_bssid_correlation.sh | BSSID/SSID correlation and AP vendor identification |
| A3 | a3_hidden_ssid.sh | Hidden SSID disclosure via probe responses and deauth |
| A4 | a4_client_fingerprinting.sh | Client fingerprinting with MAC randomization correlation |
| A5 | a5_wifi6_detection.sh | Wi-Fi 6/6E environment detection and HE capability mapping |
| B1 | b1_client_isolation.sh | Client isolation enforcement testing between wireless peers |
| B2 | b2_mgmt_exposure.sh | Management interface exposure scanning (Web, SSH, SNMP) |
| B3 | b3_cdp_lldp_leaks.sh | CDP/LLDP protocol leak detection from infra devices |
| B4 | b4_mdns_leaks.sh | mDNS/Bonjour information leak detection for service mapping |
| B5 | b5_snmp_exposure.sh | SNMP exposure and community string brute-force testing |
| B6 | b6_dhcp_analysis.sh | DHCP option analysis and rogue server detection |
| B7 | b7_ipv6_leaks.sh | IPv6 leak and SLAAC/DHCPv6 misconfiguration testing |
| B8 | b8_broadcast_leaks.sh | Broadcast traffic analysis for sensitive plaintext data |
| B9 | b9_ap_vulnerability.sh | AP firmware/CVE vulnerability fingerprinting |
| B10 | b10_airsnitch.sh | Passive wireless traffic sniffing and protocol analysis |
| C1 | c1_dns_resolution.sh | DNS resolution and split-horizon testing across segments |
| C2 | c2_private_network_scan.sh | Private network segment discovery and route testing |
| C3 | c3_vlan_hopping.sh | VLAN hopping attack testing via 802.1Q tagging |
| C4 | c4_radius_reachability.sh | RADIUS server reachability and configuration validation |
| C5 | c5_egress_filtering.sh | Egress filter bypass testing (DNS, HTTP, ICMP, NTP) |
| D1 | d1_wpa_handshake.sh | WPA2 PMKID (primary) and 4-way handshake capture with inline hashcat cracking |
| D2 | d2_wep_cracking.sh | WEP IV capture and inline aircrack-ng key recovery |
| D3 | d3_wps_testing.sh | WPS Pixie Dust (primary) and PIN brute-force with inline PSK recovery |
| D4 | d4_wpa3_dragonblood.sh | WPA3-SAE Dragonblood timing/cache side-channel testing |
| D5 | d5_eap_attack.sh | PEAP/MSCHAPv2 credential capture via rogue RADIUS with inline asleap |
| D6 | d6_owe_downgrade.sh | OWE Transition Mode downgrade to open association |
| D7 | d7_wpa3_downgrade_active.sh | Active WPA3 downgrade to WPA2 via beacon manipulation |
| D8 | d8_eap_cert_validation.sh | EAP certificate validation testing (most common enterprise misconfiguration) |
| E1 | e1_krack_attack.sh | KRACK (CVE-2017-13077) key reinstallation testing |
| E2 | e2_fragattacks.sh | FragAttacks (CVE-2020-24586/24587/24588) frame injection |
| E3 | e3_deauth_resilience.sh | 802.11w PMF / deauth resilience and spoofing testing |
| E4 | e4_wireless_fuzzing.sh | 802.11 frame fuzzing for wireless driver vulnerabilities |
| E5 | e5_kr00k_test.sh | Kr00k (CVE-2019-15126) all-zero key vulnerability check |
| F1 | f1_rogue_ap.sh | Rogue AP / Evil Twin with deauth and client capture |
| F2 | f2_pineap_karma.sh | PineAP/KARMA attack against unassociated probe requests |
| F3 | f3_captive_portal.sh | Captive portal with vendor fingerprinting (ISE, ClearPass, FortiGate, Meraki) |
| F4 | f4_portal_bypass.sh | Captive portal bypass techniques (MAC/IP/DNS) |
| F5 | f5_dns_tunnel.sh | DNS tunneling capability detection for data exfiltration |
| G1 | g1_arp_spoofing.sh | ARP spoofing and MitM positioning on the subnet |
| G2 | g2_ssl_interception.sh | SSL/TLS interception with certificate impersonation |
| G3 | g3_dns_spoofing.sh | DNS spoofing for targeted traffic redirection |
| G4 | g4_nac_bypass.sh | NAC bypass via authorized client MAC cloning (Cisco ISE, Aruba ClearPass) |
| G5 | g5_bss_transition_attack.sh | BSS Transition Management abuse (802.11v steering) |
| G6 | g6_responder_pivot.sh | Responder-based NTLM capture and pivot to internal resources |
| H1 | h1_wids_detection.sh | WIDS/WIPS detection and evasion testing |
| H2 | h2_pmf_check.sh | 802.11w Protected Management Frame enforcement validation |

### Environment Variables Injected by Controller

All modules receive these env vars from the Go controller at launch. All values are sanitized by `pkg/executor.SanitizeEnv` before being set.

| Variable | Description |
|----------|-------------|
| MONITOR_INTERFACE | Monitor mode adapter name (e.g., `wlan1mon`) |
| AP_INTERFACE | Managed-mode adapter for Evil Twin / hostapd modules (F1, F2, F3, D5). Empty in single-adapter setups — affected modules run in degraded mode. |
| GUEST_BSSID | Target AP BSSID in `AA:BB:CC:DD:EE:FF` format |
| GUEST_SSID | Target AP SSID (may be empty for hidden networks) |
| GUEST_CHANNEL | Target AP channel number (1–196) |
| SESSION_DIR | Absolute path to the session root directory |
| SESSION_EVIDENCE_DIR | Absolute path to this module's evidence subdirectory |
| CAPTURE_TIME | Packet capture duration in seconds |
| SCAN_TIME | Channel scan duration in seconds |
| TARGET_CLIENT | Specific client MAC address to target (optional, module-dependent) |
| ASTRA_BIN | Path to the `wifi-astra` binary; use for `record-finding` and `record-progress` calls within module scripts |
| ASTRA_HEADLESS | Set to `true` when running in headless/unattended mode; modules can skip interactive prompts |
| ASTRA_INDEFINITE | Set to `true` when capture time is indefinite (operator-controlled stop); modules should loop and report progress until interrupted |

### Tool Preflight

`pkg/prereq.ModuleToolMap` maps each module ID to its required tools. `prereq.PreflightModules()` runs at session launch — modules with missing tools are marked `[tools missing]` in the menu but the session continues for other modules.

---

## 4. Session Workflow

1. **Start**: `sudo bin/wifi-astra start`
2. **Session Manager**: Create a new session, resume a previous one from SQLite, or delete old sessions.
3. **Adapter Setup Wizard**: Assign one interface to MONITOR role, one to MANAGEMENT role. Locked for the session via `hw.Roles`.
4. **Run A1**: Mandatory first step. Runs airodump-ng/hcxdumptool to populate the network table across all bands.
5. **Scope Selection**: Operator selects authorized BSSIDs from the live scan results. No manual BSSID entry — scope is built from discovered data.
6. **Scope Enforcement**: Controller validates every module launch. Targets not in scope are blocked and recorded as `SCOPE_VIOLATION` in `session_replay.log`.
7. **Module Execution**: Navigate category menus. TUI shows: checkmark for completed, X for failure, `[tools missing]` for unavailable modules.
8. **Inline Cracking**: After D1/D2/D3/D5 capture, the controller prompts to run cracking inline — keeps the full attack lifecycle inside one tool.
9. **Generate Report**: "Generate Assessment Report" from the session menu produces a structured report from all findings.
10. **End Engagement**: Cleanup Checklist verifies interfaces restored, background processes killed, evidence indexed and hashed.

### Headless Mode

Supply a `.json` audit plan to run unattended:

```bash
sudo bin/wifi-astra start --config engagement_plan.json
```

`headless.RunAutonomousAudit()` drives module execution without interactive prompts. `ASTRA_HEADLESS=true` is set in the environment so modules can detect this mode.

---

## 5. Evidence System

All artifacts are written to `sessions/<session-id>/evidence/`. Treated as an append-only forensic store.

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
| `EVIDENCE_INDEX.txt` | Flat human-readable listing of all artifacts with hash, module, and size |
| `manifest.sha256` | SHA256 hash of every file in evidence/, append-only during session for chain of custody |

### Inline Cracking Integration

The controller dispatches cracking automatically after successful captures:

| Module | Cracking Path |
|--------|--------------|
| D1 (WPA2) | `hashcat -m 22000` (PMKID) or `-m 2500` (EAPOL 4-way); PSK recorded as CRITICAL finding |
| D2 (WEP) | `aircrack-ng` inline key recovery; WEP key recorded as finding |
| D3 (WPS) | `oneshot`/`bully --pixie` Pixie Dust primary; PIN brute-force fallback; PSK recorded |
| D5 (PEAP) | `asleap` auto-runs on MSCHAPv2 pairs; `hashcat -m 5500/-m 5600` offered as fallback |

---

## 6. Key Go Packages

| Package | Path | Responsibility |
|---------|------|---------------|
| cmd | `cmd/` | Cobra CLI entry points: `root.go` (Execute, signal handling, panic recovery), `start.go` (sessionWizard, launchMainMenu, ensureAdapterSetup) |
| controller | `internal/controller/` | AssessmentController: ExecuteModule, HandlePostRun dispatcher, inline cracking helpers, CleanupChecklist, scope enforcement |
| evidence | `internal/evidence/` | Manifest writer, replay log, evidence index generation |
| ingest | `internal/ingest/` | Result JSON ingestion, airodump-ng output parsing, OUI database updates |
| session | `internal/session/` | Session struct, SQLite DB (module_state, config tables), NewSession/LoadSession |
| module | `internal/module/` | DiscoverModules: parses MODULE_META headers from `modules/*.sh` |
| headless | `internal/headless/` | RunAutonomousAudit: non-interactive JSON plan execution |
| report | `internal/report/` | GenerateReport: structured engagement report from session findings |
| ui | `internal/ui/` | PromptString, PromptConfirm, Menu, GetManager |
| executor | `pkg/executor/` | Manager: process lifecycle, `SanitizeEnv` (strips newlines/null bytes/shell metacharacters from all env vars before module launch), KillAll |
| hw | `pkg/hw/` | ListInterfaces, Recover(bool), InterfaceRoleRegistry (RoleMonitor/RoleAP), monitor mode control; all ops use CombinedOutput() for full error capture |
| prereq | `pkg/prereq/` | VerifyEnvironment, PreflightModules, ModuleToolMap, GetSudoUser, HasRequiredCapabilities |
| constants | `pkg/constants/` | StatusCompleted/Failed/Running, color codes, config key names |

---

## 7. Development Guidelines

### Before Every Commit

```bash
go test ./...
shellcheck -S warning modules/*.sh
go build -o /dev/null ./cmd/astra/
```

All three must pass. No exceptions.

### Adding a New Module

1. Create `modules/<id>_<name>.sh` with a complete MODULE_META header.
2. Begin the script with `set -euo pipefail`.
3. Double-quote every variable expansion touching external data: `"$SSID"`, `"$BSSID"`, `"$GUEST_CHANNEL"`.
4. Never use `eval` — use explicit variable expansion.
5. Write all output files to `"$SESSION_EVIDENCE_DIR/"`.
6. Exit 0 on success, non-zero on failure. The controller captures stderr on any non-zero exit.
7. Add the module ID and its required tools to `pkg/prereq/prereq.go` ModuleToolMap.

### Security Rules

- **SanitizeEnv is mandatory**: Applied to all env vars before module launch. Never bypass it.
- **Scope enforcement is not optional**: Every module targeting a BSSID must have the controller validate it against the session scope list.
- **AP interface is managed-mode only**: Modules must never put the interface assigned to RoleAP into monitor mode.
- **Heredocs**: Use `cat <<'EOF'` (no interpolation) in module scripts to prevent special characters in SSIDs/passwords from breaking execution.

### Code Generation

- The gemini-code-generator agent is used for bulk code production (invoked by the primary Claude agent).
- The primary agent reviews all generated code before commit.
- Generated modules must pass shellcheck before acceptance.

---

## 8. MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
