# Dual-Adapter AP Role Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a dedicated `RoleAP` adapter slot so Evil Twin and rogue AP modules (F1, F2, F3, D5) can run hostapd on a second card while the monitor card stays in monitor mode throughout, enabling simultaneous capture and AP broadcasting.

**Architecture:** Rename the existing `RoleManagement` slot to `RoleAP` in the hw role registry. Thread the assigned interface through as `AP_INTERFACE` env var. Add a guard prompt that warns and offers degraded single-adapter mode when no AP card is assigned.

**Affected files:** `pkg/hw/roles.go`, `pkg/constants/constants.go`, `cmd/start.go`, `internal/module/prompts.go`, `internal/controller/assessment.go`, `internal/headless/headless.go`, `modules/f1_rogue_ap.sh`, `modules/f2_pineap_karma.sh`, `modules/f3_captive_portal.sh`, `modules/d5_eap_attack.sh`, `internal/headless/headless_test.go`

---

## Background

### Why this is needed

The framework currently assigns one wireless adapter to `RoleMonitor` (attack/sniff) and optionally one to `RoleManagement` (operator internet/C2). In practice, operators run wifi-astra directly on their laptop or inside a VM with NAT internet, so neither wireless adapter is needed for C2. Both cards are free for attack use.

The Evil Twin category (F1, F2, F3) and PEAP capture (D5) require hostapd, which cannot run on a monitor-mode interface. Today these modules work around this by stripping the `mon` suffix from `MONITOR_INTERFACE` to derive the physical interface name, then toggling it back to managed mode. While the AP is up, the monitor card is gone — simultaneous capture and AP broadcasting is impossible.

### Design principle

Both wireless adapters are dedicated to the engagement. Adapter 1 stays in monitor mode for sniffing and injection throughout. Adapter 2 runs in managed mode as the AP interface for modules that need it. Operators without a second adapter still get a working (degraded) experience with a clear explanation.

---

## Section 1 — Role System (`pkg/hw/roles.go`)

### Change

Rename `RoleManagement` to `RoleAP`. No iota value change — the integer stays the same so no serialization breaks.

```go
const (
    RoleMonitor    InterfaceRole = iota // Injection and capture — used by attack modules
    RoleAP                              // AP adapter — managed-mode card for Evil Twin / hostapd operations
)
```

Update the comment on `RoleRegistry.AssertMonitor` to reflect the new semantic: it prevents the AP card from being passed as a monitor interface (correct — the AP card must stay in managed mode).

### Safety

`AssertMonitor` behaviour is unchanged. It reads `roles[RoleAP]` (formerly `roles[RoleManagement]`) and returns an error if the caller tries to use that interface for a monitor operation. The protection is correct in both the old and new naming.

---

## Section 2 — Constants (`pkg/constants/constants.go`)

### Change

```go
// Before
ConfigManagementIface = "MANAGEMENT_INTERFACE"

// After
ConfigAPInterface = "AP_INTERFACE"
```

The Go constant is renamed and the string value changes. All callers in `cmd/start.go` are updated in Section 3. No other files reference `ConfigManagementIface`.

### Session resume compatibility

Old sessions stored the second adapter under key `"MANAGEMENT_INTERFACE"`. After this change, the lookup key is `"AP_INTERFACE"` — old sessions will find nothing, `AP_INTERFACE` will be empty, and the affected modules will display the degraded-mode warning. No crash, no data loss. The operator can reassign adapters by restarting the tool.

---

## Section 3 — Setup Wizard (`cmd/start.go`)

### Changes to `ensureAdapterSetup()`

**On session resume** — read `ConfigAPInterface` instead of `ConfigManagementIface`. Assign `hw.RoleAP` instead of `hw.RoleManagement`.

**On fresh setup** — update all prompt labels from "management adapter" to "AP adapter". New description shown to the operator:

```
[?] Assign an AP adapter for Evil Twin / Rogue AP modules (F1, F2, F3, D5):
    Enables simultaneous monitor-mode capture + rogue AP broadcasting.
    Without this, those modules toggle the monitor card between modes (degraded).
```

**Persistence** — write `ConfigAPInterface` to DB (was `ConfigManagementIface`).

**Role assignment** — `hw.Roles.Assign(hw.RoleAP, apIface)` (was `hw.RoleManagement`).

**Log line** — `"Adapter setup complete: monitor=%s ap=%s"` (was `management`).

**Main menu header** — The status bar currently shows `IFACE: <monitor>`. No change needed; the AP interface is contextual to specific modules, not a session-global display value.

---

## Section 4 — Env Var Flow

`AP_INTERFACE` is stored in the session SQLite `config` table under key `"AP_INTERFACE"`. The existing bulk-load in `internal/controller/assessment.go` (`SELECT key, value FROM config`) already injects every config row as an environment variable before each module launch. `AP_INTERFACE` rides this path automatically — no new injection code is required.

For headless mode, see Section 7.

---

## Section 5 — Guard Prompt (`internal/module/prompts.go`)

### New function: `promptAPAdapterGuard`

```go
func promptAPAdapterGuard(database *sql.DB, m *module.Module) bool
```

**Triggered for:** F1, F2, F3, D5 (exact module IDs, checked with a switch statement).

**Logic:**
1. Call `db.GetConfig(database, "AP_INTERFACE")`.
2. If non-empty → return `true` immediately. Full dual-adapter mode; no warning shown.
3. If empty → display warning, prompt operator.

**Warning template:**

```
[!] DUAL-ADAPTER NOTICE — <Module Name>

This module works best with two wireless adapters.

WHY: <module-specific line — see below>

WITH ONE ADAPTER (current setup): The monitor card will be temporarily switched
to managed mode to broadcast the AP. Packet capture and frame injection are
suspended during this window — you will not sniff client associations or inject
deauth frames while the rogue AP is running.

To enable full dual-adapter mode, connect a second adapter and restart the tool
to reassign roles.

Continue in degraded single-adapter mode? [y/N]:
```

**Module-specific WHY lines:**

| Module | WHY text |
|--------|----------|
| F1 | Evil Twin requires hostapd (managed mode) on one card and airodump-ng (monitor mode) on another to simultaneously broadcast the fake AP and capture victim traffic and credentials. |
| F2 | KARMA/PineAP uses hostapd-mana (managed mode) to respond to client probes. A second card in monitor mode captures associations and traffic in real time. |
| F3 | Captive portal requires hostapd (managed mode) for client association while monitor mode tracks which clients connect and what they submit to the phishing page. |
| D5 | PEAP capture deploys a rogue RADIUS AP (hostapd, managed mode). A second card in monitor mode captures the full EAP handshake needed for credential extraction. |

**Return values:**
- `true` — proceed (either AP adapter is set, or user confirmed degraded mode)
- `false` — user chose to abort; `ExecuteModule` skips the module

### Call site in `assessment.go`

In `ExecuteModule`, call `promptAPAdapterGuard` after the existing `promptPMFGuard` call and before the module is launched. If it returns `false`, return `nil` (same pattern as the existing guard — the user chose not to proceed, which is not an error).

```go
if !prompts.PromptAPAdapterGuard(c.Session.DB, m) {
    return nil
}
```

---

## Section 6 — Module Changes

### Pattern (identical for all four modules)

Near the top of each script, after existing env var reads, add:

```bash
_AP_IFACE="${AP_INTERFACE:-}"
```

Then, wherever the script currently derives the managed-mode interface (strip `mon` suffix, or read `WIFI_INTERFACE`), replace with:

```bash
if [[ -n "$_AP_IFACE" ]]; then
    # Full dual-adapter mode — use dedicated AP card
    _HOSTAPD_IFACE="$_AP_IFACE"
else
    # Degraded single-adapter mode — derive from monitor card
    _HOSTAPD_IFACE="<existing derivation logic>"
fi
```

The degraded path's existing logic is preserved exactly — it still toggles the monitor card between modes as today.

### F1 (`modules/f1_rogue_ap.sh`)

- Full mode: `_HOSTAPD_IFACE="$AP_INTERFACE"`. Monitor card (`MONITOR_INTERFACE`) stays in monitor mode throughout. Deauth catalyst continues using `MONITOR_INTERFACE` for injection — correct.
- Degraded mode: existing `_RAW_IFACE` strip-`mon`-suffix + toggle logic unchanged.

### F2 (`modules/f2_pineap_karma.sh`)

- Currently reads `INTERFACE="${WIFI_INTERFACE:-}"` for hostapd-mana.
- Full mode: `INTERFACE="${AP_INTERFACE}"`.
- Degraded mode: `INTERFACE="${WIFI_INTERFACE:-}"` (existing behaviour).

### F3 (`modules/f3_captive_portal.sh`)

- Currently reads `INTERFACE="${WIFI_INTERFACE:-}"` for hostapd.
- Full mode: `INTERFACE="${AP_INTERFACE}"`.
- Degraded mode: `INTERFACE="${WIFI_INTERFACE:-}"` (existing behaviour).

### D5 (`modules/d5_eap_attack.sh`)

- Currently reads `INTERFACE="${MONITOR_INTERFACE:-}"` for the rogue RADIUS AP — incorrect today because hostapd cannot use a monitor-mode interface.
- Full mode: `_HOSTAPD_IFACE="${AP_INTERFACE}"`.
- Degraded mode: derive physical interface from `MONITOR_INTERFACE` by stripping `mon` suffix (same approach as F1 degraded mode). This also fixes the existing bug.

---

## Section 7 — Headless Mode (`internal/headless/headless.go`)

### AuditPlan struct addition

```go
type AuditPlan struct {
    SessionName      string   `json:"session_name"`
    MonitorInterface string   `json:"monitor_interface"`
    APInterface      string   `json:"ap_interface"`       // NEW — optional
    Modules          []string `json:"modules"`
    CaptureTime      int      `json:"capture_time"`
    ScanTime         int      `json:"scan_time"`
}
```

### Injection logic

After the existing `MonitorInterface` handling, add:

```go
if plan.APInterface != "" {
    os.Setenv("AP_INTERFACE", plan.APInterface)
    s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "AP_INTERFACE", plan.APInterface)
}
```

Headless plans without `ap_interface` produce an empty env var. The guard prompt is suppressed in headless mode (`ASTRA_HEADLESS=true`) — modules run in degraded mode silently, which is the correct unattended behaviour.

---

## Section 8 — Safety Analysis

| Concern | Status |
|---------|--------|
| All A/B/C/E/G/H modules | Never reference `AP_INTERFACE` — untouched |
| F4 (portal bypass), F5 (DNS tunnel) | Work as a client, no AP needed — untouched |
| D1–D4, D6–D8 | Monitor/inject only — untouched |
| Scope enforcement | Checks BSSIDs, not interface assignments — untouched |
| Interface locking (`LockInterface`/`UnlockInterface`) | Monitor and AP cards are separate names → separate lock slots → concurrent use safe |
| `airmon-ng check kill` | Only called when enabling monitor mode on the monitor card — AP card stays managed, not killed |
| Session resume with old `MANAGEMENT_INTERFACE` key | Key not found → empty AP → degraded-mode warning → safe |
| Headless plan without `ap_interface` | Field zero-value → empty → degraded mode, no crash |
| `AssertMonitor` safety check | Now protects RoleAP from monitor misuse — same invariant, correct new semantics |
| `hw.Roles` singleton | `RoleAP` is same iota value as old `RoleManagement` — registry map slot unchanged |

---

## Section 9 — Tests (`internal/headless/headless_test.go` + `internal/module/prompts_test.go`)

### New tests

**`TestAPAdapterGuardFires`**
- Create session DB with no `AP_INTERFACE` entry.
- Call `promptAPAdapterGuard` for module F1 with a mock `PromptConfirm` that returns `false`.
- Assert return value is `false` (user aborted).

**`TestAPAdapterGuardSkips`**
- Create session DB with `AP_INTERFACE = "wlan1"`.
- Call `promptAPAdapterGuard` for module F1.
- Assert return value is `true` without any prompt being shown.

**`TestAPAdapterGuardNotTriggered`**
- Call `promptAPAdapterGuard` for modules A1, D1, G4.
- Assert return value is `true` for all (guard is a no-op for non-AP modules).

**`TestHeadlessAPInterfaceInjected`**
- Create an `AuditPlan` with `APInterface: "wlan2"`.
- Run `RunAutonomousAudit` with a mock run function that reads `AP_INTERFACE` from env.
- Assert the mock sees `AP_INTERFACE=wlan2`.

---

## CLAUDE.md Updates Required

After implementation, update CLAUDE.md:

1. **Section 2 — CLI Reference** — headless plan format: add `"ap_interface"` field to the example JSON block.
2. **Section 3 — Environment Variables table** — add `AP_INTERFACE` row: "Managed-mode adapter for Evil Twin / hostapd modules (F1, F2, F3, D5). Empty in single-adapter setups."
3. **Section 6 — Key Go Packages** — hw row: mention `RoleAP` alongside `RoleMonitor`.
