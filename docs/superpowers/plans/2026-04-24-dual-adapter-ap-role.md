# Dual-Adapter AP Role Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated `RoleAP` adapter so Evil Twin and rogue AP modules (F1, F2, F3, D5) can run hostapd on a second card while the monitor card stays in monitor mode, enabling simultaneous capture and AP broadcasting.

**Architecture:** Rename the existing `RoleManagement` slot to `RoleAP` in the hw registry; expose the assigned interface as `AP_INTERFACE` env var; add a Go-level guard prompt that warns single-adapter users before those four modules launch; update module scripts to prefer `AP_INTERFACE` and fall back to existing toggle behavior.

**Tech Stack:** Go 1.21+, Bash 5, SQLite (via existing session DB), airmon-ng, hostapd/hostapd-mana, eaphammer

---

## File Map

| File | Change |
|------|--------|
| `pkg/hw/roles.go` | Rename `RoleManagement` → `RoleAP` |
| `pkg/constants/constants.go` | Rename `ConfigManagementIface` → `ConfigAPInterface` (string `"AP_INTERFACE"`) |
| `cmd/start.go` | Update `ensureAdapterSetup` — labels, DB key, role assignment |
| `internal/module/prompts.go` | Add `PromptAPAdapterGuard` function |
| `internal/module/prompts_test.go` | New — three guard unit tests |
| `internal/controller/assessment.go` | Call `PromptAPAdapterGuard` before tactical prompts |
| `modules/f1_rogue_ap.sh` | Use `AP_INTERFACE` for hostapd; degrade gracefully |
| `modules/f2_pineap_karma.sh` | Use `AP_INTERFACE` for hostapd-mana |
| `modules/f3_captive_portal.sh` | Use `AP_INTERFACE` for hostapd |
| `modules/d5_eap_attack.sh` | Use `AP_INTERFACE` for eaphammer |
| `internal/headless/headless.go` | Add `APInterface` field to `AuditPlan` |
| `internal/headless/headless_test.go` | Add `TestHeadlessAPInterfaceInjected` |
| `CLAUDE.md` | Update headless plan example, env var table, hw package row |

---

## Task 1: Rename RoleManagement → RoleAP and ConfigManagementIface → ConfigAPInterface

**Files:**
- Modify: `pkg/hw/roles.go:11-14`
- Modify: `pkg/constants/constants.go:12`
- Modify: `cmd/start.go:594-692`

- [ ] **Step 1: Update the role enum in roles.go**

Open `pkg/hw/roles.go`. Replace lines 11–14:

```go
const (
	RoleMonitor    InterfaceRole = iota // Injection and capture — used by attack modules
	RoleManagement                      // Internet/C2 — never touched by attack modules
)
```

With:

```go
const (
	RoleMonitor InterfaceRole = iota // Injection and capture — used by attack modules
	RoleAP                           // AP adapter — managed-mode card for Evil Twin / hostapd operations
)
```

- [ ] **Step 2: Update the constant in constants.go**

Open `pkg/constants/constants.go`. Replace line 12:

```go
	ConfigManagementIface = "MANAGEMENT_INTERFACE"
```

With:

```go
	ConfigAPInterface = "AP_INTERFACE"
```

- [ ] **Step 3: Update ensureAdapterSetup in cmd/start.go**

Open `cmd/start.go`. Apply all changes below (the function starts at line 592).

**3a.** On session resume (around line 594), replace:

```go
	s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigManagementIface).Scan(&mgmtIface)
```

With:

```go
	s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigAPInterface).Scan(&mgmtIface)
```

**3b.** Still in the resume block (around line 600), replace:

```go
		hw.Roles.Assign(hw.RoleManagement, mgmtIface)
```

With:

```go
		hw.Roles.Assign(hw.RoleAP, mgmtIface)
```

**3c.** The log line in the resume block (around line 603), replace:

```go
		logging.Info("Adapter setup restored: monitor=%s management=%s", monIface, mgmtIface)
```

With:

```go
		logging.Info("Adapter setup restored: monitor=%s ap=%s", monIface, mgmtIface)
```

**3d.** The optional second-adapter prompt section (around line 644–670), replace the entire block:

```go
	// Pick management adapter (optional, only when >1 interface)
	if len(ifaces) > 1 {
		fmt.Printf("\n%s[✓] Attack adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, monIface)
		fmt.Printf("%s[?]%s Optionally select a management adapter for internet/C2 connectivity:\n",
			constants.ThemeHeader, constants.ColorReset)
		// Build a filtered list excluding the monitor adapter, with sequential numbering
		var mgmtCandidates []hw.Interface
		for _, iface := range ifaces {
			if iface.Name != monIface {
				mgmtCandidates = append(mgmtCandidates, iface)
			}
		}
		for i, iface := range mgmtCandidates {
			fmt.Printf("   %d) %-12s %s (%s)\n", i+1, iface.Name, iface.Chipset, iface.Driver)
		}
		mgmtChoice := ui.PromptString(fmt.Sprintf("Management adapter [1-%d] (or Enter to skip)", len(mgmtCandidates)), "")
		if mgmtChoice != "" {
			mgmtIdx, _ := strconv.Atoi(mgmtChoice)
			if mgmtIdx >= 1 && mgmtIdx <= len(mgmtCandidates) {
				mgmtIface = mgmtCandidates[mgmtIdx-1].Name
				fmt.Printf("%s[✓] Management adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, mgmtIface)
			} else {
				fmt.Printf("%s[!] Invalid selection — no management adapter set.%s\n",
					constants.ThemeHigh, constants.ColorReset)
			}
		} else {
			fmt.Printf("%s[*] No management adapter selected.%s\n", constants.ColorGray, constants.ColorReset)
		}
	}
```

With:

```go
	// Pick AP adapter (optional, only when >1 interface)
	if len(ifaces) > 1 {
		fmt.Printf("\n%s[✓] Attack/Monitor adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, monIface)
		fmt.Printf("%s[?]%s Assign an AP adapter for Evil Twin / Rogue AP modules (F1, F2, F3, D5):\n",
			constants.ThemeHeader, constants.ColorReset)
		fmt.Printf("    Enables simultaneous monitor-mode capture + rogue AP broadcasting.\n")
		fmt.Printf("    Without this, those modules toggle the monitor card between modes (degraded).\n\n")
		var mgmtCandidates []hw.Interface
		for _, iface := range ifaces {
			if iface.Name != monIface {
				mgmtCandidates = append(mgmtCandidates, iface)
			}
		}
		for i, iface := range mgmtCandidates {
			fmt.Printf("   %d) %-12s %s (%s)\n", i+1, iface.Name, iface.Chipset, iface.Driver)
		}
		mgmtChoice := ui.PromptString(fmt.Sprintf("AP adapter [1-%d] (or Enter to skip)", len(mgmtCandidates)), "")
		if mgmtChoice != "" {
			mgmtIdx, _ := strconv.Atoi(mgmtChoice)
			if mgmtIdx >= 1 && mgmtIdx <= len(mgmtCandidates) {
				mgmtIface = mgmtCandidates[mgmtIdx-1].Name
				fmt.Printf("%s[✓] AP adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, mgmtIface)
			} else {
				fmt.Printf("%s[!] Invalid selection — no AP adapter set.%s\n",
					constants.ThemeHigh, constants.ColorReset)
			}
		} else {
			fmt.Printf("%s[*] No AP adapter selected — Evil Twin modules will run in degraded mode.%s\n", constants.ColorGray, constants.ColorReset)
		}
	}
```

**3e.** Role assignment on fresh setup (around line 679), replace:

```go
	if mgmtIface != "" {
		if err := hw.Roles.Assign(hw.RoleManagement, mgmtIface); err != nil {
			logging.Warn("Failed to assign management role: %v", err)
			mgmtIface = ""
		}
	}
```

With:

```go
	if mgmtIface != "" {
		if err := hw.Roles.Assign(hw.RoleAP, mgmtIface); err != nil {
			logging.Warn("Failed to assign AP role: %v", err)
			mgmtIface = ""
		}
	}
```

**3f.** DB persistence (around line 687), replace:

```go
	if mgmtIface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigManagementIface, mgmtIface)
	}
```

With:

```go
	if mgmtIface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigAPInterface, mgmtIface)
	}
```

**3g.** Log line at end of function (around line 692), replace:

```go
	logging.Success("Adapter setup complete: monitor=%s management=%s", monIface, mgmtIface)
```

With:

```go
	logging.Success("Adapter setup complete: monitor=%s ap=%s", monIface, mgmtIface)
```

- [ ] **Step 4: Build to verify no compile errors**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go build -o /dev/null ./cmd/astra/
```

Expected: no output, exit 0. If you see `RoleManagement` or `ConfigManagementIface` errors, you missed an occurrence — grep and fix:

```bash
grep -r "RoleManagement\|ConfigManagementIface" . --include="*.go"
```

- [ ] **Step 5: Run tests**

```bash
go test ./...
```

Expected: all packages pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/hw/roles.go pkg/constants/constants.go cmd/start.go
git commit -m "feat: rename RoleManagement→RoleAP, ConfigManagementIface→ConfigAPInterface"
```

---

## Task 2: Add PromptAPAdapterGuard to prompts.go and wire call site

**Files:**
- Modify: `internal/module/prompts.go`
- Modify: `internal/controller/assessment.go`

- [ ] **Step 1: Add PromptAPAdapterGuard to prompts.go**

Open `internal/module/prompts.go`. At the end of the file (after `promptActiveReveal`), add:

```go
// PromptAPAdapterGuard warns when a dual-adapter module is launched without an AP
// adapter assigned. Returns true to proceed, false to abort.
// Fires only for modules F1, F2, F3, D5. No-op for all others.
// No-op in headless mode (ASTRA_HEADLESS=true) — runs degraded silently.
func PromptAPAdapterGuard(database *sql.DB, m *Module) bool {
	switch m.ID {
	case "F1", "F2", "F3", "D5":
		// continue
	default:
		return true
	}

	if os.Getenv("ASTRA_HEADLESS") == "true" {
		return true
	}

	apIface, _ := db.GetConfig(database, "AP_INTERFACE")
	if apIface != "" {
		return true
	}

	whyLines := map[string]string{
		"F1": "Evil Twin requires hostapd (managed mode) on one card and airodump-ng\n(monitor mode) on another to simultaneously broadcast the fake AP and capture\nvictim traffic and credentials.",
		"F2": "KARMA/PineAP uses hostapd-mana (managed mode) to respond to client probes.\nA second card in monitor mode captures associations and traffic in real time.",
		"F3": "Captive portal requires hostapd (managed mode) for client association while\nmonitor mode tracks which clients connect and what they submit to the phishing page.",
		"D5": "PEAP capture deploys a rogue RADIUS AP (hostapd, managed mode). A second card\nin monitor mode captures the full EAP handshake needed for credential extraction.",
	}

	fmt.Printf("\n%s[!] DUAL-ADAPTER NOTICE — %s%s\n", constants.ThemeHigh, m.Name, constants.ColorReset)
	fmt.Println()
	fmt.Println("This module works best with two wireless adapters.")
	fmt.Println()
	fmt.Printf("WHY: %s\n", whyLines[m.ID])
	fmt.Println()
	fmt.Printf("%sWITH ONE ADAPTER (current setup):%s The monitor card will be temporarily\n", constants.ColorBold, constants.ColorReset)
	fmt.Println("switched to managed mode to broadcast the AP. Packet capture and frame")
	fmt.Println("injection are suspended during this window — you will not sniff client")
	fmt.Println("associations or inject deauth frames while the rogue AP is running.")
	fmt.Println()
	fmt.Println("To enable full dual-adapter mode, connect a second adapter and restart")
	fmt.Println("the tool to reassign roles.")
	fmt.Println()

	return ui.PromptConfirm("Continue in degraded single-adapter mode?", false)
}
```

- [ ] **Step 2: Add call site in assessment.go**

Open `internal/controller/assessment.go`. Find the comment line:

```go
	// 4.7. SMART TACTICAL PROMPTS (Go-Side Interactivity)
```

Insert the AP adapter guard call BEFORE that comment:

```go
	// AP Adapter Guard — warns for F/D5 modules when no dedicated AP card is assigned.
	// Returns false if the user chooses to abort; we treat that as a clean exit.
	if !module.PromptAPAdapterGuard(c.Session.DB, m) {
		return nil
	}

	// 4.7. SMART TACTICAL PROMPTS (Go-Side Interactivity)
```

- [ ] **Step 3: Build to verify**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go build -o /dev/null ./cmd/astra/
```

Expected: exit 0.

- [ ] **Step 4: Write the tests**

Create `internal/module/prompts_test.go`:

```go
package module

import (
	"os"
	"testing"
	"wifi-astra/internal/session"
)

func makePromptTestSession(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.NewSession("prompt_test", t.TempDir())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}

// Guard must return true immediately for modules that are not in the AP-adapter list.
// We pass nil for the DB — the switch returns before any DB access.
func TestAPAdapterGuardNonTargetModules(t *testing.T) {
	for _, id := range []string{"A1", "B3", "D1", "G4", "H1"} {
		m := &Module{ID: id, Name: "Test"}
		if !PromptAPAdapterGuard(nil, m) {
			t.Errorf("PromptAPAdapterGuard returned false for non-AP module %s; expected true (no-op)", id)
		}
	}
}

// Guard must return true without prompting when AP_INTERFACE is set in the DB.
func TestAPAdapterGuardSkipsWhenAPSet(t *testing.T) {
	s := makePromptTestSession(t)
	s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('AP_INTERFACE', 'wlan1')")

	for _, id := range []string{"F1", "F2", "F3", "D5"} {
		m := &Module{ID: id, Name: "Test Module"}
		if !PromptAPAdapterGuard(s.DB, m) {
			t.Errorf("PromptAPAdapterGuard returned false for %s when AP_INTERFACE is set; expected true", id)
		}
	}
}

// Guard must return true in headless mode without prompting, regardless of DB state.
func TestAPAdapterGuardSkipsInHeadlessMode(t *testing.T) {
	os.Setenv("ASTRA_HEADLESS", "true")
	defer os.Unsetenv("ASTRA_HEADLESS")

	s := makePromptTestSession(t)
	// DB has no AP_INTERFACE entry — would normally trigger the prompt

	for _, id := range []string{"F1", "F2", "F3", "D5"} {
		m := &Module{ID: id, Name: "Test Module"}
		if !PromptAPAdapterGuard(s.DB, m) {
			t.Errorf("PromptAPAdapterGuard returned false in headless mode for %s; expected true", id)
		}
	}
}
```

- [ ] **Step 5: Run the new tests to verify they pass**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go test ./internal/module/... -v -run TestAPAdapter
```

Expected output:
```
=== RUN   TestAPAdapterGuardNonTargetModules
--- PASS: TestAPAdapterGuardNonTargetModules (0.00s)
=== RUN   TestAPAdapterGuardSkipsWhenAPSet
--- PASS: TestAPAdapterGuardSkipsWhenAPSet (0.00s)
=== RUN   TestAPAdapterGuardSkipsInHeadlessMode
--- PASS: TestAPAdapterGuardSkipsInHeadlessMode (0.00s)
PASS
```

- [ ] **Step 6: Run full test suite**

```bash
go test ./...
```

Expected: all packages pass.

- [ ] **Step 7: Commit**

```bash
git add internal/module/prompts.go internal/module/prompts_test.go internal/controller/assessment.go
git commit -m "feat: add PromptAPAdapterGuard for dual-adapter notice on F1/F2/F3/D5"
```

---

## Task 3: Fix F1 to use AP_INTERFACE

**Files:**
- Modify: `modules/f1_rogue_ap.sh:34-71`

- [ ] **Step 1: Replace the interface derivation block**

Open `modules/f1_rogue_ap.sh`. Replace lines 34–71 (from the comment `# F1 needs a managed-mode interface...` through `INTERFACE="$_PHYS_IFACE"`):

**Old block:**
```bash
# F1 needs a managed-mode interface for hostapd. Derive the physical interface
# from MONITOR_INTERFACE (which may be wlan0mon) by stripping the 'mon' suffix.
_RAW_IFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
if [[ "$_RAW_IFACE" == *mon ]]; then
    _PHYS_IFACE="${_RAW_IFACE%mon}"
else
    _PHYS_IFACE="$_RAW_IFACE"
fi

SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f1"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F1"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

# Tactical Selections from Go Brain
AP_MODE="${AP_MODE:-ssid}" # ssid or clone
CATALYST="${CATALYST:-0}" # 0=None, 1=Deauth, 2=CSA
LAUNCH_RESPONDER="${LAUNCH_RESPONDER:-no}"

if [[ -z "$_PHYS_IFACE" || -z "$SSID" ]]; then
    echo "[!] No wireless interface or GUEST_SSID not set."
    exit 1
fi

# Restore interface to managed mode — hostapd cannot use a monitor-mode interface
echo "[*] Restoring ${_PHYS_IFACE} to managed mode for AP operation..."
airmon-ng stop "${_RAW_IFACE}" > /dev/null 2>&1 || true
ip link set "$_PHYS_IFACE" down 2>/dev/null || true
iw dev "$_PHYS_IFACE" set type managed 2>/dev/null || true
ip link set "$_PHYS_IFACE" up 2>/dev/null || true
sleep 1

INTERFACE="$_PHYS_IFACE"
```

**New block:**
```bash
# AP_INTERFACE: dedicated managed-mode card (dual-adapter setup).
# Fallback: derive physical interface from MONITOR_INTERFACE, toggle to managed (single-adapter degraded mode).
_AP_IFACE="${AP_INTERFACE:-}"
if [[ -n "$_AP_IFACE" ]]; then
    _PHYS_IFACE="$_AP_IFACE"
    echo "[*] Dual-adapter mode: using ${_PHYS_IFACE} as AP interface (monitor card stays active)."
else
    _RAW_IFACE="${WIFI_INTERFACE:-${MONITOR_INTERFACE:-}}"
    if [[ "$_RAW_IFACE" == *mon ]]; then
        _PHYS_IFACE="${_RAW_IFACE%mon}"
    else
        _PHYS_IFACE="$_RAW_IFACE"
    fi
    # Single-adapter degraded mode: restore monitor card to managed mode for hostapd.
    # Capture and injection are suspended while the AP is running.
    echo "[*] Single-adapter mode: restoring ${_PHYS_IFACE} to managed mode for AP operation..."
    airmon-ng stop "${_RAW_IFACE}" > /dev/null 2>&1 || true
    ip link set "$_PHYS_IFACE" down 2>/dev/null || true
    iw dev "$_PHYS_IFACE" set type managed 2>/dev/null || true
    ip link set "$_PHYS_IFACE" up 2>/dev/null || true
    sleep 1
fi

SSID="${GUEST_SSID:-}"
TARGET_BSSID="${GUEST_BSSID:-}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
EVIDENCE_PREFIX="${EVIDENCE_DIR}/f1"
SCAN_TIME="${SCAN_TIME:-120}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="F1"
INTERNAL_IP="${INTERNAL_IP:-192.168.44.1}"

# Tactical Selections from Go Brain
AP_MODE="${AP_MODE:-ssid}" # ssid or clone
CATALYST="${CATALYST:-0}"  # 0=None, 1=Deauth, 2=CSA
LAUNCH_RESPONDER="${LAUNCH_RESPONDER:-no}"

if [[ -z "$_PHYS_IFACE" || -z "$SSID" ]]; then
    echo "[!] No wireless interface or GUEST_SSID not set."
    exit 1
fi

INTERFACE="$_PHYS_IFACE"
```

- [ ] **Step 2: Run shellcheck**

```bash
shellcheck -S warning modules/f1_rogue_ap.sh
```

Expected: exit 0, no output.

- [ ] **Step 3: Build**

```bash
go build -o /dev/null ./cmd/astra/
```

Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add modules/f1_rogue_ap.sh
git commit -m "feat(f1): use AP_INTERFACE for hostapd in dual-adapter mode"
```

---

## Task 4: Fix F2 and F3 to use AP_INTERFACE

**Files:**
- Modify: `modules/f2_pineap_karma.sh:34`
- Modify: `modules/f3_captive_portal.sh:34`

- [ ] **Step 1: Fix F2**

Open `modules/f2_pineap_karma.sh`. Find line 34:

```bash
INTERFACE="${WIFI_INTERFACE:-}"
```

Replace with:

```bash
# AP_INTERFACE: dedicated managed-mode card (dual-adapter).
# Fallback: WIFI_INTERFACE = physical monitor adapter name (single-adapter degraded mode).
_AP_IFACE="${AP_INTERFACE:-}"
INTERFACE="${_AP_IFACE:-${WIFI_INTERFACE:-}}"
```

Also update the guard at line 46 (currently `if [[ -z "$INTERFACE" ]]`) — no change needed; the condition still works.

Run shellcheck:

```bash
shellcheck -S warning modules/f2_pineap_karma.sh
```

Expected: exit 0.

- [ ] **Step 2: Fix F3**

Open `modules/f3_captive_portal.sh`. Find line 34:

```bash
INTERFACE="${WIFI_INTERFACE:-}"
```

Replace with:

```bash
# AP_INTERFACE: dedicated managed-mode card (dual-adapter).
# Fallback: WIFI_INTERFACE = physical monitor adapter name (single-adapter degraded mode).
_AP_IFACE="${AP_INTERFACE:-}"
INTERFACE="${_AP_IFACE:-${WIFI_INTERFACE:-}}"
```

Run shellcheck:

```bash
shellcheck -S warning modules/f3_captive_portal.sh
```

Expected: exit 0.

- [ ] **Step 3: Build and test**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go build -o /dev/null ./cmd/astra/
go test ./...
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add modules/f2_pineap_karma.sh modules/f3_captive_portal.sh
git commit -m "feat(f2,f3): use AP_INTERFACE for hostapd-mana/hostapd in dual-adapter mode"
```

---

## Task 5: Fix D5 to use AP_INTERFACE

**Files:**
- Modify: `modules/d5_eap_attack.sh:22-34`

D5 currently passes `MONITOR_INTERFACE` directly to eaphammer. This is wrong even in single-adapter mode — eaphammer manages its own interface mode, but the interface name it gets (`wlan1mon`) is wrong when passed through airmon-ng. The fix: prefer `AP_INTERFACE`; in degraded mode, derive the physical interface from `MONITOR_INTERFACE` by stripping the `mon` suffix.

- [ ] **Step 1: Replace the interface block in d5_eap_attack.sh**

Open `modules/d5_eap_attack.sh`. Find lines 22–34:

```bash
# Inputs from Environment
INTERFACE="${MONITOR_INTERFACE:-}"
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D5"
EAP_OUT="${EVIDENCE_DIR}/${TC_ID}_eaphammer_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] MONITOR_INTERFACE not set."
    exit 1
fi
```

Replace with:

```bash
# Inputs from Environment
# AP_INTERFACE: dedicated managed-mode card (dual-adapter). eaphammer handles its own mode switch.
# Fallback: derive physical interface from MONITOR_INTERFACE by stripping 'mon' suffix (single-adapter degraded).
_AP_IFACE="${AP_INTERFACE:-}"
if [[ -n "$_AP_IFACE" ]]; then
    INTERFACE="$_AP_IFACE"
else
    _RAW_IFACE="${MONITOR_INTERFACE:-}"
    if [[ "$_RAW_IFACE" == *mon ]]; then
        INTERFACE="${_RAW_IFACE%mon}"
    else
        INTERFACE="$_RAW_IFACE"
    fi
fi
SSID="${GUEST_SSID:-}"
SCAN_TIME="${SCAN_TIME:-60}"
SESSION_DIR="${SESSION_DIR:-.}"
EVIDENCE_DIR="${SESSION_EVIDENCE_DIR:-${SESSION_DIR}/evidence}"
ASTRA_BIN="${ASTRA_BIN:-wifi-astra}"
TC_ID="D5"
EAP_OUT="${EVIDENCE_DIR}/${TC_ID}_eaphammer_results.txt"

if [[ -z "$INTERFACE" ]]; then
    echo "[!] No interface available: set AP_INTERFACE (dual-adapter) or MONITOR_INTERFACE (single-adapter)."
    exit 1
fi
```

- [ ] **Step 2: Run shellcheck**

```bash
shellcheck -S warning modules/d5_eap_attack.sh
```

Expected: exit 0.

- [ ] **Step 3: Build and test**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go build -o /dev/null ./cmd/astra/
go test ./...
```

Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add modules/d5_eap_attack.sh
git commit -m "feat(d5): use AP_INTERFACE for eaphammer; fix physical iface derivation in degraded mode"
```

---

## Task 6: Add APInterface to headless AuditPlan

**Files:**
- Modify: `internal/headless/headless.go`

- [ ] **Step 1: Write the failing test first**

Open `internal/headless/headless_test.go`. Add after `TestAuditPlanTimingInjected`:

```go
func TestHeadlessAPInterfaceInjected(t *testing.T) {
	os.Unsetenv("AP_INTERFACE")

	tmpDir := "test_apif_sessions"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	plan := AuditPlan{
		SessionName: "apif_test",
		Modules:     []string{"MOCK"},
		APInterface: "wlan2",
	}
	planPath := "test_apif_plan.json"
	data, _ := json.Marshal(plan)
	os.WriteFile(planPath, data, 0644)
	defer os.Remove(planPath)

	modDir := "test_apif_mods"
	os.MkdirAll(modDir, 0755)
	defer os.RemoveAll(modDir)
	modFile := filepath.Join(modDir, "mock_test.sh")
	os.WriteFile(modFile, []byte("# MODULE_META\n# NAME=\"Mock\"\n# CATEGORY=\"M\"\n"), 0755)

	var gotAPInterface string
	mockRunFunc := func(s *session.Session, m *module.Module) error {
		gotAPInterface = os.Getenv("AP_INTERFACE")
		return nil
	}

	cwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(cwd)

	if err := RunAutonomousAudit(filepath.Join("..", planPath), filepath.Join("..", modDir), mockRunFunc); err != nil {
		t.Fatalf("RunAutonomousAudit failed: %v", err)
	}

	if gotAPInterface != "wlan2" {
		t.Errorf("expected AP_INTERFACE=wlan2, got %q", gotAPInterface)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go test ./internal/headless/... -v -run TestHeadlessAPInterfaceInjected
```

Expected: FAIL — `AuditPlan` has no `APInterface` field yet, so the JSON field is ignored and `AP_INTERFACE` will be empty.

- [ ] **Step 3: Add APInterface to AuditPlan and inject it**

Open `internal/headless/headless.go`. In the `AuditPlan` struct (lines 15–25), add the new field after `MonitorInterface`:

```go
type AuditPlan struct {
	SessionName      string   `json:"session_name"`
	Interface        string   `json:"interface"`
	MonitorInterface string   `json:"monitor_interface"`
	APInterface      string   `json:"ap_interface"`
	TargetSSID       string   `json:"target_ssid"`
	TargetBSSID      string   `json:"target_bssid"`
	TargetChan       string   `json:"target_channel"`
	Modules          []string `json:"modules"`
	CaptureTime      int      `json:"capture_time"`
	ScanTime         int      `json:"scan_time"`
}
```

Then in `RunAutonomousAudit`, find the block after the `MonitorInterface` persistence (around line 65–66):

```go
	if plan.MonitorInterface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "MONITOR_INTERFACE", plan.MonitorInterface)
	}
```

Add immediately after:

```go
	if plan.APInterface != "" {
		os.Setenv("AP_INTERFACE", plan.APInterface)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "AP_INTERFACE", plan.APInterface)
	}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test ./internal/headless/... -v -run TestHeadlessAPInterfaceInjected
```

Expected:
```
=== RUN   TestHeadlessAPInterfaceInjected
--- PASS: TestHeadlessAPInterfaceInjected (0.00s)
PASS
```

- [ ] **Step 5: Run full test suite**

```bash
go test ./...
```

Expected: all packages pass.

- [ ] **Step 6: Commit**

```bash
git add internal/headless/headless.go internal/headless/headless_test.go
git commit -m "feat(headless): add ap_interface field to AuditPlan; inject AP_INTERFACE before module run"
```

---

## Task 7: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the headless plan format JSON example**

In `CLAUDE.md`, find the headless audit plan format block (under `**Headless audit plan format**`):

```json
{
  "session_name": "corp-wifi-2026",
  "monitor_interface": "wlan1",
  "modules": ["A1", "D1", "D3"],
  "capture_time": 60,
  "scan_time": 30
}
```

Replace with:

```json
{
  "session_name": "corp-wifi-2026",
  "monitor_interface": "wlan1",
  "ap_interface": "wlan0",
  "modules": ["A1", "D1", "D3"],
  "capture_time": 60,
  "scan_time": 30
}
```

- [ ] **Step 2: Add AP_INTERFACE to the environment variables table**

In `CLAUDE.md`, find the Environment Variables table under Section 3. Find the `ASTRA_INDEFINITE` row and add a new row after it:

```markdown
| AP_INTERFACE | Dedicated managed-mode adapter for Evil Twin / hostapd modules (F1, F2, F3, D5). Empty in single-adapter setups; affected modules fall back to degraded mode with a warning. |
```

- [ ] **Step 3: Update the hw package row in Section 6**

Find the row in the Key Go Packages table:

```markdown
| hw | `pkg/hw/` | ListInterfaces, Recover(bool), InterfaceRoleRegistry (RoleMonitor/RoleManagement), monitor mode control; all ops use CombinedOutput() for full error capture |
```

Replace with:

```markdown
| hw | `pkg/hw/` | ListInterfaces, Recover(bool), InterfaceRoleRegistry (RoleMonitor/RoleAP), monitor mode control; all ops use CombinedOutput() for full error capture |
```

- [ ] **Step 4: Build and test one final time**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT
go build -o /dev/null ./cmd/astra/
go test ./...
shellcheck -S warning modules/f1_rogue_ap.sh modules/f2_pineap_karma.sh modules/f3_captive_portal.sh modules/d5_eap_attack.sh
```

Expected: all three commands exit 0.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for AP_INTERFACE, RoleAP, headless plan ap_interface field"
```
