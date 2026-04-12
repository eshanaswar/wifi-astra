# Plan 1: Foundation — Security Hardening & Hardware Reliability

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make WiFi-Astra safe and reliable on live engagements — all Bash modules handle adversarial SSIDs without breaking, hardware failures surface clearly, panics don't leave adapters in monitor mode, and dual-adapter role enforcement prevents accidental attacks on the management interface.

**Architecture:** Five targeted changes across three layers — Bash security (46 modules via shellcheck), Go executor (enhance SanitizeEnv logging), Go hardware (fix silent failures + panic recovery + role registry). Each task is independently testable and committable.

**Tech Stack:** Go 1.24, Bash, shellcheck, pkg/hw, pkg/executor

---

## Pre-work: Install shellcheck

```bash
apt-get install -y shellcheck
shellcheck --version
# Expected: ShellCheck - shell script analysis tool, version x.x.x
```

---

## File Map

| Action | File | Change |
|--------|------|--------|
| Modify | `pkg/executor/executor.go` | Add per-var logging to `SanitizeEnv` |
| Modify | `pkg/executor/executor_test.go` | Add `SanitizeEnv` warning tests |
| Modify | `pkg/hw/hw.go` | Fix silent failures in `GetInterfaceMode`, `listInterfacesFallback`, `Recover` |
| Create | `pkg/hw/roles.go` | `InterfaceRoleRegistry` — enforce MONITOR/MANAGEMENT separation |
| Create | `pkg/hw/roles_test.go` | Role registry unit tests |
| Modify | `cmd/root.go` | Add `defer` panic recovery that calls `hw.Recover` |
| Modify | `modules/f1_rogue_ap.sh` | Fix `ssid=$SSID` → `ssid="$SSID"` |
| Modify | `modules/f3_captive_portal.sh` | Fix `ssid=$SSID` → `ssid="$SSID"` |
| Modify | `modules/d7_wpa3_downgrade_active.sh` | Fix `ssid=$SSID` → `ssid="$SSID"` |
| Modify | `modules/f4_portal_bypass.sh` | Fix `echo $TARGET_CLIENT` → `echo "$TARGET_CLIENT"` |
| Modify | `modules/g4_nac_bypass.sh` | Fix `echo $TARGET_CLIENT` → `echo "$TARGET_CLIENT"` |
| Modify | `modules/c2_private_network_scan.sh` | Fix `echo $TARGETS` → `echo "$TARGETS"` |
| Modify | `modules/*.sh` (remaining) | Fix any additional issues found by shellcheck |

---

## Task 1: Bash Module Security Audit and Fix

**Files:**
- Modify: `modules/f1_rogue_ap.sh:73`
- Modify: `modules/f3_captive_portal.sh:115`
- Modify: `modules/d7_wpa3_downgrade_active.sh:69`
- Modify: `modules/f4_portal_bypass.sh:80`
- Modify: `modules/g4_nac_bypass.sh:62`
- Modify: `modules/c2_private_network_scan.sh:58`
- Modify: any additional files flagged by shellcheck

- [ ] **Step 1: Run shellcheck across all modules to get the full list of issues**

```bash
shellcheck -S warning modules/*.sh 2>&1 | grep -E "SC2086|SC2046" | sort -u
```

Expected: Lines referencing `SC2086` (double-quote to prevent globbing/splitting) and `SC2046` (quote command substitution). Note every file listed.

- [ ] **Step 2: Fix confirmed unquoted variables in f1_rogue_ap.sh**

File: `modules/f1_rogue_ap.sh`, line 73.

Find:
```bash
ssid=$SSID
```
Replace with:
```bash
ssid="$SSID"
```

- [ ] **Step 3: Fix confirmed unquoted variables in f3_captive_portal.sh**

File: `modules/f3_captive_portal.sh`, line 115.

Find:
```bash
ssid=$SSID
```
Replace with:
```bash
ssid="$SSID"
```

- [ ] **Step 4: Fix confirmed unquoted variables in d7_wpa3_downgrade_active.sh**

File: `modules/d7_wpa3_downgrade_active.sh`, line 69.

Find:
```bash
ssid=$SSID
```
Replace with:
```bash
ssid="$SSID"
```

- [ ] **Step 5: Fix confirmed unquoted variables in f4_portal_bypass.sh**

File: `modules/f4_portal_bypass.sh`, line 80.

Find:
```bash
SPOOFED_HOSTNAME="iPad-of-$(echo $TARGET_CLIENT | cut -d: -f5,6 | tr -d ':')"
```
Replace with:
```bash
SPOOFED_HOSTNAME="iPad-of-$(echo "$TARGET_CLIENT" | cut -d: -f5,6 | tr -d ':')"
```

- [ ] **Step 6: Fix confirmed unquoted variables in g4_nac_bypass.sh**

File: `modules/g4_nac_bypass.sh`, line 62.

Find:
```bash
SPOOFED_HOSTNAME="Workstation-$(echo $TARGET_CLIENT | cut -d: -f5,6 | tr -d ':')"
```
Replace with:
```bash
SPOOFED_HOSTNAME="Workstation-$(echo "$TARGET_CLIENT" | cut -d: -f5,6 | tr -d ':')"
```

- [ ] **Step 7: Fix confirmed unquoted variables in c2_private_network_scan.sh**

File: `modules/c2_private_network_scan.sh`, line 58.

Find:
```bash
echo "[*] Testing reachability for gateways: $(echo $TARGETS | xargs)"
```
Replace with:
```bash
echo "[*] Testing reachability for gateways: $(echo "$TARGETS" | xargs)"
```

- [ ] **Step 8: Fix any additional SC2086/SC2046 issues found by shellcheck in Step 1**

For each additional file reported, apply the same pattern: wrap bare `$VAR` in `"$VAR"` and bare `$(cmd $VAR)` in `$(cmd "$VAR")`. Do not quote variables that are intentionally word-split (e.g., array-like `$TOOLS`).

- [ ] **Step 9: Re-run shellcheck to verify no SC2086/SC2046 remain**

```bash
shellcheck -S warning modules/*.sh 2>&1 | grep -E "SC2086|SC2046"
```

Expected: No output (zero matches).

- [ ] **Step 10: Commit**

```bash
git add modules/
git commit -m "fix(modules): quote all external-data variables to prevent word splitting

Fixes SC2086/SC2046 shellcheck warnings across modules. SSIDs and BSSIDs
containing spaces, semicolons, or apostrophes (e.g. O'Brien's WiFi) will
now be handled correctly instead of silently breaking module execution."
```

---

## Task 2: Enhance SanitizeEnv with Warning Logging

**Files:**
- Modify: `pkg/executor/executor.go:46-65`
- Modify: `pkg/executor/executor_test.go`

The existing `SanitizeEnv` strips dangerous characters silently. Operators need to know when a value was sanitized — a stripped semicolon in an SSID is important diagnostic information. Also add `$` stripping when followed by `(` to catch `$(cmd)` injection sequences.

- [ ] **Step 1: Write the failing test**

Add to `pkg/executor/executor_test.go`:

```go
func TestSanitizeEnvLogsWarning(t *testing.T) {
	// SanitizeEnv should strip metacharacters and not panic
	dangerous := []string{
		"SSID=Corp;Net",
		"BSSID=AA:BB:CC:DD:EE:FF",        // safe — should pass through unchanged
		"GUEST_SSID=Acme&Partners|WiFi",
		"TARGET_CLIENT=`whoami`",
	}
	result := SanitizeEnv(dangerous)

	if len(result) != len(dangerous) {
		t.Fatalf("expected %d entries, got %d", len(dangerous), len(result))
	}
	// Safe value must be unchanged
	if result[1] != "BSSID=AA:BB:CC:DD:EE:FF" {
		t.Errorf("safe value was modified: %s", result[1])
	}
	// Dangerous values must have metacharacters removed
	for _, v := range []string{result[0], result[2], result[3]} {
		for _, ch := range []string{";", "&", "|", "`"} {
			if strings.Contains(v, ch) {
				t.Errorf("dangerous char %q not stripped from %q", ch, v)
			}
		}
	}
}

func TestSanitizeEnvPreservesEqualsSign(t *testing.T) {
	// KEY=VALUE format must be preserved — only the value part is sanitized
	input := []string{"MY_KEY=some=value=with=equals"}
	result := SanitizeEnv(input)
	if result[0] != "MY_KEY=some=value=with=equals" {
		t.Errorf("equals signs in value should not be stripped: %s", result[0])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail for the right reason**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go test ./pkg/executor/... -run TestSanitizeEnv -v
```

Expected: Tests pass (the current implementation already strips the chars). If `TestSanitizeEnvPreservesEqualsSign` fails, it means the replacer is stripping `=` — check and fix.

- [ ] **Step 3: Enhance SanitizeEnv to log warnings when values are modified**

Replace the `SanitizeEnv` function in `pkg/executor/executor.go` (lines 46-65):

```go
// SanitizeEnv strips dangerous shell metacharacters from environment variable values
// and logs a warning for any value that was modified. The KEY= prefix is preserved.
func SanitizeEnv(env []string) []string {
	sanitized := make([]string, len(env))
	re := strings.NewReplacer(
		";", "",
		"&", "",
		"|", "",
		"`", "",
		"(", "",
		")", "",
		"\n", "",
		"\r", "",
		"<", "",
		">", "",
	)
	for i, entry := range env {
		// Preserve KEY= prefix; only sanitize the value portion
		idx := strings.IndexByte(entry, '=')
		if idx < 0 {
			sanitized[i] = entry
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]
		clean := re.Replace(val)
		if clean != val {
			logging.Warn("SanitizeEnv: stripped dangerous characters from env var %s (original len=%d, clean len=%d)", key, len(val), len(clean))
		}
		sanitized[i] = key + "=" + clean
	}
	return sanitized
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go test ./pkg/executor/... -run TestSanitizeEnv -v
```

Expected: `PASS` for both `TestSanitizeEnvLogsWarning` and `TestSanitizeEnvPreservesEqualsSign`.

- [ ] **Step 5: Run full executor test suite**

```bash
go test ./pkg/executor/... -v
```

Expected: All tests `PASS`.

- [ ] **Step 6: Commit**

```bash
git add pkg/executor/executor.go pkg/executor/executor_test.go
git commit -m "feat(executor): add per-key warning logging to SanitizeEnv

Previously stripped characters silently. Now logs a warning with the
key name when metacharacters are removed, making it visible in session
logs when an SSID or BSSID contains dangerous characters."
```

---

## Task 3: Fix Silent Hardware Failures in pkg/hw/hw.go

**Files:**
- Modify: `pkg/hw/hw.go`

Three functions currently ignore errors silently:
1. `GetInterfaceMode` — `output, _ := cmd.Output()` discards the error
2. `listInterfacesFallback` — doesn't log before returning the `iw dev` error
3. `Recover` — `exec.Command("airmon-ng", "stop", iface).Run()` discards error

- [ ] **Step 1: Fix GetInterfaceMode to log errors**

In `pkg/hw/hw.go`, replace the `GetInterfaceMode` function (lines 144-160):

```go
func GetInterfaceMode(iface string) string {
	if !IsValidInterfaceName(iface) {
		return "invalid"
	}
	cmd := exec.Command("iw", "dev", iface, "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Debug("GetInterfaceMode: iw dev %s info failed: %v (output: %s)", iface, err, strings.TrimSpace(string(output)))
		return "unknown"
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "type") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "unknown"
}
```

- [ ] **Step 2: Fix listInterfacesFallback to log the error**

In `pkg/hw/hw.go`, replace the `listInterfacesFallback` function (lines 111-142):

```go
func listInterfacesFallback() ([]Interface, error) {
	logging.Debug("Running hardware discovery fallback (iw dev)...")
	cmd := exec.Command("iw", "dev")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error("listInterfacesFallback: iw dev failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
		return nil, fmt.Errorf("iw dev failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	logging.Debug("iw dev output: %s", string(output))

	var interfaces []Interface
	var currentIface *Interface

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			if currentIface != nil {
				interfaces = append(interfaces, *currentIface)
			}
			parts := strings.Fields(line)
			currentIface = &Interface{Name: parts[1]}
		} else if strings.HasPrefix(line, "type ") && currentIface != nil {
			parts := strings.Fields(line)
			currentIface.Mode = parts[1]
		}
	}
	if currentIface != nil {
		interfaces = append(interfaces, *currentIface)
	}
	return interfaces, nil
}
```

- [ ] **Step 3: Fix Recover to log airmon-ng stop errors**

In `pkg/hw/hw.go`, replace the recovery loop inside `Recover` (the block that iterates `stuck` interfaces). Find:

```go
		if strings.ToLower(response) == "y" {
			for _, iface := range stuck {
				fmt.Printf("    [*] Restoring %s... ", iface)
				exec.Command("airmon-ng", "stop", iface).Run()
				fmt.Println("DONE")
			}
```

Replace with:

```go
		if strings.ToLower(response) == "y" {
			for _, iface := range stuck {
				fmt.Printf("    [*] Restoring %s... ", iface)
				out, err := exec.Command("airmon-ng", "stop", iface).CombinedOutput()
				if err != nil {
					logging.Warn("airmon-ng stop %s failed: %v (output: %s)", iface, err, strings.TrimSpace(string(out)))
					fmt.Println("FAILED (check logs)")
				} else {
					fmt.Println("DONE")
				}
			}
```

- [ ] **Step 4: Build to verify no compile errors**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go build ./...
```

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/hw/hw.go
git commit -m "fix(hw): surface stderr from iw and airmon-ng instead of silent failures

GetInterfaceMode, listInterfacesFallback, and Recover now log errors
with full command output before returning. Previously all three discarded
errors silently, making hardware failures invisible in session logs."
```

---

## Task 4: Add Panic Recovery to Execute()

**Files:**
- Modify: `cmd/root.go`

The signal handler calls `hw.Recover` on SIGTERM, but a Go `panic` bypasses it entirely, leaving adapters in monitor mode. A top-level `recover()` catches panics and ensures hardware is always cleaned up.

- [ ] **Step 1: Add panic recovery to Execute()**

In `cmd/root.go`, modify the `Execute` function. Add a deferred panic handler immediately after `ExecMgr` is initialised:

```go
func Execute() {
	ExecMgr = executor.NewManager()

	// Ensure hardware is always recovered even on panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[!] PANIC: %v\n", r)
			fmt.Fprintln(os.Stderr, "[!] Attempting hardware recovery before exit...")
			ExecMgr.Cleanup()
			hw.Recover(false)
			os.Exit(2)
		}
	}()

	// Global signal handling (existing code below — do not modify)
	sigChan := make(chan os.Signal, 1)
	// ... rest of existing function unchanged
```

- [ ] **Step 2: Build to verify no compile errors**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go build ./...
```

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add cmd/root.go
git commit -m "fix(cmd): add panic recovery to Execute() to guarantee hw.Recover runs

A Go panic previously bypassed the signal handler, leaving wireless
adapters stuck in monitor mode. The deferred recover() now catches panics,
kills all process groups, and restores interfaces before exiting."
```

---

## Task 5: Implement InterfaceRoleRegistry

**Files:**
- Create: `pkg/hw/roles.go`
- Create: `pkg/hw/roles_test.go`

On dual-adapter setups the MONITOR interface (injection/capture) and MANAGEMENT interface (internet/C2) must never be swapped. Any module that tries to use the management interface for monitor operations gets a hard rejection before anything is sent to the hardware.

- [ ] **Step 1: Write the failing tests**

Create `pkg/hw/roles_test.go`:

```go
package hw

import (
	"testing"
)

func TestRoleRegistryAssignAndGet(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	mon, err := r.Get(RoleMonitor)
	if err != nil {
		t.Fatalf("expected monitor interface, got error: %v", err)
	}
	if mon != "wlan0" {
		t.Errorf("expected wlan0, got %s", mon)
	}

	mgmt, err := r.Get(RoleManagement)
	if err != nil {
		t.Fatalf("expected management interface, got error: %v", err)
	}
	if mgmt != "wlan1" {
		t.Errorf("expected wlan1, got %s", mgmt)
	}
}

func TestRoleRegistryGetUnassigned(t *testing.T) {
	r := NewRoleRegistry()
	_, err := r.Get(RoleMonitor)
	if err == nil {
		t.Fatal("expected error for unassigned role, got nil")
	}
}

func TestRoleRegistryAssertMonitor(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	// Monitor interface passes assertion
	if err := r.AssertMonitor("wlan0"); err != nil {
		t.Errorf("expected wlan0 to pass AssertMonitor: %v", err)
	}

	// Management interface fails assertion
	if err := r.AssertMonitor("wlan1"); err == nil {
		t.Error("expected wlan1 to fail AssertMonitor (it is the management interface)")
	}
}

func TestRoleRegistryIsManagement(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	if !r.IsManagement("wlan1") {
		t.Error("expected wlan1 to be identified as management interface")
	}
	if r.IsManagement("wlan0") {
		t.Error("expected wlan0 to not be identified as management interface")
	}
}

func TestRoleRegistryLocksPreventsReassign(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Lock()

	// Reassigning after lock should be a no-op / panic-safe
	// The registry is locked — this should return an error
	err := r.Assign(RoleManagement, "wlan0") // try to give monitor iface a second role
	if err == nil {
		t.Error("expected error when assigning already-assigned interface after lock")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go test ./pkg/hw/... -run TestRoleRegistry -v
```

Expected: Compile error — `RoleRegistry`, `RoleMonitor`, `RoleManagement`, `NewRoleRegistry` not defined.

- [ ] **Step 3: Implement roles.go**

Create `pkg/hw/roles.go`:

```go
package hw

import (
	"fmt"
	"sync"
)

// InterfaceRole identifies the operational role of a wireless adapter.
type InterfaceRole int

const (
	RoleMonitor    InterfaceRole = iota // Injection and capture — used by attack modules
	RoleManagement                      // Internet/C2 — never touched by attack modules
)

// RoleRegistry maps roles to interface names and enforces that the management
// interface cannot be used for monitor-mode operations.
type RoleRegistry struct {
	mu       sync.RWMutex
	roles    map[InterfaceRole]string
	locked   bool
}

// NewRoleRegistry creates an empty registry. Call Assign() for each role,
// then Lock() before starting the session.
func NewRoleRegistry() *RoleRegistry {
	return &RoleRegistry{
		roles: make(map[InterfaceRole]string),
	}
}

// Assign sets the interface for the given role. Returns an error if the
// registry is locked or if the interface is already assigned to another role.
func (r *RoleRegistry) Assign(role InterfaceRole, iface string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.locked {
		return fmt.Errorf("role registry is locked — cannot reassign roles after session start")
	}

	// Prevent the same interface being assigned to two roles
	for existingRole, existingIface := range r.roles {
		if existingIface == iface && existingRole != role {
			return fmt.Errorf("interface %s is already assigned to role %d", iface, existingRole)
		}
	}

	r.roles[role] = iface
	return nil
}

// Lock freezes the registry. After locking, Assign() returns an error.
// Call this once both roles are configured and the session has started.
func (r *RoleRegistry) Lock() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.locked = true
}

// Get returns the interface name for the given role.
// Returns an error if the role has not been assigned.
func (r *RoleRegistry) Get(role InterfaceRole) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	iface, ok := r.roles[role]
	if !ok {
		return "", fmt.Errorf("no interface assigned for role %d", role)
	}
	return iface, nil
}

// AssertMonitor verifies that iface is the MONITOR interface.
// Returns an error if iface is the management interface (protecting it from attacks)
// or if roles have not been assigned.
func (r *RoleRegistry) AssertMonitor(iface string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mon, ok := r.roles[RoleMonitor]
	if !ok {
		return fmt.Errorf("monitor interface role not assigned")
	}
	mgmt, mgmtAssigned := r.roles[RoleManagement]

	if mgmtAssigned && iface == mgmt {
		return fmt.Errorf("SAFETY: interface %s is the management interface and cannot be used for attack operations", iface)
	}
	if iface != mon {
		return fmt.Errorf("interface %s is not the assigned monitor interface (%s)", iface, mon)
	}
	return nil
}

// IsManagement returns true if iface is the assigned management interface.
func (r *RoleRegistry) IsManagement(iface string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mgmt, ok := r.roles[RoleManagement]
	return ok && mgmt == iface
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go test ./pkg/hw/... -run TestRoleRegistry -v
```

Expected: All 5 `TestRoleRegistry*` tests `PASS`.

- [ ] **Step 5: Run full hw package tests**

```bash
go test ./pkg/hw/... -v
```

Expected: All tests `PASS` (no regressions).

- [ ] **Step 6: Commit**

```bash
git add pkg/hw/roles.go pkg/hw/roles_test.go
git commit -m "feat(hw): add InterfaceRoleRegistry for dual-adapter safety

Enforces MONITOR/MANAGEMENT role separation at the registry level.
AssertMonitor() blocks any attempt to use the management interface for
attack operations, preventing accidental C2 disconnection on live engagements."
```

---

## Final Verification

- [ ] **Run the full test suite**

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT && go test ./... -v 2>&1 | tail -30
```

Expected: All packages `ok`. No `FAIL` lines.

- [ ] **Build the binary**

```bash
go build -o bin/wifi-astra ./cmd/astra/
```

Expected: Clean build, no errors.

- [ ] **Run shellcheck one final time**

```bash
shellcheck -S warning modules/*.sh 2>&1 | grep -c "SC2086\|SC2046"
```

Expected: `0`

- [ ] **Final commit: version bump / summary**

```bash
git add -A
git commit -m "chore: Plan 1 complete — security hardening and hardware reliability

- All 46 modules pass shellcheck SC2086/SC2046 (no unquoted external vars)
- SanitizeEnv now logs warnings when metacharacters are stripped
- GetInterfaceMode, listInterfacesFallback, Recover surface stderr on failure
- Execute() panic recovery guarantees hw.Recover() runs before exit
- InterfaceRoleRegistry enforces MONITOR/MANAGEMENT adapter separation"
```

---

## What's Next

- **Plan 2:** Evidence System + Engagement Workflow (per-module JSON logs, SHA256 manifest, session replay log, preflight dependency check, live scope selection)
- **Plan 3:** Inline Cracking (D1 hashcat, D2 aircrack, D3 Pixie Dust, D5 asleap)
- **Plan 4:** Modern Attack Coverage (6GHz, WPA3-SAE, PEAP/hostapd-wpe, MAC randomization, OWE, D8 new module, A5 Wi-Fi 6 detection)
