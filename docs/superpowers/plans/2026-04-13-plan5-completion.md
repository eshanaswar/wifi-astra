# Plan 5: Completion — D3 Inline Cracking, F3 Vendor Fingerprinting, G4 A4 Integration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the remaining items from the professional overhaul spec: D3 inline WPS cracking (success criterion 10), F3 captive portal vendor fingerprinting, and G4 A4 client auto-selection.

**Architecture:** `ParseWPSCreds` added to cracking.go following the same pattern as `ParseEaphammerCreds`. `HandleD3PostRun` follows the same pattern as `HandleD1PostRun`. F3 gets a pre-hostapd curl probe block. G4 gets a Go-side client picker that reads A4 evidence and saves TARGET_CLIENT to DB config before the module env is built.

**Tech Stack:** Go stdlib, existing `pkg/executor.Manager`, existing `internal/session.Session.DB`, bash + curl.

---

## TASK 1: ParseWPSCreds helper + tests

### Step 1.1 - Write failing tests

- [ ] Add to `internal/controller/cracking_test.go`:

```go
func TestParseWPSCreds_ReaverFormat(t *testing.T) {
	input := "[+] WPS PIN: '12345670'\n[+] WPA PSK: 'password123'"
	psk, pin := ParseWPSCreds(input)
	if psk != "password123" {
		t.Errorf("expected PSK 'password123', got '%s'", psk)
	}
	if pin != "12345670" {
		t.Errorf("expected PIN '12345670', got '%s'", pin)
	}
}

func TestParseWPSCreds_BullyFormat(t *testing.T) {
	input := "[+] Passphrase is: 'password123'\n[+] WPS pin is: 12345670"
	psk, pin := ParseWPSCreds(input)
	if psk != "password123" {
		t.Errorf("expected PSK 'password123', got '%s'", psk)
	}
	if pin != "12345670" {
		t.Errorf("expected PIN '12345670', got '%s'", pin)
	}
}

func TestParseWPSCreds_Empty(t *testing.T) {
	psk, pin := ParseWPSCreds("")
	if psk != "" || pin != "" {
		t.Errorf("expected empty results, got psk='%s' pin='%s'", psk, pin)
	}
}

func TestParseWPSCreds_PINOnly(t *testing.T) {
	input := "[+] WPS PIN: '87654321'"
	psk, pin := ParseWPSCreds(input)
	if psk != "" {
		t.Errorf("expected empty PSK, got '%s'", psk)
	}
	if pin != "87654321" {
		t.Errorf("expected PIN '87654321', got '%s'", pin)
	}
}
```

- [ ] Run the failing test:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/ -run TestParseWPSCreds -v 2>&1
```

Expected output:

```
# github.com/eshanaswar/wifi-astra/internal/controller [...]
./cracking_test.go:XX:XX: undefined: ParseWPSCreds
FAIL	github.com/eshanaswar/wifi-astra/internal/controller [build failed]
```

### Step 1.2 - Write the implementation

- [ ] Add `ParseWPSCreds` to `internal/controller/cracking.go`. Ensure `regexp` and `strings` are in the import block (they likely already are from `ParseEaphammerCreds`).

```go
// ParseWPSCreds extracts WPS PIN and WPA PSK from reaver or bully output logs.
// It returns the first found psk and pin, stripping surrounding single quotes.
// Supports both reaver format ([+] WPS PIN / [+] WPA PSK) and
// bully format ([+] WPS pin is / [+] Passphrase is).
func ParseWPSCreds(logText string) (psk, pin string) {
	// reaver PIN:  [+] WPS PIN: '12345670'
	reavPIN := regexp.MustCompile(`(?i)\[\+\]\s+WPS PIN:\s+'?([0-9]+)'?`)
	// reaver PSK:  [+] WPA PSK: 'password123'
	reavPSK := regexp.MustCompile(`(?i)\[\+\]\s+WPA PSK:\s+'?([^'\n]+)'?`)
	// bully PIN:   [+] WPS pin is: 12345670
	bullyPIN := regexp.MustCompile(`(?i)\[\+\]\s+WPS pin is:\s+'?([0-9]+)'?`)
	// bully PSK:   [+] Passphrase is: 'password123'
	bullyPSK := regexp.MustCompile(`(?i)\[\+\]\s+Passphrase is:\s+'?([^'\n]+)'?`)

	if m := reavPIN.FindStringSubmatch(logText); len(m) > 1 {
		pin = strings.TrimSpace(strings.Trim(m[1], "'"))
	} else if m := bullyPIN.FindStringSubmatch(logText); len(m) > 1 {
		pin = strings.TrimSpace(strings.Trim(m[1], "'"))
	}

	if m := reavPSK.FindStringSubmatch(logText); len(m) > 1 {
		psk = strings.TrimSpace(strings.Trim(m[1], "'"))
	} else if m := bullyPSK.FindStringSubmatch(logText); len(m) > 1 {
		psk = strings.TrimSpace(strings.Trim(m[1], "'"))
	}
	return
}
```

### Step 1.3 - Run tests (expect PASS)

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/ -run TestParseWPSCreds -v 2>&1
```

Expected output:

```
=== RUN   TestParseWPSCreds_ReaverFormat
--- PASS: TestParseWPSCreds_ReaverFormat (0.00s)
=== RUN   TestParseWPSCreds_BullyFormat
--- PASS: TestParseWPSCreds_BullyFormat (0.00s)
=== RUN   TestParseWPSCreds_Empty
--- PASS: TestParseWPSCreds_Empty (0.00s)
=== RUN   TestParseWPSCreds_PINOnly
--- PASS: TestParseWPSCreds_PINOnly (0.00s)
PASS
ok      github.com/eshanaswar/wifi-astra/internal/controller   0.XXXs
```

### Step 1.4 - Commit

- [ ] Commit:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && git add internal/controller/cracking.go internal/controller/cracking_test.go && git commit -m 'feat(controller): add ParseWPSCreds for reaver/bully output parsing'
```

---

## TASK 2: HandleD3PostRun in assessment.go

### Step 2.1 - Write failing test

- [ ] Add to `internal/controller/cracking_test.go`:

```go
// TestHandleD3PostRun_ParseIntegration confirms ParseWPSCreds feeds correct
// data for the D3 flow (realistic multi-line reaver output).
func TestHandleD3PostRun_ParseIntegration(t *testing.T) {
	log := "[+] Nothing done yet, but:\n[+] WPS PIN: '33669913'\n[+] WPA PSK: 'SuperSecret!'"
	psk, pin := ParseWPSCreds(log)
	if psk != "SuperSecret!" {
		t.Errorf("D3 flow PSK mismatch: got '%s'", psk)
	}
	if pin != "33669913" {
		t.Errorf("D3 flow PIN mismatch: got '%s'", pin)
	}
}
```

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/ -run TestHandleD3PostRun -v 2>&1
```

Expected output:

```
=== RUN   TestHandleD3PostRun_ParseIntegration
--- PASS: TestHandleD3PostRun_ParseIntegration (0.00s)
PASS
ok      github.com/eshanaswar/wifi-astra/internal/controller   0.XXXs
```

### Step 2.2 - Write HandleD3PostRun implementation

- [ ] Add the following method to `internal/controller/assessment.go`, alongside the existing `HandleD1PostRun` and `HandleD5PostRun` methods. Ensure `os`, `fmt`, `log`, and `path/filepath` are in the import block.

```go
// HandleD3PostRun processes results from the D3 WPS testing module.
// It reads D3_reaver_info.txt from the evidence directory, parses WPS credentials
// using ParseWPSCreds, and records any recovered PSK or PIN into the session database.
func (c *AssessmentController) HandleD3PostRun() {
	logFile := filepath.Join(c.Session.EvidenceDir, "D3_reaver_info.txt")
	data, err := os.ReadFile(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[D3] No reaver/bully output file found at %s — skipping post-run", logFile)
			return
		}
		log.Printf("[D3] Error reading %s: %v", logFile, err)
		return
	}

	psk, pin := ParseWPSCreds(string(data))

	if psk == "" && pin == "" {
		log.Printf("[D3] No WPS credentials found in output")
		return
	}

	// Fetch BSSID and SSID from session config for the credential record.
	var bssid, ssid string
	_ = c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
	_ = c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)

	if psk != "" {
		fmt.Printf("[D3] WPS attack recovered PSK: %s\n", psk)
		if pin != "" {
			fmt.Printf("[D3] WPS PIN used: %s\n", pin)
		}
		_, dbErr := c.Session.DB.Exec(
			`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"D3", ssid, psk, "WPA2-PSK", bssid, logFile, "WPS PIN attack recovered PSK.",
		)
		if dbErr != nil {
			log.Printf("[D3] Failed to record credential: %v", dbErr)
		} else {
			fmt.Printf("[D3] Credential recorded in session database.\n")
		}
		return
	}

	// PIN found but no PSK — record as a finding note for manual follow-up.
	fmt.Printf("[D3] WPS PIN recovered (no PSK): %s — consider manual follow-up\n", pin)
	_, dbErr := c.Session.DB.Exec(
		`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"D3", "(WPS PIN)", pin, "WPS-PIN", bssid, logFile, "WPS PIN recovered; no PSK extracted.",
	)
	if dbErr != nil {
		log.Printf("[D3] Failed to record PIN finding: %v", dbErr)
	}
}
```

### Step 2.3 - Wire into switch dispatcher

- [ ] In `internal/controller/assessment.go`, find the `HandlePostRun` switch block and add the `D3` case:

```go
switch m.ID {
case "A1":
    c.HandleA1PostRun()
case "D1":
    c.HandleD1PostRun()
case "D3":
    c.HandleD3PostRun()
case "D5":
    c.HandleD5PostRun()
}
```

### Step 2.4 - Build check

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go build ./... 2>&1
```

Expected output: no output (clean build).

### Step 2.5 - Run all controller tests

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/... -v 2>&1
```

Expected: all tests PASS with no failures.

### Step 2.6 - Commit

- [ ] Commit:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && git add internal/controller/assessment.go internal/controller/cracking_test.go && git commit -m 'feat(controller): add HandleD3PostRun for WPS post-run credential extraction'
```

---

## TASK 3: F3 captive portal vendor fingerprinting

### Step 3.1 - Inspect current F3 structure

- [ ] Read the top of the module to identify the correct insertion point (before hostapd is launched):

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && head -n 100 modules/f3_captive_portal.sh 2>&1
```

Locate the line that starts hostapd (typically `hostapd /tmp/hostapd.conf &` or similar). The vendor detection block must be inserted **before** that line, after initial variable declarations.

### Step 3.2 - Insert vendor detection block

- [ ] Insert the following bash block into `modules/f3_captive_portal.sh` immediately before the hostapd/dnsmasq setup section. The block is self-contained and fails gracefully if no internet route is available.

```bash
# ─── Vendor fingerprinting ───────────────────────────────────────────────────
# Probe captive portal redirect before standing up rogue AP.
# Runs on whatever internet route is currently available.
# Fails silently (DETECTED_VENDOR='unknown') if no route exists.
echo '[F3] Probing captive portal vendor...'
PROBE_RESPONSE=$(curl -siL --max-time 5 http://1.1.1.1 2>/dev/null || true)
DETECTED_VENDOR='unknown'
if echo "$PROBE_RESPONSE" | grep -qiE 'identityservicesengine|guestportal|sponsorportal|cisco\.com/auth'; then
    DETECTED_VENDOR='cisco_ise'
elif echo "$PROBE_RESPONSE" | grep -qiE 'clearpass|aruba|onguard'; then
    DETECTED_VENDOR='aruba_clearpass'
elif echo "$PROBE_RESPONSE" | grep -qiE 'meraki\.com|meraki-splash'; then
    DETECTED_VENDOR='meraki'
elif echo "$PROBE_RESPONSE" | grep -qiE 'fgtauth|fortigate|fortiap'; then
    DETECTED_VENDOR='fortigate'
elif echo "$PROBE_RESPONSE" | grep -qiE 'ubnt\.com|unifi|guest/s/'; then
    DETECTED_VENDOR='unifi'
elif echo "$PROBE_RESPONSE" | grep -qiE 'pfsense|captiveportal'; then
    DETECTED_VENDOR='pfsense'
fi
echo "[F3] Detected vendor: ${DETECTED_VENDOR}"

# Write detection result to evidence directory.
cat > "${EVIDENCE_DIR}/F3_vendor.json" <<JSON_EOF
{"detected_vendor": "${DETECTED_VENDOR}", "probe_url": "http://1.1.1.1", "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"}
JSON_EOF

# Auto-select PHISH_TEMPLATE from detected vendor only when still at the
# default 'generic' value. Explicit operator overrides are preserved.
PHISH_TEMPLATE="${PHISH_TEMPLATE:-generic}"
if [[ "$PHISH_TEMPLATE" == 'generic' ]]; then
    case "$DETECTED_VENDOR" in
        cisco_ise)       PHISH_TEMPLATE='cisco_ise' ;;
        aruba_clearpass) PHISH_TEMPLATE='aruba' ;;
        meraki)          PHISH_TEMPLATE='meraki' ;;
        *)               PHISH_TEMPLATE='generic' ;;
    esac
    echo "[F3] Auto-selected template: ${PHISH_TEMPLATE}"
fi
# ─────────────────────────────────────────────────────────────────────────────
```

### Step 3.3 - Verify bash syntax

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && bash -n modules/f3_captive_portal.sh && echo 'syntax OK'
```

Expected output:

```
syntax OK
```

### Step 3.4 - Commit

- [ ] Commit:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && git add modules/f3_captive_portal.sh && git commit -m 'feat(modules/f3): add pre-hostapd captive portal vendor fingerprinting'
```

---

## TASK 4: G4 A4 client selection in assessment.go

### Step 4.1 - Write failing tests for parseA4ClientMACs

- [ ] Create `internal/controller/assessment_helpers_test.go`:

```go
package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseA4ClientMACs_Basic(t *testing.T) {
	csv := `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes
AA:BB:CC:DD:EE:01, 2024-01-01 12:00:00, 2024-01-01 12:01:00, -65, 100, 00:11:22:33:44:55, MySSID
AA:BB:CC:DD:EE:02, 2024-01-01 12:00:00, 2024-01-01 12:01:00, -72, 50, 00:11:22:33:44:55,
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 2 {
		t.Fatalf("expected 2 clients, got %d: %v", len(macs), macs)
	}
	if macs[0] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("unexpected first MAC: %s", macs[0])
	}
	if macs[1] != "AA:BB:CC:DD:EE:02" {
		t.Errorf("unexpected second MAC: %s", macs[1])
	}
}

func TestParseA4ClientMACs_NoStationSection(t *testing.T) {
	csv := "BSSID, First time seen\n00:11:22:33:44:55, 2024-01-01\n"
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 0 {
		t.Errorf("expected 0 clients (no Station MAC section), got %d: %v", len(macs), macs)
	}
}

func TestParseA4ClientMACs_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 0 {
		t.Errorf("expected 0 clients for empty file, got %d", len(macs))
	}
}

func TestParseA4ClientMACs_NonexistentFile(t *testing.T) {
	macs := parseA4ClientMACs("/nonexistent/path/a4_results.csv")
	if len(macs) != 0 {
		t.Errorf("expected 0 clients for missing file, got %d", len(macs))
	}
}
```

- [ ] Run the failing test:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/ -run TestParseA4ClientMACs -v 2>&1
```

Expected output:

```
# github.com/eshanaswar/wifi-astra/internal/controller [...]
./assessment_helpers_test.go:XX:XX: undefined: parseA4ClientMACs
FAIL	github.com/eshanaswar/wifi-astra/internal/controller [build failed]
```

### Step 4.2 - Write parseA4ClientMACs implementation

- [ ] Add to `internal/controller/assessment.go`. Ensure `os`, `log`, and `strings` are in the import block.

```go
// parseA4ClientMACs reads an airodump-ng CSV file and extracts client (Station) MAC
// addresses. It locates the "Station MAC" header line and collects the first field
// (MAC address) from all subsequent non-empty lines.
// Returns nil (not an error) when the file does not exist or contains no client section.
func parseA4ClientMACs(csvPath string) []string {
	data, err := os.ReadFile(csvPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[G4] Could not read A4 CSV at %s: %v", csvPath, err)
		}
		return nil
	}

	var macs []string
	inStationSection := false

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Station MAC") {
			inStationSection = true
			continue
		}
		if inStationSection {
			parts := strings.SplitN(trimmed, ",", 2)
			if len(parts) >= 1 {
				mac := strings.TrimSpace(parts[0])
				if mac != "" {
					macs = append(macs, mac)
				}
			}
		}
	}
	return macs
}
```

### Step 4.3 - Write prepareG4Env method

- [ ] Add to `internal/controller/assessment.go`. Ensure `fmt`, `log`, `path/filepath`, and `strings` are in the import block.

```go
// prepareG4Env checks whether TARGET_CLIENT is already set in the session DB config.
// If not, it reads the A4 airodump CSV from the evidence directory, presents a numbered
// list of discovered client MACs to the operator, prompts for a selection, and saves the
// chosen MAC as TARGET_CLIENT in the DB config. Because all config rows are automatically
// exported as environment variables during ExecuteModule, G4 will receive TARGET_CLIENT
// in its environment with no additional wiring needed.
func (c *AssessmentController) prepareG4Env() {
	// Skip if TARGET_CLIENT is already configured.
	var existing string
	err := c.Session.DB.QueryRow("SELECT value FROM config WHERE key = 'TARGET_CLIENT'").Scan(&existing)
	if err == nil && strings.TrimSpace(existing) != "" {
		fmt.Printf("[G4] TARGET_CLIENT already set: %s\n", existing)
		return
	}

	csvPath := filepath.Join(c.Session.EvidenceDir, "a4_results.csv")
	macs := parseA4ClientMACs(csvPath)
	if len(macs) == 0 {
		fmt.Println("[G4] No client MACs found in A4 evidence — G4 will exit gracefully.")
		return
	}

	fmt.Println("[G4] Select target client for NAC bypass:")
	for i, mac := range macs {
		fmt.Printf("  [%d] %s\n", i+1, mac)
	}
	fmt.Print("Enter number (or 0 to skip): ")

	var choice int
	if _, scanErr := fmt.Scan(&choice); scanErr != nil || choice <= 0 || choice > len(macs) {
		fmt.Println("[G4] No client selected — G4 will exit gracefully.")
		return
	}

	selected := macs[choice-1]
	_, dbErr := c.Session.DB.Exec(
		`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`,
		"TARGET_CLIENT", selected,
	)
	if dbErr != nil {
		log.Printf("[G4] Failed to save TARGET_CLIENT: %v", dbErr)
		return
	}
	fmt.Printf("[G4] TARGET_CLIENT set to %s\n", selected)
}
```

### Step 4.4 - Wire prepareG4Env into ExecuteModule

- [ ] In `internal/controller/assessment.go`, inside `ExecuteModule`, after the scope enforcement block and before the env setup loop, add:

```go
// Pre-run hooks: modules that need operator input before the env is built.
if m.ID == "G4" {
    c.prepareG4Env()
}
```

The env setup loop that follows (which reads all `config` rows and exports them as env vars) will then automatically include `TARGET_CLIENT` for G4.

### Step 4.5 - Run parseA4ClientMACs tests (expect PASS)

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go test ./internal/controller/ -run TestParseA4ClientMACs -v 2>&1
```

Expected output:

```
=== RUN   TestParseA4ClientMACs_Basic
--- PASS: TestParseA4ClientMACs_Basic (0.00s)
=== RUN   TestParseA4ClientMACs_NoStationSection
--- PASS: TestParseA4ClientMACs_NoStationSection (0.00s)
=== RUN   TestParseA4ClientMACs_EmptyFile
--- PASS: TestParseA4ClientMACs_EmptyFile (0.00s)
=== RUN   TestParseA4ClientMACs_NonexistentFile
--- PASS: TestParseA4ClientMACs_NonexistentFile (0.00s)
PASS
ok      github.com/eshanaswar/wifi-astra/internal/controller   0.XXXs
```

### Step 4.6 - Full build and test suite

- [ ] Run:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && go build ./... && go test ./... 2>&1
```

Expected output:

```
ok      github.com/eshanaswar/wifi-astra/cmd          0.XXXs
ok      github.com/eshanaswar/wifi-astra/internal/controller   0.XXXs
ok      github.com/eshanaswar/wifi-astra/internal/ingest       0.XXXs
ok      github.com/eshanaswar/wifi-astra/internal/module       0.XXXs
ok      github.com/eshanaswar/wifi-astra/pkg/executor          0.XXXs
ok      github.com/eshanaswar/wifi-astra/pkg/hw                0.XXXs
```

All packages build and all tests pass. Any package with no test files outputs `[no test files]` rather than FAIL — that is acceptable.

### Step 4.7 - Commit

- [ ] Commit:

```bash
cd /home/kali/Documents/Antigravity/WiFi_PT/.worktrees/plan5-completion && git add internal/controller/assessment.go internal/controller/assessment_helpers_test.go && git commit -m 'feat(controller): add G4 A4 client picker with prepareG4Env pre-run hook'
```

---

## Completion Checklist

- [ ] `ParseWPSCreds` function added to `internal/controller/cracking.go`
- [ ] All 4 `ParseWPSCreds` tests passing (`ReaverFormat`, `BullyFormat`, `Empty`, `PINOnly`)
- [ ] `HandleD3PostRun` method added to `internal/controller/assessment.go`
- [ ] `D3` case wired into `HandlePostRun` switch dispatcher
- [ ] `TestHandleD3PostRun_ParseIntegration` test passing
- [ ] F3 vendor detection bash block inserted before hostapd in `modules/f3_captive_portal.sh`
- [ ] F3 writes `F3_vendor.json` to `${EVIDENCE_DIR}` with `detected_vendor` and `probe_url` fields
- [ ] F3 auto-selects `PHISH_TEMPLATE` from detected vendor (only when still at default `generic`)
- [ ] `parseA4ClientMACs` function added to `internal/controller/assessment.go`
- [ ] All 4 `parseA4ClientMACs` tests passing (`Basic`, `NoStationSection`, `EmptyFile`, `NonexistentFile`)
- [ ] `prepareG4Env` method added to `internal/controller/assessment.go`
- [ ] G4 pre-run hook wired into `ExecuteModule` (`if m.ID == "G4" { c.prepareG4Env() }`)
- [ ] Full build passes: `go build ./...`
- [ ] Full test suite passes: `go test ./...`
