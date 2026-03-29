# Modernization & Tactical Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an intelligence-driven assessment engine that automatically detects target protections (PMF) and guides the operator toward modern, effective attack vectors while retaining legacy support.

**Architecture:** 
- **Module Metadata:** Add `TAGS` to Bash headers to classify modules (Modern, Legacy, Obsolete).
- **Go Brain:** Implement `DetectPMF()` in `internal/controller/assessment.go` to scout targets before disruptive modules.
- **Environment Injection:** Pass `ASTRA_PMF_STATUS` to modules.
- **UI Enhancement:** Update the TUI to display module tags and modern warnings.

**Tech Stack:** Go, Bash, Tshark, airodump-ng.

---

### Task 1: Module Metadata & Discovery Enhancement

**Files:**
- Modify: `internal/module/discovery.go`
- Modify: `modules/*.sh` (Add Tags)

- [ ] **Step 1: Update Module struct and parsing**

```go
type Module struct {
    // ... existing ...
    Tags          []string `json:"tags"`
}

// In parseModuleMeta:
case "TAGS":
    m.Tags = strings.Split(val, ",")
```

- [ ] **Step 2: Add TAGS to core modules**
  - A1: `current`
  - A4: `limited,modern-mitigated`
  - D1: `current`
  - D2: `legacy,obsolete`
  - D3: `legacy,obsolete`
  - D7: `cutting-edge,modern`
  - F2: `limited,legacy-only`
  - B10: `state-of-the-art,modern`

- [ ] **Step 3: Commit**

```bash
git add internal/module/discovery.go modules/
git commit -m "feat: add tactical tagging to module metadata"
```

---

### Task 2: Intelligence Layer - Auto PMF Detection

**Files:**
- Modify: `internal/controller/assessment.go`

- [ ] **Step 1: Implement DetectPMF function**

```go
func (c *AssessmentController) DetectPMF(bssid string, iface string) string {
    // 1. Check if already in DB
    // 2. If not, run quick 5s tshark capture for beacon
    // 3. Parse RSN IE for PMF bits
    // 4. Return "Required", "Capable", or "None"
}
```

- [ ] **Step 2: Inject PMF Status into Module Environment**

```go
// In runModuleWithCode:
pmfStatus := c.DetectPMF(config[constants.ConfigGuestBSSID], monIface)
env = append(env, fmt.Sprintf("ASTRA_PMF_STATUS=%s", pmfStatus))
```

- [ ] **Step 3: Commit**

```bash
git add internal/controller/assessment.go
git commit -m "feat: implement auto-PMF detection in Go brain"
```

---

### Task 3: Hardening Disruptive Modules (PMF-Awareness)

**Files:**
- Modify: `modules/d1_wpa_handshake.sh`
- Modify: `modules/e3_deauth_resilience.sh`
- Modify: `modules/f1_rogue_ap.sh`

- [ ] **Step 1: Update D1 to handle PMF Required**

```bash
if [[ "$ASTRA_PMF_STATUS" == "Required" ]]; then
    echo "[!] WARNING: PMF is REQUIRED by target AP. Active deauthentication will fail."
    echo "[*] Falling back to Passive Capture mode..."
    # Force choice 0 (Skip Deauth) or warn operator
fi
```

- [ ] **Step 2: Update F1/D7 to prefer CSA catalysts if PMF is enabled**

```bash
if [[ "$ASTRA_PMF_STATUS" != "None" ]]; then
    echo "[!] Target supports PMF. Deauth may be ignored."
    echo "[*] Strategically prioritizing CSA catalyst (Option 3) for roaming..."
fi
```

- [ ] **Step 3: Commit**

```bash
git add modules/d1_wpa_handshake.sh modules/e3_deauth_resilience.sh modules/f1_rogue_ap.sh
git commit -m "fix: make disruptive modules PMF-aware"
```

---

### Task 4: UI Modernization & Operator Warnings

**Files:**
- Modify: `cmd/start.go`
- Modify: `internal/ui/ui.go`

- [ ] **Step 1: Show Tags in Menu**

```go
// In launchMainMenu:
tagStr := ""
if len(m.Tags) > 0 {
    tagStr = fmt.Sprintf(" [%s]", strings.Join(m.Tags, ","))
}
categories[m.Category].AddOption(prefix+m.ID+": "+m.Name+tagStr, ...)
```

- [ ] **Step 2: Add Obsolescence Warnings to Karma/Fingerprinting prompts**

```bash
# In modules/f2_pineap_karma.sh
if [[ "$vector_choice" == "1" ]]; then
    echo "[!] MODERN CLIENT WARNING: Dynamic MANA is obsolete against iOS 15+ / Android 12+."
    echo "    Unless targeting legacy devices, success probability is near zero."
fi
```

- [ ] **Step 3: Commit**

```bash
git add cmd/start.go internal/ui/ui.go modules/f2_pineap_karma.sh
git commit -m "feat: modernize UI with tactical tags and modern client warnings"
```

---

### Task 5: Final Validation

- [ ] **Step 1: Run E2E test with simulated PMF environment**
- [ ] **Step 2: Verify all 42 modules still load and legacy ones are correctly tagged**
- [ ] **Step 3: Commit final build**
