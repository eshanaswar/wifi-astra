# Smart Tactical Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform WiFi-Astra into a smart, intelligence-driven framework that automatically guides operators based on real-time target scouting, while maintaining the existing attack-type menu structure and legacy support.

**Architecture:**
- **Intelligence Core:** Implement `hw.ScoutTarget()` in Go to extract PMF, Encryption, and Signal details before active module execution.
- **Context Injection:** Pass target intelligence to Bash modules via environment variables.
- **Smart Logic:** Update Category D, E, and F modules to adapt their interactive recommendations based on the target's profile.
- **Global Synchronization:** Fix hardcoded channel and identity spoofing gaps across all categories.

**Tech Stack:** Go (Controller), Bash (Modules), Tshark/Airodump-ng (Intelligence).

---

### Task 1: The "Scout" Engine (Go Core Intelligence)

**Files:**
- Modify: `pkg/hw/hw.go`
- Modify: `internal/controller/assessment.go`

- [ ] **Step 1: Implement ScoutTarget in pkg/hw**

```go
func ScoutTarget(bssid string, monIface string) (map[string]string, error) {
    // 1. Run 5s capture for Beacon/Probe Response
    // 2. Parse via tshark for:
    //    - RSN (PMF bits)
    //    - Auth (WPA3 vs WPA2)
    //    - Signal Level (RSSI)
    // 3. Return map of attributes
}
```

- [ ] **Step 2: Integrate Scouting into ExecuteModule**

```go
// In internal/controller/assessment.go
if bssid != "" && monIface != "" {
    intel, _ := hw.ScoutTarget(bssid, monIface)
    for k, v := range intel {
        os.Setenv("ASTRA_TARGET_"+k, v)
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add pkg/hw/ internal/controller/
git commit -m "feat: implement target scouting intelligence in Go brain"
```

---

### Task 2: Tactical Resilience (Smart Categories D & E)

**Files:**
- Modify: `modules/d1_wpa_handshake.sh`
- Modify: `modules/e3_deauth_resilience.sh`

- [ ] **Step 1: Update D1 to warn about PMF Required**

```bash
if [[ "${ASTRA_TARGET_PMF:-}" == "Required" ]]; then
    echo "[!] INTELLIGENCE ALERT: Target enforces PMF (802.11w)."
    echo "[*] Active deauthentication will fail. Recommending Passive Capture (Option 0)."
fi
```

- [ ] **Step 2: Update E3 to handle pre-attack signal warnings**

```bash
if [[ "${ASTRA_TARGET_RSSI:-0}" -lt -75 ]]; then
    echo "[!] WARNING: Low Signal Strength (${ASTRA_TARGET_RSSI}dBm)."
    echo "    Injection attacks are unreliable at this distance."
fi
```

- [ ] **Step 3: Commit**

```bash
git add modules/d1_wpa_handshake.sh modules/e3_deauth_resilience.sh
git commit -m "fix: make Category D/E modules intelligence-aware"
```

---

### Task 3: Smart Roaming & MITM (Category F)

**Files:**
- Modify: `modules/f1_rogue_ap.sh`
- Modify: `modules/f2_pineap_karma.sh`
- Modify: `modules/f3_captive_portal.sh`

- [ ] **Step 1: Update F1/F3 to use dynamic $GUEST_CHANNEL**

```bash
channel=${GUEST_CHANNEL:-6}
```

- [ ] **Step 2: Update F1 to recommend CSA for PMF targets**

```bash
if [[ "${ASTRA_TARGET_PMF:-}" != "None" ]]; then
    echo "[!] INTELLIGENCE ALERT: Target supports PMF."
    echo "[*] Recommended Roaming Catalyst: CSA (Option 3)."
fi
```

- [ ] **Step 3: Add Modernity Disclaimers to F2 Karma**

```bash
if [[ "$vector_choice" == "1" ]]; then
    echo "[!] MODERNITY ALERT: Dynamic MANA is obsolete against iOS 15+/Android 12+."
    echo "    Recommended for legacy IoT/technical debt targets only."
fi
```

- [ ] **Step 4: Commit**

```bash
git add modules/f1_rogue_ap.sh modules/f2_pineap_karma.sh modules/f3_captive_portal.sh
git commit -m "fix: harden Category F with dynamic channels and smart roaming"
```

---

### Task 4: Identity & Isolation (Categories B & G)

**Files:**
- Modify: `modules/g4_nac_bypass.sh`
- Modify: `modules/b10_airsnitch.sh`

- [ ] **Step 1: Apply Full Identity Spoofing to G4 (to match F4)**
  - MAC + Hostname + DHCP Option 55.

- [ ] **Step 2: Ensure B10 covers multi-frequency AirSnitch scenarios**

- [ ] **Step 3: Commit**

```bash
git add modules/g4_nac_bypass.sh modules/b10_airsnitch.sh
git commit -m "feat: apply full identity evasion to Category G and finalize AirSnitch"
```

---

### Task 5: Final Verification

- [ ] **Step 1: Run all 42 modules to ensure menu stability**
- [ ] **Step 2: Verify Stdin interactivity works perfectly after Go executor fix**
- [ ] **Step 3: Commit final synchronized build**
