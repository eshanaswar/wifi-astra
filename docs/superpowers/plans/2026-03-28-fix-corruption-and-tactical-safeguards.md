# Fix Corruption and Tactical Safeguards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve file corruption, implement dynamic network intelligence, and add tactical safeguards across WiFi-Astra modules.

**Architecture:** 
- **De-corruption:** Strip Git merge markers and standardize headers for Categories B and C.
- **Dynamic Intel:** Update Category C modules to use `${GATEWAY_IP}` and `${SUBNET}`.
- **SNR Safeguards:** Add a global RSSI check for all active modules (D, E, F, G).
- **Active De-cloaking (A3):** Add interactive deauth to reveal hidden SSIDs.
- **Active BSS Transition (G5):** Rewrite module to use Scapy for active transition management requests.

**Tech Stack:** Bash, Python, Scapy, aireplay-ng, nmap.

---

### Task 1: File De-Corruption (Categories B & C)

**Files:**
- Modify: `modules/b3_cdp_lldp_leaks.sh`
- Modify: `modules/b4_mdns_leaks.sh`
- Modify: `modules/b5_snmp_exposure.sh`
- Modify: `modules/b6_dhcp_analysis.sh`
- Modify: `modules/b7_ipv6_leaks.sh`
- Modify: `modules/b8_broadcast_leaks.sh`
- Modify: `modules/b9_ap_vulnerability.sh`
- Modify: `modules/c1_dns_resolution.sh`
- Modify: `modules/c2_private_network_scan.sh`
- Modify: `modules/c3_vlan_hopping.sh`

- [ ] **Step 1: Strip merge markers and fix headers**
  - Remove `<<<<<<<`, `=======`, `>>>>>>>`
  - Ensure `set -euo pipefail` is placed after the `MODULE_META` block but before the main logic.
  - Follow the format from `a1_identify_networks.sh`.

- [ ] **Step 2: Verify all 10 files are clean and loadable**
  - Run: `for f in modules/{b3,b4,b5,b6,b7,b8,b9,c1,c2,c3}*.sh; do bash -n "$f" || echo "FAIL: $f"; done`

- [ ] **Step 3: Commit**
  - Commit message: "fix: strip git merge markers and standardize module headers"

---

### Task 2: Dynamic Network Intelligence (Category C)

**Files:**
- Modify: `modules/c1_dns_resolution.sh`
- Modify: `modules/c2_private_network_scan.sh`
- Modify: `modules/c4_radius_reachability.sh`

- [ ] **Step 1: Implement Dynamic Targeting in C1 (DNS)**
  - Use `${GATEWAY_IP}` if `DNS_SERVER` is not set.
  - Scan for more internal hostnames if needed but prefer dynamic detection.

- [ ] **Step 2: Implement Dynamic Targeting in C2 (Private Network Scan)**
  - Replace hardcoded `RANGES` with `${GATEWAY_IP}` and a scan of `${SUBNET}`.
  - Logic: `nmap -sn ${SUBNET}` or similar.

- [ ] **Step 3: Implement Dynamic Targeting in C4 (RADIUS Reachability)**
  - Replace hardcoded `RADIUS_CANDIDATES` with dynamic logic.
  - Logic: Probe `${GATEWAY_IP}` and `.10`, `.1` in `${SUBNET}`.

- [ ] **Step 4: Commit**
  - Commit message: "feat: implement dynamic network intelligence in Category C modules"

---

### Task 3: SNR Safeguards (Categories D, E, F, G)

**Files:**
- Modify: 21 modules in Categories D, E, F, G.

- [ ] **Step 1: Add Signal Strength Check to the start of all 21 modules**
  - Logic:
    ```bash
    # SNR Safeguard
    if [[ -n "${ASTRA_TARGET_RSSI:-}" ]] && [[ "$ASTRA_TARGET_RSSI" -lt -75 ]]; then
        echo "[!] WARNING: Low Signal Strength detected ($ASTRA_TARGET_RSSI dBm). Injection is likely to fail."
    fi
    ```

- [ ] **Step 2: Commit**
  - Commit message: "feat: add global SNR safeguards to active modules"

---

### Task 4: Active De-cloaking (A3)

**Files:**
- Modify: `modules/a3_hidden_ssid.sh`

- [ ] **Step 1: Add interactive deauth prompt**
  - Detect clients on hidden BSSIDs (from airodump output).
  - Prompt: "Clients detected on hidden BSSID. Force reveal via surgical deauth? [y/N]"
  - If 'y', use `aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> <INTERFACE>`.

- [ ] **Step 2: Commit**
  - Commit message: "feat: add active de-cloaking to A3 (Hidden SSID Discovery)"

---

### Task 5: Active BSS Transition (G5)

**Files:**
- Modify: `modules/g5_bss_transition_attack.sh`

- [ ] **Step 1: Rewrite G5 to include Scapy-based active injector**
  - Use Python/Scapy script for BSS Transition Management Request.
  - Prompt for Target Client and Rogue AP BSSID.

- [ ] **Step 2: Commit**
  - Commit message: "feat: rewrite G5 to use Scapy for active BSS Transition attacks"

---

### Task 6: Final Verification

- [ ] **Step 1: Ensure all 42 modules are clean, loadable, and theoretically sound**
  - Run: `for f in modules/*.sh; do bash -n "$f" || echo "FAIL: $f"; done`

- [ ] **Step 2: Commit final changes**
  - Commit message: "fix: resolve file corruption, implement dynamic network intel, and add tactical safeguards"
