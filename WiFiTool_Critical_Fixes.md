# CRITICAL FIXES MANIFEST (100% COVERAGE PASS)
**Target:** WiFi-Astra Assessment Framework

These issues represent the remaining tactical risks identified during the full 42-module audit.

## 1. Hardcoded Rogue AP Channels (F1, F3)
- **Problem:** Modules `f1_rogue_ap.sh` and `f3_captive_portal.sh` hardcode `channel=11` and `channel=6`.
- **Impact:** Decreased roam probability (~70% failure in 5GHz-only targets).
- **Priority:** HIGH.

## 2. Phishing Template Customization (F3)
- **Problem:** The basic white-box HTML template is not suitable for high-security red teaming.
- **Impact:** Low user conversion rate.
- **Priority:** MEDIUM.

## 3. Passive Scan Coverage (A1)
- **Problem:** Fixed 60s scan interval.
- **Impact:** Missed APs in dense DFS environments.
- **Priority:** MEDIUM.

## 4. MAC-Only Spoofing (F4, G4)
- **Problem:** Hostname and DHCP Option 55 are not spoofed alongside the MAC.
- **Impact:** Detection by advanced NAC solutions (Aruba/Cisco).
- **Priority:** LOW.
