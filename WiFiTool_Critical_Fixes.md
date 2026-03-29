# CRITICAL FIXES MANIFEST (MODERNIZATION)
**Target:** WiFi-Astra Assessment Framework

The tool is structurally sound following the recent Go-core and Bash wrapper rewrites. However, a strict modern lens reveals a few remaining architectural priorities to align the framework with 2026 realities.

## 1. WPA3 / PMF Assumption Awareness (Category: OPERATIONAL)
- **Problem:** Modules like `d1_wpa_handshake.sh` default to Active Deauthentication. Against modern WPA3 or PMF-enabled WPA2 networks, these frames are silently dropped by the AP/Client.
- **Modern Reality:** Pentesters waste time waiting for deauths that will never work, triggering WIPS alarms for zero gain.
- **Impact:** Failed captures and blown operational security.
- **Exact Fix:** Integrate `h2_pmf_check.sh` output directly into `D1` and `E3`. If the AP broadcasts "PMF: Required", the script MUST automatically disable active deauthentication and default to either Passive Capture or CSA-based roaming.
- **Priority:** HIGH.

## 2. Karma Attack Deprecation Warning (Category: SOCIAL ENGINEERING)
- **Problem:** `f2_pineap_karma.sh` includes "Dynamic MANA" as the primary vector.
- **Modern Reality:** iOS, Android, and Windows 11 have entirely mitigated dynamic Karma by randomizing MACs and suppressing directed probes.
- **Impact:** False hope for the operator. The module will run for hours and capture nothing.
- **Exact Fix:** Add a massive CLI warning when the operator selects "Dynamic MANA", explicitly stating: *"WARNING: This vector is obsolete against iOS 15+ and Android 12+. Use Known Beacon Attack (Option 2) for modern targets."*
- **Priority:** MEDIUM.

## 3. Deprecation of Legacy Modules (Category: FRAMEWORK BLOAT)
- **Problem:** `d2_wep_cracking.sh` and `d3_wps_testing.sh` exist alongside modern WPA3 attacks.
- **Modern Reality:** WEP and WPS are virtually extinct in professional target environments.
- **Impact:** Clutters the tactical menu and encourages reliance on "low-hanging fruit" that doesn't exist.
- **Exact Fix:** Move these modules into a `legacy/` directory or mark them with a `[LEGACY]` tag in the UI to guide operators toward modern attacks (EAP, WPA3 Downgrade, AirSnitch).
- **Priority:** LOW.
