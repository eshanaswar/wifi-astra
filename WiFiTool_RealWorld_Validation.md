# REAL-WORLD VALIDATION REPORT (MODERN LENS)
**Target:** WiFi-Astra Assessment Framework
**Auditor:** Senior Wireless Security Researcher

This report evaluates the practical effectiveness of the WiFi-Astra framework against **current (2025/2026)** real-world environments. Attacks that rely on deprecated behaviors are penalized.

---

## [A1] Network Discovery
1. **REAL-WORLD EXECUTABILITY:** YES
2. **MODERN ENVIRONMENT CHECK:** Fully relevant. Works against WPA3 and OWE networks.
3. **CLIENT BEHAVIOR REALITY:** Passive discovery is unaffected by client OS protections.
4. **TIMING & RF CONDITIONS:** The Deep Scan (120s) option effectively handles modern 5GHz DFS constraints.
5. **HARDWARE REALITY:** Well-supported by common adapters.
6. **DETECTION & DEFENSES:** Undetectable (Passive).
7. **OUTDATED TECHNIQUES CHECK:** Still relevant. Fundamental step 0.
8. **FAILURE MODES:** None.
9. **FIELD USABILITY SCORE:** 10/10

---

## [A4] Client Fingerprinting (Probe Sniffing)
1. **REAL-WORLD EXECUTABILITY:** PARTIAL
2. **MODERN ENVIRONMENT CHECK:** iOS 15+ and Android 12+ have eradicated unprompted Directed Probe Requests. Devices use Passive Scanning exclusively unless geofenced.
3. **CLIENT BEHAVIOR REALITY:** Random MACs while disconnected mean tracking is impossible until association. The tool correctly targets *associated* stations, but associated stations rarely leak PNLs.
4. **TIMING & RF CONDITIONS:** 60s is unlikely to catch a modern burst.
5. **HARDWARE REALITY:** No issues.
6. **DETECTION & DEFENSES:** Undetectable.
7. **OUTDATED TECHNIQUES CHECK:** **Partially obsolete.** Relying on PNL leaks from modern mobile devices is a low-probability event.
8. **FAILURE MODES:** Silent failure (Empty results).
9. **FIELD USABILITY SCORE:** 3/10

---

## [D1/E3] Handshake / Deauth Testing
1. **REAL-WORLD EXECUTABILITY:** PARTIAL
2. **MODERN ENVIRONMENT CHECK:** WPA3 enforces 802.11w (PMF) mandatorily. Modern WPA2 enterprise deployments often require PMF. Active deauth (E3) will fail silently against these networks.
3. **CLIENT BEHAVIOR REALITY:** iOS will instantly blacklist an AP sending excessive deauths and refuse to roam to Evil Twins.
4. **TIMING & RF CONDITIONS:** Highly sensitive to SNR.
5. **HARDWARE REALITY:** Injection requires specific Alfa/TP-Link chipsets.
6. **DETECTION & DEFENSES:** Highly detectable by modern WIPS (Cisco, Meraki, Aruba).
7. **OUTDATED TECHNIQUES CHECK:** **Partially obsolete.** PMKID via `hcxdumptool` is heavily patched in modern AP firmware (Cisco disabled it years ago) and nonexistent in WPA3.
8. **FAILURE MODES:** Client refuses connection; WIPS triggers physical port shutdown on AP.
9. **FIELD USABILITY SCORE:** 5/10

---

## [D3] WPS PIN Brute-Force
1. **REAL-WORLD EXECUTABILITY:** NO (for Enterprise), YES (for legacy IoT)
2. **MODERN ENVIRONMENT CHECK:** WPS is physically removed from enterprise APs and disabled by default on modern consumer routers.
3. **CLIENT BEHAVIOR REALITY:** N/A.
4. **TIMING & RF CONDITIONS:** Online brute-force takes hours to days.
5. **HARDWARE REALITY:** High driver fatigue during prolonged injection.
6. **DETECTION & DEFENSES:** Instantly detected by any IDS. APs implement strict rate-limiting (lockouts).
7. **OUTDATED TECHNIQUES CHECK:** **Fully obsolete** for modern professional assessments. Only relevant for auditing legacy technical debt.
8. **FAILURE MODES:** AP locks out after 3 attempts.
9. **FIELD USABILITY SCORE:** 1/10

---

## [F1/F2] Evil Twin / Karma
1. **REAL-WORLD EXECUTABILITY:** PARTIAL
2. **MODERN ENVIRONMENT CHECK:** F1 (Evil Twin) requires defeating PMF to force a roam. F2 (Karma) dynamic response is dead on modern OSes. The "Known Beacon Attack" (Loud MANA) is the only viable path.
3. **CLIENT BEHAVIOR REALITY:** iOS/Android ignore Karma responses. WPA3 transition mode (D7) is required to successfully attack modern clients.
4. **TIMING & RF CONDITIONS:** Attacker must have vastly superior SNR.
5. **HARDWARE REALITY:** `hostapd` is stable.
6. **DETECTION & DEFENSES:** High probability of detection (BSSID spoofing alarms).
7. **OUTDATED TECHNIQUES CHECK:** Basic Karma is **Obsolete**. Known Beacon / BSSID Cloning is **Current**.
8. **FAILURE MODES:** Clients see the AP but refuse to connect due to cached profile mismatches.
9. **FIELD USABILITY SCORE:** 7/10

---

## [F3] Captive Portal
1. **REAL-WORLD EXECUTABILITY:** YES
2. **MODERN ENVIRONMENT CHECK:** Highly relevant. The addition of Microsoft 365 templates and POST support makes this highly effective.
3. **CLIENT BEHAVIOR REALITY:** Modern OS Captive Portal Detection (CPD) triggers reliably. However, HSTS (HTTP Strict Transport Security) on modern browsers prevents spoofing `google.com` directly; the tool correctly relies on the OS pseudo-browser.
4. **TIMING & RF CONDITIONS:** Fast execution.
5. **HARDWARE REALITY:** Low overhead.
6. **DETECTION & DEFENSES:** Users may spot lack of valid TLS certificates in the pseudo-browser if they are observant.
7. **OUTDATED TECHNIQUES CHECK:** **Current.**
8. **FAILURE MODES:** User abandons the portal without typing credentials.
9. **FIELD USABILITY SCORE:** 9/10

---

## [F4] MAC / Identity Spoofing
1. **REAL-WORLD EXECUTABILITY:** YES
2. **MODERN ENVIRONMENT CHECK:** Highly relevant. Modern NACs profile devices using MAC + Hostname + DHCP Option 55. The tool correctly spoofs all three.
3. **CLIENT BEHAVIOR REALITY:** The real client must be aggressively suppressed via deauth to prevent switch-level port security from seeing MAC flapping.
4. **TIMING & RF CONDITIONS:** Fast. The 15s DHCP timeout prevents fatal hangs.
5. **HARDWARE REALITY:** Standard Linux capabilities.
6. **DETECTION & DEFENSES:** Medium. 802.1X (EAP-TLS) defeats this entirely (MAC is ignored in favor of certificates).
7. **OUTDATED TECHNIQUES CHECK:** **Current** (due to the full identity spoofing update).
8. **FAILURE MODES:** DHCP denies lease; 802.1X blocks port.
9. **FIELD USABILITY SCORE:** 8/10

---

## [D7] WPA3 Downgrade
1. **REAL-WORLD EXECUTABILITY:** YES
2. **MODERN ENVIRONMENT CHECK:** Essential for modern networks. Tests WPA3 Transition mode vulnerabilities.
3. **CLIENT BEHAVIOR REALITY:** The inclusion of mdk4 CSA (Channel Switch Announcements) bypasses PMF protections that would otherwise prevent the forced roam.
4. **TIMING & RF CONDITIONS:** Evil Twin must be perfectly synchronized on the target's channel (fixed in recent patch).
5. **HARDWARE REALITY:** Requires adapters supporting WPA2 AP mode.
6. **DETECTION & DEFENSES:** WIPS alarms on BSSID/SSID profile mismatches.
7. **OUTDATED TECHNIQUES CHECK:** **Cutting Edge.**
8. **FAILURE MODES:** OS remembers SAE was used and refuses to downgrade.
9. **FIELD USABILITY SCORE:** 9/10

---

## [B10] AirSnitch (Client Isolation Bypass)
1. **REAL-WORLD EXECUTABILITY:** YES
2. **MODERN ENVIRONMENT CHECK:** Addresses NDSS 2026 research. Bypasses standard L2/L3 isolation on modern controllers (Cisco, Meraki).
3. **CLIENT BEHAVIOR REALITY:** Does not rely on client interaction.
4. **TIMING & RF CONDITIONS:** Instantaneous packet injection.
5. **HARDWARE REALITY:** Scapy requires root and raw socket access.
6. **DETECTION & DEFENSES:** Undetectable by standard WIPS (looks like normal internal routing traffic).
7. **OUTDATED TECHNIQUES CHECK:** **State-of-the-Art.**
8. **FAILURE MODES:** Switch enforces strict IP-to-MAC binding, dropping the bounced packet.
9. **FIELD USABILITY SCORE:** 10/10

---

## GLOBAL REALITY GAPS
- **Over-reliance on Deprecated Vectors:** The inclusion of WPS testing (D3) and WEP cracking (D2) adds bloat. While mathematically correct, they are obsolete for modern enterprise audits.
- **Enterprise 802.1X:** The tool has `d5_eap_attack.sh`, but attacking modern EAP-TLS (certificate-based) environments is fundamentally impossible without compromising a physical device first. EAP-PEAP/MSCHAPv2 downgrades are the only viable path, and even those are declining as MDMs enforce strict certificate validation.
