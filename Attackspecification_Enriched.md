# WIRELESS SECURITY THREAT SPECIFICATION (ENRICHED & MODERNIZED)
**AUTHORITY:** Lead Penetration Tester / Senior Wireless Security Researcher
**PURPOSE:** Canonical Reference Standard for Modern (2026) 802.11 Protocol Exploitation

---

## 1. Channel Hopping and Network Discovery
**1. Edge Case Scenarios:** Dynamic 160MHz channel widths on WiFi 6/6E.
**2. Real-World Failure Scenarios:** Drivers failing to interpret 6GHz (WiFi 6E) beacon frames.
**3. Advanced Modern Variants:** Software-Defined Radio (SDR) sweeping for ultra-fast, multi-band correlation.
**4. Detection Evasion Techniques:** Complete RF shielding of the attacking chassis.
**5. Performance Stress Conditions:** Dense stadium environments.
**6. MODERN RELEVANCE TAG:** **Current** (Mandatory baseline).

---

## 2. Probe Request Sniffing / Client Tracking
**1. Edge Case Scenarios:** Geofenced probing (devices only probe when GPS indicates they are near the target network).
**2. Real-World Failure Scenarios:** iOS 15+ completely silences PNLs.
**3. Advanced Modern Variants:** Correlation of randomized MACs via subtle timing side-channels and Information Element fingerpints.
**4. Detection Evasion Techniques:** 100% passive listening.
**5. Performance Stress Conditions:** High-density transit hubs.
**6. MODERN RELEVANCE TAG:** **Limited** (Heavily mitigated by modern mobile OSes).

---

## 3. Deauthentication Attack
**1. Edge Case Scenarios:** IoT devices ignoring Reason Codes to artificially maintain uptime.
**2. Real-World Failure Scenarios:** 802.11w (PMF) silently drops spoofed cleartext frames.
**3. Advanced Modern Variants:** Channel Switch Announcements (CSA) via `mdk4` to force roams without triggering PMF/Deauth alarms.
**4. Detection Evasion Techniques:** Randomized Source MACs and single-frame micro-injections.
**5. Performance Stress Conditions:** Multi-radio suppression.
**6. MODERN RELEVANCE TAG:** **Limited** (Fails against WPA3 and modern Enterprise WPA2).

---

## 4. WPA2 4-Way Handshake Capture
**1. Edge Case Scenarios:** Asymmetric routing dropping the crucial M2 frame from the mobile client.
**2. Real-World Failure Scenarios:** Inability to force a deauth (due to PMF) means waiting days for a natural DHCP renewal.
**3. Advanced Modern Variants:** EAPOL-M2 only cracking via Hashcat (requires only the client's response).
**4. Detection Evasion Techniques:** Zero-packet passive capture over 72+ hours.
**5. Performance Stress Conditions:** Buffer overruns on slow disk I/O.
**6. MODERN RELEVANCE TAG:** **Current** (Still the primary vector for PSK networks).

---

## 5. PMKID Attack
**1. Edge Case Scenarios:** Enterprise networks with roaming enabled.
**2. Real-World Failure Scenarios:** Modern AP firmware (Cisco/Meraki) explicitly patched to remove PMKID from PSK associations.
**3. Advanced Modern Variants:** Enterprise PMKID extraction for RADIUS mapping.
**4. Detection Evasion Techniques:** Spoofing an authorized MAC to bypass basic WIPS alerts.
**5. Performance Stress Conditions:** Driver panics during mass extraction.
**6. MODERN RELEVANCE TAG:** **Limited** (Patched in modern WPA2; deprecated in WPA3).

---

## 6. Full Identity / MAC Spoofing
**1. Edge Case Scenarios:** Sticky ARP tables on enterprise switches locking the port.
**2. Real-World Failure Scenarios:** 802.1X (EAP-TLS) enforcing certificate-based identity, rendering MAC cloning useless.
**3. Advanced Modern Variants:** Spoofing MAC + Hostname + DHCP Option 55 simultaneously to bypass advanced AI-driven NACs (e.g., Aruba ClearPass).
**4. Detection Evasion Techniques:** Continuous suppression of the original victim to prevent ACK storms.
**5. Performance Stress Conditions:** Rapid bouncing between profiles.
**6. MODERN RELEVANCE TAG:** **Current** (Essential for Open/Guest networks).

---

## 7. Evil Twin / Rogue Access Point
**1. Edge Case Scenarios:** Mobile Device Management (MDM) profiles pinning clients to specific BSSIDs.
**2. Real-World Failure Scenarios:** OS Captive Portal Detection failing due to broken attacker NAT, causing the client to instantly disconnect.
**3. Advanced Modern Variants:** Deploying WPA2 Evil Twins against WPA3 networks (Downgrade attacks).
**4. Detection Evasion Techniques:** Exact matching of Vendor IEs, Beacon Intervals, and Tx Power.
**5. Performance Stress Conditions:** Software NAT routing limits.
**6. MODERN RELEVANCE TAG:** **Current** (The foundation of modern MITM).

---

## 8. Karma Attack / Auto-Connect Exploitation
**1. Edge Case Scenarios:** Actual target networks physically present, creating an RSSI bidding war.
**2. Real-World Failure Scenarios:** Modern OSes dropping dynamic MANA responses.
**3. Advanced Modern Variants:** "Known Beacon Attack" — statically broadcasting the top 1,000 global SSIDs to catch devices that scan passively.
**4. Detection Evasion Techniques:** Limiting responses to a single target MAC.
**5. Performance Stress Conditions:** `hostapd` RAM exhaustion.
**6. MODERN RELEVANCE TAG:** **Limited** (Dynamic Karma is dead; Known Beacon is the only survivor).

---

## 9. Captive Portal Credential Harvesting
**1. Edge Case Scenarios:** HSTS Preloading causing fatal certificate errors before redirection occurs.
**2. Real-World Failure Scenarios:** Attack server failing to process HTTP POST requests (resulting in 501 errors).
**3. Advanced Modern Variants:** Real-Time 2FA Relay proxying MFA pushes back to the victim.
**4. Detection Evasion Techniques:** High-fidelity Microsoft 365 / Okta templates with typo-squatted TLS domains.
**5. Performance Stress Conditions:** High concurrent connection spikes.
**6. MODERN RELEVANCE TAG:** **Current** (Highly effective against human targets).

---

## 10. WPA3 Transition Downgrade
**1. Edge Case Scenarios:** OS caching previous SAE (WPA3) states and refusing to downgrade.
**2. Real-World Failure Scenarios:** PMF preventing the required deauthentication to force the initial roam.
**3. Advanced Modern Variants:** Utilizing CSA (Channel Switch Announcements) to trick the client into roaming to the WPA2 Evil Twin without triggering PMF alarms.
**4. Detection Evasion Techniques:** Precise channel synchronization.
**5. Performance Stress Conditions:** Maintaining clean RF separation.
**6. MODERN RELEVANCE TAG:** **Current** (The primary attack against modern encryption).

---

## 11. AirSnitch (Client Isolation Bypass)
**1. Edge Case Scenarios:** Enterprise APs enforcing strict L3 firewall rules directly at the bridge level.
**2. Real-World Failure Scenarios:** Switches dropping packets with mismatched IP-to-MAC bindings.
**3. Advanced Modern Variants:** Gateway Bouncing (L3), GTK Abuse (Crypto layer), Port Stealing.
**4. Detection Evasion Techniques:** Blends in with standard ICMP/ARP background noise.
**5. Performance Stress Conditions:** Injecting encapsulated packets rapidly without dropping sequence numbers.
**6. MODERN RELEVANCE TAG:** **Current** (Cutting-edge 2026 research).
