# WIRELESS SECURITY THREAT SPECIFICATION & METHODOLOGY BASELINE (ENRICHED)
**AUTHORITY:** Lead Penetration Tester / Senior Wireless Security Researcher
**PURPOSE:** Canonical Reference Standard for 802.11 Protocol Exploitation and Tool Validation

---

## 1. Channel Hopping and Network Discovery
**Edge Case Scenarios:**
- **Hidden SSIDs:** APs transmitting beacons with 0-length SSID fields. Requires monitoring for specific Probe Responses or EAPOL frames to deanonymize.
- **Dynamic Channel Widths:** APs switching between 20/40/80/160MHz bounds dynamically based on traffic.
- **DFS Radar Eviction:** APs forcefully changing channels mid-scan due to weather/military radar detection.
**Real-World Failure Scenarios:**
- USB Bus Saturation crashing the driver during high beacon volume.
- Realtek drivers silently dropping Management frames under heavy load.
**Advanced Attack Variants:**
- **Dual-Radio Synchronization:** Utilizing two physical NICs mapped via software to synchronously sweep 2.4GHz and 5GHz bands.
**Detection Evasion Techniques:**
- Passive Local Oscillator (LO) shielding using RF enclosures.
**Performance Stress Conditions:**
- Processing 10,000+ beacons per second in stadium environments requires RAM-disk backed state tables.

---

## 2. Probe Request Sniffing / Client Tracking
**Edge Case Scenarios:**
- **Transient Roaming:** Devices rapidly switching APs may only emit probes during millisecond transitional states.
- **iOS Staggered Bursts:** Apple devices randomizing the timing intervals of probe bursts.
**Real-World Failure Scenarios:**
- Physical obstructions (human bodies) absorbing weak mobile transmission power.
**Advanced Attack Variants:**
- **De-anonymizing Randomized MACs:** Utilizing highly specific Information Elements (HT/VHT Capabilities) to create a static fingerprint.
**Detection Evasion Techniques:**
- Strict passive listening. Do not inject directed probes.
**Performance Stress Conditions:**
- Aggressive de-duplication of randomized MACs required to prevent RAM exhaustion in transit hubs.

---

## 3. Deauthentication Attack
**Edge Case Scenarios:**
- **Driver Ignoring Reasons:** Certain IoT drivers ignore standard reason codes (7/8) entirely.
- **Exponential Backoff:** Clients exponentially increasing reconnection time after successive deauths.
**Real-World Failure Scenarios:**
- Attacker TX power is too low to reach the client.
- PMF (802.11w) is silently enforced, dropping cleartext injections.
**Advanced Attack Variants:**
- **Targeted Micro-Injection:** Injecting exactly one deauth frame micro-seconds after EAPOL M2 to test AP state machines.
**Detection Evasion Techniques:**
- Never use broadcast destination MACs (`FF:FF:FF:FF:FF:FF`). Limit to 1-2 targeted frames with randomized source MACs.
**Performance Stress Conditions:**
- Sustaining surgical Deauths against 100+ clients requires multiple physical radios.

---

## 4. WPA2 4-Way Handshake Capture
**Edge Case Scenarios:**
- **Asymmetric Routing / Deafness:** Close to the AP (captures M1/M3) but far from the mobile client (drops M2/M4).
**Real-World Failure Scenarios:**
- Corrupted M2 MIC due to background RF noise causes false-positive capture validation but fails cracking.
**Advanced Attack Variants:**
- **Zero-Packet Injection Capture:** Utilizing strict BPF filters and waiting 72+ hours for natural DHCP lease renewals.
**Detection Evasion Techniques:**
- Avoid active deauthentication. Rely purely on physical proximity and time.
**Performance Stress Conditions:**
- Writing high-volume EAPOL streams to slow SD cards leading to kernel buffer overflows.

---

## 5. PMKID Attack
**Edge Case Scenarios:**
- **Mesh Networks / ESS:** Different AP nodes running different firmware versions; one vulnerable, others patched.
**Real-World Failure Scenarios:**
- AP rate-limits Association Requests, dropping connection before M1.
**Advanced Attack Variants:**
- **Enterprise PMKID Mapping:** Extracting hashes to map internal RADIUS node responses.
**Detection Evasion Techniques:**
- Spoof the MAC address of an already-authorized client to avoid "Unknown MAC" WIPS alerts.
**Performance Stress Conditions:**
- Forcing kernel drivers to switch contexts across 50 APs per second causes driver panics.

---

## 6. MAC Address Spoofing
**Edge Case Scenarios:**
- **Sticky ARP Tables:** Enterprise switches enforcing sticky MAC-to-Port bindings.
- **DHCP Option Fingerprinting:** Servers rejecting leases because the OS fingerprint (Linux) conflicts with the historical spoofed MAC (iOS).
**Real-World Failure Scenarios:**
- Dual-MAC collision: Failing to deauth the victim causes ACK storms and immediate disconnects.
**Advanced Attack Variants:**
- **Full Identity Cloning:** Spoofing MAC, Hostname, and DHCP Option 55 parameter list simultaneously.
**Detection Evasion Techniques:**
- Continuously and precisely suppress the original victim using targeted deauthentication.
**Performance Stress Conditions:**
- Rapid MAC hopping to accurately map NAC response times.

---

## 7. WPS PIN Brute-Force Attack
**Edge Case Scenarios:**
- **Randomized UUIDs:** APs randomizing the WPS UUID on every request to break state tracking.
- **False Lockouts:** APs broadcasting "WPS Locked" in their beacons to deter attackers, but failing to actually enforce the lockout logic in the backend.
**Real-World Failure Scenarios:**
- RF distance causing severe EAP-WSC frame fragmentation, desyncing M4/M5.
**Advanced Attack Variants:**
- **NVRAM Reset via Crash:** Inducing an AP reboot to clear RAM-based WPS lockout timer.
**Detection Evasion Techniques:**
- Using Pixie Dust is near-silent. Pace online brute-forcing 301 seconds apart to evade lockouts.
**Performance Stress Conditions:**
- Maintaining driver stability while handling thousands of EAP-NACKs over 72 hours.

---

## 8. Evil Twin / Rogue Access Point
**Edge Case Scenarios:**
- **BSSID Pinning:** Modern enterprise clients configured via MDM to explicitly pin to known BSSIDs.
**Real-World Failure Scenarios:**
- **Routing Blackhole:** Attacker fails to properly configure iptables IP Masquerading, causing OS CPD checks to fail and drop the connection.
**Advanced Attack Variants:**
- **Channel Switch Announcements (CSA):** Injecting fake CSA frames to trick clients into a seamless, zero-deauth roam.
**Detection Evasion Techniques:**
- Cloning exact AP beacon intervals, vendor IEs, and matching Tx power.
**Performance Stress Conditions:**
- Routing 1Gbps+ of corporate traffic through software NAT on low-end hardware.

---

## 9. Karma Attack / Auto-Connect Exploitation
**Edge Case Scenarios:**
- **Strict PNL Masking:** Modern OSes silencing directed probes unless physically geofenced.
**Real-World Failure Scenarios:**
- Competing Karma APs responding to each other, creating infinite loops of virtual interfaces.
**Advanced Attack Variants:**
- **Known Beacon Attack:** Statically broadcasting the top 1,000 global SSIDs to catch passively scanning clients.
**Detection Evasion Techniques:**
- Limit responses to Directed Probes originating from a single target MAC address.
**Performance Stress Conditions:**
- Handling 10,000+ probe requests per second leading to hostapd RAM exhaustion.

---

## 10. Captive Portal Credential Harvesting
**Edge Case Scenarios:**
- **HSTS Preloading:** Victim attempts to navigate to an HSTS domain directly; browser throws fatal certificate error.
- **Hardcoded Client DNS:** Client manually configures 8.8.8.8, ignoring the rogue DHCP offer.
**Real-World Failure Scenarios:**
- **DNS Spoofer Misconfiguration:** Failing to resolve # (all) to the attacker IP.
- **POST Method Rejection:** Using simple HTTP servers that return 501 on credentials submission.
**Advanced Attack Variants:**
- **Real-Time 2FA Relay:** Proxying the MFA push notification request back to the victim in real-time.
**Detection Evasion Techniques:**
- Utilizing Let's Encrypt certificates mapped to typo-squatted domains.
**Performance Stress Conditions:**
- Phishing web server handling high concurrent HTTP spikes instantly following a mass deauth event.

---

## 11. WPA3 Downgrade Attacks
**Edge Case Scenarios:**
- **Strict OS Profiles:** Client OS hardcoded to "WPA3 Personal Only" by MDM.
- **PMF Enforcement:** Attacker cannot deauthenticate the client to force the initial roam.
**Real-World Failure Scenarios:**
- Target AP operating on a different channel than the Rogue AP, breaking the roaming illusion.
**Advanced Attack Variants:**
- **Enterprise EAP Downgrade:** Forcing downgrade to WPA2-Enterprise, then intercepting inner-auth to downgrade to GTC.
**Detection Evasion Techniques:**
- Utilizing CSA to move the target seamlessly, avoiding mass active deauthentication noise.
**Performance Stress Conditions:**
- Continuous RF jamming of the specific WPA3 frequency while maintaining a clean WPA2 channel.
