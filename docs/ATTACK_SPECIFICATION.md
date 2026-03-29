# WIRELESS SECURITY THREAT SPECIFICATION & METHODOLOGY BASELINE
**AUTHORITY:** Lead Penetration Tester / Senior Wireless Security Researcher
**PURPOSE:** Canonical Reference Standard for 802.11 Protocol Exploitation and Tool Validation

This document establishes the absolute ground-truth methodology for executing 802.11 attacks. It is written at the protocol level. Any professional penetration testing tool must map its automated workflows directly to these technical foundations. "Black box" execution without acknowledging these primitives is unacceptable in professional environments.

---

## 1. Channel Hopping and Network Discovery

**1. ATTACK NAME**
Channel Hopping and Network Discovery

**2. CATEGORY**
Passive Reconnaissance

**3. OBJECTIVE**
To systematically map the RF environment, enumerating all Basic Service Set Identifiers (BSSIDs), Service Set Identifiers (SSIDs), supported cryptographic suites, operating channels, and associated clients without transmitting any frames.

**4. PREREQUISITES**
- 802.11 Network Interface Controller (NIC) supporting Monitor Mode.
- Host OS capable of directly manipulating NIC radio frequencies (e.g., `mac80211` driver stack).

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
802.11 APs periodically broadcast Management frames (Subtype 8: Beacons), typically every 102.4ms (the Target Beacon Transmission Time or TBTT). Beacons contain Information Elements (IEs) detailing the BSSID (AP MAC), SSID, and RSN (Robust Security Network) capabilities. Because 802.11 operates across multiple distinct frequency bands (2.4GHz, 5GHz, 6GHz) divided into narrow channels, a passive observer tuned to Channel 1 cannot hear frames on Channel 6. Therefore, the radio must iteratively tune to a channel, dwell for a calculated period (e.g., 200ms to ensure capturing at least two Beacons), record all frames, and hop to the next channel.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Define the target frequency bands (e.g., 2.4GHz and 5GHz).
2. **Target Selection:** N/A (Global enumeration).
3. **Execution Steps:**
   - Set NIC to Monitor Mode.
   - Initiate a loop tuning the NIC to Channel $C_i$.
   - Dwell for $T$ milliseconds.
   - Increment $i$ and repeat.
4. **Data Capture:** Parse incoming 802.11 headers. Extract Source MAC (BSSID), Destination MAC (Client or Broadcast), and Tagged Parameters (SSID, Crypto).
5. **Verification of Success:** A populated state table correlating BSSIDs to channels, encryption types, and associated client MACs.

**7. VARIANTS & MODERN TECHNIQUES**
- **Active Scanning:** Transmitting Broadcast Probe Requests (Subtype 4) on each channel to force APs to respond immediately with Probe Responses (Subtype 5), bypassing the TBTT wait. Used to force hidden networks to respond.
- **Optimized Dwell Times:** Dynamically shortening dwell times on empty channels based on SNR noise floors.

**8. SUCCESS CONDITIONS & VALIDATION**
Generation of a comprehensive, accurate state table of the local RF environment.

**9. LIMITATIONS & FAILURE CASES**
- Passive hopping misses APs if the dwell time misaligns with the TBTT.
- 5GHz/6GHz DFS (Dynamic Frequency Selection) channels are numerous, significantly increasing the time required to complete a full sweep.

**10. DETECTION & DEFENSES**
Passive hopping is fundamentally undetectable at the RF layer. Active scanning variants can be detected by WIDS (Wireless Intrusion Detection Systems) flagging high volumes of Broadcast Probe Requests.

**11. REAL-WORLD USAGE CONTEXT**
The mandatory Step 0 of every wireless engagement. Determines the exact operational boundaries of the target space.

**12. EDGE CASE SCENARIOS**
- **Hidden SSIDs:** APs transmitting beacons with 0-length SSID fields. Requires monitoring for specific Probe Responses or EAPOL frames to deanonymize.
- **Multiple APs with same SSID:** Enterprise roaming environments (ESS). Must track by BSSID (MAC) rather than SSID.
- **Channel Switching:** DFS radar detection forces sudden AP channel migrations during a scan.

**13. ADVANCED TEST SCENARIOS**
- **High-Density Environments:** Large campuses where airodump/kismet memory maps can exceed limits due to thousands of transient MACs.
- **Mixed Encryption:** Tracking BSSIDs that broadcast WPA2 and WPA3 transitions simultaneously.

**14. FAILURE INJECTION CASES**
- Adapter locked to 2.4GHz hardware bounds while targeting a 5GHz-only network.
- Kernel driver (e.g., Realtek) dropping Management frames under heavy load.

**15. DETECTION EVASION CONSIDERATIONS**
- Strictly enforce passive scanning (no injected Probe Requests).
- Ensure MAC address is spoofed even during passive scans if the OS attempts background associations.

**16. PERFORMANCE STRESS SCENARIOS**
- Processing 10,000+ beacons per second in a stadium environment. Parsing engines must be highly optimized.

---

## 2. Probe Request Sniffing / Client Tracking

**1. ATTACK NAME**
Probe Request Sniffing / Client Tracking

**2. CATEGORY**
Passive Reconnaissance / Privacy Exploitation

**3. OBJECTIVE**
To harvest Preferred Network Lists (PNLs) from unconnected client devices and physically or logically track client movement.

**4. PREREQUISITES**
- NIC in Monitor Mode.
- Unassociated or actively roaming client devices in physical proximity.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
When an 802.11 client is disconnected or roaming, it utilizes Active Scanning to find known networks. It transmits Management frames (Subtype 4: Probe Requests). Historically, these requests explicitly contained the SSID the client was looking for (e.g., "Are you 'Corp_Guest'?"). By harvesting these frames, an attacker extracts the exact SSIDs the client trusts. Furthermore, because these frames contain the client's MAC address, the client acts as an RF beacon, allowing an attacker to track their physical presence over time via Received Signal Strength Indicator (RSSI) trilateration.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Lock the NIC to common channels (1, 6, 11) where clients typically probe.
2. **Target Selection:** Filter traffic for 802.11 Subtype 4 frames.
3. **Execution Steps:** Listen passively. 
4. **Data Capture / Interaction:** Extract the Source MAC address and the SSID Information Element from the payload.
5. **Verification of Success:** Aggregation of a database mapping Client MACs to their respective PNLs.

**7. VARIANTS & MODERN TECHNIQUES**
- **Null Probing:** Modern clients send "Null" (Zero-length SSID) Probe Requests. The attacker tracks the MAC, but cannot extract the PNL.
- **Sequence Number Tracking:** If MAC randomization is used, attackers analyze the 802.11 Sequence Number field or specific frame timing anomalies to correlate randomized MACs back to a single physical device.

**8. SUCCESS CONDITIONS & VALIDATION**
Extraction of cleartext SSIDs associated with a specific client, or successful correlation of client presence over time.

**9. LIMITATIONS & FAILURE CASES**
- MAC Randomization (iOS 14+, Android 10+, Windows 10) changes the client's MAC address periodically while disconnected, severely degrading long-term tracking.
- Modern OSes default to passive scanning (listening for beacons) rather than active probing for hidden/saved networks.

**10. DETECTION & DEFENSES**
Undetectable. Defended against strictly by client-side OS mitigations (MAC randomization, passive scanning).

**11. REAL-WORLD USAGE CONTEXT**
Critical for planning targeted Evil Twin and Karma attacks by knowing exactly which fake AP names to broadcast to entrap a specific VIP device.

**12. EDGE CASE SCENARIOS**
- **Roaming Clients:** Devices rapidly switching APs may only emit probes during brief transitional states.
- **Low Signal Environments:** Probe requests originate from low-power mobile devices and often drop before reaching the attacker antenna.

**13. ADVANCED TEST SCENARIOS**
- **Targeted Tracking:** Filtering capture logic to solely alert on a specific VIP's MAC address or a unique corporate SSID.
- **Correlating Randomized MACs:** Using Information Elements (like supported rates, HT capabilities) to fingerprint unique devices despite rotating MACs.

**14. FAILURE INJECTION CASES**
- No unassociated clients are present in the physical area.
- Channel hopping speed is too slow, missing the transient probe requests on specific channels.

**15. DETECTION EVASION CONSIDERATIONS**
- 100% passive. No evasion necessary.

**16. PERFORMANCE STRESS SCENARIOS**
- High-density public transit hubs generating hundreds of probes per second. The state table must de-duplicate efficiently to prevent RAM exhaustion.

---

## 3. Deauthentication Attack

**1. ATTACK NAME**
Deauthentication Attack

**2. CATEGORY**
Active / Denial of Service (DoS)

**3. OBJECTIVE**
To forcibly disconnect a legitimate client from an Access Point.

**4. PREREQUISITES**
- NIC supporting packet injection.
- Target AP and Client operating on a known channel.
- AP must **not** enforce 802.11w (Protected Management Frames / PMF).

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
In pre-802.11w standards, 802.11 Management frames are transmitted in cleartext and are unauthenticated. A Deauthentication frame (Subtype 12) is a notification, not a request; it informs the receiver that the sender has terminated the connection. Because there is no cryptographic signature, an attacker can trivially spoof the Source MAC address. By sending a Deauth frame with the Source MAC of the AP and the Destination MAC of the Client, the client assumes the AP kicked it off and immediately destroys its state machine, severing the connection.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Identify Target BSSID, Target Client MAC, and Operating Channel.
2. **Target Selection:** Lock the attacker NIC to the operating channel.
3. **Execution Steps:** 
   - Construct an 802.11 frame (Subtype 12).
   - Set BSSID = AP MAC. Set Source = AP MAC. Set Dest = Client MAC.
   - Set Reason Code (e.g., 7: Class 3 frame received from nonassociated STA).
4. **Data Capture / Interaction:** Inject the crafted frames at high velocity (e.g., 10-50 frames per second).
5. **Verification of Success:** Monitor data frames. Success is validated when the client stops transmitting Data frames and subsequently transmits Authentication/Association Requests to reconnect.

**7. VARIANTS & MODERN TECHNIQUES**
- **Disassociation Flood:** Using Subtype 10 frames instead of Subtype 12.
- **Broadcast Deauth:** Setting the Destination MAC to `FF:FF:FF:FF:FF:FF` to drop all clients simultaneously. Highly noisy.

**8. SUCCESS CONDITIONS & VALIDATION**
Immediate cessation of client data traffic and observation of the client attempting to re-establish the connection.

**9. LIMITATIONS & FAILURE CASES**
- **802.11w (PMF):** If PMF is required, the AP and Client encrypt/authenticate Management frames using the IGTK (Integrity Group Temporal Key). Forged cleartext Deauth frames are silently dropped.
- Channel mismatch between attacker and target.

**10. DETECTION & DEFENSES**
Easily detected by WIDS/WIPS due to the high anomaly threshold of Subtype 12 frames. Defended exclusively by migrating to WPA3 (which mandates PMF) or enabling PMF on WPA2.

**11. REAL-WORLD USAGE CONTEXT**
Never used merely for DoS in professional assessments. It is a critical catalyst used to force clients to re-authenticate, thereby generating EAPOL frames for Handshake Capture, or forcing clients to roam to a deployed Evil Twin.

**12. EDGE CASE SCENARIOS**
- **Deauth Ignoring Clients:** Certain IoT drivers ignore reason codes 7/8 entirely to maintain uptime.
- **5GHz DFS Radar:** Injection on certain DFS channels is blocked by driver firmware.

**13. ADVANCED TEST SCENARIOS**
- **Targeted vs Broadcast:** Injecting solely against a specific device MAC to minimize WIDS alert profiles.
- **Timing Attacks:** Injecting exactly one deauth frame the moment a client completes an EAPOL exchange to test PMF activation windows.

**14. FAILURE INJECTION CASES**
- Attacker TX power is too low to reach the client, so the client never receives the spoofed packet from the "AP".
- Network card lacks injection capabilities (`aireplay-ng -9` test failure).

**15. DETECTION EVASION CONSIDERATIONS**
- Do not use broadcast (`FF:FF:FF:FF:FF:FF`). Limit injection to 1-2 frames rather than a continuous flood.

**16. PERFORMANCE STRESS SCENARIOS**
- Sustaining a Deauth flood across 5 channels simultaneously requires multiple physical radios.

---

## 4. WPA2 4-Way Handshake Capture

**1. ATTACK NAME**
WPA2 4-Way Handshake Capture

**2. CATEGORY**
Passive-to-Active / Credential Harvesting

**3. OBJECTIVE**
To capture the cryptographic exchange between an AP and a client to facilitate offline brute-forcing of the WPA2 Pre-Shared Key (PSK).

**4. PREREQUISITES**
- Target WPA2-PSK network with at least one associated client.
- NIC in Monitor Mode.
- (Optional) Injection capability for forced deauthentication.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
WPA2-PSK relies on a 256-bit Pairwise Master Key (PMK), derived via PBKDF2 from the cleartext passphrase and the SSID. When a client connects, it must prove it possesses the PMK without sending it over the air. This is done via the 802.11i 4-Way Handshake using EAPOL (Extensible Authentication Protocol over LAN) frames.
- **Msg 1 (AP -> Client):** Contains the AP's cryptographic nonce (ANonce).
- **Msg 2 (Client -> AP):** Contains the Client's nonce (SNonce) and a Message Integrity Code (MIC).
- **Msg 3 (AP -> Client):** Contains the encrypted Group Temporal Key (GTK) and a MIC.
- **Msg 4 (Client -> AP):** ACK.

The PTK (Pairwise Transient Key) used to encrypt the session is derived from: `PMK + ANonce + SNonce + AP_MAC + Client_MAC`. 
If an attacker captures Msg 1 (ANonce) and Msg 2 (SNonce, MIC, Client MAC), they have all inputs except the PMK. Offline, the attacker guesses passphrases, derives the PMK, derives the PTK, and calculates the expected MIC. If the calculated MIC matches the captured MIC from Msg 2, the passphrase is correct.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Identify BSSID, Channel, and an associated Client MAC.
2. **Target Selection:** Lock NIC to target channel. Filter captures for EtherType `0x888e` (EAPOL).
3. **Execution Steps:**
   - Wait passively for a natural client connection.
   - OR, inject a targeted Deauthentication attack (see Attack 3) to force the client to disconnect and immediately reconnect.
4. **Data Capture / Interaction:** Write captured EAPOL frames to a PCAP file.
5. **Verification of Success:** Parse the PCAP. Ensure EAPOL frames containing both the ANonce and SNonce, along with a valid MIC, are present.

**7. VARIANTS & MODERN TECHNIQUES**
- **Half-Handshake Capture:** Advanced cracking tools (like `hashcat`) only strictly require Msg 1 and Msg 2, or Msg 2 and Msg 3. Capturing all 4 is not strictly mathematically necessary.

**8. SUCCESS CONDITIONS & VALIDATION**
A verified PCAP file containing the EAPOL exchange that can be successfully loaded into `aircrack-ng` or `hashcat` (WPA*01/02* module).

**9. LIMITATIONS & FAILURE CASES**
- Fails if no clients are present.
- Fails if EAPOL frames are dropped due to high RF noise or distance from the target.
- Useless if the underlying passphrase exceeds the computational limits of the attacker's cracking hardware (e.g., >16 character random string).

**10. DETECTION & DEFENSES**
If executed passively, it is undetectable. Active execution is detected via the underlying Deauth attack. Defense relies entirely on strong password policies and migrating to WPA3.

**11. REAL-WORLD USAGE CONTEXT**
The absolute backbone of standard WPA2 pentesting. The primary method for proving weak password compliance on PSK networks.

**12. EDGE CASE SCENARIOS**
- **Dropped Packets:** Msg 2 drops, but Msg 3 is caught. WPA2 cracking can still occur with Msg 2/3 pairs in some tools.
- **Client Distance:** The AP is loud (we hear Msg 1) but the client is too far (we miss Msg 2). Handshake is incomplete.

**13. ADVANCED TEST SCENARIOS**
- **Deauth-less Capture:** Waiting 12-24 hours for natural DHCP lease renewals or physical user movement to capture the handshake completely silently.

**14. FAILURE INJECTION CASES**
- Executing a deauth flood that is *too intense*, causing the client to blacklist the AP entirely and refuse to reconnect, yielding no EAPOL frames.

**15. DETECTION EVASION CONSIDERATIONS**
- Avoid `aireplay-ng` entirely. Rely on physical proximity and time to gather EAPOL frames naturally.

**16. PERFORMANCE STRESS SCENARIOS**
- Writing all raw packet data to SD cards on low-end hardware can cause buffer overflows. BPF filters (`ether proto 0x888e`) are mandatory for performance.

---

## 5. PMKID Attack

**1. ATTACK NAME**
RSN PMKID Extraction (PMKID Attack)

**2. CATEGORY**
Active / Credential Harvesting

**3. OBJECTIVE**
To obtain the PMKID hash from an AP to execute an offline brute-force attack against the WPA2-PSK, *without needing any connected clients*.

**4. PREREQUISITES**
- Target AP firmware that appends PMKIDs to EAPOL Message 1 (typically APs supporting 802.11r/Fast BSS Transition).
- NIC supporting packet injection.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
In modern WPA2 implementations supporting roaming, the AP calculates a Pairwise Master Key Identifier (PMKID). 
The formula is: `PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_Client)`.
Notice that the PMKID is a static hash derived directly from the PMK (which is derived from the passphrase) and the MAC addresses. 
The vulnerability: When an attacker initiates a connection and sends an Association Request containing a dummy RSN PMKID, vulnerable APs will respond with EAPOL Message 1 and append the *actual, correct* PMKID of the network into the RSN Information Element of that frame. The attacker now has a direct cryptographic hash of the PMK and can crack it offline, without ever capturing a 4-way handshake from a real user.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Identify Target BSSID and Channel.
2. **Target Selection:** Lock NIC to channel.
3. **Execution Steps:**
   - Attacker authenticates to the AP (Open System Auth).
   - Attacker sends an Association Request frame.
4. **Data Capture / Interaction:**
   - The AP replies with an Association Response.
   - The AP initiates the 4-way handshake by sending EAPOL Message 1.
   - Attacker captures Message 1 and parses the RSN IE to extract the PMKID.
5. **Verification of Success:** Extraction of a 128-bit hex string from the EAPOL frame corresponding to the PMKID.

**7. VARIANTS & MODERN TECHNIQUES**
- Using `hcxdumptool` to automate the mass request of PMKIDs across all visible APs in an environment simultaneously.

**8. SUCCESS CONDITIONS & VALIDATION**
Capture of a valid PMKID hash, exportable to `hashcat` format 16800 or 22000.

**9. LIMITATIONS & FAILURE CASES**
- Highly dependent on AP firmware. Many vendors (Cisco, Meraki) patched this behavior and no longer append the PMKID for generic PSK associations.
- WPA3 deprecates this entirely.

**10. DETECTION & DEFENSES**
WIDS can detect abnormal volumes of aborted handshakes or Association Requests featuring invalid/dummy PMKID fields.

**11. REAL-WORLD USAGE CONTEXT**
The preferred modern attack for WPA2-PSK when targeting remote or empty facilities (e.g., after-hours auditing) where no clients are present to deauth.

**12. EDGE CASE SCENARIOS**
- **Mesh Networks:** Different nodes of the same ESSID may have different PMKID calculation bugs depending on firmware versions.
- **Mac Filtering:** If MAC filtering is enabled, the Open System Authentication step will fail, preventing the AP from sending EAPOL Msg 1.

**13. ADVANCED TEST SCENARIOS**
- Executing against WPA2-Enterprise (802.1x). While PMKIDs exist in Enterprise, cracking them requires knowing both the inner EAP credentials and the PMK, rendering it computationally unviable, but structurally possible to extract.

**14. FAILURE INJECTION CASES**
- Connecting with a non-dummy RSN IE will result in a standard handshake without PMKID extrusion.

**15. DETECTION EVASION CONSIDERATIONS**
- Do not sweep. Target only the specific BSSID to avoid triggering volumetric WIDS alerts on dummy associations.

**16. PERFORMANCE STRESS SCENARIOS**
- `hcxdumptool` can crash kernel drivers if instructed to attack 50+ APs simultaneously due to rapid state-machine transitions.

---

## 6. MAC Address Spoofing

**1. ATTACK NAME**
MAC Address Spoofing / Cloning

**2. CATEGORY**
Active / Identity Evasion & Masquerading

**3. OBJECTIVE**
To impersonate an authorized client device to bypass Layer 2 Network Access Controls (NAC), MAC filtering, or Captive Portal authorization states.

**4. PREREQUISITES**
- Root access to the attacker's local OS to modify NIC drivers.
- Knowledge of a currently authorized or whitelisted MAC address.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
Layer 2 wireless communications rely on the 48-bit Media Access Control (MAC) address embedded in the cleartext 802.11 frame headers. Because these headers are unauthenticated (unless using specific enterprise protections), the network infrastructure inherently trusts that a frame originating from `MAC X` actually came from `Device X`. Many Captive Portals (hotels, corporate guest networks) track authenticated sessions purely by storing the client's MAC address in a temporary firewall bypass rule.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Use passive sniffing (Attack 1 & 2) to identify clients successfully passing data frames (indicating they are authenticated and authorized).
2. **Target Selection:** Select a high-traffic Client MAC.
3. **Execution Steps:**
   - Bring down the local NIC (`ip link set wlan0 down`).
   - Modify the hardware address to match the target (`macchanger -m <TARGET_MAC> wlan0`).
   - Bring the NIC up (`ip link set wlan0 up`).
   - (Optional but recommended) Deauthenticate the legitimate client to prevent ACK storms and IP conflicts.
4. **Data Capture / Interaction:** Connect to the target Open network or Captive Portal SSID.
5. **Verification of Success:** The attacker achieves immediate outbound routing (e.g., Internet access) without being prompted by the Captive Portal or blocked by the NAC.

**7. VARIANTS & MODERN TECHNIQUES**
- **OUI Spoofing:** Changing only the first 3 bytes of the MAC to match specific vendor profiles (e.g., spoofing an Apple OUI) to bypass naive profiling systems.

**8. SUCCESS CONDITIONS & VALIDATION**
Successful Layer 3 ICMP/TCP routing to external resources bypassing expected authorization gates.

**9. LIMITATIONS & FAILURE CASES**
- **ARP Flapping/ACK Storms:** If the legitimate client remains active, both devices will acknowledge packets, causing severe network instability and dropped connections for the attacker.
- **Enterprise NAC:** 802.1x (EAP-TLS) defeats this entirely, as identity is tied to cryptographic certificates, not MAC addresses.

**10. DETECTION & DEFENSES**
WIDS profiling sequence numbers (which will instantly desync when an attacker spoofs the MAC). Switch-level port security detecting rapid MAC transitions.

**11. REAL-WORLD USAGE CONTEXT**
Standard technique for bypassing Captive Portals on engagements where providing phone numbers/emails to a portal is unacceptable.

**12. EDGE CASE SCENARIOS**
- **DHCP Leases:** IP conflicts occur if the legitimate client holds the DHCP lease. The attacker must manually assign the client's IP to their interface.
- **Port Security:** Enterprise switches may lock the port if a MAC address jumps between APs faster than physically possible.

**13. ADVANCED TEST SCENARIOS**
- Bypassing airline or hotel inflight WiFi billing systems by identifying MAC addresses that have paid for premium access.

**14. FAILURE INJECTION CASES**
- Forgetting to deauthenticate the victim leads to dual-ACK transmission, causing the AP to drop the session due to sequence confusion.

**15. DETECTION EVASION CONSIDERATIONS**
- Silence the victim using a constant Deauth flood (if PMF is disabled) to ensure the AP only sees the attacker's spoofed MAC.

**16. PERFORMANCE STRESS SCENARIOS**
- N/A. Very low hardware overhead.

---

## 7. WPS PIN Brute-Force Attack

**1. ATTACK NAME**
Wi-Fi Protected Setup (WPS) PIN Brute-Force / Pixie Dust

**2. CATEGORY**
Active / Protocol Exploit

**3. OBJECTIVE**
To recover the WPA2 PSK by exploiting cryptographic and design flaws in the WPS PIN authentication mechanism.

**4. PREREQUISITES**
- Target AP with WPS PIN authentication enabled.
- NIC supporting packet injection.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
WPS allows users to connect by entering an 8-digit PIN. The 8th digit is a checksum, leaving 7 effective digits. 
**The Design Flaw:** The WPS protocol authenticates the PIN in two halves. It checks the first 4 digits (10,000 combinations) and confirms if they are correct before checking the last 3 digits (1,000 combinations). This reduces the brute-force search space from 10,000,000 to a mere 11,000 requests.
**The Cryptographic Flaw (Pixie Dust / CVE-2014-9583):** During the WPS exchange, the AP generates nonces (E-S1, E-S2) to hash the PIN. Several prominent chipset vendors (Ralink, Realtek, MediaTek) implemented catastrophic Pseudo-Random Number Generators (PRNGs) where the nonces could be derived from public data in the exchange. This allows an attacker to capture a single WPS transaction and brute-force the PIN entirely offline in milliseconds.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Use tools like `wash` to scan for Beacons containing the WPS Information Element indicating "WPS Locked: No".
2. **Target Selection:** Identify a vulnerable BSSID.
3. **Execution Steps (Pixie Dust):**
   - Initiate a WPS transaction (M1 through M3 messages).
   - Extract the Enrollee Nonce, Registrar Nonce, AuthKey, and hashes.
   - Abort the transaction.
4. **Data Capture / Interaction:** Run the offline PixieWPS algorithm against the extracted nonces to deduce the PIN.
5. **Verification of Success:** Re-initiate the WPS transaction providing the deduced PIN. The AP responds with the WPA2 PSK in cleartext inside an EAP-WSC message.

**7. VARIANTS & MODERN TECHNIQUES**
- **Online Brute-Force (Reaver):** If Pixie Dust fails, falling back to sequentially guessing all 11,000 PINs over the air.

**8. SUCCESS CONDITIONS & VALIDATION**
Retrieval of the cleartext WPA2 Passphrase directly from the AP.

**9. LIMITATIONS & FAILURE CASES**
- **Rate Limiting:** Modern APs implement strict lockouts (e.g., locking WPS after 3 failed attempts). Online brute-forcing takes days and is often rendered impossible by these locks.
- **WPS v2.0:** Fixes the PRNG flaws, eliminating Pixie Dust.

**10. DETECTION & DEFENSES**
Detection of excessive EAP-WSC (WPS) authentication failures. Mitigation requires disabling WPS entirely in the AP firmware.

**11. REAL-WORLD ASAGE CONTEXT**
Largely considered a legacy attack. Used primarily during physical engagements against older IoT devices, legacy printers, or misconfigured small-business routers.

**12. EDGE CASE SCENARIOS**
- **Push Button Configuration (PBC):** Some APs report WPS enabled but only support PBC, not PIN. Brute force will immediately fail.
- **False Lockouts:** Some APs report "WPS Locked" in beacons but fail to actually enforce the lockout logic.

**13. ADVANCED TEST SCENARIOS**
- Inducing a reboot of the AP (via DoS or power disruption) to clear the RAM-based WPS lockout timer and resume brute-forcing.

**14. FAILURE INJECTION CASES**
- Distance from AP causing EAP-WSC M4/M5 messages to drop, desyncing the transaction.

**15. DETECTION EVASION CONSIDERATIONS**
- Using Pixie Dust is near-silent (1 transaction). Online brute-forcing is the loudest attack in WiFi and will trigger any WIDS immediately.

**16. PERFORMANCE STRESS SCENARIOS**
- Leaving `reaver` running for 72 hours requires immense stability from the `mac80211` driver, which frequently panics under sustained injection loads.

---

## 8. Evil Twin / Rogue Access Point

**1. ATTACK NAME**
Evil Twin / Rogue Access Point

**2. CATEGORY**
Active / Man-in-the-Middle (MITM)

**3. OBJECTIVE**
To trick client devices into connecting to an attacker-controlled AP instead of the legitimate infrastructure, enabling full Layer 3 traffic interception and manipulation.

**4. PREREQUISITES**
- NIC supporting Master (AP) Mode.
- Routing/NAT capabilities on the attacker host to provide an Internet uplink.
- Software AP daemon (e.g., `hostapd`).

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
802.11 roaming algorithms are handled entirely client-side. When a client sees multiple APs broadcasting the exact same SSID and matching cryptographic requirements, it will seamlessly roam to the AP presenting the strongest signal (RSSI) and best SNR. The client cannot cryptographically distinguish between the legitimate router and an attacker's laptop broadcasting the same name (unless Mutual Authentication like EAP-TLS is enforced). 

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Identify the Target SSID and the encryption type of the legitimate network.
2. **Target Selection:** Select a high-value SSID (often an Open Guest network to avoid handshake complexities).
3. **Execution Steps:**
   - Configure `hostapd` with the exact Target SSID and identical security parameters.
   - Configure a local DHCP server (`dnsmasq`) to assign IPs to victims.
   - Configure `iptables` to NAT victim traffic out through the attacker's uplink interface (e.g., LTE modem).
   - Launch the Rogue AP.
   - (Optional) Continuously Deauthenticate clients from the legitimate BSSID to force them to re-evaluate the RF environment and roam to the stronger Rogue AP.
4. **Data Capture / Interaction:** Client connects. Attacker intercepts DNS, HTTP, and TLS handshakes.
5. **Verification of Success:** Client MAC appears in the `hostapd` association logs, and victim traffic flows through the attacker's `tcpdump` or proxy.

**7. VARIANTS & MODERN TECHNIQUES**
- **OWE Downgrade:** If the target is an Opportunistic Wireless Encryption (OWE) network, the attacker broadcasts the same SSID as an Open network. Clients lacking strict OWE-enforcement will silently downgrade to the unencrypted Open Rogue AP.

**8. SUCCESS CONDITIONS & VALIDATION**
Full Layer 2 and Layer 3 control over the victim's data stream.

**9. LIMITATIONS & FAILURE CASES**
- **WPA2/3 Enterprise:** Evil Twins against 802.1x networks fail because the client validates the RADIUS server's TLS certificate. The attacker cannot forge the corporate CA.
- **Physical Distance:** If the attacker's transmit power is weaker than the legitimate AP, clients will not roam.

**10. DETECTION & DEFENSES**
WIDS detects BSSID spoofing (same BSSID, different physical radio signature) or rogue APs (known SSID broadcast from an unknown BSSID).

**11. REAL-WORLD USAGE CONTEXT**
The cornerstone of advanced wireless MITM. Used to bypass encryption entirely by bringing the client onto a hostile network fabric.

**12. EDGE CASE SCENARIOS**
- **BSSID Spoofing:** To force roaming, an attacker may spoof the *exact* BSSID of the legitimate AP. This causes immense Layer 2 confusion unless the legitimate AP is entirely jammed.
- **Channel Isolation:** Deploying the Evil Twin on a clean channel (e.g., CH 11) while jamming the legitimate AP on CH 1.

**13. ADVANCED TEST SCENARIOS**
- Deploying EAP-hammer to spoof an 802.1x network specifically to downgrade the inner-auth protocol to GTC and capture MSCHAPv2 hashes.

**14. FAILURE INJECTION CASES**
- Forgetting to provide a valid Internet uplink (NAT/DNS). Modern OSes detect the lack of internet via CPD and instantly drop the WiFi connection, preventing MITM.

**15. DETECTION EVASION CONSIDERATIONS**
- Randomizing the Rogue AP's BSSID prevents immediate WIDS detection rules based on BSSID whitelists, but alerts on unauthorized AP creation.

**16. PERFORMANCE STRESS SCENARIOS**
- Capturing full packet payloads for 10+ clients requires high I/O throughput and SSD write speeds.

---

## 9. Karma Attack / Auto-Connect Exploitation

**1. ATTACK NAME**
Karma Attack (PineAP / Loud AP)

**2. CATEGORY**
Active / MITM

**3. OBJECTIVE**
To force a client to connect to an attacker's AP by dynamically spoofing any network the client is actively searching for.

**4. PREREQUISITES**
- NIC in Master Mode.
- Custom AP daemon capable of dynamic beaconing (e.g., `hostapd-mana`).

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
As noted in Attack 2, legacy clients broadcast Directed Probe Requests (e.g., "Are you 'Starbucks_WiFi'?"). The Karma attack modifies the standard AP behavior. Instead of broadcasting a static SSID, a Karma-enabled AP listens for these Directed Probes. The moment it hears a request, it dynamically spins up a virtual AP or sends a Directed Probe Response saying, "Yes, I am 'Starbucks_WiFi'." The client, believing it has found its trusted network, immediately authenticates and associates.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Passive listening is not required; the AP reacts dynamically.
2. **Target Selection:** Global. Affects all vulnerable clients in RF range.
3. **Execution Steps:**
   - Launch `hostapd-mana` with `mana_loud=1` enabled.
   - Provide DHCP and NAT routing.
4. **Data Capture / Interaction:** 
   - Client sends Probe Request for "Hotel_Guest".
   - Attacker AP replies with Probe Response for "Hotel_Guest".
   - Client completes Open System authentication and associates.
5. **Verification of Success:** Unwitting clients connect to the attacker AP under various different SSIDs simultaneously.

**7. VARIANTS & MODERN TECHNIQUES**
- **MANA Attack:** Modern clients mitigate Karma by ignoring Probe Responses for networks they didn't explicitly probe for. MANA circumvents this by capturing MAC addresses that previously connected to *any* SSID and broadcasting Directed Probe Responses for *all* known SSIDs specifically to that MAC, forcing association.

**8. SUCCESS CONDITIONS & VALIDATION**
Victim association and IP lease acquisition on the rogue infrastructure.

**9. LIMITATIONS & FAILURE CASES**
- Modern OSes (iOS, Android, Windows) rely primarily on passive scanning and drop Directed Probes, heavily mitigating standard Karma.
- Cannot easily spoof PSK networks, as the attacker does not know the password the client is expecting to use for the 4-way handshake. Primarily effective against Open networks.

**10. DETECTION & DEFENSES**
Difficult to detect on the enterprise side, as the attack targets the client's historical PNL, not the corporate SSID. 

**11. REAL-WORLD USAGE CONTEXT**
Used extensively in physical red teaming and social engineering engagements in public spaces to harvest credentials from employee mobile devices.

**12. EDGE CASE SCENARIOS**
- **Collision with Reality:** If the actual "Starbucks_WiFi" is present in the environment, the client will see two APs and select based on RSSI, potentially defeating the Karma AP.

**13. ADVANCED TEST SCENARIOS**
- **Known Beacon Attack:** Broadcasting the 50 most common hotel/airport SSIDs statically to catch clients that use passive scanning, bypassing Karma mitigations.

**14. FAILURE INJECTION CASES**
- Client attempts to associate using WPA2-PSK to the Karma AP. Karma AP accepts association but fails the 4-way handshake, resulting in a dropped connection.

**15. DETECTION EVASION CONSIDERATIONS**
- Karma APs responding to literally every SSID probe create massive RF noise and are instantly obvious to any pentester looking at a waterfall graph.

**16. PERFORMANCE STRESS SCENARIOS**
- Responding to 1,000+ probe requests per second in a crowded area can exhaust AP daemon RAM.

---

## 10. Captive Portal Credential Harvesting

**1. ATTACK NAME**
Captive Portal Phishing / Credential Harvesting

**2. CATEGORY**
Active / Social Engineering / Credential Harvesting

**3. OBJECTIVE**
To deceive a user connected to a Rogue AP into surrendering cleartext credentials, WPA passphrases, or MFA tokens via a spoofed web interface.

**4. PREREQUISITES**
- Successful execution of an Evil Twin (Attack 8) or Karma (Attack 9).
- Attacker-controlled DNS server.
- Attacker-controlled HTTP web server.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
Modern Operating Systems feature Captive Portal Detection (CPD). Upon connecting to a network, the OS attempts to fetch a specific cleartext HTTP URL (e.g., `http://captive.apple.com/hotspot-detect.html`). If it receives a `200 OK` with a specific string ("Success"), it assumes internet access is granted. If the request is hijacked via DNS or intercepted and returns an HTTP `302 Redirect` or a modified HTML page, the OS assumes it is behind a Captive Portal (like at a hotel or airport). The OS then spawns a pseudo-browser window to display the intercepted page, forcing user interaction before allowing the OS to access the internet.

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Trap the victim on a Rogue AP.
2. **Target Selection:** All associated clients.
3. **Execution Steps:**
   - Configure the rogue DHCP server to assign the attacker's IP as the DNS server.
   - Configure the rogue DNS server (`dnsmasq`) to resolve ALL queries (`#`) to the attacker's IP.
   - Host a cloned, high-fidelity phishing page (e.g., "Corporate IT: Enter Active Directory credentials to upgrade firmware") on port 80.
4. **Data Capture / Interaction:** 
   - Client connects. OS runs CPD.
   - CPD request is DNS-spoofed and redirected to the attacker's HTTP server.
   - Pseudo-browser opens automatically on the victim's screen.
   - Victim submits credentials. 
   - Attacker logs HTTP POST data.
   - Attacker script authenticates the MAC, modifies `iptables` to grant actual internet access, and forwards the victim to legitimate infrastructure to avoid suspicion.
5. **Verification of Success:** Capture of valid, cleartext credentials in web server logs.

**7. VARIANTS & MODERN TECHNIQUES**
- **WPA-PSK Phishing:** Asking the user for the actual WPA2 password of the network being spoofed, bypassing the need to crack handshakes.
- **OAuth Phishing:** Presenting fake Google/Microsoft login prompts to steal session tokens.

**8. SUCCESS CONDITIONS & VALIDATION**
User interaction resulting in compromised data.

**9. LIMITATIONS & FAILURE CASES**
- Depends entirely on social engineering and human gullibility.
- Strict HSTS (HTTP Strict Transport Security) policies prevent spoofing domains the user attempts to visit directly, though this does not stop the initial OS CPD trigger.

**10. DETECTION & DEFENSES**
End-user awareness training. Client-side certificate warnings.

**11. REAL-WORLD USAGE CONTEXT**
The ultimate fallback attack. When a WPA2-PSK is 20+ characters and uncrackable, pentesters pivot to Captive Portal phishing to ask the user for the password directly.

**12. EDGE CASE SCENARIOS**
- **HTTPS CPD:** Newer Android versions attempt HTTPS for CPD. If the attacker doesn't have a valid cert, the OS throws an untrusted connection error, breaking the illusion.
- **Custom DNS:** If the client hardcodes `8.8.8.8` locally, the rogue AP's DNS DHCP offer is ignored. The AP must intercept and NAT port 53 traffic to force routing.

**13. ADVANCED TEST SCENARIOS**
- **2FA Relay:** Phishing for Username/Password, then dynamically requesting a 2FA token and proxying it to the real service in real-time.

**14. FAILURE INJECTION CASES**
- Failing to provide actual internet access *after* the user submits credentials causes them to retry or alert IT.

**15. DETECTION EVASION CONSIDERATIONS**
- Host the phishing page using a typo-squatted domain with a legitimate Let's Encrypt certificate to bypass basic browser warnings.

**16. PERFORMANCE STRESS SCENARIOS**
- Web server must handle simultaneous connections and session states for dozens of victims without hanging.

---

## 11. WPA3 Downgrade Attacks

**1. ATTACK NAME**
WPA3 Downgrade Attack (e.g., Dragonblood Transition Downgrade)

**2. CATEGORY**
Active / Protocol Exploit

**3. OBJECTIVE**
To force a client device capable of WPA3 (SAE) to downgrade its connection to vulnerable WPA2 (PSK) or Open standards.

**4. PREREQUISITES**
- Target AP operating in "WPA3 Transition Mode" (supporting both WPA2 and WPA3 simultaneously).
- Rogue AP capabilities.

**5. TECHNICAL FOUNDATION (DEEP DIVE)**
To support legacy devices, WPA3 includes a "Transition Mode" where a single BSSID advertises support for both WPA2-PSK and WPA3-SAE in its RSN Information Elements. The vulnerability lies in the fact that the initial Management frames negotiating the security parameters are unauthenticated. An attacker can manipulate the environment to convince the client that the AP does not actually support WPA3, forcing it to fall back to the weaker WPA2 standard, which is susceptible to dictionary attacks (Attack 4).

**6. CANONICAL ATTACK METHODOLOGY (STEP-BY-STEP)**
1. **Recon Phase:** Identify APs broadcasting Transition Mode RSN IEs.
2. **Target Selection:** Target a client actively attempting to connect using WPA3-SAE.
3. **Execution Steps:**
   - Deploy an Evil Twin AP broadcasting the exact same SSID, but manipulate the Beacon frames to remove the WPA3-SAE AKM (Authentication and Key Management) suite, advertising *only* WPA2-PSK.
   - Inject Deauthentication frames to knock the client off the legitimate Transition Mode AP.
4. **Data Capture / Interaction:** 
   - The client reconnects. Seeing the strongest AP (the Evil Twin) only supports WPA2, the client's OS downgrades its security posture and initiates the 802.11i 4-Way Handshake.
   - Attacker captures the WPA2 handshake.
5. **Verification of Success:** A WPA2 PCAP capture from a device that previously utilized WPA3.

**7. VARIANTS & MODERN TECHNIQUES**
- **OWE Downgrade:** Forcing an Opportunistic Wireless Encryption (OWE) transition network client to connect to a purely Open Evil Twin, stripping all encryption.

**8. SUCCESS CONDITIONS & VALIDATION**
Successful negotiation of a deprecated or weaker protocol suite by the victim client.

**9. LIMITATIONS & FAILURE CASES**
- Fails if the network is configured as "WPA3-Only" (no transition mode).
- Fails if the client OS is strictly configured to "Require WPA3" for that specific SSID profile.
- 802.11w (PMF) is mandatory in WPA3, making the required deauthentication step difficult if the client is already securely connected to the legitimate AP.

**10. DETECTION & DEFENSES**
WIDS alerting on APs broadcasting mismatched RSN IEs for known SSIDs.

**11. REAL-WORLD USAGE CONTEXT**
The primary methodology for attacking modern networks during the current industry transition period where full WPA3 enforcement is rarely deployed due to legacy hardware constraints.

**12. EDGE CASE SCENARIOS**
- **PMF Enforcement:** If the client is already connected via WPA3, PMF prevents the attacker from deauthenticating them to force the roam. The attacker must wait for the client to naturally disconnect or physically jam the channel.

**13. ADVANCED TEST SCENARIOS**
- Downgrading WPA3-Enterprise to WPA2-Enterprise, then further downgrading the inner EAP protocol to GTC via EAPhammer to steal credentials.

**14. FAILURE INJECTION CASES**
- Client OS strictly implements BSS Transition caching and refuses to connect to an AP lacking SAE if it previously connected via SAE on that same BSSID.

**15. DETECTION EVASION CONSIDERATIONS**
- Downgrade attacks require deploying an Evil Twin, which is inherently noisy.

**16. PERFORMANCE STRESS SCENARIOS**
- N/A.

---
---

## FINAL SECTION: MASTER ATTACK CHECKLIST

This checklist serves as the compliance baseline. Any "Production-Grade" wireless penetration testing tool must possess the underlying logic and hardware abstraction capabilities to execute the **Common** and **Advanced** techniques listed below.

| Category | Attack Name | Status | Tool Compliance Requirement |
| :--- | :--- | :---: | :--- |
| **Reconnaissance** | Channel Hopping & Network Discovery | **Common** | Must support 2.4/5GHz hopping and robust IE parsing. |
| **Reconnaissance** | Probe Request Sniffing / Client Tracking | **Common** | Must extract PNLs and handle randomized MACs gracefully. |
| **Active/DoS** | Deauthentication / Disassociation | **Common** | Must support targeted, precise injection (no blind broadcast floods). |
| **Evasion** | MAC Address Spoofing | **Common** | Must seamlessly handle NIC state transitions (down, spoof, up). |
| **Credential Harvest**| WPA2 4-Way Handshake Capture | **Common** | Must feature real-time capture verification (Smart Exits). |
| **Credential Harvest**| RSN PMKID Extraction | **Advanced** | Must support clientless extraction (e.g., `hcxdumptool` integration). |
| **MITM** | Evil Twin / Rogue Access Point | **Advanced** | Must manage DHCP, DNS routing, and NAT seamlessly. |
| **MITM** | Karma / PineAP Attacks | **Advanced** | Must support dynamic beacon generation and MANA logic. |
| **Protocol Exploit** | WPA3 Transition Downgrade | **Advanced** | Must support RSN manipulation and targeted WPA2 fallback. |
| **Social Engineering**| Captive Portal Phishing | **Advanced** | Must manipulate OS CPD mechanisms and capture HTTP POSTs. |
| **Protocol Exploit** | WPS PIN Brute-Force (Pixie Dust) | *Legacy* | Good for backwards compatibility, but low priority for modern tools. |
