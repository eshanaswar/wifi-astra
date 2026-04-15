# WiFi-Astra User Guide

Practical guidance for running wireless security assessments with WiFi-Astra.

---

## Pre-Engagement Checklist

Before starting any session, verify:

- [ ] **Written authorization** obtained from the network owner
- [ ] **Hardware**: at least one adapter with monitor mode + injection support
- [ ] **Signal**: adapter positioned for reliable signal to target AP (RSSI > -70 dBm for active attacks)
- [ ] **Dependencies**: all required tools installed (see below)
- [ ] **Build**: binary compiled and working

```bash
# Verify build
go build -o bin/wifi-astra ./cmd/astra/
sudo ./bin/wifi-astra --version

# Install core dependencies (Kali/Debian)
sudo apt-get install -y aircrack-ng tshark tcpdump iw hcxdumptool \
    nmap mdk4 hostapd dnsmasq macchanger iodine hashcat \
    bettercap responder
```

---

## Hardware Setup

### Adapter Recommendations

| Chipset | Bands | Notes |
|---------|-------|-------|
| Alfa AWUS036ACM (MT7612U) | 2.4/5 GHz | Most reliable for monitor + injection |
| Alfa AWUS036ACS (RTL8811AU) | 2.4/5 GHz | Good 5 GHz injection |
| TP-Link Archer T2U Plus | 2.4/5 GHz | Budget option; verify injection support |
| Hak5 Wi-Fi Coconut | 2.4 GHz | Multi-channel passive capture |

### Verifying Monitor Mode Support

```bash
iw list | grep -A 10 "Supported interface modes"
# Should include: * monitor

# Test injection
sudo airmon-ng start wlan1
sudo aireplay-ng --test wlan1mon
```

### Dual-Adapter Setup

WiFi-Astra works best with two adapters:
- **Adapter 1 (MONITOR)**: placed in monitor mode for all attack operations
- **Adapter 2 (MANAGEMENT)**: stays in managed mode connected to your control network

The assignment wizard handles this at session start. If you only have one adapter, assign it to MONITOR and accept the loss of control-network connectivity during the engagement.

---

## Running a Session

### Start

```bash
sudo ./bin/wifi-astra start
```

For verbose hardware and process logging:

```bash
sudo ./bin/wifi-astra start -v
```

### Session Manager

On first run, create a new session. On subsequent runs, you can resume a previous session to continue adding findings or regenerate the report.

Sessions are stored in `sessions/<id>/` and tracked in a local SQLite database.

### Adapter Assignment Wizard

The wizard lists all detected wireless interfaces with their current mode, driver, and chipset. Assign:
1. **MONITOR role** — the adapter to be placed in monitor mode
2. **MANAGEMENT role** — the adapter to keep in managed mode (or skip if only one adapter)

Roles are locked for the entire session. The management interface cannot be requested by any attack module.

### A1 — Network Discovery (Mandatory)

Every session starts with A1. This runs airodump-ng (and hcxdumptool on 6 GHz-capable adapters) to enumerate all visible networks.

```
[A1] Starting airodump-ng scan on wlan1mon for 60s...
```

After the scan completes, a network table is displayed. Select the BSSIDs you are authorized to test — this becomes the session scope.

> **Note**: You cannot manually enter a BSSID. Scope is built exclusively from discovered data to prevent targeting errors.

### Scope Selection

The scope list controls what every subsequent module can target. Any module attempting to target a BSSID not in scope is blocked by the controller and logged as `SCOPE_VIOLATION` in `session_replay.log`.

---

## Module Categories

### Category A — Discovery & Recon

| Module | Purpose |
|--------|---------|
| A1 | Enumerate all SSIDs, BSSIDs, channels, encryption |
| A2 | Correlate BSSIDs by OUI, detect multi-SSID APs and rogue AP indicators |
| A3 | Reveal hidden SSIDs via deauth-triggered probe responses |
| A4 | Map associated clients, detect PNL leaks and MAC randomization |
| A5 | Profile Wi-Fi 6/6E HE capabilities in the environment |

**A2 tip**: The sequential-BSSID analysis (`aa:bb:cc:dd:ee:00/01/02`) identifies enterprise APs serving multiple SSIDs on the same hardware. Finding the same SSID on multiple OUIs flags potential evil twins.

**A3 tip**: A3 requires at least one associated client on the target hidden network. If no clients are found during the discovery scan, the deauth-based reveal cannot be attempted.

### Category B — Internal Recon (Connected)

Run these after associating to the target network (Category F can establish the association).

| Module | Purpose |
|--------|---------|
| B1 | Test if clients can communicate peer-to-peer (client isolation enforcement) |
| B2 | Scan for exposed AP management interfaces (Web UI, SSH, SNMP) |
| B3 | Capture CDP/LLDP frames revealing switch/AP infrastructure details |
| B4 | Enumerate mDNS services for device discovery |
| B5 | Test SNMP community strings |
| B6 | Analyze DHCP options; detect rogue DHCP servers |
| B7 | Check for IPv6 leaks, SLAAC misconfiguration, DHCPv6 exposure |
| B8 | Analyze broadcast traffic for cleartext protocols |
| B9 | Fingerprint AP firmware version and check against CVE database |
| B10 | Passive protocol sniffing (HTTP credentials, DNS, etc.) |

### Category C — Segmentation & Egress

Tests whether the wireless segment is properly isolated from other network zones.

| Module | Purpose |
|--------|---------|
| C1 | DNS resolution testing (split-horizon, cross-segment) |
| C2 | Internal network route discovery |
| C3 | VLAN hopping via 802.1Q double-tagging |
| C4 | RADIUS server reachability |
| C5 | Egress filter bypass (DNS over 53, HTTP over 80, ICMP, NTP) |

### Category D — Encryption & Authentication Attacks

| Module | When to run | Notes |
|--------|-------------|-------|
| D1 | WPA2-PSK networks | PMKID capture is clientless; falls back to deauth + 4-way handshake |
| D2 | WEP networks (legacy) | Requires fake-auth + ARP replay; WEP is obsolete |
| D3 | WPS-enabled APs | Pixie Dust first (seconds); PIN brute-force only if Pixie Dust fails |
| D4 | WPA3-SAE networks | Tests timing/cache side-channels; requires SAE-capable adapter |
| D5 | 802.1X/EAP networks | Rogue RADIUS captures PEAP/MSCHAPv2 handshakes |
| D6 | OWE Transition Mode APs | Tests if clients downgrade to open association |
| D7 | WPA3 networks | Tests beacon manipulation to force WPA2 association |
| D8 | EAP deployments | Tests if clients validate server certificates |

**Inline cracking**: After a successful D1/D2/D3/D5 capture, the controller offers to run cracking inline. Recovered PSKs and credentials are recorded as CRITICAL findings.

### Category E — Implementation & Design Flaws

Tests for specific CVEs in wireless implementations.

| Module | CVE | Description |
|--------|-----|-------------|
| E1 | CVE-2017-13077 | KRACK key reinstallation |
| E2 | CVE-2020-24586/7/8 | FragAttacks frame injection |
| E3 | — | 802.11w deauthentication spoofing resilience |
| E4 | — | Driver fuzzing via mdk4 frame injection |
| E5 | CVE-2019-15126 | Kr00k all-zero key vulnerability |

### Category F — Rogue AP & Evil Twin

These modules require the **managed interface** (`WIFI_INTERFACE`) for AP operation, and the monitor interface for deauth catalysts.

| Module | Description |
|--------|-------------|
| F1 | Full evil twin: hostapd AP + deauth to force client association |
| F2 | KARMA/PineAP: respond to any probe request with a matching AP |
| F3 | Captive portal with vendor-aware fingerprinting (ISE, ClearPass, Meraki, FortiGate) |
| F4 | Portal bypass techniques: MAC spoofing, IP spoofing, DNS tunneling |
| F5 | DNS tunnel capability testing via iodine |

### Category G — Man-in-the-Middle & Pivoting

Run after associating to the target network.

| Module | Description |
|--------|-------------|
| G1 | ARP spoofing via bettercap — MitM positioning |
| G2 | Transparent TLS interception via mitmdump |
| G3 | DNS spoofing for targeted traffic redirection |
| G4 | NAC bypass: clone MAC + hostname + DHCP fingerprint of an authorized device |
| G5 | BSS Transition Management abuse — steer clients to rogue AP |
| G6 | LLMNR/NBT-NS poisoning via Responder — NTLM hash capture |

**G4 tip**: The module re-associates to the AP after the MAC change. Without re-association, the new MAC gets no DHCP lease and the NAC bypass is untestable.

### Category H — Policy & WIDS Validation

| Module | Description |
|--------|-------------|
| H1 | Injects deauth bursts, fake AP beacons, and auth floods; analyzes AP response for WIDS counter-measures |
| H2 | Parses RSN capability fields from beacon frames to determine PMF status: Required / Capable / None |

**H1 methodology**: The module counts counter-deauth frames (type/subtype 12 or 10) originating FROM the AP and detects channel changes. A WIDS that detects attacks will generate these responses. No response = WIDS absent or misconfigured.

**H2 finding interpretation**:
- `PMF Required` (MFPR=1, MFPC=1) — strongest protection; clients without 802.11w are rejected
- `PMF Capable` (MFPR=0, MFPC=1) — optional; legacy clients remain unprotected
- `PMF None` (MFRC=0, MFPC=0) — all clients vulnerable to deauth flooding and handshake capture

---

## Headless Mode

For automated or scheduled audits, provide a JSON plan:

```bash
sudo ./bin/wifi-astra start --config plan.json
```

```json
{
  "session_name": "Q2_Guest_Audit",
  "interface": "wlan1",
  "target_ssid": "Corp-Guest",
  "target_bssid": "AA:BB:CC:DD:EE:FF",
  "target_channel": 11,
  "scan_time": 120,
  "modules": ["A1", "A2", "A3", "B1", "B2", "D1", "D3", "H1", "H2"]
}
```

Modules run sequentially in the specified order. `ASTRA_HEADLESS=true` is injected into each module environment.

---

## Reporting

After completing the assessment, generate the report from the main menu or:

```bash
sudo ./bin/wifi-astra report --session <session-id>
```

The report is written to `sessions/<id>/reports/` and includes:
- Executive summary with finding counts by severity
- Network map (all discovered BSSIDs, SSIDs, channels, encryption)
- Per-finding detail: description, target, evidence files, rationale, remediation
- Evidence index with SHA256 hashes for chain of custody

---

## Tactical Tips

**Signal quality**: For active attacks (deauth, injection, rogue AP), position your adapter for strong signal. RSSI weaker than -70 dBm causes unreliable injection and missed handshakes. Use `iwconfig` or `airodump-ng` to verify RSSI before running Category D/E/F.

**PMF awareness**: If H2 reports `PMF Required`, deauthentication-based attacks (A3, D1 handshake path, F1 catalyst) will be blocked by the AP. Use PMKID capture (D1 clientless path) and passive association monitoring instead.

**WPA3 downgrade (D7)**: Only effective against Transition Mode deployments where the AP advertises both WPA3 and WPA2. Pure WPA3-SAE APs cannot be downgraded.

**Evil twin ordering (F1)**: The deauth catalyst only forces clients if PMF is not required. Always run H2 before F1 to confirm PMF status.

**NAC bypass (G4)**: Requires identifying an already-authorized device MAC. Run B10 (passive sniff) or review ARP tables from B1 to identify candidate MACs before attempting the bypass.

---

## Maintenance

```bash
# Update IEEE OUI vendor database
sudo ./bin/wifi-astra update-oui

# Delete old sessions
sudo ./bin/wifi-astra sessions --delete <session-id>
```
