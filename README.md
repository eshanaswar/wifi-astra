# WiFi-Astra

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](License.txt)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-blue)](https://www.kali.org/)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-red)](License.txt)

**WiFi-Astra** is a professional wireless penetration testing framework built for authorized security assessments. A compiled Go orchestrator manages session state, hardware roles, scope enforcement, and evidence collection, while 46 modular Bash scripts execute the actual 802.11 attack techniques across the full pentest lifecycle — from passive discovery through exploitation and reporting.

---

## Overview

Most wireless pentesting involves juggling a dozen separate tools, manually correlating output files, and hoping nothing is left running when the engagement ends. WiFi-Astra wraps the full lifecycle into one coherent session:

- Hardware is assigned roles at session start and locked for the duration
- Every module writes structured findings directly into the evidence store
- Scope is enforced at the controller level — no module can target a BSSID not in scope
- Inline cracking runs automatically after successful captures (D1/D2/D3/D5)
- A cleanup checklist verifies interfaces are restored and all processes are stopped before exit
- A structured report is generated from all session findings

---

## Features

- **Dual-adapter enforcement** — Monitor interface for injection/sniffing, management interface for operator connectivity. Roles are locked for the entire session; the management interface is never touched by attack modules.
- **46 assessment modules** across 8 attack categories covering 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E)
- **Full encryption coverage** — WPA2-PSK, WPA3-SAE, OWE, WPA-Enterprise (802.1X/PEAP/MSCHAPv2)
- **Inline cracking** — hashcat, aircrack-ng, and asleap run automatically after captures; PSKs recorded as findings
- **Scope enforcement** — every module target is validated against the operator-selected scope list; violations are logged
- **Evidence chain of custody** — SHA256 manifest, append-only replay log, structured per-module run records
- **Headless mode** — JSON audit plans for automated or scheduled engagements
- **Self-healing hardware** — `hw.Recover()` restores interfaces stuck in monitor mode on crash or exit
- **OUI vendor lookup** — built-in IEEE OUI database for vendor identification in BSSID correlation

---

## Assessment Categories

| Cat | Name | Modules |
|-----|------|---------|
| **A** | Discovery & Recon | A1–A5 |
| **B** | Internal Network Recon | B1–B10 |
| **C** | Segmentation & Egress | C1–C5 |
| **D** | Encryption & Auth Attacks | D1–D8 |
| **E** | Implementation & Design Flaws | E1–E5 |
| **F** | Rogue AP & Evil Twin | F1–F5 |
| **G** | Man-in-the-Middle & Pivoting | G1–G6 |
| **H** | Policy & WIDS Validation | H1–H2 |

### Full Module List

| ID | Module | Description |
|----|--------|-------------|
| A1 | Identify Networks | Passive/active WiFi discovery across 2.4/5/6 GHz using airodump-ng + hcxdumptool |
| A2 | BSSID Correlation | OUI grouping, sequential-BSSID clustering (multi-SSID APs), evil twin detection |
| A3 | Hidden SSID Discovery | Deauth-triggered probe response capture to reveal hidden network names |
| A4 | Client Fingerprinting | Associated client enumeration, PNL leak detection, MAC randomization analysis |
| A5 | Wi-Fi 6/6E Detection | HE capability mapping and 6 GHz environment profiling |
| B1 | Client Isolation | Peer-to-peer traffic testing between wireless stations |
| B2 | Management Exposure | Web UI, SSH, SNMP, Telnet scanning of AP management interfaces |
| B3 | CDP/LLDP Leaks | Infrastructure device information leaking via discovery protocols |
| B4 | mDNS/Bonjour Leaks | Service enumeration via multicast DNS |
| B5 | SNMP Exposure | Community string discovery and SNMP enumeration |
| B6 | DHCP Analysis | Option fingerprinting and rogue DHCP server detection |
| B7 | IPv6 Leaks | SLAAC/DHCPv6 misconfiguration and IPv6 tunnel detection |
| B8 | Broadcast Leaks | Broadcast traffic analysis for sensitive cleartext protocols |
| B9 | AP Vulnerability | Firmware version fingerprinting and CVE correlation |
| B10 | AirSnitch | Passive wireless traffic sniffing and protocol analysis |
| C1 | DNS Resolution | Split-horizon testing and cross-segment DNS resolution |
| C2 | Private Network Scan | Internal subnet discovery and route enumeration |
| C3 | VLAN Hopping | 802.1Q double-tagging and VLAN hopping attacks |
| C4 | RADIUS Reachability | RADIUS server availability and configuration validation |
| C5 | Egress Filtering | Bypass testing across DNS, HTTP, ICMP, and NTP egress paths |
| D1 | WPA Handshake Capture | PMKID capture (primary) + 4-way handshake; inline hashcat cracking |
| D2 | WEP Cracking | IV collection via ARP replay + fake-auth; inline aircrack-ng key recovery |
| D3 | WPS Testing | Pixie Dust attack (primary); PIN brute-force fallback; PSK extraction |
| D4 | WPA3 Dragonblood | SAE timing and cache side-channel testing (CVE-2019-9494) |
| D5 | EAP Attack | Rogue RADIUS for PEAP/MSCHAPv2 capture; inline asleap cracking |
| D6 | OWE Downgrade | OWE Transition Mode downgrade to open association |
| D7 | WPA3 Downgrade | Active beacon manipulation to force WPA2 association |
| D8 | EAP Cert Validation | Client certificate validation testing for 802.1X misconfiguration |
| E1 | KRACK | Key reinstallation attack testing (CVE-2017-13077) |
| E2 | FragAttacks | Frame aggregation and fragmentation vulnerabilities (CVE-2020-24586/7/8) |
| E3 | Deauth Resilience | 802.11w PMF and deauthentication spoofing resilience testing |
| E4 | Wireless Fuzzing | 802.11 frame fuzzing for wireless driver vulnerabilities (mdk4) |
| E5 | Kr00k | All-zero key vulnerability check (CVE-2019-15126) |
| F1 | Rogue AP / Evil Twin | Rogue AP with deauth catalyst and client credential capture |
| F2 | PineAP / KARMA | KARMA attack against unassociated probe requests |
| F3 | Captive Portal | Vendor-fingerprinted captive portal (ISE, ClearPass, FortiGate, Meraki) |
| F4 | Portal Bypass | Captive portal bypass via MAC/IP/DNS techniques |
| F5 | DNS Tunnel | DNS tunneling capability detection and iodine testing |
| G1 | ARP Spoofing | ARP spoofing and MitM positioning via bettercap |
| G2 | SSL Interception | Transparent TLS interception via mitmdump |
| G3 | DNS Spoofing | DNS spoofing for targeted traffic redirection |
| G4 | NAC Bypass | MAC + hostname + DHCP fingerprint cloning against ISE/ClearPass |
| G5 | BSS Transition Attack | 802.11v BSS Transition Management abuse to steer clients |
| G6 | Responder Pivot | LLMNR/NBT-NS poisoning for NTLM hash capture |
| H1 | WIDS/WIPS Detection | Attack signature injection with counter-measure response analysis |
| H2 | PMF Check | 802.11w RSN capability parsing — Required / Capable / None |

---

## Requirements

**Hardware:**
- One wireless adapter capable of **monitor mode and packet injection** (monitor role)
- A second wireless adapter in managed mode for operator connectivity (management role — optional but recommended)
- Tested adapters: Alfa AWUS036ACM, Alfa AWUS036ACS, TP-Link Archer T2U Plus

**Software:**
- Linux — Kali Linux 2024+ recommended
- Go 1.24+
- Root access (for hardware operations; privileges are dropped after adapter setup)

**Core tool dependencies** (installed via package manager):

```
aircrack-ng  aireplay-ng  airodump-ng  airmon-ng
tshark       tcpdump      iw           hcxdumptool
nmap         mdk4         hostapd      dnsmasq
bettercap    mitmdump     responder    hashcat
macchanger   iodine       asleap
```

---

## Installation

```bash
# Clone
git clone https://github.com/eshanaswar/wifi-astra.git
cd wifi-astra

# Install dependencies (Kali/Debian)
sudo apt-get update && sudo apt-get install -y \
    aircrack-ng tshark tcpdump iw hcxdumptool nmap mdk4 \
    hostapd dnsmasq macchanger iodine hashcat \
    bettercap responder golang-go

# Build
go build -o bin/wifi-astra ./cmd/astra/

# Update OUI vendor database
sudo ./bin/wifi-astra update-oui
```

---

## Quick Start

### Interactive Session

```bash
sudo ./bin/wifi-astra start
```

The session wizard guides you through:
1. **Session management** — create new, resume previous, or delete old sessions
2. **Adapter assignment** — assign MONITOR and MANAGEMENT roles (locked for the session)
3. **A1 discovery** — mandatory first step; populates the network table
4. **Scope selection** — pick authorized BSSIDs from the scan results
5. **Module execution** — navigate category menus; completed/failed/missing-tools status shown inline
6. **Report generation** — structured report from all session findings

### Headless Autonomous Audit

```bash
sudo ./bin/wifi-astra start --config plan.json
```

```json
{
  "session_name": "Corp_Guest_Audit",
  "interface": "wlan1",
  "target_ssid": "Corp-Guest",
  "target_bssid": "AA:BB:CC:DD:EE:FF",
  "target_channel": 6,
  "modules": ["A1", "A2", "A3", "B1", "B2", "D1", "D3", "H1", "H2"]
}
```

### Verbose Logging

```bash
sudo ./bin/wifi-astra start -v
```

---

## Session Workflow

```
Start → Session Manager → Adapter Wizard → A1 Discovery
      → Scope Selection → Module Execution → Report → Cleanup Checklist
```

- The **cleanup checklist** verifies interfaces are restored, background processes are killed, and evidence is hashed before exit
- **Scope enforcement** is applied at the controller level — any module targeting an out-of-scope BSSID is blocked and logged as `SCOPE_VIOLATION` in `session_replay.log`
- **Inline cracking** is offered automatically after D1 (PMKID/handshake), D2 (WEP), D3 (WPS), and D5 (EAP) captures

---

## Evidence & Reporting

All artifacts are written to `sessions/<session-id>/evidence/`:

| File | Contents |
|------|----------|
| `<TC_ID>_run_<timestamp>.json` | Structured run log: module, target, tools, files, exit code, duration |
| `<TC_ID>_result.json` | Security finding for report generation |
| `<TC_ID>_failure.log` | Full stderr + last 50 lines of stdout (non-zero exit only) |
| `session_replay.log` | Chronological event stream: SESSION_START, MODULE_START, SCOPE_VIOLATION, etc. |
| `manifest.sha256` | Append-only SHA256 hash of every evidence file (chain of custody) |

Generate the final report from the main menu or:

```bash
sudo ./bin/wifi-astra report --session <session-id>
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Engagement workflow, tactical tips, best practices |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Framework internals, package structure, communication contract |
| [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Adding modules, writing parsers, coding standards |

---

## Development

```bash
# Run tests
go test ./...

# Lint all modules
shellcheck -S warning modules/*.sh

# Build (no output)
go build -o /dev/null ./cmd/astra/
```

All three must pass before committing. The `pre-commit` convention: build + shellcheck + test.

---

## Legal

Distributed under the **MIT License** — see [License.txt](License.txt).

> **This tool is for authorized security assessments only.**
> You must have explicit written permission from the network owner before use.
> Unauthorized use against networks you do not own or have permission to test is illegal.
> The developers assume no liability for misuse.
