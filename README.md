# WiFi-Astra

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](License.txt)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=linux&logoColor=white)](https://www.kali.org/)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-critical?style=flat-square)](License.txt)
[![Shell: Bash](https://img.shields.io/badge/Modules-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](modules/)

**WiFi-Astra** is a professional wireless penetration testing framework for authorized security assessments. A compiled Go orchestrator manages session state, dual-adapter hardware roles, scope enforcement, NAT routing, and evidence collection — while 50 modular Bash scripts execute 802.11 attack techniques across the full engagement lifecycle.

> **Authorized use only.** You must have explicit written permission from the network owner before running any module. See [Legal](#legal).

---

## Table of Contents

- [Why WiFi-Astra](#why-wifi-astra)
- [Architecture Overview](#architecture-overview)
- [Dual-Adapter Design](#dual-adapter-design)
- [Assessment Categories](#assessment-categories)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Session Workflow](#session-workflow)
- [CLI Reference](#cli-reference)
- [Evidence & Reporting](#evidence--reporting)
- [Headless Mode](#headless-mode)
- [Documentation](#documentation)
- [Development](#development)
- [Contributing](#contributing)
- [Legal](#legal)

---

## Why WiFi-Astra

Most wireless pentests involve juggling a dozen separate tools, manually correlating output files across terminal windows, and hoping nothing is still running when the engagement ends. WiFi-Astra wraps the entire lifecycle into one coherent, auditable session:

| Without WiFi-Astra | With WiFi-Astra |
|--------------------|-----------------|
| Manually start/stop airodump-ng, hostapd, dnsmasq, hashcat, ... | Single command launches, monitors, and tears down each module |
| Scope left to the operator's memory | BSSID scope enforced at the controller — out-of-scope targets are blocked and logged |
| Evidence scattered across terminal history | Structured JSON findings, SHA256 manifest, replay log — chain of custody built-in |
| Cracking is a separate step after capture | Inline hashcat / asleap runs automatically after D1, D2, D3, D5 captures |
| Interfaces left in monitor mode after a crash | `hw.Recover()` restores interfaces on crash, panic, or SIGTERM |
| Rogue AP gets no internet routing without manual iptables | Controller owns NAT masquerade — set up before launch, torn down after |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Go Core (wifi-astra)                    │
│                                                                 │
│  ┌───────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │Session Manager│  │Hardware Layer│  │  Scope Enforcer       │ │
│  │(SQLite)       │  │(RoleRegistry)│  │  (BSSID allowlist)    │ │
│  └──────┬────────┘  └──────┬───────┘  └──────────┬────────────┘ │
│         └─────────────────┴──────────────────────┘              │
│                            │                                     │
│               ┌────────────▼────────────┐                       │
│               │   AssessmentController  │                       │
│               │  • NAT setup/teardown   │                       │
│               │  • Env var injection    │                       │
│               │  • Tactical prompts     │                       │
│               │  • Post-run cracking    │                       │
│               └────────────┬────────────┘                       │
└────────────────────────────┼────────────────────────────────────┘
                             │  injects full env (all config + prompt results)
                ┌────────────▼────────────┐
                │   Bash Module (*.sh)    │
                │   aircrack-ng           │
                │   hostapd / dnsmasq     │
                │   hcxdumptool           │
                │   tshark / tcpdump      │
                │   eaphammer / asleap    │
                └────────────┬────────────┘
                             │  $ASTRA_BIN record-finding / record-progress
                             ▼
                ┌────────────────────────┐
                │    Evidence Store      │
                │  sessions/<id>/        │
                │  evidence/             │
                │  manifest.sha256       │
                └────────────────────────┘
```

The Go core never touches the radio. All 802.11 operations run inside isolated Bash scripts that report findings back through a structured callback API.

---

## Dual-Adapter Design

WiFi-Astra enforces a strict two-role adapter model:

| Role | Env Var | Purpose |
|------|---------|---------|
| **MONITOR** | `MONITOR_INTERFACE` (e.g. `wlan0mon`) | Monitor mode — packet injection, sniffing, capture, active attacks |
| **AP** | `AP_INTERFACE` (e.g. `wlan1`) | Managed mode — hostapd for Evil Twin / KARMA / Captive Portal / rogue RADIUS |

The `InterfaceRoleRegistry` (`pkg/hw/roles.go`) assigns and locks these roles at session start. No attack module can use the AP interface for monitor-mode operations — the registry enforces this at the Go layer before the script even launches.

### Single-Adapter Degraded Mode

If only one adapter is available, Evil Twin modules (F1, F2, F3, D5) toggle the monitor card to managed mode for hostapd, then restore it via `airmon-ng start` on exit. The operator is warned via a pre-flight prompt that passive capture is suspended while the rogue AP is running.

### What the Controller Handles Automatically

When running a module with `REQS="nat"` (F1, F2, F3):
1. Detects the uplink interface via `ip route get 8.8.8.8` (re-detected live on each launch)
2. Enables IPv4 forwarding (`sysctl net.ipv4.ip_forward=1`)
3. Installs an idempotent `iptables MASQUERADE` rule on the uplink
4. Assigns `192.168.44.1/24` to the AP interface so dnsmasq can bind and serve DHCP
5. Tears everything down via deferred cleanup after the module exits

---

## Assessment Categories

| Cat | Name | Modules | Coverage |
|-----|------|---------|----------|
| **A** | Discovery & Recon | A1–A5 | Passive/active scan, BSSID correlation, hidden SSID, client fingerprinting, Wi-Fi 6/6E |
| **B** | Internal Network Recon | B1–B10 | Client isolation, mgmt exposure, CDP/LLDP, mDNS, SNMP, DHCP, IPv6, broadcasts, AP CVEs |
| **C** | Segmentation & Egress | C1–C5 | DNS split-horizon, private subnet routing, VLAN hopping, RADIUS reachability, egress bypass |
| **D** | Encryption & Auth Attacks | D1–D8 | WPA2 PMKID/handshake, WEP, WPS Pixie Dust, WPA3 Dragonblood, PEAP capture, OWE/WPA3 downgrade, EAP cert validation |
| **E** | Implementation Flaws | E1–E5 | KRACK, FragAttacks, PMF/deauth resilience, wireless fuzzing, Kr00k |
| **F** | Rogue AP & Evil Twin | F1–F5 | Evil Twin, KARMA/PineAP, captive portal, portal bypass, DNS tunneling |
| **G** | MitM & Pivoting | G1–G6 | ARP spoofing, SSL interception, DNS spoofing, NAC bypass, BSS Transition abuse, Responder NTLM |
| **H** | Policy & WIDS | H1–H2 | WIDS/WIPS detection, 802.11w PMF enforcement |

### Full Module List

<details>
<summary>Click to expand all 50 modules</summary>

| ID | Module | Key Tools | Description |
|----|--------|-----------|-------------|
| A1 | Identify Networks | airodump-ng, hcxdumptool | Passive/active WiFi discovery across 2.4/5/6 GHz |
| A2 | BSSID Correlation | airodump-ng | OUI grouping, sequential-BSSID clustering, evil twin detection |
| A3 | Hidden SSID Discovery | aireplay-ng, airodump-ng | Deauth-triggered probe response capture |
| A4 | Client Fingerprinting | airodump-ng, tshark | PNL leak detection, MAC randomization analysis |
| A5 | Wi-Fi 6/6E Detection | iw, hcxdumptool | HE capability mapping, 6 GHz environment profiling |
| B1 | Client Isolation | nmap, ping | Peer-to-peer traffic testing between wireless stations |
| B2 | Management Exposure | nmap | Web UI, SSH, SNMP, Telnet scanning of AP management interfaces |
| B3 | CDP/LLDP Leaks | tshark | Infrastructure device information via discovery protocols |
| B4 | mDNS/Bonjour Leaks | tcpdump, avahi-browse | Service enumeration via multicast DNS |
| B5 | SNMP Exposure | snmpwalk, onesixtyone | Community string discovery and SNMP enumeration |
| B6 | DHCP Analysis | tshark, nmap | Option fingerprinting, rogue DHCP server detection |
| B7 | IPv6 Leaks | tcpdump, nmap | SLAAC/DHCPv6 misconfiguration, IPv6 tunnel detection |
| B8 | Broadcast Leaks | tcpdump | Broadcast traffic analysis for sensitive cleartext protocols |
| B9 | AP Vulnerability | nmap, curl | Firmware fingerprinting and CVE correlation |
| B10 | AirSnitch | tshark, tcpdump | Passive wireless traffic sniffing and protocol analysis |
| C1 | DNS Resolution | dig, nmap | Split-horizon testing and cross-segment DNS resolution |
| C2 | Private Network Scan | nmap | Internal subnet discovery and route enumeration |
| C3 | VLAN Hopping | 802.1Q tagging | Double-tagging and VLAN hopping attacks |
| C4 | RADIUS Reachability | radtest, nmap | RADIUS server availability and configuration validation |
| C5 | Egress Filtering | curl, nmap, iodine | Bypass testing across DNS, HTTP, ICMP, and NTP egress paths |
| D1 | WPA Handshake | hcxdumptool, hashcat | PMKID capture (primary) + 4-way handshake; inline hashcat cracking |
| D2 | WEP Cracking | aireplay-ng, aircrack-ng | IV collection via ARP replay + fake-auth; inline key recovery |
| D3 | WPS Testing | bully, oneshot | Pixie Dust (primary); PIN brute-force fallback; PSK extraction |
| D4 | WPA3 Dragonblood | dragonslayer | SAE timing and cache side-channel testing (CVE-2019-9494) |
| D5 | EAP Attack | eaphammer, asleap | Rogue RADIUS for PEAP/MSCHAPv2 capture; inline asleap cracking |
| D6 | OWE Downgrade | hostapd, iw | OWE Transition Mode downgrade to open association |
| D7 | WPA3 Downgrade | hostapd, mdk4 | Active beacon manipulation to force WPA2 association |
| D8 | EAP Cert Validation | eaphammer | Client certificate validation testing for 802.1X misconfiguration |
| E1 | KRACK | custom scripts | Key reinstallation attack (CVE-2017-13077) |
| E2 | FragAttacks | custom scripts | Frame aggregation and fragmentation flaws (CVE-2020-24586/7/8) |
| E3 | Deauth Resilience | aireplay-ng, mdk4 | 802.11w PMF deauthentication spoofing resilience |
| E4 | Wireless Fuzzing | mdk4 | 802.11 frame fuzzing for wireless driver vulnerabilities |
| E5 | Kr00k | custom scripts | All-zero key vulnerability check (CVE-2019-15126) |
| F1 | Rogue AP / Evil Twin | hostapd, dnsmasq | Evil Twin with deauth/CSA catalyst; NAT routing; client capture |
| F2 | PineAP / KARMA | hostapd-mana, dnsmasq | KARMA attack against unassociated probe requests |
| F3 | Captive Portal | hostapd, dnsmasq, python3 | Vendor-fingerprinted portal (ISE, ClearPass, FortiGate, Meraki) |
| F4 | Portal Bypass | macchanger, curl | Captive portal bypass via MAC/IP/DNS techniques |
| F5 | DNS Tunnel | iodine | DNS tunneling capability detection |
| G1 | ARP Spoofing | bettercap | ARP spoofing and MitM positioning |
| G2 | SSL Interception | bettercap, mitmdump | Transparent TLS interception and certificate impersonation |
| G3 | DNS Spoofing | bettercap | DNS spoofing for targeted traffic redirection |
| G4 | NAC Bypass | macchanger, nmap | MAC + hostname + DHCP fingerprint cloning (ISE/ClearPass) |
| G5 | BSS Transition Attack | mdk4 | 802.11v BSS Transition Management steering abuse |
| G6 | Responder Pivot | responder | LLMNR/NBT-NS poisoning for NTLM hash capture |
| H1 | WIDS/WIPS Detection | mdk4, aireplay-ng | Attack signature injection with counter-measure analysis |
| H2 | PMF Check | tshark, iw | 802.11w RSN capability parsing — Required / Capable / None |

</details>

---

## Requirements

### Hardware

- **MONITOR adapter** — must support monitor mode and packet injection (required)
- **AP adapter** — any managed-mode adapter; used by Evil Twin modules (F1, F2, F3, D5) for hostapd (optional but strongly recommended)

Tested adapters:

| Adapter | Chipset | Bands | Notes |
|---------|---------|-------|-------|
| Alfa AWUS036ACM | MT7612U | 2.4/5 GHz | Most reliable for injection |
| Alfa AWUS036ACS | RTL8811AU | 2.4/5 GHz | Good 5 GHz injection |
| TP-Link Archer T2U Plus | RTL8812AU | 2.4/5 GHz | Budget option |
| Hak5 Wi-Fi Coconut | MT7612U ×14 | 2.4 GHz | Multi-channel passive capture |

Verify monitor mode support:

```bash
iw list | grep -A 10 "Supported interface modes"
# Should include: * monitor

sudo airmon-ng start wlan1
sudo aireplay-ng --test wlan1mon
```

### Software

- **OS**: Kali Linux 2024+ (recommended) or any Debian/Ubuntu derivative
- **Go**: 1.24+
- **Root access** for hardware operations

---

## Installation

```bash
# 1. Clone
git clone https://github.com/eshanaswar/wifi-astra.git
cd wifi-astra

# 2. Install all tool dependencies automatically
sudo ./bin/wifi-astra setup

# Or install manually on Kali/Debian:
sudo apt-get update && sudo apt-get install -y \
    aircrack-ng aireplay-ng airodump-ng airmon-ng \
    tshark tcpdump iw hcxdumptool nmap mdk4 \
    hostapd hostapd-mana dnsmasq macchanger \
    iodine hashcat bettercap responder golang-go

# 3. Build
go build -o bin/wifi-astra ./cmd/astra/

# 4. Fetch the IEEE OUI vendor database
sudo ./bin/wifi-astra update-oui

# 5. Verify
sudo ./bin/wifi-astra --help
```

---

## Quick Start

### Interactive Session

```bash
sudo ./bin/wifi-astra start
```

The session wizard walks you through:

```
1. Session Manager     — create, resume, or delete sessions
2. Adapter Setup       — assign MONITOR and AP adapter roles (locked for session)
3. A1 Discovery        — mandatory first step; populates network + client tables
4. Scope Selection     — pick authorized BSSIDs from discovered results
5. Module Execution    — category menus with live status (✓ / ✗ / [tools missing])
6. Report Generation   — HTML + Markdown report from all session findings
7. Cleanup Checklist   — verify interfaces restored, processes killed, evidence hashed
```

For verbose hardware and process logging:

```bash
sudo ./bin/wifi-astra start -v
```

---

## Session Workflow

```
Start
  │
  ▼
Session Manager ────── Create / Resume / Delete
  │
  ▼
Adapter Setup ───────── MONITOR role  →  wlan0  →  wlan0mon (monitor mode)
  │                     AP role       →  wlan1  (managed mode, for Evil Twin)
  │                     Roles locked in InterfaceRoleRegistry for session duration
  │                     Uplink interface auto-detected for NAT (F1/F2/F3)
  ▼
A1 Discovery ──────────  Populate network and client tables
  │
  ▼
Scope Selection ─────── Operator picks authorized BSSIDs from scan results
  │                     No manual BSSID entry — scope built from discovered data only
  ▼
Module Execution ─────── Pre-flight: tool availability checked per module
  │                     Scope validated before every launch
  │                     Tactical prompts: duration, catalyst, template, target client…
  │                     SCOPE_VIOLATION events logged to session_replay.log
  │                     Post-run: inline cracking for D1/D2/D3/D5
  ▼
Report Generation ─────  HTML and Markdown reports from all session findings
  │
  ▼
Cleanup Checklist ─────  Interfaces restored, processes killed, manifest verified
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `astra start` | Start or resume an interactive assessment session |
| `astra start --config plan.json` | Run a headless audit from a JSON plan |
| `astra start -v` | Start with verbose debug logging |
| `astra setup` | Install all required system dependencies via apt |
| `astra clean` | Remove session directories older than N days (default: 30) |
| `astra clean --dry-run` | List sessions that would be removed without deleting them |
| `astra clean -t 7` | Remove sessions older than 7 days |
| `astra update-oui` | Force-refresh the local IEEE OUI vendor database |
| `astra lookup-oui <MAC>` | Look up hardware vendor for a MAC address or OUI prefix |

**Global flags:**

| Flag | Description |
|------|-------------|
| `--config <path>` | YAML config file or JSON audit plan (triggers headless mode) |
| `--mod-dir <path>` | Path to module scripts directory (default: `./modules`) |
| `-v, --verbose` | Debug-level logging to console and session log file |

---

## Evidence & Reporting

All artifacts are written to `sessions/<session-id>/evidence/` — treated as an append-only forensic store.

### Per-Module Artifacts

| File | Contents |
|------|----------|
| `<TC_ID>_run_<timestamp>.json` | Structured run log: module, target, tools, exit code, duration |
| `<TC_ID>_result.json` | Security finding record for report generation |
| `<TC_ID>_failure.log` | Full stderr + last 50 lines of stdout (non-zero exit only) |
| `<TC_ID>_capture.pcap` | Raw packet capture (modules with `PCAP="yes"`) |

### Session-Level Artifacts

| File | Contents |
|------|----------|
| `session_replay.log` | Chronological event stream: SESSION_START, MODULE_START, SCOPE_VIOLATION, MODULE_END… |
| `EVIDENCE_INDEX.txt` | Human-readable listing of all artifacts with hash, module, and size |
| `manifest.sha256` | SHA256 hash of every evidence file — append-only chain of custody |

### Report Generation

Generate reports from the main menu or during a session:

```
Main Menu → Generate Assessment Report   (HTML)
Main Menu → Generate Markdown Report     (Markdown)
```

Both formats include findings by severity (CRITICAL / HIGH / MEDIUM / INFO), evidence paths, rationale, and module coverage statistics.

---

## Headless Mode

Run a fully automated audit without interactive prompts by supplying a JSON plan:

```bash
sudo ./bin/wifi-astra start --config plan.json
```

```json
{
  "session_name": "Corp_Guest_Audit_2026",
  "monitor_interface": "wlan1",
  "ap_interface": "wlan2",
  "modules": ["A1", "A2", "B1", "B2", "D1", "D3", "F1", "H1", "H2"],
  "capture_time": 60,
  "scan_time": 30
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `session_name` | No | Human-readable label for the session |
| `monitor_interface` | Yes | Physical interface to place in monitor mode |
| `ap_interface` | No | Dedicated AP adapter for Evil Twin modules |
| `modules` | Yes | Module IDs to run in order |
| `capture_time` | No | Capture duration per module in seconds (default: 60) |
| `scan_time` | No | Scan duration per module in seconds (default: 30) |

Modules detect headless mode via `ASTRA_HEADLESS=true` and skip interactive prompts. `SCOPE_VIOLATION` events are still enforced and logged.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Engagement workflow, adapter selection, tactical tips, module-by-module guidance |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Framework internals, package structure, module communication contract |
| [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Adding modules, writing parsers, contribution standards |
| [docs/ATTACK_SPECIFICATION.md](docs/ATTACK_SPECIFICATION.md) | Full technical specification for each attack module |

---

## Development

```bash
# Run tests
go test ./...

# Lint all module scripts
shellcheck -S warning modules/*.sh

# Build check (no output written)
go build -o /dev/null ./cmd/astra/
```

All three must pass before committing. No exceptions.

### Adding a Module

1. Create `modules/<id>_<name>.sh` with a complete `MODULE_META` header
2. Start with `set -euo pipefail`
3. Double-quote every variable expansion touching external data
4. Write all output to `"$SESSION_EVIDENCE_DIR/"`
5. Call `"$ASTRA_BIN" record-finding` and `record-progress` for callbacks
6. Add the module ID and required tools to `pkg/prereq/prereq.go` `ModuleToolMap`
7. Verify with `shellcheck -S warning modules/<your-module>.sh`

See [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) for the full contract.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes — all three checks must pass:
   ```bash
   go test ./...
   shellcheck -S warning modules/*.sh
   go build -o /dev/null ./cmd/astra/
   ```
4. Commit with a clear message describing the *why*, not just the *what*
5. Open a pull request against `main`

Please do not submit modules targeting specific vendors, individual users, or real-world infrastructure without appropriate responsible disclosure context.

---

## Legal

Distributed under the **MIT License** — see [License.txt](License.txt).

> **This tool is for authorized security assessments only.**
>
> You must have **explicit written permission** from the network owner before running any assessment module. Unauthorized use against networks you do not own or have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent laws in most jurisdictions.
>
> The authors and contributors assume **no liability** for misuse, damage, or legal consequences arising from use of this tool outside of properly authorized engagements.
