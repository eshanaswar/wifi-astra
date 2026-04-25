<div align="center">

```
  ██╗    ██╗██╗███████╗██╗      █████╗ ███████╗████████╗██████╗  █████╗
  ██║    ██║██║██╔════╝██║     ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
  ██║ █╗ ██║██║█████╗  ██║     ███████║███████╗   ██║   ██████╔╝███████║
  ██║███╗██║██║██╔══╝  ██║     ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
  ╚███╔███╔╝██║██║     ██║     ██║  ██║███████║   ██║   ██║  ██║██║  ██║
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Professional Wireless Penetration Testing Framework**

<br>

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](License.txt)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://www.kali.org/)
[![Use](https://img.shields.io/badge/Use-Authorized%20Only-critical?style=for-the-badge)](License.txt)

<br>

[![Modules](https://img.shields.io/badge/Modules-50-blueviolet?style=flat-square)](modules/)
[![Categories](https://img.shields.io/badge/Categories-8-blue?style=flat-square)](#assessment-categories)
[![Bands](https://img.shields.io/badge/Bands-2.4%20%7C%205%20%7C%206%20GHz-orange?style=flat-square)](#)
[![Shell](https://img.shields.io/badge/Modules-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](modules/)

<br>

A compiled **Go orchestrator** manages session state, dual-adapter hardware roles, scope enforcement, NAT routing, and evidence collection — while **50 modular Bash scripts** execute 802.11 attack techniques across the full engagement lifecycle.

</div>

<br>

> [!IMPORTANT]
> **Authorized use only.** You must have explicit written permission from the network owner before running any module against any wireless network. Unauthorized use is illegal. See [Legal](#legal).

---

## Terminal Preview

<details open>
<summary><strong>Main Assessment Menu</strong></summary>

```
  SESSION: Corp_Guest_Audit   TARGET: CorpGuest (AA:BB:CC:DD:EE:FF) CH6   IFACE: wlan0mon
  ──────────────────────────────────────────────────────────────────────────────────────────

  Assessment Menu

   1) Category A: Discovery & Recon (Passive/Active)          [5/5]  ✓
   2) Category B: Internal Network Recon (Connected)          [3/10]
   3) Category C: Segmentation & Egress Testing               [0/5]
   4) Category D: Encryption & Authentication Attacks         [2/8]
   5) Category E: Implementation & Design Flaws               [0/5]
   6) Category F: Rogue AP & Evil Twin Attacks                [0/5]
   7) Category G: Man-in-the-Middle (MITM) & Pivoting         [0/6]
   8) Category H: Policy & WIDS Validation                    [0/2]

   Switch Active Target  (current: CorpGuest / AA:BB:CC:DD:EE:FF)
   List All Available Modules
   Run Module Directly (by ID)
   Generate Assessment Report
   End Engagement (Cleanup Checklist)

  Select an option (? for help): _
```

</details>

<details>
<summary><strong>Mission Execution Feed (D1 — WPA2 Handshake Capture)</strong></summary>

```
  ══════════════════════════════════════════════════════════════════════════
  🚀 MISSION START: WPA Handshake Capture (D1)
  ──────────────────────────────────────────────────────────────────────────
  📝 Description: PMKID capture (primary) + 4-way handshake; inline hashcat

  📡 [Target Briefing]
     • Interface: wlan0mon
     • Target:    CorpGuest (AA:BB:CC:DD:EE:FF) [CH 6]

  🛠️  [Pre-flight Check]
     ✓ hcxdumptool    found at /usr/bin/hcxdumptool
     ✓ hashcat        found at /usr/bin/hashcat
     ✓ airodump-ng    found at /usr/bin/airodump-ng

  ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈
  🛰️  MISSION FEED:
  ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈

  [*] Enabling monitor mode on wlan0 → wlan0mon
  [*] Starting PMKID capture (hcxdumptool)...
  [+] PMKID captured: AA:BB:CC:DD:EE:FF → d4f3a2...
  [*] Sending deauth to accelerate 4-way handshake...
  [+] Handshake captured for CorpGuest

  [?] Run inline hashcat cracking? [Y/n]: Y
  [*] hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt
  [+] ✓ PSK CRACKED: P@ssw0rd2024

  ✅ MISSION COMPLETE
  ┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈

  📝 [Mission Observations]
     • [CRITICAL] WPA2 PSK Recovered: P@ssw0rd2024
       Rationale: Pre-shared key enables full traffic decryption and network access.

  📁 [Generated Evidence]
     • evidence/d1_capture.pcap
     • evidence/d1_run_20260424_143022.json
```

</details>

---

## Features

<table>
<tr>
<td width="50%">

**🎯 Scope Enforcement**
Every module target is validated against the operator-selected BSSID list before launch. Out-of-scope attempts are blocked at the controller level and logged as `SCOPE_VIOLATION` events — the module never runs.

</td>
<td width="50%">

**📡 Dual-Adapter Architecture**
Strict MONITOR + AP role separation. The monitor card handles injection and capture; the AP card stays in managed mode for Evil Twin and rogue RADIUS. Registry prevents cross-role misuse.

</td>
</tr>
<tr>
<td>

**⚡ Inline Credential Cracking**
hashcat, aircrack-ng, and asleap launch automatically after successful D1 (WPA2), D2 (WEP), D3 (WPS), and D5 (PEAP/MSCHAPv2) captures. PSKs are recorded as CRITICAL findings.

</td>
<td>

**🌐 Automatic NAT Routing**
The Go controller owns `iptables` masquerade for F-category rogue AP modules. Uplink re-detected live on each launch. AP interface IP assigned automatically. Teardown deferred on exit.

</td>
</tr>
<tr>
<td>

**🔗 Evidence Chain of Custody**
SHA256 manifest, append-only replay log, and structured JSON run records for every module. Built for professional engagement reporting and legal defensibility.

</td>
<td>

**🤖 Headless Autonomous Mode**
JSON audit plans drive the full assessment lifecycle without interactive prompts. Ideal for scheduled engagements, CI pipelines, or repeatable compliance checks.

</td>
</tr>
<tr>
<td>

**🛡️ Self-Healing Hardware**
`hw.Recover()` restores interfaces stuck in monitor mode on crash, panic, or SIGTERM. A cleanup checklist verifies every process is stopped before session exit.

</td>
<td>

**🔍 Full 802.11 Coverage**
50 modules across 8 categories. 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E). WPA2-PSK, WPA3-SAE, OWE, WPA-Enterprise. Discovery through exploitation through reporting.

</td>
</tr>
</table>

---

## Table of Contents

- [Why WiFi-Astra](#why-wifi-astra)
- [Architecture](#architecture)
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

Most wireless pentests involve juggling a dozen separate tools, manually correlating output files, and hoping nothing is still running when the engagement ends.

| Without WiFi-Astra | With WiFi-Astra |
|--------------------|-----------------|
| Manually start/stop airodump-ng, hostapd, dnsmasq, hashcat across terminals | Single workflow — launch, monitor, and tear down each module from one menu |
| Scope left to the operator's memory | BSSID scope enforced at the controller — out-of-scope targets blocked and logged |
| Evidence scattered across terminal history | Structured JSON findings, SHA256 manifest, replay log — chain of custody built-in |
| Cracking is a separate step after capture | Inline hashcat / asleap runs automatically after D1, D2, D3, D5 captures |
| Rogue AP with no internet routing (clients get nothing) | Controller owns NAT masquerade — set up before launch, torn down after, no manual iptables |
| Interfaces left in monitor mode after crash | `hw.Recover()` restores interfaces on crash, panic, or SIGTERM |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Go Core  (wifi-astra)                        │
│                                                                     │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐    │
│  │ Session Manager │  │  Hardware Layer  │  │ Scope Enforcer  │    │
│  │   (SQLite)      │  │ (RoleRegistry)   │  │ (BSSID list)    │    │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬────────┘    │
│           └───────────────────┴────────────────────┘              │
│                               │                                     │
│              ┌────────────────▼──────────────────┐                 │
│              │        AssessmentController        │                 │
│              │  • Scope validation                │                 │
│              │  • Tactical prompts                │                 │
│              │  • NAT setup / teardown            │                 │
│              │  • Full env injection              │                 │
│              │  • Post-run inline cracking        │                 │
│              └────────────────┬──────────────────┘                 │
└───────────────────────────────┼─────────────────────────────────────┘
                                │  injects full environment
               ┌────────────────▼──────────────────┐
               │        Bash Module  (*.sh)         │
               │   airodump-ng  hostapd  dnsmasq    │
               │   hcxdumptool  eaphammer  asleap   │
               │   bettercap    responder  hashcat   │
               └────────────────┬──────────────────┘
                                │  $ASTRA_BIN record-finding / record-progress
                                ▼
               ┌───────────────────────────────────┐
               │          Evidence Store            │
               │   sessions/<id>/evidence/          │
               │   manifest.sha256  replay.log      │
               └───────────────────────────────────┘
```

> [!NOTE]
> The Go core never touches the radio. All 802.11 operations run inside isolated Bash scripts that report findings back through a structured callback API (`record-finding`, `record-progress`).

---

## Dual-Adapter Design

WiFi-Astra enforces a strict two-role adapter model locked at session start:

| Role | Constant | Env Var | Purpose |
|------|----------|---------|---------|
| **MONITOR** | `hw.RoleMonitor` | `MONITOR_INTERFACE` (e.g. `wlan0mon`) | Monitor mode — injection, sniffing, capture, active attacks |
| **AP** | `hw.RoleAP` | `AP_INTERFACE` (e.g. `wlan1`) | Managed mode — hostapd for Evil Twin, KARMA, Captive Portal, rogue RADIUS |

The `InterfaceRoleRegistry` (`pkg/hw/roles.go`) enforces this at the Go layer. No attack module can request the AP interface for monitor-mode operations — `AssertMonitor()` blocks it before the script launches.

### Single-Adapter Degraded Mode

With one adapter, Evil Twin modules (F1, F2, F3, D5) toggle the monitor card to managed mode for hostapd, then restore it via `airmon-ng start` on exit. The operator is warned via a pre-flight prompt that passive capture is suspended while the rogue AP runs.

### Automatic NAT for Rogue AP Modules

When launching F1, F2, or F3 (modules with `REQS="nat"`), the controller automatically:

```
1. ip route get 8.8.8.8        →  detect uplink interface (live, not cached)
2. sysctl net.ipv4.ip_forward=1  →  enable forwarding
3. iptables -t nat -A POSTROUTING -o <uplink> -j MASQUERADE
4. ip addr add 192.168.44.1/24 dev <AP interface>   →  dnsmasq can now bind
5. [module runs]
6. iptables -t nat -D POSTROUTING ...   →  deferred teardown on exit
```

---

## Assessment Categories

| Cat | Name | Modules | Coverage |
|-----|------|:-------:|----------|
| **A** | Discovery & Recon | A1–A5 | Passive/active scan, BSSID correlation, hidden SSID, client fingerprinting, Wi-Fi 6/6E |
| **B** | Internal Network Recon | B1–B10 | Client isolation, mgmt exposure, CDP/LLDP, mDNS, SNMP, DHCP, IPv6, broadcast leaks, AP CVEs |
| **C** | Segmentation & Egress | C1–C5 | DNS split-horizon, private routing, VLAN hopping, RADIUS reachability, egress bypass |
| **D** | Encryption & Auth Attacks | D1–D8 | WPA2 PMKID/handshake, WEP, WPS Pixie Dust, WPA3 Dragonblood, PEAP capture, OWE/WPA3 downgrade |
| **E** | Implementation Flaws | E1–E5 | KRACK, FragAttacks, PMF/deauth resilience, wireless fuzzing, Kr00k |
| **F** | Rogue AP & Evil Twin | F1–F5 | Evil Twin, KARMA/PineAP, captive portal (vendor-fingerprinted), portal bypass, DNS tunneling |
| **G** | MitM & Pivoting | G1–G6 | ARP spoofing, SSL interception, DNS spoofing, NAC bypass, BSS Transition abuse, Responder NTLM |
| **H** | Policy & WIDS | H1–H2 | WIDS/WIPS detection & evasion, 802.11w PMF enforcement |

<details>
<summary><strong>Full Module List (50 modules)</strong></summary>

<br>

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
| B8 | Broadcast Leaks | tcpdump | Broadcast traffic analysis for cleartext protocols |
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
| E1 | KRACK | custom scripts | Key reinstallation attack testing (CVE-2017-13077) |
| E2 | FragAttacks | custom scripts | Frame aggregation/fragmentation vulnerabilities (CVE-2020-24586/7/8) |
| E3 | Deauth Resilience | aireplay-ng, mdk4 | 802.11w PMF deauthentication spoofing resilience |
| E4 | Wireless Fuzzing | mdk4 | 802.11 frame fuzzing for wireless driver vulnerabilities |
| E5 | Kr00k | custom scripts | All-zero key vulnerability check (CVE-2019-15126) |
| F1 | Rogue AP / Evil Twin | hostapd, dnsmasq | Evil Twin with deauth/CSA catalyst; auto NAT routing; client capture |
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
| H1 | WIDS/WIPS Detection | mdk4, aireplay-ng | Attack signature injection with counter-measure response analysis |
| H2 | PMF Check | tshark, iw | 802.11w RSN capability parsing — Required / Capable / None |

</details>

---

## Requirements

### Hardware

| Role | Requirement | Recommended Adapters |
|------|-------------|----------------------|
| **MONITOR** (required) | Monitor mode + packet injection | Alfa AWUS036ACM (MT7612U), Alfa AWUS036ACS (RTL8811AU) |
| **AP** (recommended) | Managed mode, any 802.11 adapter | Any second wireless adapter |

> [!TIP]
> Two adapters is strongly recommended. With a single adapter, Evil Twin modules (F1, F2, F3, D5) toggle between monitor and managed mode — passive capture stops while the rogue AP runs.

Verify monitor mode support on your adapter:

```bash
iw list | grep -A 10 "Supported interface modes"   # must include: * monitor
sudo airmon-ng start wlan1
sudo aireplay-ng --test wlan1mon                   # must show injection working
```

### Software

- **OS**: Kali Linux 2024+ (recommended) or any Debian/Ubuntu derivative
- **Go**: 1.24+
- **Root access** for hardware operations

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/eshanaswar/wifi-astra.git
cd wifi-astra

# 2. Install all tool dependencies automatically
sudo ./bin/wifi-astra setup

# — or install manually on Kali/Debian —
sudo apt-get update && sudo apt-get install -y \
    aircrack-ng aireplay-ng airodump-ng airmon-ng \
    tshark tcpdump iw hcxdumptool nmap mdk4 \
    hostapd hostapd-mana dnsmasq macchanger \
    iodine hashcat bettercap responder golang-go

# 3. Build the binary
go build -o bin/wifi-astra ./cmd/astra/

# 4. Fetch the IEEE OUI vendor database
sudo ./bin/wifi-astra update-oui

# 5. Verify
sudo ./bin/wifi-astra --help
```

---

## Quick Start

```bash
sudo ./bin/wifi-astra start
```

The session wizard walks you through:

```
1. Session Manager   →  Create, resume, or delete sessions
2. Adapter Setup     →  Assign MONITOR and AP adapter roles (locked for session)
3. A1 Discovery      →  Mandatory first step — populates network + client tables
4. Scope Selection   →  Pick authorized BSSIDs from discovered scan results
5. Module Execution  →  Category menus with live status (✓ / ✗ / [tools missing])
6. Report Generation →  HTML + Markdown report from all session findings
7. Cleanup Checklist →  Verify interfaces restored, processes killed, evidence hashed
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
Session Manager ──────── Create / Resume / Delete
  │
  ▼
Adapter Setup ─────────── MONITOR role  →  wlan0  →  wlan0mon (monitor mode)
  │                        AP role       →  wlan1  (managed mode, Evil Twin)
  │                        Roles locked in RoleRegistry for session duration
  │                        Uplink interface auto-detected for NAT (F1/F2/F3)
  ▼
A1 Discovery ──────────── Populate network and client tables across all bands
  │
  ▼
Scope Selection ──────── Operator selects authorized BSSIDs from scan results
  │                       No manual entry — scope is built from discovered data only
  ▼
Module Execution ─────── Pre-flight: tool availability checked per module
  │                       Scope validated against authorized list before every launch
  │                       Tactical prompts: duration, catalyst, template, target…
  │                       SCOPE_VIOLATION events logged to session_replay.log
  │                       Post-run: inline cracking offered for D1/D2/D3/D5
  ▼
Report Generation ─────── HTML and Markdown from all session findings
  │
  ▼
Cleanup Checklist ─────── Interfaces restored · processes killed · manifest verified
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `astra start` | Start or resume an interactive assessment session |
| `astra start --config plan.json` | Run a headless audit from a JSON plan |
| `astra start -v` | Start with verbose debug logging |
| `astra setup` | Install all required system dependencies via apt |
| `astra clean` | Remove session directories older than 30 days |
| `astra clean -t 7` | Remove sessions older than 7 days |
| `astra clean --dry-run` | List sessions that would be removed without deleting |
| `astra update-oui` | Force-refresh the local IEEE OUI vendor database |
| `astra lookup-oui <MAC>` | Look up hardware vendor for a MAC address or OUI prefix |

**Global flags:**

| Flag | Description |
|------|-------------|
| `--config <path>` | YAML config file or JSON audit plan (JSON triggers headless mode) |
| `--mod-dir <path>` | Path to module scripts directory (default: `./modules`) |
| `-v, --verbose` | Debug-level logging to console and session log file |

---

## Evidence & Reporting

All artifacts are written to `sessions/<session-id>/evidence/` — an append-only forensic store.

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
| `session_replay.log` | Chronological event stream: `SESSION_START` → `MODULE_START` → `SCOPE_VIOLATION` → `MODULE_END` |
| `EVIDENCE_INDEX.txt` | Human-readable listing of all artifacts with hash, module, and size |
| `manifest.sha256` | SHA256 hash of every evidence file — append-only chain of custody |

Generate reports from the main menu:

```
Main Menu → Generate Assessment Report   →  Full HTML report
Main Menu → Generate Markdown Report     →  Markdown for tickets / wikis
```

Both formats include findings by severity, evidence file paths, rationale, and module coverage statistics.

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
|-------|:--------:|-------------|
| `session_name` | No | Human-readable label for the session |
| `monitor_interface` | Yes | Physical interface to place in monitor mode |
| `ap_interface` | No | Dedicated AP adapter for Evil Twin modules |
| `modules` | Yes | Module IDs to run in order |
| `capture_time` | No | Capture duration per module in seconds (default: 60) |
| `scan_time` | No | Scan duration per module in seconds (default: 30) |

Modules detect headless mode via `ASTRA_HEADLESS=true` and skip interactive prompts. Scope enforcement and `SCOPE_VIOLATION` logging remain active.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Engagement workflow, adapter selection, tactical tips, best practices |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Framework internals, package structure, module communication contract |
| [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Adding modules, writing parsers, coding standards |
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

> [!WARNING]
> All three checks must pass before committing. No exceptions.

### Adding a Module

1. Create `modules/<id>_<name>.sh` with a complete `MODULE_META` header
2. Start with `set -euo pipefail` and double-quote all external variable expansions
3. Write all output to `"$SESSION_EVIDENCE_DIR/"`
4. Use `"$ASTRA_BIN" record-finding` and `record-progress` for findings and progress
5. Add the module ID and required tools to `pkg/prereq/prereq.go` `ModuleToolMap`
6. Verify: `shellcheck -S warning modules/<your-module>.sh`

See [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) for the full contract and MODULE_META field reference.

---

## Contributing

1. Fork the repository and create a feature branch: `git checkout -b feat/your-feature`
2. Make changes — all three checks must pass (`go test`, `shellcheck`, `go build`)
3. Write a commit message that explains *why*, not just *what*
4. Open a pull request against `main`

Please do not submit modules that target specific vendors, individual users, or real-world infrastructure outside the context of responsible disclosure or authorized research.

---

## Legal

Distributed under the **MIT License** — see [License.txt](License.txt).

> [!CAUTION]
> **This tool is for authorized security assessments only.**
>
> You must have **explicit written permission** from the network owner before running any assessment module. Unauthorized use against networks you do not own or have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in most jurisdictions.
>
> The authors and contributors accept **no liability** for misuse, damage, or legal consequences arising from use of this tool outside of properly authorized engagements.
