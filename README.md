# 🛡️ WiFi-Astra: Advanced Wireless Security Assessment Framework

[![Go Report Card](https://goreportcard.com/badge/github.com/youruser/wifi-astra)](https://goreportcard.com/report/github.com/youruser/wifi-astra)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

WiFi-Astra is a professional-grade, Go-native orchestration framework designed for high-fidelity wireless security assessments. Unlike traditional script-heavy tools, WiFi-Astra combines a high-performance compiled core with modular attack wrappers to provide a stable, evidence-linked, and production-ready auditing experience.

---

## 🚀 Key Features

*   **Go-Native Core:** Built for performance and stability, replacing fragile Bash orchestration.
*   **Modular "Golden Wrappers":** 40+ assessment modules across 8 categories, easily extensible via simple Bash scripts.
*   **Guardian Privilege System:** Runs hardware-level operations as root but drops privileges for TUI and data processing to minimize attack surface.
*   **Forensic Reporting:** Generates professional HTML reports with direct links to PCAPs, handshakes, and logs.
*   **Self-Healing Hardware:** Automated recovery of interfaces stuck in monitor mode.
*   **Headless Mode:** Support for JSON mission plans for automated or scheduled audits.
*   **Deep Ingestion:** Intelligent parsing of Nmap XML, Bettercap JSON, and Airodump CSVs.

---

## 📂 Assessment Categories

| Category | Name | Focus Area |
|:---:|:---|:---|
| **A** | **Discovery** | SSID/BSSID mapping, Hidden SSID reveal, Client fingerprinting. |
| **B** | **Internal Recon** | Management interface exposure, DHCP/mDNS/LLDP leaks. |
| **C** | **Segmentation** | Egress filtering, RADIUS reachability, VLAN hopping. |
| **D** | **Encryption** | WPA2/3 handshakes, WEP cracking, WPS vulnerabilities. |
| **E** | **Design Flaws** | KRACK, FragAttacks, Kr00k, 802.11w resilience. |
| **F** | **Rogue AP** | Evil Twin deployment, Captive portal phishing. |
| **G** | **MITM** | ARP/DNS spoofing, SSL/TLS interception. |
| **H** | **Policy** | WIDS/WIPS detection, PMF configuration checks. |

---

## 🛠️ Installation & Setup

WiFi-Astra requires a Kali Linux or similar Debian-based environment with a wireless adapter capable of monitor mode and injection.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/youruser/wifi-astra.git
    cd wifi-astra
    ```

2.  **Run the Native Setup:**
    ```bash
    sudo ./bin/wifi-astra setup
    ```
    *This command will automatically install all required dependencies (aircrack-ng, nmap, bettercap, etc.) via apt.*

3.  **Update Hardware Data:**
    ```bash
    sudo ./bin/wifi-astra update-oui
    ```

---

## 🛰️ Quick Start

### Interactive Mission
```bash
sudo ./bin/wifi-astra start
```
Follow the wizard to create a session, select your hardware, and launch attack categories from the TUI cockpit.

### Headless Autonomous Audit
```bash
sudo ./bin/wifi-astra start --config mission_plan.json
```

---

## 📖 Documentation

*   [**User Guide**](docs/USER_GUIDE.md): Detailed usage instructions and attack methodology.
*   [**Developer Guide**](docs/DEVELOPER_GUIDE.md): Architecture overview and instructions for adding new modules.
*   [**Architecture**](docs/ARCHITECTURE.md): Deep dive into the framework's nervous system.

---

## ⚖️ License & Ethics

Distributed under the MIT License. See `License.txt` for more information.

**Warning:** This tool is for authorized security auditing only. Unauthorized use against networks without explicit permission is illegal. The developers assume no liability for misuse.
