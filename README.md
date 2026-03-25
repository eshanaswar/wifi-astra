# 🛡️ WiFi-Astra: Wireless Security Assessment Framework

> **Automated, enterprise-grade wireless penetration testing toolkit.**
> Aligned with industry-standard assessment methodologies for Guest and Corporate WiFi security.

## 🚀 Overview

WiFi-Astra is a comprehensive, modular Bash framework designed for end-to-end wireless security auditing. It automates **35+ specialized test cases**, moving from passive reconnaissance to advanced protocol exploitation and policy validation.

### Key Capabilities
*   **Modern Protocol Support**: Native modules for **WPA3-SAE (Dragonblood)**, **OWE (Enhanced Open)**, and **WPA-Enterprise (802.1X)**.
*   **Advanced Exploitation**: Integrated tests for **Kr00k**, **FragAttacks**, and **KRACK** vulnerabilities.
*   **Intelligent UI**: Interactive TUI with session persistence, resume support, and a unified progress tracking system.
*   **Dynamic Customization**:
    *   **Target Auto-Config**: Select targets directly from scan results (`A1`) to automatically sync BSSID, SSID, and Channel across all attack modules.
    *   **Custom Rogue APs**: Fully customizable SSIDs and phishing templates for Evil Twin and Captive Portal attacks.
*   **Professional Reporting**: Generates structured JSON artifacts and high-quality assessment reports.

---

## 📂 Assessment Categories

| Cat | Name | Description |
|:---:|:---|:---|
| **A** | **Discovery** | Passive/Active SSID discovery, BSSID correlation, and client profiling. |
| **B** | **Infrastructure** | Network service leaks (mDNS, CDP, LLDP), IPv6 RAs, and AP vulnerability mapping. |
| **C** | **Segmentation** | VLAN hopping, RADIUS reachability, and egress filtering policy validation. |
| **D** | **Encryption** | WPA3 Dragonblood, OWE Downgrade, WPA Handshakes, and legacy WEP. |
| **E** | **Protocols** | Hardware-level bugs like Kr00k (all-zero keys), FragAttacks, and KRACK. |
| **F** | **Rogue AP** | Multi-mode Evil Twin, PineAP-style Karma attacks, and Captive Portal bypass. |
| **G** | **MITM** | ARP spoofing, SSL/TLS interception, and DNS/Responder poisoning. |
| **H** | **Defense** | WIDS/WIPS detection validation and auto-containment testing. |

---

## 🚀 Quick Start

### 1. Installation
The toolkit is designed for **Kali Linux**.
```bash
sudo ./install.sh
```

### 2. Documentation
- 📖 **[User Guide](docs/USER_GUIDE.md)**: Full workflow and report interpretation.
- 🛠️ **[Developer Guide](docs/DEVELOPER_GUIDE.md)**: Library API and module creation.

### 3. Launch
Start the interactive framework launcher:
```bash
sudo wifi-astra
```

## 🛡️ Safety & Reliability
- **Process Tracking**: All background tools are tracked via a centralized PID registry.
- **Reliable Cleanup**: Automatic interface scrubbing and service restoration on exit.
- **Data Integrity**: Atomic writes and rolling backups for all session data.
- **Professional Reporting**: Standardized findings with automated confidence scoring.
