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

## 🛠️ Quick Start

### 1. Installation
The toolkit requires a Kali Linux or Debian-based environment with root privileges.
```bash
sudo ./install.sh
```

### 2. Launch
Start the interactive framework launcher:
```bash
sudo wifi-astra
# OR
sudo ./wifi-astra.sh
```

### 3. Workflow
1.  **Run A1**: Perform an initial scan to identify surrounding networks.
2.  **Select Target**: Use the `[T] Select Target` option in any attack module to pull details from the A1 scan.
3.  **Execute & Pivot**: Move through categories (B-G) to validate specific vulnerabilities.
4.  **Generate Report**: Use `[R]` in the main menu to compile all evidence into a final report.

---

## 🛡️ Safety & Reliability
*   **Process Tracking**: All background tools (tcpdump, hostapd, yersinia) are tracked via PID.
*   **Safe Abort**: Press `Ctrl+\` to abort a single test case safely, or `Ctrl+C` to terminate the entire session and restore network interfaces.
*   **Dependency Management**: Modules perform pre-flight checks to ensure all required binary tools are installed.
