# WiFi-Astra: User Guide

Welcome to the **WiFi-Astra** User Guide. This document provides everything you need to know to perform professional wireless security assessments using the framework.

## 📋 Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Workflow Walkthrough](#workflow-workflow)
5. [Reporting & Evidence](#reporting--evidence)
6. [Safety & Best Practices](#safety--best-practices)

---

## 1. Introduction
WiFi-Astra is an automated, menu-driven framework for auditing wireless networks. It moves beyond simple handshake capturing, offering 35+ test cases covering infrastructure leaks, segmentation vulnerabilities, and modern protocol flaws (WPA3, Kr00k, etc.).

## 2. Installation
The toolkit is designed for **Kali Linux**.

```bash
git clone <repository_url>
cd WiFi_PT
sudo ./install.sh
```

The installer will:
- Install all required binary dependencies (`aircrack-ng`, `nmap`, `jq`, etc.).
- Configure system settings.
- Create a global `wifi-astra` alias.

## 3. Core Concepts
- **Session-Based**: Every audit is a session. State is saved automatically. You can resume an interrupted audit at any time.
- **Centralized Storage**: All data is stored in `~/.wifi-astra/sessions/<session_id>/`.
- **Target Sync**: Once you identify a target network in module `A1`, its details (SSID, BSSID, Channel) are automatically synced to all other modules.

## 4. Workflow Walkthrough

### Step 1: Launch
```bash
sudo wifi-astra
```

### Step 2: Reconnaissance (Category A)
Always start with **A1 (Identify All Wireless Networks)**. This uses monitor mode to map the environment.
- After the scan, select your **Target SSID**.
- (Optional) Select an **Internal SSID** to test for data leaks from the corporate network.

### Step 3: Network Testing (Category B & C)
Connect your managed interface to the target WiFi and run modules like:
- **B1 (Client Isolation)**: Test if guests can see each other.
- **C2 (Private Network Scan)**: Check if you can reach internal corporate subnets.

### Step 4: Protocol Attacks (Category D & E)
Switch back to monitor mode for active attacks:
- **D1 (WPA Handshake)**: Capture and test PSK strength.
- **E2 (FragAttacks)**: Test for hardware-level 802.11 vulnerabilities.

### Step 5: MITM & Rogue AP (Category F & G)
- **F1 (Rogue AP)**: Deploy an Evil Twin to test client susceptibility.
- **G2 (SSL Interception)**: Attempt to intercept encrypted traffic.

## 5. Reporting & Evidence
At any point, or at the end of your audit, select **[R] Generate Report** from the main menu.
- **TXT Report**: Quick summary for the console.
- **HTML Report**: Professional, responsive dashboard with grouped findings.
- **PDF Report**: Executive-ready document (requires `wkhtmltopdf`).

All raw evidence (PCAPs, logs) is available in the `evidence/` folder of your session.

## 6. Safety & Best Practices
- **Legal Authorization**: Only audit networks you have explicit written permission to test.
- **Interface Management**: If your interface gets "stuck", the framework will attempt to "Scrub" it on exit.
- **System Stability**: The toolkit automatically stops conflicting services (like NetworkManager) during monitor mode tasks and restores them afterwards.
