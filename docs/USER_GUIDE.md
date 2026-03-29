# WiFi-Astra User Guide

This guide provides comprehensive instructions for conducting wireless security assessments using the WiFi-Astra framework.

---

## 🚦 Pre-Engagement Checklist

Before starting, ensure your environment is ready:
1.  **Hardware:** A wireless adapter that supports **Monitor Mode** and **Packet Injection** (e.g., Alfa AWUS036ACM).
2.  **OS:** Kali Linux, Parrot OS, or a Debian-based system with `sudo` privileges.
3.  **Dependencies:** Run the setup command to install all required tools:
    ```bash
    sudo ./bin/wifi-astra setup
    ```

---

## 🛰️ Running your first Mission

### 1. Interactive Start
Launch the tool and follow the wizard:
```bash
sudo ./bin/wifi-astra start
```
*   **Session Name:** Give your audit a descriptive name (e.g., `ClientX_Audit`).
*   **Interface Selection:** Select the adapter you wish to use. The tool will automatically check for stuck monitor interfaces.

### 2. Discovery (Phase A)
Start with module **A1 (Identify Networks)**. This will scan the airwaves and build your target map. 
*   Once finished, the tool will present a list of discovered networks.
*   Select your **Target SSID** to save it to the session configuration. This target will be used automatically for all subsequent attack modules.

### 3. Execution
Navigate through the Category menus to launch specific tests:
*   **Category D:** WPA Handshake Capture, WEP Cracking.
*   **Category F:** Rogue AP and Captive Portal phishing.
*   **Category G:** MITM and traffic interception.

### 4. Reporting
When the assessment is complete, select **"Generate Assessment Report"** from the main menu.
*   A professional HTML report will be generated in `sessions/<ID>/reports/`.
*   The report includes a mission summary, a map of all discovered hardware, and all vulnerabilities found during the audit.

---

## 🤖 Headless (Automated) Audits

For automated testing or scheduled audits, use a JSON mission plan:

**plan.json:**
```json
{
  "session_name": "Monthly_Audit",
  "interface": "wlan0",
  "target_ssid": "Corp-Guest",
  "modules": ["A1", "D1", "B1", "B2"]
}
```

**Execute:**
```bash
sudo ./bin/wifi-astra start --config plan.json
```

---

## 🧹 Maintenance

*   **Update OUI Data:** Keep your vendor mapping up to date:
    ```bash
    sudo ./bin/wifi-astra update-oui
    ```
*   **Cleanup:** Remove old sessions to save disk space:
    ```bash
    sudo ./bin/wifi-astra clean --older-than 30
    ```

---

## 🎯 Tactical Best Practices

*   **Intelligence Prompts:** Pay attention to the "Expert Notes" provided by the Go brain. If the tool warns that **PMF is Required**, do not waste time on active deauthentication; use **Passive Capture** or **CSA catalysts**.
*   **Signal Guard:** Ensure your target has an RSSI better than **-70dBm** for active roams (Category F) or deauths (Category D/E).
*   **Full Identity Spoofing:** When bypassing NACs (Category G), use the **Full Identity** option to clone MAC, Hostname, and DHCP Option 55 fingerprints simultaneously.
