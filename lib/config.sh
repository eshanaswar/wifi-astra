#!/usr/bin/env bash
#===============================================================================
#  lib/config.sh — Global Configuration & Variables
#===============================================================================

#--- Version ---
export TOOLKIT_VERSION="1.0"

#--- Global Tool Paths ---
declare -gA TOOL_PATHS
TOOL_PATHS=(
    ["airmon-ng"]=""
    ["airodump-ng"]=""
    ["aireplay-ng"]=""
    ["hcxdumptool"]=""
    ["hcxpcapngtool"]=""
    ["nmap"]=""
    ["masscan"]=""
    ["tcpdump"]=""
    ["tshark"]=""
    ["nbtscan"]=""
    ["onesixtyone"]=""
    ["snmpwalk"]=""
    ["searchsploit"]=""
    ["nuclei"]=""
    ["msfconsole"]=""
    ["iodine"]=""
    ["ptunnel-ng"]=""
    ["chisel"]=""
    ["yersinia"]=""
    ["fping"]=""
    ["arping"]=""
    ["avahi-browse"]=""
    ["dig"]=""
    ["nslookup"]=""
    ["ip"]=""
    ["jq"]=""
    ["curl"]=""
    ["wget"]=""
    ["mdk4"]=""
    ["wash"]=""
    ["reaver"]=""
    ["bully"]=""
    ["hostapd"]=""
    ["dnsmasq"]=""
    ["macchanger"]=""
    ["aircrack-ng"]=""
    ["packetforge-ng"]=""
    ["airsnitch"]=""
    ["eaphammer"]=""
    ["hostapd-mana"]=""
    ["iw"]=""
)
export TOOL_PATHS

#--- Configuration Loading ---
# Load from /etc if available, otherwise use defaults
if [[ -f "/etc/wifi-astra.conf" ]]; then
    source "/etc/wifi-astra.conf"
fi

#--- Directory Structure ---
export LIB_DIR="${SCRIPT_DIR}/lib"
export MOD_DIR="${SCRIPT_DIR}/modules"
export EVIDENCE_BASE="${OUTPUT_DIR:-${SCRIPT_DIR}/evidence}"
export WORDLIST_DIR="${SCRIPT_DIR}/wordlists"
export ROCKYOU_PATH="/usr/share/wordlists/rockyou.txt"

#--- Create directories if missing ---
mkdir -p "$EVIDENCE_BASE" "$WORDLIST_DIR"

#--- Session Variables (set during init) ---
export SESSION_ID=""
export SESSION_DIR=""
export SESSION_STATE_FILE=""
export SESSION_LOG_DIR=""
export SESSION_EVIDENCE_DIR=""
export SESSION_REPORT_DIR=""
export SESSION_RESULTS_DIR=""

#--- Color Codes ---
export C_RESET=$'\033[0m'
export C_RED=$'\033[1;31m'
export C_GREEN=$'\033[1;32m'
export C_YELLOW=$'\033[1;33m'
export C_BLUE=$'\033[1;34m'
export C_MAGENTA=$'\033[1;35m'
export C_CYAN=$'\033[1;36m'
export C_WHITE=$'\033[1;37m'
export C_GRAY=$'\033[0;37m'
export C_BOLD=$'\033[1m'
export C_DIM=$'\033[2m'
export C_BLINK=$'\033[5m'
export C_BG_RED=$'\033[41m'
export C_BG_GREEN=$'\033[42m'
export C_BG_YELLOW=$'\033[43m'

#--- Status Icons (text only for alignment, colors added in menu.sh) ---
export ICON_DONE="[✓]"
export ICON_PENDING="[ ]"
export ICON_FAIL="[x]"
export ICON_WARN="[!]"
export ICON_INFO="[i]"
export ICON_RUNNING="[>]"
export ICON_CRITICAL="*"
export ICON_LOCK="[L]"
export ICON_KEY="[K]"

#--- Test Case Registry ---
# Key: MODULE_ID (e.g. A1, B3, G2)
# Value Format: NAME|CATEGORY|DEPENDENCIES|CRITICAL|DESCRIPTION
# Dependencies: comma-separated module IDs. "none" if no deps.
declare -gA TC_REGISTRY
TC_REGISTRY=(
    # ── A: Passive Wireless Recon ──
    ["A1"]="Identify All Wireless Networks|A|none|no|Enumerate all SSIDs, BSSIDs, channels, encryption using monitor mode"
    ["A2"]="BSSID Correlation Analysis|A|A1|no|Map BSSIDs to same controller, detect infra overlap"
    ["A3"]="Discover Hidden SSIDs|A|A1|no|Deauthenticate and capture hidden SSID probe responses"
    ["A4"]="Client Fingerprinting & Profiling|A|none|no|Passive device profiling via probe requests, OUI lookup, signal mapping"
    # ── B: Network & Service Recon ──
    ["B1"]="Client-to-Client Isolation|B|none|no|Test if connected clients on target WiFi can see each other"
    ["B2"]="Gateway & WLC Management Exposure|B|none|no|Check if gateway/WLC admin panels are reachable from target WiFi"
    ["B3"]="CDP/LLDP Information Leaks|B|none|no|Capture CDP/LLDP frames leaking infrastructure details"
    ["B4"]="mDNS/Bonjour Information Leaks|B|none|no|Detect mDNS/Bonjour service announcements from corporate devices"
    ["B5"]="SNMP Exposure|B|none|no|Probe for SNMP services with default/common communities"
    ["B6"]="DHCP Architecture Analysis|B|none|no|Analyze DHCP configuration and check for rogue DHCP servers"
    ["B7"]="IPv6 SLAAC & RA Leaks|B|none|no|Listen for corporate IPv6 router advertisements bleeding into target VLAN"
    ["B8"]="Broadcast & Multicast Leaks|B|none|no|Analyze UDP traffic for SSDP/LLMNR/NetBIOS storms bleeding from corporate"
    ["B9"]="AP/WLC Vulnerability Assessment|B|B2|no|Fingerprint APs, check firmware CVEs, test default credentials"
    ["B10"]="AirSnitch — Client Isolation Bypass|B|B1|no|Test client isolation bypass via GTK abuse, gateway bouncing, port stealing (airsnitch)"
    # ── C: Segmentation & Filtering ──
    ["C1"]="Internal DNS Resolution|C|none|no|Test if target WiFi DNS resolves internal hostnames"
    ["C2"]="Private Network Scan|C|none|yes|Scan RFC1918 ranges for reachable corporate hosts from target WiFi"
    ["C3"]="VLAN Hopping|C|none|no|Attempt 802.1Q double-tagging and DTP spoofing to reach other VLANs"
    ["C4"]="RADIUS / NAC Server Reachability|C|none|yes|Attempt direct communication to auth servers via restricted ports"
    ["C5"]="Egress Filtering Assessment|C|none|no|Test which outbound ports and protocols are allowed from target WiFi"
    # ── D: Encryption & Auth Attacks ──
    ["D1"]="WPA Handshake & PMKID Capture|D|A1|yes|Capture WPA PMKID and 4-way handshakes, test PSK strength"
    ["D2"]="WEP Network Cracking [Past Attacks]|D|A1|no|Detect and crack legacy WEP networks via ARP replay, fragmentation, ChopChop"
    ["D3"]="WPS PIN Attack|D|A1|no|Scan for WPS-enabled APs and test PIN brute-force vulnerability"
    ["D4"]="WPA3 Dragonblood|D|A1|yes|Test WPA3-SAE timing side-channel, transition mode downgrade (CVE-2019-9494+)"
    ["D5"]="WPA-Enterprise / EAP Attack|D|A1|yes|Deploy rogue RADIUS to capture EAP credentials and test cert validation"
    ["D6"]="OWE Transition Downgrade|D|A1|no|Test for OWE transition mode vulnerability (force fallback to open)"
    ["D7"]="WPA3 Active Downgrade|D|A1|yes|Perform active transition mode downgrade attack via rogue WPA2 AP"
    # ── E: Protocol Vulnerability ──
    ["E1"]="KRACK Attack Testing|E|A1|yes|Test WPA2 key reinstallation (CVE-2017-13077), nonce reuse, GTK reinstall"
    ["E2"]="FragAttacks Testing|E|A1|no|Test 802.11 fragmentation/aggregation vulns (CVE-2020-24586+)"
    ["E3"]="Deauth Resilience (802.11w/MFP)|E|A1|no|Test 802.11w MFP protection and deauthentication attack resilience"
    ["E4"]="Wireless Fuzzing & AP Stress|E|A1|no|Auth/probe/assoc flood, Michael MIC, malformed frames to test AP robustness"
    ["E5"]="Kr00k Vulnerability Test|E|A1|no|Test for all-zero encryption key upon disassociation (CVE-2019-15126)"
    # ── F: Rogue AP & Client Attacks ──
    ["F1"]="Rogue AP / Evil Twin|F|A1|yes|Deploy evil twin AP to test client susceptibility and WIDS response"
    ["F2"]="PineAP / Karma Attack|F|A1|yes|Beacon spam, Karma/MANA auto-probe response, Dogma deauth+karma"
    ["F3"]="Captive Portal Pre-Auth Bypass|F|none|no|Optional: Test for DNS and ICMP tunneling before authentication"
    ["F4"]="Captive Portal Bypass|F|F3|no|Test MAC cloning, DNS/ICMP tunneling to bypass captive portal"
    # ── G: MITM & Network Attacks ──
    ["G1"]="ARP Spoofing / MITM Test|G|B1|yes|Attempt to ARP-spoof the gateway to intercept traffic"
    ["G2"]="SSL/TLS Interception & MITM|G|B1|yes|ARP spoof + SSL strip to test HSTS enforcement and credential exposure"
    ["G3"]="DNS Spoofing & Poisoning|G|none|yes|LLMNR/NBT-NS/WPAD poisoning via Responder, NTLMv2 hash capture"
    ["G4"]="NAC / 802.1X Bypass|G|C2|no|Test MAC whitelist bypass, VLAN assignment, and NAC exception discovery"
    ["G5"]="BSS Transition Roaming Attack|G|A1,F1|yes|Exploit 802.11v BTM frames to force clients to roam to rogue AP"
    # ── H: Defense Validation ──
    ["H1"]="WIDS/WIPS Detection|H|A1|no|Test if infrastructure detects deauth, fake AP, and auth flood attacks"
    ["H2"]="PMF Enforcement|H|A1|yes|Verify if 802.11w Protected Management Frames are enforced"
)

#--- Category Labels ---
declare -gA CATEGORY_LABELS
CATEGORY_LABELS=(
    ["A"]="A — PASSIVE WIRELESS RECON"
    ["B"]="B — NETWORK & SERVICE RECON"
    ["C"]="C — SEGMENTATION & FILTERING"
    ["D"]="D — ENCRYPTION & AUTH ATTACKS"
    ["E"]="E — PROTOCOL VULNERABILITY"
    ["F"]="F — ROGUE AP & CLIENT ATTACKS"
    ["G"]="G — MITM & NETWORK ATTACKS"
    ["H"]="H — DEFENSE VALIDATION"
)

#--- Category Display Order ---
declare -ga CATEGORY_ORDER=("A" "B" "C" "D" "E" "F" "G" "H")

#--- Module Display Order (within each category, auto-sorted) ---
declare -ga TC_ORDER=(
    "A1" "A2" "A3" "A4"
    "B1" "B2" "B3" "B4" "B5" "B6" "B7" "B8" "B9" "B10"
    "C1" "C2" "C3" "C4" "C5"
    "D1" "D2" "D3" "D4" "D5" "D6" "D7"
    "E1" "E2" "E3" "E4" "E5"
    "F1" "F2" "F3" "F4"
    "G1" "G2" "G3" "G4" "G5"
    "H1" "H2"
)

#--- Input Requirements per Module ---
# Comma-separated: monitor_iface, managed_iface, dual_iface,
#                   target_ssid, target_bssid, target_channel,
#                   gateway_ip, my_ip, dns_server
declare -gA TC_REQUIREMENTS
TC_REQUIREMENTS=(
    # A: Passive Recon — need monitor mode interface
    ["A1"]="monitor_iface"
    ["A2"]="monitor_iface,target_ssid"
    ["A3"]="monitor_iface,target_ssid,target_bssid"
    ["A4"]="monitor_iface"
    # B: Network Recon — need managed/connected interface
    ["B1"]="managed_iface,gateway_ip"
    ["B2"]="managed_iface,gateway_ip"
    ["B3"]="managed_iface"
    ["B4"]="managed_iface"
    ["B5"]="managed_iface,gateway_ip"
    ["B6"]="managed_iface"
    ["B7"]="managed_iface"
    ["B8"]="managed_iface"
    ["B9"]="managed_iface,gateway_ip"
    ["B10"]="managed_iface,gateway_ip,monitor_iface"
    # C: Segmentation — need managed interface + network info
    ["C1"]="managed_iface,dns_server"
    ["C2"]="managed_iface,gateway_ip"
    ["C3"]="managed_iface"
    ["C4"]="managed_iface,gateway_ip"
    ["C5"]="managed_iface"
    # D: Encryption Attacks — need monitor mode + target info
    ["D1"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["D2"]="monitor_iface,target_ssid"
    ["D3"]="monitor_iface,target_ssid"
    ["D4"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["D5"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["D6"]="monitor_iface,target_ssid,target_bssid,target_channel"
    # E: Protocol Attacks — need monitor mode + target info
    ["E1"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["E2"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["E3"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["E4"]="monitor_iface,target_ssid,target_bssid,target_channel"
    ["E5"]="monitor_iface,target_ssid,target_bssid,target_channel"
    # F: Rogue AP — need dual interface for some, monitor for others
    ["F1"]="dual_iface,target_ssid,target_channel"
    ["F2"]="monitor_iface,target_ssid,target_channel"
    ["F3"]="managed_iface"
    ["F4"]="managed_iface"
    # G: MITM — need managed/connected interface + gateway
    ["G1"]="managed_iface,gateway_ip"
    ["G2"]="managed_iface,gateway_ip"
    ["G3"]="managed_iface,my_ip"
    ["G4"]="managed_iface,gateway_ip,my_ip"
    # H: Defense — need monitor mode + target info
    ["H1"]="monitor_iface,target_ssid,target_bssid,target_channel"
)

#--- PCAP capture policy per test case (Wave 1 core subset) ---
# If TC_PCAP_REQUIRED[TC]="yes", the runner will start a ${TOOL_PATHS[tcpdump]} capture and
# (if available) run a ${TOOL_PATHS[tshark]} decode profile after the module finishes.
declare -gA TC_PCAP_REQUIRED
TC_PCAP_REQUIRED=(
    ["A1"]="no"
    ["A2"]="no"
    ["A3"]="no"
    ["A4"]="no"
    ["B3"]="yes"
    ["B4"]="yes"
    ["B6"]="yes"
    ["B7"]="yes"
    ["B8"]="yes"
    ["B10"]="yes"
    ["D1"]="yes"
    ["D2"]="yes"
    ["D3"]="yes"
    ["D4"]="yes"
    ["D5"]="yes"
    ["D6"]="no"
    ["E1"]="yes"
    ["E2"]="yes"
    ["E3"]="yes"
    ["E4"]="yes"
    ["E5"]="no"
    ["F1"]="yes"
    ["F2"]="yes"
    ["G1"]="yes"
    ["G2"]="yes"
    ["G3"]="yes"
    ["G4"]="yes"
    ["H1"]="yes"
    ["C3"]="yes"
)

#--- Tshark decode profiles per test case (Wave 1 core subset) ---
# Supported: dns, l2_discovery, wifi_mgmt, dhcp, mitm_arp_tls, none
declare -gA TC_DECODE_PROFILE
TC_DECODE_PROFILE=(
    ["A1"]="wifi_mgmt"
    ["A2"]="wifi_mgmt"
    ["A3"]="wifi_mgmt"
    ["A4"]="wifi_mgmt"
    ["B3"]="l2_discovery"
    ["B4"]="dns"
    ["B6"]="dhcp"
    ["B7"]="none"
    ["B8"]="l2_discovery"
    ["B10"]="wifi_mgmt"
    ["D1"]="wifi_mgmt"
    ["D2"]="wifi_mgmt"
    ["D3"]="wifi_mgmt"
    ["D4"]="wifi_mgmt"
    ["D5"]="wifi_mgmt"
    ["D6"]="wifi_mgmt"
    ["E1"]="wifi_mgmt"
    ["E2"]="wifi_mgmt"
    ["E3"]="wifi_mgmt"
    ["E4"]="wifi_mgmt"
    ["E5"]="wifi_mgmt"
    ["F1"]="dhcp"
    ["F2"]="dhcp"
    ["G1"]="mitm_arp_tls"
    ["G2"]="mitm_arp_tls"
    ["G3"]="l2_discovery"
    ["H1"]="wifi_mgmt"
    ["G4"]="dhcp"
    ["C3"]="none"
)

#--- TC Status Tracking (in-memory, persisted to session file) ---
declare -gA TC_STATUS
# Possible values: "not_run" "running" "done" "failed" "aborted"
for _tc in "${TC_ORDER[@]}"; do
    TC_STATUS["$_tc"]="not_run"
done

#--- TC Result Data (in-memory cache) ---
declare -gA TC_RESULTS_FILE
# Maps TC-ID to its results JSON file path

#--- Global Runtime State ---
export CURRENT_TC=""            # Currently running TC-ID
export CURRENT_TC_PID=""        # PID of current background process (if any)
export TC_ABORT_REQUESTED=0     # Flag: Ctrl+\ was pressed
export SCRIPT_EXIT_REQUESTED=0  # Flag: Ctrl+C was pressed

#--- Network Configuration (populated during tests) ---
export WIFI_INTERFACE=""        # e.g., wlan0
export MONITOR_INTERFACE=""     # e.g., wlan0mon
export GUEST_SSID=""            # Target network SSID (GUEST prefix kept for variable consistency)
export GUEST_BSSID=""           # Target network BSSID
export GUEST_CHANNEL=""         # Target channel
export GATEWAY_IP=""            # Default gateway on target network
export MY_IP=""                 # Our IP on target network
export MY_MAC=""                # Our MAC address
export DNS_SERVER=""            # DNS server on target network
export INTERNAL_SSID=""         # Reference internal/corporate SSID for segregation tests
export INTERNAL_BSSID=""        # Reference internal/corporate BSSID

#--- Assessment preferences (preflight wizard) ---
export C2_SCOPE=""              # Optional scan scope hint for C2 (e.g. 192.168.1.0/24)
export PREFLIGHT_DONE=0         # 1 when wizard has been completed for this session

#--- VPS Configuration (for egress tests) ---
export VPS_IP=""
export VPS_DOMAIN=""
export VPS_SSH_KEY=""
export VPS_CONFIGURED=0

#--- Captive Portal Configuration ---
export CAPTIVE_PORTAL=""            # "yes", "no", or "" (unknown)

#--- Timing Defaults ---
export AIRODUMP_SCAN_TIME=60         # Seconds for initial WiFi scan
export CDP_CAPTURE_TIME=120          # Seconds for CDP/LLDP capture
export MDNS_CAPTURE_TIME=60          # Seconds for mDNS capture
export MASSCAN_RATE=1000             # Packets per second for masscan
export NMAP_TIMING="-T3"            # Nmap timing template
export PMKID_CAPTURE_TIME=120       # Seconds for PMKID capture attempt
