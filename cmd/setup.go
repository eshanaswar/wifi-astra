package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/ui"

	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install required system dependencies (requires root)",
	Long: `Install all wireless auditing tools needed by WiFi-Astra via apt.

Packages installed via apt:
  aircrack-ng, hcxdumptool, hcxtools, hashcat, mdk4, reaver, bully, iodine,
  nmap, tcpdump, tshark, hostapd, hostapd-wpe, dnsmasq, yersinia, responder,
  bettercap, mitmproxy, macchanger, curl, jq, fping, arping, dnsutils,
  snmp, snmp-mibs-downloader, onesixtyone,
  python3-pip, python3-dev, libssl-dev, libffi-dev, libpcap-dev, asleap.

Must be run as root (sudo astra setup). Runs 'apt update' then 'apt install -y'
for the full dependency list.

Tools requiring manual installation (instructions printed after setup):
  eaphammer  — D5 EAP/PEAP rogue RADIUS attacks
  nuclei     — B9 AP vulnerability fingerprinting
  fragattack — E2 FragAttacks frame injection testing`,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Println("[✗] Setup requires root privileges (sudo).")
			os.Exit(1)
		}

		fmt.Println("\n--- WiFi-Astra: System Setup ---")
		fmt.Println("This will install all required wireless auditing tools via apt.")
		
		if !ui.PromptConfirm("Proceed with installation?", true) {
			fmt.Println("Setup aborted.")
			return
		}

		dependencies := []string{
			// Core wireless attack suite
			"aircrack-ng", "hcxdumptool", "hcxtools", "hashcat",
			"mdk4", "reaver", "bully", "iodine", "asleap",
			// AP / Evil Twin stack
			"hostapd", "hostapd-wpe", "dnsmasq",
			// Network recon
			"nmap", "tcpdump", "tshark", "bettercap", "mitmproxy",
			"fping", "arping", "dnsutils",
			// SNMP
			"snmp", "snmp-mibs-downloader", "onesixtyone",
			// MitM / pivot
			"yersinia", "responder", "macchanger",
			// Utilities
			"curl", "jq",
			// Build deps (for pip-based tools)
			"python3-pip", "python3-dev",
			"libssl-dev", "libffi-dev", "libpcap-dev",
		}

		fmt.Printf("[*] Updating package lists...\n")
		updateCmd := exec.Command("apt", "update")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		updateCmd.Run()

		fmt.Printf("[*] Installing dependencies: %s\n", strings.Join(dependencies, ", "))
		installArgs := append([]string{"install", "-y"}, dependencies...)
		installCmd := exec.Command("apt", installArgs...)
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		
		if err := installCmd.Run(); err != nil {
			logging.Error("Installation failed: %v", err)
			os.Exit(1)
		}

		logging.Success("System setup complete. apt packages installed.")

		fmt.Printf("\n\033[33m[!] Three tools require manual installation:\033[0m\n")
		fmt.Println()
		fmt.Println("  eaphammer (required for D5 — EAP/PEAP rogue RADIUS):")
		fmt.Println("    git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer")
		fmt.Println("    cd /opt/eaphammer && python3 -m pip install -r requirements.txt")
		fmt.Println()
		fmt.Println("  nuclei (required for B9 — AP vulnerability fingerprinting):")
		fmt.Println("    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		fmt.Println("    # or: download binary from https://github.com/projectdiscovery/nuclei/releases")
		fmt.Println()
		fmt.Println("  fragattack (required for E2 — FragAttacks testing):")
		fmt.Println("    git clone https://github.com/vanhoefm/fragattacks /opt/fragattacks")
		fmt.Println("    cd /opt/fragattacks/research && python3 -m pip install -r requirements.txt")
	},
}

func init() {
	RootCmd.AddCommand(setupCmd)
}
