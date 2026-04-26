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

Packages installed: aircrack-ng, nmap, tcpdump, tshark, hostapd, dnsmasq,
yersinia, responder, bettercap, macchanger, curl, jq, fping, snmp, onesixtyone.

Must be run as root (sudo astra setup). Runs 'apt update' then 'apt install -y'
for the full dependency list.`,
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
			"aircrack-ng", "nmap", "tcpdump", "tshark", "hostapd",
			"dnsmasq", "yersinia", "responder", "bettercap",
			"macchanger", "curl", "jq", "fping", "snmp", "onesixtyone",
			"python3-pip", "python3-dev", "libssl-dev", "libffi-dev",
			"libpcap-dev", "asleap",
			"hcxdumptool", "hcxtools", "mdk4", "iodine",
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

		logging.Success("System setup complete. All dependencies installed.")

		fmt.Printf("\n\033[33m[!] eaphammer requires manual installation (not available via apt):\033[0m\n")
		fmt.Println("    git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer")
		fmt.Println("    cd /opt/eaphammer && python3 -m pip install -r requirements.txt")
		fmt.Println("    (Required for D5 EAP/PEAP enterprise attacks)")
	},
}

func init() {
	RootCmd.AddCommand(setupCmd)
}
