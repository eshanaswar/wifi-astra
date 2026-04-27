package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"wifi-astra/internal/logging"
	"wifi-astra/internal/ui"
	"wifi-astra/pkg/constants"
)

// HandlePostConnectScan offers an nmap scan against a client that just connected to a rogue AP.
// clientIP is the DHCP-assigned IP detected from dnsmasq logs.
// If clientIP is empty, prompts the operator to enter one manually.
// module: "F1" or "F2" (used for evidence file naming).
func (c *AssessmentController) HandlePostConnectScan(clientIP, module string) {
	if _, err := exec.LookPath("nmap"); err != nil {
		fmt.Printf("\n%s[!] nmap not found — skipping post-connect scan offer.%s\n",
			constants.ColorGray, constants.ColorReset)
		return
	}

	fmt.Printf("\n%s[+] Kill Chain: Client connected to rogue AP%s\n",
		constants.ThemeHeader, constants.ColorReset)

	if clientIP == "" {
		clientIP = ui.PromptString("    Enter client IP to scan (or Enter to skip)", "")
	} else {
		fmt.Printf("    Detected client IP: %s%s%s\n", constants.ThemeSuccess, clientIP, constants.ColorReset)
	}
	if clientIP == "" {
		return
	}

	if !ui.PromptConfirm(fmt.Sprintf("    Run nmap service+OS scan against %s?", clientIP), false) {
		return
	}

	logFile := filepath.Join(c.Session.EvidenceDir,
		fmt.Sprintf("%s_nmap_client_%s.txt", strings.ToLower(module), strings.ReplaceAll(clientIP, ".", "_")))
	xmlOut := strings.TrimSuffix(logFile, ".txt") + ".xml"

	args := []string{
		"-sV",
		"-O",
		"--open",
		"-oN", logFile,
		"-oX", xmlOut,
		clientIP,
	}

	fmt.Printf("%s[*] nmap %s ...%s\n", constants.ThemeHeader, strings.Join(args, " "), constants.ColorReset)
	exitCode, err := c.ExecMgr.Run(context.Background(), "nmap-client", "nmap", args, "/dev/null")
	if err != nil || exitCode != 0 {
		logging.Warn("nmap post-connect scan failed (exit %d): %v", exitCode, err)
		fmt.Printf("%s[!] nmap scan failed — check %s%s\n", constants.ThemeHigh, logFile, constants.ColorReset)
		return
	}

	desc := fmt.Sprintf(
		"Post-connect nmap scan of client %s (connected via rogue AP %s). Full output: %s",
		clientIP, module, filepath.Base(logFile))
	c.Session.DB.Exec(
		`INSERT INTO vulnerability (tc_id, target_host, name, severity, description, evidence_file, rationale)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		module, clientIP,
		"Post-Connect Client Scan",
		"INFO",
		desc,
		logFile,
		"Client was scanned after connecting to rogue AP — confirms network position and potential pivot targets.",
	)

	fmt.Printf("%s[✓]%s Scan complete.\n", constants.ThemeSuccess, constants.ColorReset)
	fmt.Printf("    Normal output: %s\n", logFile)
	fmt.Printf("    XML output:    %s\n", xmlOut)
	logging.Info("kill-chain: nmap post-connect scan complete for %s/%s", module, clientIP)
}

// DetectConnectedClientIP reads the dnsmasq lease file or log from the evidence directory
// and returns the most recently DHCP-assigned client IP, or empty string if none found.
// The gateway IP (192.168.44.1) is excluded.
func DetectConnectedClientIP(evidenceDir, module string) string {
	// Primary: dnsmasq lease file
	leaseFile := filepath.Join(evidenceDir, strings.ToLower(module)+"_dnsmasq.leases")
	if data, err := os.ReadFile(leaseFile); err == nil {
		lastIP := ""
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			// Format: <expiry> <mac> <ip> <hostname> <clientid>
			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[2] != "192.168.44.1" {
				lastIP = parts[2]
			}
		}
		if lastIP != "" {
			return lastIP
		}
	}

	// Fallback: scan dnsmasq log for DHCPACK lines
	logFile := filepath.Join(evidenceDir, strings.ToUpper(module)+"_dnsmasq.log")
	logData, err := os.ReadFile(logFile)
	if err != nil {
		return ""
	}
	lastIP := ""
	for _, line := range strings.Split(string(logData), "\n") {
		if !strings.Contains(line, "DHCPACK") {
			continue
		}
		parts := strings.Fields(line)
		for _, p := range parts {
			if strings.Count(p, ".") == 3 && p != "192.168.44.1" {
				lastIP = p
				break
			}
		}
	}
	return lastIP
}
