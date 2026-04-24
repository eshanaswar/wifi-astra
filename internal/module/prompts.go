package module

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"wifi-astra/internal/db"
	"wifi-astra/internal/ui"
	"wifi-astra/pkg/constants"
)

// TacticalPrompt defines a function that performs a tactical interaction
type TacticalPrompt func(m *Module, database *sql.DB) error

// PromptRegistry maps metadata keys to their Go implementations
var PromptRegistry = map[string]TacticalPrompt{
	"scan_depth":        promptScanDepth,
	"target_client":     promptTargetClient,
	"wps_vector":        promptWPSVector,
	"roaming_catalyst":  promptRoamingCatalyst,
	"rogue_ap_mode":     promptRogueAPMode,
	"karma_vector":      promptKarmaVector,
	"phishing_template": promptPhishingTemplate,
	"tunnel_config":     promptTunnelConfig,
	"rogue_bssid":       promptRogueBSSID,
	"active_reveal":     promptActiveReveal,
	"pmf_guard":         promptPMFGuard,
	"managed_connect":   promptManagedConnect,
}

func promptManagedConnect(m *Module, database *sql.DB) error {
	iface, _ := db.GetConfig(database, constants.ConfigWifiInterface)
	if iface == "" {
		return fmt.Errorf("WIFI_INTERFACE not set in session")
	}

	// Check if interface already has an IP and a subnet route
	out, err := exec.Command("ip", "-4", "addr", "show", iface).Output()
	if err == nil && strings.Contains(string(out), "inet ") {
		// Also check for route
		routeOut, _ := exec.Command("ip", "-4", "route", "show", "dev", iface).Output()
		if strings.Contains(string(routeOut), "kernel") {
			return nil // Already connected and routed
		}
	}

	ssid, _ := db.GetConfig(database, constants.ConfigGuestSSID)
	bssid, _ := db.GetConfig(database, constants.ConfigGuestBSSID)

	fmt.Printf("\n%s[!] CONNECTION REQUIRED: Module %s requires a managed IP and route on %s.%s\n", constants.ThemeHigh, m.ID, iface, constants.ColorReset)
	if ssid != "" {
		fmt.Printf("[*] Target Network: %s (%s)\n", ssid, bssid)
	}
	fmt.Println("[*] Please connect to the target WiFi manually (nmcli, wpa_supplicant, etc.)")
	fmt.Println("[*] Ensure you have a valid DHCP lease and can see the local subnet route.")

	if !ui.PromptConfirm("Are you connected and ready to proceed?", true) {
		return fmt.Errorf("interrupted")
	}

	// Final check
	out, err = exec.Command("ip", "-4", "addr", "show", iface).Output()
	if err != nil || !strings.Contains(string(out), "inet ") {
		fmt.Printf("%s[✗] Error: Still no IP detected on %s. Module will likely fail.%s\n", constants.ThemeCritical, iface, constants.ColorReset)
		if !ui.PromptConfirm("Continue anyway?", false) {
			return fmt.Errorf("interrupted")
		}
	}

	routeOut, _ := exec.Command("ip", "-4", "route", "show", "dev", iface).Output()
	if !strings.Contains(string(routeOut), "kernel") {
		fmt.Printf("%s[✗] Error: No local subnet route found on %s. Module will likely fail.%s\n", constants.ThemeCritical, iface, constants.ColorReset)
		if !ui.PromptConfirm("Continue anyway?", false) {
			return fmt.Errorf("interrupted")
		}
	}

	return nil
}

func promptPMFGuard(m *Module, database *sql.DB) error {
	pmf, _ := db.GetConfig(database, "ASTRA_TARGET_PMF")
	if pmf == "Required" && (m.ID == "A3" || m.ID == "F4") {
		fmt.Printf("\n%s[!] INTELLIGENCE ALERT: Target enforces PMF (802.11w).%s\n", constants.ThemeHigh, constants.ColorReset)
		fmt.Println("[*] Active deauthentication WILL FAIL. Passive monitoring is recommended.")
		if m.ID == "A3" {
			if !ui.PromptConfirm("Continue with active reveal anyway?", false) {
				os.Setenv("ACTIVE_REVEAL", "no")
			}
		} else if m.ID == "F4" {
			fmt.Println("[*] CSA suppression will be used as primary mechanism.")
		}
	}
	return nil
}

func promptScanDepth(m *Module, _ *sql.DB) error {
	if os.Getenv("ASTRA_INDEFINITE") == "true" {
		return nil
	}
	options := []string{"Standard (60s)", "Deep Scan (120s - Recommended for DFS/5GHz)"}
	choice := ui.PromptList("Select Scan Depth", options)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if choice == 1 {
		os.Setenv("SCAN_TIME", "120")
	} else {
		os.Setenv("SCAN_TIME", "60")
	}
	return nil
}

func promptTargetClient(m *Module, database *sql.DB) error {
	clients, err := db.ListClients(database)
	if err != nil || len(clients) == 0 {
		return nil
	}

	var options []string
	for _, cl := range clients {
		options = append(options, fmt.Sprintf("%s (%s) [%ddBm]", cl.MAC, cl.Vendor, cl.LastSignal))
	}
	if m.ID == "D1" {
		options = append(options, "BROADCAST (Loud/Destructive)")
	}

	choice := ui.PromptList("Select Target Client", options)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if m.ID == "D1" && choice == len(clients) {
		os.Setenv("TARGET_CLIENT", "FF:FF:FF:FF:FF:FF")
	} else if choice >= 0 {
		os.Setenv("TARGET_CLIENT", clients[choice].MAC)
	}
	return nil
}

func promptWPSVector(m *Module, _ *sql.DB) error {
	options := []string{"Pixie Dust (Fast, 1 transaction)", "Online Brute-Force (Sequential)"}
	choice := ui.PromptList("Select WPS Vector", options)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if choice == 1 {
		os.Setenv("WPS_ATTACK", "online")
		if os.Getenv("ASTRA_INDEFINITE") != "true" {
			delay := ui.PromptString("Enter delay (seconds)", "300")
			if delay == "" {
				return fmt.Errorf("interrupted")
			}
			os.Setenv("WPS_DELAY", delay)
		} else {
			os.Setenv("WPS_DELAY", "0")
		}
	} else {
		os.Setenv("WPS_ATTACK", "pixie")
	}
	return nil
}

func promptRoamingCatalyst(m *Module, _ *sql.DB) error {
	options := []string{"None", "Targeted Deauth (Surgical)", "CSA (Stealthier)"}
	choice := ui.PromptList("Select Roaming Catalyst", options)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	os.Setenv("CATALYST", strconv.Itoa(choice))
	return nil
}

func promptRogueAPMode(m *Module, _ *sql.DB) error {
	opts := []string{"SSID Only (Random BSSID)", "BSSID Clone (Match Target)"}
	choice := ui.PromptList("Select Rogue AP Mode", opts)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if choice == 1 {
		os.Setenv("AP_MODE", "clone")
	} else {
		os.Setenv("AP_MODE", "ssid")
	}
	return nil
}

func promptKarmaVector(m *Module, _ *sql.DB) error {
	opts := []string{"Dynamic MANA (Directed Probes)", "Known Beacon Attack (Loud - Recommended)"}
	choice := ui.PromptList("Select Karma Vector", opts)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if choice == 1 {
		os.Setenv("KARMA_MODE", "loud")
	} else {
		os.Setenv("KARMA_MODE", "mana")
	}
	return nil
}

func promptPhishingTemplate(m *Module, _ *sql.DB) error {
	opts := []string{"Generic Corporate", "Microsoft 365 (High-Fidelity)"}
	choice := ui.PromptList("Select Phishing Template", opts)
	if choice == -1 {
		return fmt.Errorf("interrupted")
	}
	if choice == 1 {
		os.Setenv("PHISH_TEMPLATE", "m365")
	} else {
		os.Setenv("PHISH_TEMPLATE", "generic")
	}
	return nil
}

func promptTunnelConfig(m *Module, _ *sql.DB) error {
	domain := ui.PromptString("Enter tunnel domain", "")
	if domain == "" {
		return fmt.Errorf("interrupted")
	}
	os.Setenv("TUNNEL_DOMAIN", domain)

	fmt.Printf("%s[*] Leave password blank if the iodined server has no password. Ctrl+C here cannot cancel — use Ctrl+C at the domain prompt to abort.%s\n", constants.ColorGray, constants.ColorReset)
	pass := ui.PromptString("Enter tunnel password (blank = no password)", "")
	os.Setenv("TUNNEL_PASS", pass)
	return nil
}

func promptRogueBSSID(m *Module, _ *sql.DB) error {
	bssid := ui.PromptString("Enter Rogue AP BSSID", "")
	if bssid == "" {
		return fmt.Errorf("interrupted")
	}
	os.Setenv("ROGUE_BSSID", bssid)
	return nil
}

func promptActiveReveal(m *Module, _ *sql.DB) error {
	if ui.PromptConfirm("Force reveal via surgical deauth?", true) {
		os.Setenv("ACTIVE_REVEAL", "yes")
	} else {
		os.Setenv("ACTIVE_REVEAL", "no")
	}
	return nil
}

// PromptAPAdapterGuard warns when a dual-adapter module is launched without an AP
// adapter assigned. Returns true to proceed, false to abort.
// Fires only for modules F1, F2, F3, D5. No-op for all others.
// No-op in headless mode (ASTRA_HEADLESS=true) — runs degraded silently.
func PromptAPAdapterGuard(database *sql.DB, m *Module) bool {
	switch m.ID {
	case "F1", "F2", "F3", "D5":
		// continue
	default:
		return true
	}

	if os.Getenv("ASTRA_HEADLESS") == "true" {
		return true
	}

	apIface, err := db.GetConfig(database, "AP_INTERFACE")
	if err != nil {
		log.Printf("[debug] PromptAPAdapterGuard: failed to read AP_INTERFACE from DB: %v", err)
	}
	if apIface != "" {
		return true
	}

	// whyLines must contain an entry for each module ID listed in the switch above.
	whyLines := map[string]string{
		"F1": "Evil Twin requires hostapd (managed mode) on one card and airodump-ng\n(monitor mode) on another to simultaneously broadcast the fake AP and capture\nvictim traffic and credentials.",
		"F2": "KARMA/PineAP uses hostapd-mana (managed mode) to respond to client probes.\nA second card in monitor mode captures associations and traffic in real time.",
		"F3": "Captive portal requires hostapd (managed mode) for client association while\nmonitor mode tracks which clients connect and what they submit to the phishing page.",
		"D5": "PEAP capture deploys a rogue RADIUS AP (hostapd, managed mode). A second card\nin monitor mode captures the full EAP handshake needed for credential extraction.",
	}

	fmt.Printf("\n%s[!] DUAL-ADAPTER NOTICE — %s%s\n", constants.ThemeHigh, m.Name, constants.ColorReset)
	fmt.Println()
	fmt.Println("This module works best with two wireless adapters.")
	fmt.Println()
	fmt.Printf("WHY: %s\n", whyLines[m.ID])
	fmt.Println()
	fmt.Printf("%sWITH ONE ADAPTER (current setup):%s The monitor card will be temporarily\n", constants.ColorBold, constants.ColorReset)
	fmt.Println("switched to managed mode to broadcast the AP. Packet capture and frame")
	fmt.Println("injection are suspended during this window — you will not sniff client")
	fmt.Println("associations or inject deauth frames while the rogue AP is running.")
	fmt.Println()
	fmt.Println("To enable full dual-adapter mode, connect a second adapter and restart")
	fmt.Println("the tool to reassign roles.")
	fmt.Println()

	return ui.PromptConfirm("Continue in degraded single-adapter mode?", false)
}
