package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wifi-astra/internal/config"
	"wifi-astra/internal/controller"
	"wifi-astra/internal/headless"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/module"
	"wifi-astra/internal/report"
	"wifi-astra/internal/session"
	"wifi-astra/internal/ui"
	"wifi-astra/pkg/constants"
	"wifi-astra/pkg/hw"
	"wifi-astra/pkg/prereq"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start or resume an assessment session",
	Long: `Launch an interactive wireless assessment session.

On first run, the session wizard prompts for a session name and adapter role assignment
(monitor interface and AP interface). All subsequent module execution is scoped
to BSSIDs discovered and authorized during the initial A1 discovery scan.

Headless / unattended mode: supply a JSON audit plan via --config to drive the full
assessment lifecycle without interactive prompts. Example plan structure:

  {
    "session_name": "corp-wifi-2026",
    "monitor_interface": "wlan1",
    "modules": ["A1","D1","D3"],
    "capture_time": 60,
    "scan_time": 30
  }

Requires root privileges for hardware operations (monitor mode, packet injection).
The process runs as root throughout; SUDO_UID/SUDO_GID are captured only for chown
operations on session directories.`,
	Run: func(cmd *cobra.Command, args []string) {
		// 1. Load Global Config
		cfg, err := config.LoadConfig(ConfigFile)
		if err != nil {
			logging.Error("Failed to load config: %v", err)
		}
		if cfg != nil && cfg.Verbose {
			Verbose = true
		}

		isHeadless := (ConfigFile != "" && strings.HasSuffix(ConfigFile, ".json"))

		// 2. Root-only Hardware Recovery
		hw.Recover(isHeadless)

		// 3. Setup Session Base Dir
		baseDir := "./sessions"
		if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
			baseDir = config.GlobalConfig.SessionDir
		}
		
		// Ensure base directory exists and is accessible by the dropped user
		os.MkdirAll(baseDir, 0755)
		if user, err := prereq.GetSudoUser(); err == nil {
			os.Chown(baseDir, user.UID, user.GID)
		}

		// 4. Check for Headless Plan
		if isHeadless {
			// In headless mode, the session is created inside RunAutonomousAudit
			_, err := headless.RunAutonomousAudit(ConfigFile, ModDir, func(s *session.Session, m *module.Module) error {
				c := controller.NewAssessmentController(s, ExecMgr, ModDir)
				return c.ExecuteModule(m)
			})
			if err != nil {
				logging.Error("Autonomous audit failed: %v", err)
				os.Exit(1)
			}
			return
		}

		sessionWizard()
	},
}

func init() {
	RootCmd.AddCommand(startCmd)
}

func sessionWizard() {
	for {
		ui.GetManager().ClearScreen()
		ui.GetManager().PrintBanner()
		baseDir := "./sessions"
		if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
			baseDir = config.GlobalConfig.SessionDir
		}

		ui.PrintHeader("Session Manager")

		sessions, _ := os.ReadDir(baseDir)
		var existing []os.DirEntry
		for _, s := range sessions {
			if s.IsDir() {
				existing = append(existing, s)
			}
		}

		fmt.Println("1) Create New Session")
		if len(existing) > 0 {
			fmt.Println("2) Resume Existing Session")
			fmt.Println("3) Delete Existing Session")
		} else {
			fmt.Printf("%s    No existing sessions — create one to get started.%s\n", constants.ColorGray, constants.ColorReset)
		}

		choice := ui.PromptString("Select an option", "1")
		if choice == "" {
			fmt.Printf("\n%s[!] Operation cancelled.%s\n", constants.ThemeHigh, constants.ColorReset)
			os.Exit(0)
		}

		if choice == "1" {
			ui.PrintHeader("New Session Setup")
			name := ui.PromptString("Enter session name (optional)", "")
			s, err := session.NewSession(name, baseDir)
			if err != nil {
				logging.Error("Failed to create session: %v", err)
				os.Exit(1)
			}
			logging.InitLogger(s.LogDir, Verbose)
			logging.Success("Session initialized: %s", s.ID)
			launchMainMenu(s)
			return
		} else if choice == "2" && len(existing) > 0 {
			ui.PrintHeader("Available Sessions")
			for i, entry := range existing {
				meta, err := session.QueryMeta(filepath.Join(baseDir, entry.Name()))
				if err != nil || meta.Name == "" {
					fmt.Printf("  %d) %s\n", i+1, entry.Name())
					continue
				}
				createdAt := meta.CreatedAt
				if len(createdAt) > 10 {
					createdAt = createdAt[:10]
				}
				fmt.Printf("  %d) %s%-20s%s  %s  |  %s%d modules done%s  |  %s%d findings%s\n",
					i+1,
					constants.ColorBold, meta.Name, constants.ColorReset,
					createdAt,
					constants.ThemeSuccess, meta.ModulesDone, constants.ColorReset,
					constants.ThemeHigh, meta.FindingCount, constants.ColorReset,
				)
			}
			sIdx := ui.PromptString(fmt.Sprintf("Select session to resume [1-%d]", len(existing)), "")
			if sIdx == "" {
				continue
			}
			idx, _ := strconv.Atoi(sIdx)
			if idx >= 1 && idx <= len(existing) {
				s, err := session.LoadSession(filepath.Join(baseDir, existing[idx-1].Name()))
				if err == nil {
					logging.InitLogger(s.LogDir, Verbose)
					logging.Success("Resumed session: %s", s.ID)
					launchMainMenu(s)
					return
				}
				logging.Error("Failed to load session: %v", err)
			} else {
				fmt.Printf("%s[!] Invalid selection. Enter a number between 1 and %d.%s\n",
					constants.ThemeHigh, len(existing), constants.ColorReset)
				ui.PromptString("Press Enter to continue", "")
			}
		} else if choice == "3" && len(existing) > 0 {
			ui.PrintHeader("Delete Session")
			for i, entry := range existing {
				meta, err := session.QueryMeta(filepath.Join(baseDir, entry.Name()))
				if err != nil || meta.Name == "" {
					fmt.Printf("  %d) %s\n", i+1, entry.Name())
					continue
				}
				createdAt := meta.CreatedAt
				if len(createdAt) > 10 {
					createdAt = createdAt[:10]
				}
				fmt.Printf("  %d) %s%-20s%s  %s  |  %s%d modules done%s  |  %s%d findings%s\n",
					i+1,
					constants.ColorBold, meta.Name, constants.ColorReset,
					createdAt,
					constants.ThemeSuccess, meta.ModulesDone, constants.ColorReset,
					constants.ThemeHigh, meta.FindingCount, constants.ColorReset,
				)
			}
			sIdx := ui.PromptString("Select session to delete (or 0 to cancel)", "0")
			if sIdx == "" {
				continue
			}
			idx, _ := strconv.Atoi(sIdx)
			if idx >= 1 && idx <= len(existing) {
				sessionID := existing[idx-1].Name()
				fmt.Printf("\n%s[!] WARNING:%s This will permanently delete all logs, evidence, and results for session %s%s%s.\n",
					constants.ThemeHigh, constants.ColorReset,
					constants.ColorBold, sessionID, constants.ColorReset)
				if ui.PromptConfirm("Are you sure?", false) {
					path := filepath.Join(baseDir, sessionID)
					if err := os.RemoveAll(path); err != nil {
						logging.Error("Failed to delete session %s: %v", sessionID, err)
					} else {
						logging.Success("Session %s deleted successfully.", sessionID)
					}
					time.Sleep(1 * time.Second)
				}
			}
			continue
		} else {
			validRange := "1"
			if len(existing) > 0 {
				validRange = "1, 2, or 3"
			}
			fmt.Printf("%s[!] Invalid option — enter %s.%s\n",
				constants.ThemeHigh, validRange, constants.ColorReset)
			ui.PromptString("Press Enter to continue", "")
		}
	}
}

func launchMainMenu(s *session.Session) {
	ui.GetManager().ClearScreen()
	Ctrl = controller.NewAssessmentController(s, ExecMgr, ModDir)

	iface := ensureAdapterSetup(s)
	if iface == "" {
		logging.Error("No wireless interface selected.")
		return
	}

	modules, _ := module.DiscoverModules(ModDir)

	// Preflight: check which modules have all required tools available
	moduleAvail := prereq.PreflightModules(prereq.ModuleToolMap)

	mainMenu := ui.NewMenu("Assessment Menu")
	mainMenu.Prompt = "Select an option (? for help): "

	catNames := map[string]string{
		"A": "Discovery & Recon (Passive/Active)",
		"B": "Internal Network Recon (Connected)",
		"C": "Segmentation & Egress Testing",
		"D": "Encryption & Authentication Attacks",
		"E": "Implementation & Design Flaws",
		"F": "Rogue AP & Evil Twin Attacks",
		"G": "Man-in-the-Middle (MITM) & Pivoting",
		"H": "Policy & WIDS Validation",
	}

	catDescs := map[string]string{
		"A": "Passive and active scanning across 2.4/5/6 GHz. Identifies APs, BSSIDs, clients, hidden SSIDs, and vendor information. Run A1 first — scope selection depends on its output.",
		"B": "Recon performed from an associated client position. Tests client isolation, management interface exposure, CDP/LLDP leaks, mDNS/Bonjour, SNMP, DHCP, IPv6, and broadcast traffic analysis.",
		"C": "Validates network segmentation from a wireless client. Tests VLAN hopping, RADIUS reachability, DNS split-horizon, private subnet routing, and egress filter bypass (DNS/HTTP/ICMP/NTP tunnels).",
		"D": "Active attacks against wireless encryption and authentication. Covers WPA2 handshake/PMKID capture, WEP cracking, WPS Pixie Dust and PIN brute-force, WPA3 Dragonblood, EAP credential capture, and OWE/WPA3 downgrade.",
		"E": "Tests for known protocol-level implementation flaws. Covers KRACK (CVE-2017-13077), FragAttacks (CVE-2020-24586/87/88), 802.11w PMF deauth resilience, Kr00k (CVE-2019-15126), and driver-level fuzzing.",
		"F": "Deploys rogue APs and evil twins to intercept client traffic. Includes KARMA/PineAP probe harvesting, captive portal with vendor fingerprinting, portal bypass techniques, and DNS tunneling detection.",
		"G": "Man-in-the-middle and lateral movement attacks from a compromised wireless position. Covers ARP spoofing, SSL/TLS interception, DNS spoofing, NAC bypass via MAC cloning, BSS Transition abuse, and Responder NTLM capture.",
		"H": "Validates wireless security policy enforcement. Tests WIDS/WIPS detection and evasion capability, and verifies 802.11w Protected Management Frame enforcement against deauth spoofing.",
	}

	// Pre-compute total module count per category from the discovered module list.
	// The DB only tracks modules that have been run, so using it as the denominator
	// causes [2/2] when only 2 of 5 modules in a category have ever been executed.
	catTotal := make(map[string]int)
	for _, m := range modules {
		catTotal[m.Category]++
	}

	categories := make(map[string]*ui.Menu)
	for _, m := range modules {
		if _, ok := categories[m.Category]; !ok {
			name := catNames[m.Category]
			if name == "" {
				name = "Unknown"
			}
			categories[m.Category] = ui.NewMenu("Category " + m.Category + ": " + name)
		}

		mod := m
		modDesc := m.Desc
		if strings.HasPrefix(modDesc, "[LEGACY]") {
			modDesc = strings.TrimPrefix(modDesc, "[LEGACY]")
		}
		categories[m.Category].AddDynamicOptionWithHelp(func() string {
			var status string
			s.DB.QueryRow("SELECT status FROM module_state WHERE tc_id = ?", mod.ID).Scan(&status)
			prefix := fmt.Sprintf("%s·%s ", constants.ColorGray, constants.ColorReset)
			switch status {
			case constants.StatusCompleted:
				prefix = fmt.Sprintf("%s✓%s ", constants.ColorGreen, constants.ColorReset)
			case constants.StatusFailed:
				prefix = fmt.Sprintf("%s✗%s ", constants.ColorRed, constants.ColorReset)
			case constants.StatusRunning:
				prefix = fmt.Sprintf("%s>%s ", constants.ColorCyan, constants.ColorReset)
			}
			suffix := ""
			if avail, known := moduleAvail[mod.ID]; known && !avail {
				suffix = fmt.Sprintf(" %s[tools missing]%s", constants.ColorGray, constants.ColorReset)
			}
			if strings.HasPrefix(mod.Desc, "[LEGACY]") {
				suffix += fmt.Sprintf(" %s[legacy]%s", constants.ColorGray, constants.ColorReset)
				return fmt.Sprintf("%s%s%s: %s%s", prefix, constants.ColorGray, mod.ID, mod.Name+suffix, constants.ColorReset)
			}
			return prefix + mod.ID + ": " + mod.Name + suffix
		}, strings.TrimSpace(modDesc), func() error {
			return Ctrl.ExecuteModule(&mod)
		})
	}

	catKeys := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	for _, k := range catKeys {
		if sub, ok := categories[k]; ok {
			catKey := k
			catName := catNames[k]
			catDesc := catDescs[k]
			mainMenu.AddDynamicOptionWithHelp(func() string {
				total := catTotal[catKey]
				var completed int
				s.DB.QueryRow("SELECT COUNT(*) FROM module_state WHERE tc_id LIKE ? AND status = ?", catKey+"%", constants.StatusCompleted).Scan(&completed)

				statusStr := fmt.Sprintf(" [%d/%d]", completed, total)
				if completed == total && total > 0 {
					statusStr += fmt.Sprintf(" %s✓%s", constants.ColorGreen, constants.ColorReset)
				}
				return fmt.Sprintf("Category %s: %s%s", catKey, catName, statusStr)
			}, catDesc, func() error {
				ui.GetManager().ClearScreen()
				return sub.Display()
			})
		}
	}

	mainMenu.PreRender = func() {
		var ssid, bssid, ch string
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestChannel).Scan(&ch)

		iface := ""
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigWifiInterface).Scan(&iface)

		scopeStr := fmt.Sprintf("%s<NOT SET — run A1>%s", constants.ThemeHigh, constants.ColorReset)
		if ssid != "" {
			scopeStr = fmt.Sprintf("%s%s%s (%s) CH%s",
				constants.ColorBold, ssid, constants.ColorReset, bssid, ch)
		}

		fmt.Printf("%s SESSION:%s %-18s  %sTARGET:%s %s  %sIFACE:%s %s\n",
			constants.ThemeHeader, constants.ColorReset, s.Name,
			constants.ThemeHeader, constants.ColorReset, scopeStr,
			constants.ThemeHeader, constants.ColorReset, iface,
		)
		fmt.Printf("%s%s%s\n", constants.ThemeHeader, strings.Repeat("─", 70), constants.ColorReset)
	}

	mainMenu.AddDynamicOptionWithHelp(func() string {
		var ssid, bssid string
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
		if ssid == "" {
			return fmt.Sprintf("%sSwitch Active Target%s  (no scope set)", constants.ThemeHigh, constants.ColorReset)
		}
		return fmt.Sprintf("Switch Active Target  (current: %s%s%s / %s)", constants.ColorBold, ssid, constants.ColorReset, bssid)
	}, "Change which authorized BSSID modules will target. Scope must be set via A1 first.", func() error {
		var scopeBSSIDs string
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigScopeBSSIDs).Scan(&scopeBSSIDs)
		if scopeBSSIDs == "" {
			// Fallback: if an active target is already set (e.g. from a headless session) but
			// SCOPE_BSSIDS was never written, reconstruct it from the current active BSSID.
			var activeBSSID string
			s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&activeBSSID)
			if activeBSSID != "" {
				scopeBSSIDs = activeBSSID
				s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigScopeBSSIDs, activeBSSID)
			} else {
				fmt.Printf("%s[!] No authorized scope set — run A1 first to select targets.%s\n",
					constants.ThemeHigh, constants.ColorReset)
				ui.PromptString("Press Enter", "")
				return nil
			}
		}

		bssidList := strings.Split(scopeBSSIDs, ",")
		ui.PrintHeader("Switch Active Target")
		for i, b := range bssidList {
			b = strings.TrimSpace(b)
			var ssid string
			var ch int
			s.DB.QueryRow("SELECT ssid, channel FROM network WHERE bssid = ?", b).Scan(&ssid, &ch)
			if ssid == "" {
				ssid = "<unknown>"
			}
			fmt.Printf("  %d) %-20s  %s  CH%d\n", i+1, ssid, b, ch)
		}

		choice := ui.PromptString("Select target number", "")
		idx, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil || idx < 1 || idx > len(bssidList) {
			fmt.Printf("%s[!] Invalid selection.%s\n", constants.ThemeHigh, constants.ColorReset)
			ui.PromptString("Press Enter", "")
			return nil
		}

		newBSSID := strings.TrimSpace(bssidList[idx-1])
		var newSSID string
		var newCh int
		s.DB.QueryRow("SELECT ssid, channel FROM network WHERE bssid = ?", newBSSID).Scan(&newSSID, &newCh)

		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestBSSID, newBSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestSSID, newSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestChannel, strconv.Itoa(newCh))

		fmt.Printf("%s[✓] Active target switched to: %s (%s) CH%d%s\n",
			constants.ThemeSuccess, newSSID, newBSSID, newCh, constants.ColorReset)
		ui.PromptString("Press Enter", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("List All Available Modules",
		"Show all modules with run status, tool availability, and descriptions.",
		func() error {
		ui.PrintHeader("All Assessment Modules")
		currentCat := ""
		for _, mod := range modules {
			if mod.Category != currentCat {
				currentCat = mod.Category
				catLabel := catNames[currentCat]
				fmt.Printf("\n  %sCategory %s: %s%s\n", constants.ThemeHeader, currentCat, catLabel, constants.ColorReset)
				fmt.Printf("  %s%s%s\n", constants.ThemeHeader, strings.Repeat("─", 60), constants.ColorReset)
			}
			var dbStatus string
			s.DB.QueryRow("SELECT status FROM module_state WHERE tc_id = ?", mod.ID).Scan(&dbStatus)
			statusIcon := fmt.Sprintf("%s·%s ", constants.ColorGray, constants.ColorReset)
			switch dbStatus {
			case constants.StatusCompleted:
				statusIcon = fmt.Sprintf("%s✓ %s", constants.ColorGreen, constants.ColorReset)
			case constants.StatusFailed:
				statusIcon = fmt.Sprintf("%s✗ %s", constants.ColorRed, constants.ColorReset)
			}
			toolsNote := ""
			if avail, known := moduleAvail[mod.ID]; known && !avail {
				toolsNote = fmt.Sprintf(" %s[tools missing]%s", constants.ColorGray, constants.ColorReset)
			}
			legacyNote := ""
			if strings.HasPrefix(mod.Desc, "[LEGACY]") {
				legacyNote = fmt.Sprintf(" %s[legacy]%s", constants.ColorGray, constants.ColorReset)
			}
			desc := mod.Desc
			if strings.HasPrefix(desc, "[LEGACY]") {
				desc = desc[8:]
			}
			fmt.Printf("  %s%-4s %-28s%s%s  %s\n",
				statusIcon, mod.ID, mod.Name, toolsNote, legacyNote, desc)
		}
		fmt.Println()
		ui.PromptString("Press Enter to return", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("Run Module Directly (by ID)",
		"Skip category menus — type a module ID (e.g. D1, G4) to run it immediately.",
		func() error {
		modID := strings.ToUpper(strings.TrimSpace(ui.PromptString("Enter module ID (e.g. D1, G4)", "")))
		if modID == "" {
			fmt.Printf("%s[*] No module selected.%s\n", constants.ColorGray, constants.ColorReset)
			ui.PromptString("Press Enter to continue", "")
			return nil
		}
		for i := range modules {
			if modules[i].ID == modID {
				return Ctrl.ExecuteModule(&modules[i])
			}
		}
		fmt.Printf("%s[!] Module %s not found.%s\n", constants.ThemeHigh, modID, constants.ColorReset)
		ui.PromptString("Press Enter to continue", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("Generate Assessment Report",
		"Generate a full HTML engagement report from all session findings.",
		func() error {
		fmt.Printf("%s[*] Generating HTML report...%s ", constants.ThemeHeader, constants.ColorReset)
		path, err := report.GenerateReport(s, ModDir)
		if err != nil {
			fmt.Printf("%sFAILED%s\n", constants.ThemeHigh, constants.ColorReset)
			ui.PromptString("Press Enter to continue", "")
			return err
		}
		fmt.Printf("%s[✓]%s Report saved to: %s\n", constants.ThemeSuccess, constants.ColorReset, path)
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("Generate Markdown Report",
		"Generate a Markdown report suitable for pasting into a ticket or wiki.",
		func() error {
		fmt.Printf("%s[*] Generating Markdown report...%s ", constants.ThemeHeader, constants.ColorReset)
		path, err := report.GenerateMarkdownReport(s, ModDir)
		if err != nil {
			fmt.Printf("%sFAILED%s\n", constants.ThemeHigh, constants.ColorReset)
			ui.PromptString("Press Enter to continue", "")
			return err
		}
		fmt.Printf("%s[✓]%s Saved to: %s\n", constants.ThemeSuccess, constants.ColorReset, path)
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("Export CSV (Excel / Sheets)",
		"Export all findings and credentials as a flat CSV file.",
		func() error {
		fmt.Printf("%s[*] Exporting CSV...%s ", constants.ThemeHeader, constants.ColorReset)
		path, err := report.GenerateCSVReport(s, ModDir)
		if err != nil {
			fmt.Printf("%sFAILED%s\n", constants.ThemeHigh, constants.ColorReset)
			ui.PromptString("Press Enter to continue", "")
			return err
		}
		fmt.Printf("%s[✓]%s Saved to: %s\n", constants.ThemeSuccess, constants.ColorReset, path)
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("Show Session Info & Coverage",
		"Display session metadata, scope, module completion percentage, and findings by severity.",
		func() error {
		ui.PrintHeader("Session Status")
		fmt.Printf("  Session:    %s%s%s (%s)\n", constants.ColorBold, s.Name, constants.ColorReset, s.ID)
		fmt.Printf("  Evidence:   %s\n", s.EvidenceDir)
		fmt.Printf("  Report dir: %s\n", s.ReportDir)

		var ssid, bssid, ch string
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestChannel).Scan(&ch)
		if ssid != "" {
			fmt.Printf("  Scope:      %s%s%s (%s) CH%s\n", constants.ColorBold, ssid, constants.ColorReset, bssid, ch)
		} else {
			fmt.Printf("  Scope:      %s<NOT SET>%s\n", constants.ThemeHigh, constants.ColorReset)
		}

		// Coverage
		total := 0
		for _, n := range catTotal {
			total += n
		}
		var done int
		s.DB.QueryRow("SELECT COUNT(*) FROM module_state WHERE status = 'completed'").Scan(&done)
		pct := 0
		if total > 0 {
			pct = done * 100 / total
		}
		fmt.Printf("\n  Coverage:   %d/%d modules completed (%d%%)\n", done, total, pct)

		sevs := []string{"CRITICAL", "HIGH", "MEDIUM", "INFO"}
		fmt.Printf("\n  Findings by severity:\n")
		for _, sev := range sevs {
			var cnt int
			s.DB.QueryRow("SELECT COUNT(*) FROM vulnerability WHERE severity = ?", sev).Scan(&cnt)
			if cnt > 0 {
				color := constants.ThemeInfo
				switch sev {
				case "CRITICAL":
					color = constants.ThemeCritical
				case "HIGH":
					color = constants.ThemeHigh
				case "MEDIUM":
					color = constants.ThemeMedium
				}
				fmt.Printf("    %s%-8s%s %d\n", color, sev, constants.ColorReset, cnt)
			}
		}

		fmt.Println()
		ui.PromptString("Press Enter to return", "")
		return nil
	})

	mainMenu.AddOptionWithHelp("End Engagement (Cleanup Checklist)",
		"Walk through post-engagement housekeeping: stop processes, restore interfaces, verify evidence.",
		func() error {
		Ctrl.CleanupChecklist()
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	})

	mainMenu.Display()
}

// ensureAdapterSetup presents the dual-adapter wizard on the first run of a
// session, then returns the monitor interface name. On session resume it
// reloads persisted values from the DB and re-locks the RoleRegistry.
func ensureAdapterSetup(s *session.Session) string {
	var monIface, mgmtIface string
	s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigWifiInterface).Scan(&monIface)
	s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigAPInterface).Scan(&mgmtIface)

	if monIface != "" {
		// Resumed session — restore registry from DB
		hw.Roles.Assign(hw.RoleMonitor, monIface)
		if mgmtIface != "" {
			hw.Roles.Assign(hw.RoleAP, mgmtIface)
		}
		hw.Roles.Lock()
		logging.Info("Adapter setup restored: monitor=%s ap=%s", monIface, mgmtIface)
		return monIface
	}

	ifaces, _ := hw.ListInterfaces()
	if len(ifaces) == 0 {
		logging.Warn("No wireless interfaces found!")
		return ""
	}

	ui.PrintHeader("Adapter Setup")
	for i, iface := range ifaces {
		fmt.Printf("%d) %-12s %s (%s) [Mode: %s]\n", i+1, iface.Name, iface.Chipset, iface.Driver, iface.Mode)
	}

	// Pick attack/monitor adapter
	if len(ifaces) == 1 {
		fmt.Printf("\nOnly one interface found: %s\n", ifaces[0].Name)
		if !ui.PromptConfirm("Use this as the attack (monitor) adapter?", true) {
			return ""
		}
		monIface = ifaces[0].Name
	} else {
		for {
			monChoice := ui.PromptString("Select attack/monitor adapter [1-"+strconv.Itoa(len(ifaces))+"]", "")
			if monChoice == "" {
				return ""
			}
			monIdx, _ := strconv.Atoi(monChoice)
			if monIdx < 1 || monIdx > len(ifaces) {
				fmt.Printf("%s[!] Invalid selection. Enter a number between 1 and %d.%s\n",
					constants.ThemeHigh, len(ifaces), constants.ColorReset)
				continue
			}
			monIface = ifaces[monIdx-1].Name
			break
		}
	}

	// Pick AP adapter (optional, only when >1 interface)
	if len(ifaces) > 1 {
		fmt.Printf("\n%s[✓] Attack/Monitor adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, monIface)
		fmt.Printf("%s[?]%s Assign an AP adapter for Evil Twin / Rogue AP modules (F1, F2, F3, D5):\n",
			constants.ThemeHeader, constants.ColorReset)
		fmt.Printf("    Enables simultaneous monitor-mode capture + rogue AP broadcasting.\n")
		fmt.Printf("    Without this, those modules toggle the monitor card between modes (degraded).\n\n")
		var mgmtCandidates []hw.Interface
		for _, iface := range ifaces {
			if iface.Name != monIface {
				mgmtCandidates = append(mgmtCandidates, iface)
			}
		}
		for i, iface := range mgmtCandidates {
			fmt.Printf("   %d) %-12s %s (%s)\n", i+1, iface.Name, iface.Chipset, iface.Driver)
		}
		mgmtChoice := ui.PromptString(fmt.Sprintf("AP adapter [1-%d] (or Enter to skip)", len(mgmtCandidates)), "")
		if mgmtChoice != "" {
			mgmtIdx, _ := strconv.Atoi(mgmtChoice)
			if mgmtIdx >= 1 && mgmtIdx <= len(mgmtCandidates) {
				mgmtIface = mgmtCandidates[mgmtIdx-1].Name
				fmt.Printf("%s[✓] AP adapter:%s %s\n", constants.ThemeSuccess, constants.ColorReset, mgmtIface)
			} else {
				fmt.Printf("%s[!] Invalid selection — no AP adapter set.%s\n",
					constants.ThemeHigh, constants.ColorReset)
			}
		} else {
			fmt.Printf("%s[*] No AP adapter selected — Evil Twin modules will run in degraded mode.%s\n", constants.ColorGray, constants.ColorReset)
		}
	}

	// Assign roles and lock
	if err := hw.Roles.Assign(hw.RoleMonitor, monIface); err != nil {
		logging.Error("Failed to assign monitor role: %v", err)
		return ""
	}
	if mgmtIface != "" {
		if err := hw.Roles.Assign(hw.RoleAP, mgmtIface); err != nil {
			logging.Warn("Failed to assign AP role: %v", err)
			mgmtIface = ""
		}
	}
	hw.Roles.Lock()

	// Persist to DB
	s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigWifiInterface, monIface)
	if mgmtIface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigAPInterface, mgmtIface)
	}

	// Detect uplink interface for NAT masquerade (used by F1, F2, F3 rogue AP modules)
	if uplinkIface, err := hw.DetectUplinkInterface(); err != nil {
		logging.Warn("Could not detect uplink interface — rogue AP NAT will not be configured: %v", err)
	} else {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigUplinkIface, uplinkIface)
		logging.Info("Uplink interface for NAT: %s", uplinkIface)
	}

	logging.Success("Adapter setup complete: monitor=%s ap=%s", monIface, mgmtIface)
	return monIface
}
