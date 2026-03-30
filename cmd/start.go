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
	"wifi-astra/internal/ingest"
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
		
		// 3b. Auto-Update OUI if missing or old
		ouiPath := filepath.Join(baseDir, "data", "oui.json")
		if info, err := os.Stat(ouiPath); os.IsNotExist(err) || (err == nil && time.Since(info.ModTime()) > 30*24*time.Hour) {
			logging.Info("OUI database is missing or outdated. Refreshing in background...")
			go func() {
				dataDir := filepath.Dir(ouiPath)
				os.MkdirAll(dataDir, 0755)
				ingest.UpdateOUIDatabase(dataDir)
			}()
		}

		// Ensure base directory exists and is accessible by the dropped user
		os.MkdirAll(baseDir, 0755)
		if user, err := prereq.GetSudoUser(); err == nil {
			os.Chown(baseDir, user.UID, user.GID)
		}

		// 4. Drop Privileges for the rest of the execution
		prereq.DropPrivileges()

		// 5. Check for Headless Plan
		if isHeadless {
			// In headless mode, the session is created inside RunAutonomousAudit
			err := headless.RunAutonomousAudit(ConfigFile, ModDir, func(s *session.Session, m *module.Module) error {
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
		baseDir := "./sessions"
		if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
			baseDir = config.GlobalConfig.SessionDir
		}

		fmt.Println("\n--- WiFi-Astra: Session Manager ---")

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
		}

		choice := ui.PromptString("Select an option", "1")

		if choice == "1" {
			fmt.Println("\n--- New Session Setup ---")
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
			fmt.Println("\n--- Available Sessions ---")
			for i, s := range existing {
				fmt.Printf("%d) %s\n", i+1, s.Name())
			}
			sIdx := ui.PromptString("Select session to resume", "")
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
			}
		} else if choice == "3" && len(existing) > 0 {
			fmt.Println("\n--- Available Sessions for Deletion ---")
			for i, s := range existing {
				fmt.Printf("%d) %s\n", i+1, s.Name())
			}
			sIdx := ui.PromptString("Select session to delete (or 0 to cancel)", "0")
			idx, _ := strconv.Atoi(sIdx)
			if idx >= 1 && idx <= len(existing) {
				sessionID := existing[idx-1].Name()
				warning := fmt.Sprintf("\n[!] WARNING: This will permanently delete all logs, evidence, and results for session %s.", sessionID)
				fmt.Println(warning)
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
		}
	}
}

func launchMainMenu(s *session.Session) {
	ui.GetManager().ClearScreen()
	Ctrl = controller.NewAssessmentController(s, ExecMgr, ModDir)

	iface := ensureInterfaceSelection(s)
	if iface == "" {
		logging.Error("No wireless interface selected.")
		return
	}

	modules, _ := module.DiscoverModules(ModDir)
	mainMenu := ui.NewMenu("Assessment Menu")

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

	categories := make(map[string]*ui.Menu)
	for _, m := range modules {
		if _, ok := categories[m.Category]; !ok {
			name := catNames[m.Category]
			if name == "" {
				name = "Unknown"
			}
			categories[m.Category] = ui.NewMenu("Category " + m.Category + ": " + name)
		}

		var status string
		s.DB.QueryRow("SELECT status FROM module_state WHERE tc_id = ?", m.ID).Scan(&status)
		prefix := ""
		switch status {
		case constants.StatusCompleted:
			prefix = fmt.Sprintf("%s✓%s ", constants.ColorGreen, constants.ColorReset)
		case constants.StatusFailed:
			prefix = fmt.Sprintf("%s✗%s ", constants.ColorRed, constants.ColorReset)
		case constants.StatusRunning:
			prefix = fmt.Sprintf("%s>%s ", constants.ColorCyan, constants.ColorReset)
		}

		mod := m
		categories[m.Category].AddOption(prefix+m.ID+": "+m.Name, func() error {
			return Ctrl.ExecuteModule(&mod)
		})
	}

	catKeys := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	for _, k := range catKeys {
		if sub, ok := categories[k]; ok {
			label := fmt.Sprintf("Category %s: %s", k, catNames[k])
			mainMenu.AddOption(label, func() error {
				ui.GetManager().ClearScreen()
				return sub.Display()
			})
		}
	}

	mainMenu.AddOption("List All Available Modules", func() error {
		fmt.Println("\n--- All Assessment Modules ---")
		for _, m := range modules {
			fmt.Printf("[%s] %-4s %-30s - %s\n", m.Category, m.ID, m.Name, m.Desc)
		}
		return nil
	})

	mainMenu.AddOption("Generate Assessment Report", func() error {
		fmt.Print("[*] Generating report... ")
		path, err := report.GenerateReport(s)
		if err != nil {
			fmt.Println("FAILED")
			return err
		}
		fmt.Printf("SUCCESS\n[+] Report saved to: %s\n", path)
		return nil
	})

	mainMenu.AddOption("Show Session Info", func() error {
		fmt.Printf("Session ID: %s\n", s.ID)
		fmt.Printf("Log Directory: %s\n", s.LogDir)
		return nil
	})

	mainMenu.Display()
}

func ensureInterfaceSelection(s *session.Session) string {
	var currentIface string
	s.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigWifiInterface).Scan(&currentIface)
	if currentIface != "" {
		logging.Info("Using persisted interface: %s", currentIface)
		return currentIface
	}

	ifaces, _ := hw.ListInterfaces()
	if len(ifaces) == 0 {
		logging.Warn("No wireless interfaces found!")
		return ""
	}

	fmt.Println("\nAvailable Wireless Interfaces:")
	for i, iface := range ifaces {
		fmt.Printf("%d) %s: %s (%s) [Mode: %s]\n", i+1, iface.Name, iface.Chipset, iface.Driver, iface.Mode)
	}

	var choice string
	if len(ifaces) == 1 {
		fmt.Printf("\nOnly one interface found: %s\n", ifaces[0].Name)
		if !ui.PromptConfirm("Use this interface?", true) {
			return ""
		}
		choice = "1"
	} else {
		choice = ui.PromptString("Select interface [1-"+strconv.Itoa(len(ifaces))+"]", "")
	}

	idx, _ := strconv.Atoi(choice)
	if idx < 1 || idx > len(ifaces) {
		return ""
	}

	selected := ifaces[idx-1].Name
	s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigWifiInterface, selected)
	logging.Success("Selected interface %s saved to session.", selected)
	return selected
}
