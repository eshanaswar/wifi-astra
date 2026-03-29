package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wifi-astra/internal/db"
	"wifi-astra/internal/ingest"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/module"
	"wifi-astra/internal/session"
	"wifi-astra/internal/ui"
	"wifi-astra/pkg/constants"
	"wifi-astra/pkg/executor"
	"wifi-astra/pkg/hw"
)

type AssessmentController struct {
	Session      *session.Session
	ExecMgr      *executor.Manager
	NetMgr       *executor.NetworkManager
	ModDir       string
	Running      string // ID of currently running module
	SupportProcs map[string]*executor.Process
}

func NewAssessmentController(s *session.Session, mgr *executor.Manager, modDir string) *AssessmentController {
	return &AssessmentController{
		Session:      s,
		ExecMgr:      mgr,
		ModDir:       modDir,
		SupportProcs: make(map[string]*executor.Process),
	}
}

func (c *AssessmentController) ExecuteModule(m *module.Module) error {
	ui.GetManager().ClearScreen()
	fmt.Printf("\n%s\n", strings.Repeat("═", 80))
	fmt.Printf("🚀 MISSION START: %s (%s)\n", m.Name, m.ID)
	fmt.Printf("%s\n", strings.Repeat("─", 80))
	fmt.Printf("📝 Description: %s\n", m.Desc)

	// 1. Load Session Config
	config := make(map[string]string)
	rows, _ := c.Session.DB.Query("SELECT key, value FROM config")
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		config[k] = v
	}
	rows.Close()

	// 2. Target Briefing
	fmt.Println("\n📡 [Target Briefing]")
	iface := config[constants.ConfigWifiInterface]
	fmt.Printf("   • Interface: %s\n", iface)
	if config[constants.ConfigGuestSSID] != "" {
		fmt.Printf("   • Target:    %s (%s) [CH %s]\n", config[constants.ConfigGuestSSID], config[constants.ConfigGuestBSSID], config[constants.ConfigGuestChannel])
	} else {
		fmt.Println("   • Target:    <NOT SET - Running Discovery>")
	}

	// 3. Dependency Check
	fmt.Println("\n🛠️  [Pre-flight Check]")
	if m.Tools != "" && m.Tools != "none" {
		tools := strings.Split(m.Tools, ",")
		foundCount := 0
		for _, t := range tools {
			t = strings.TrimSpace(t)
			if t == "" || t == "none" {
				continue
			}
			path, err := exec.LookPath(t)
			if err == nil {
				fmt.Printf("   [✓] %-12s found at %s\n", t, path)
				foundCount++
			} else {
				fmt.Printf("   [✗] %-12s NOT FOUND\n", t)
			}
		}
		if foundCount < len(tools) && m.Critical {
			return fmt.Errorf("missing critical tool dependencies")
		}
	} else {
		fmt.Println("   [✓] No tool dependencies.")
	}

	// 4. Hardware Prep & Locking
	if err := hw.LockInterface(iface, m.ID); err != nil {
		return fmt.Errorf("Hardware collision: %v. Please wait for the other module to finish", err)
	}
	defer hw.UnlockInterface(iface)

	if strings.Contains(m.Reqs, constants.ReqMonitorIface) {
		fmt.Print("   [*] Enabling Monitor Mode... ")
		if !hw.IsValidInterfaceName(iface) {
			return fmt.Errorf("invalid interface name: %s", iface)
		}
		monIface, err := hw.EnableMonitorMode(iface)
		if err != nil {
			fmt.Println("FAILED")
			return err
		}
		fmt.Println("SUCCESS (" + monIface + ")")
		
		// Lock the newly created monitor interface as well
		hw.LockInterface(monIface, m.ID)
		defer hw.UnlockInterface(monIface)
		defer hw.DisableMonitorMode(monIface)
		os.Setenv(constants.ConfigMonitorIface, monIface)

		// SMART TACTICAL: Scout target defenses if BSSID is known
		targetBSSID := config[constants.ConfigGuestBSSID]
		if targetBSSID != "" {
			intel, err := hw.ScoutTarget(targetBSSID, monIface)
			if err == nil {
				for k, v := range intel {
					os.Setenv("ASTRA_TARGET_"+k, v)
				}
			}
		}
	} else if strings.Contains(m.Reqs, constants.ReqManagedIface) {
		os.Setenv(constants.ConfigWifiInterface, iface)
	}

	// 4.5. Networking Setup (NAT/Routing) for MITM modules
	// ... (NAT logic) ...

	// 4.7. SMART TACTICAL PROMPTS (Go-Side Interactivity)
	// Handle tactical choices here to prevent TTY contention in modules
	
	// A. SNR Safeguard (Global)
	rssiStr := os.Getenv("ASTRA_TARGET_RSSI")
	if rssiStr != "" {
		rssi, _ := strconv.Atoi(rssiStr)
		if rssi != 0 && rssi < -75 {
			fmt.Printf("\n%s[!] WARNING: Low Signal Strength Detected (%ddBm)%s\n", constants.ThemeHigh, rssi, constants.ColorReset)
			if !ui.PromptConfirm("Injection/Active attacks are unreliable. Continue?", false) {
				return nil
			}
		}
	}

	// PMF Intelligence Guard
	pmf, _ := db.GetConfig(c.Session.DB, "ASTRA_TARGET_PMF")
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

	// B. Target Client Selection (Global for relevant modules)
	// Modules requiring a target client: D1, E3, F4, G4, G5
	if strings.Contains("D1,E3,F4,G4,G5", m.ID) {
		clients, err := db.ListClients(c.Session.DB)
		if err == nil && len(clients) > 0 {
			var options []string
			for _, cl := range clients {
				options = append(options, fmt.Sprintf("%s (%s) [%ddBm]", cl.MAC, cl.Vendor, cl.LastSignal))
			}
			if m.ID == "D1" {
				options = append(options, "BROADCAST (Loud/Destructive)")
			}
			
			choice := ui.PromptList("Select Target Client", options)
			if m.ID == "D1" && choice == len(clients) {
				os.Setenv("TARGET_CLIENT", "FF:FF:FF:FF:FF:FF")
			} else if choice >= 0 {
				os.Setenv("TARGET_CLIENT", clients[choice].MAC)
			}
		}
	}

	// C. Module-Specific Logic
	switch m.ID {
	case "A1":
		options := []string{"Standard (60s)", "Deep Scan (120s - Recommended for DFS/5GHz)"}
		if ui.PromptList("Select Scan Depth", options) == 1 {
			os.Setenv("SCAN_TIME", "120")
		} else {
			os.Setenv("SCAN_TIME", "60")
		}
	case "A3":
		if ui.PromptConfirm("Force reveal via surgical deauth?", true) {
			os.Setenv("ACTIVE_REVEAL", "yes")
		}
	case "D3":
		options := []string{"Pixie Dust (Fast, 1 transaction)", "Online Brute-Force (Sequential)"}
		if ui.PromptList("Select WPS Vector", options) == 1 {
			os.Setenv("WPS_ATTACK", "online")
			delay := ui.PromptString("Enter delay (seconds)", "300")
			os.Setenv("WPS_DELAY", delay)
		} else {
			os.Setenv("WPS_ATTACK", "pixie")
		}
	case "D7":
		options := []string{"Targeted Deauth (Surgical)", "CSA (Stealthier)"}
		if ui.PromptList("Select Roaming Catalyst", options) == 1 {
			os.Setenv("CATALYST", "csa")
		} else {
			os.Setenv("CATALYST", "deauth")
		}
	case "F1":
		opts := []string{"SSID Only (Random BSSID)", "BSSID Clone (Match Target)"}
		if ui.PromptList("Select Rogue AP Mode", opts) == 1 {
			os.Setenv("AP_MODE", "clone")
		} else {
			os.Setenv("AP_MODE", "ssid")
		}
		
		catOpts := []string{"None", "Targeted Deauth", "CSA"}
		os.Setenv("CATALYST", strconv.Itoa(ui.PromptList("Select Roaming Catalyst", catOpts)))
		
		if ui.PromptConfirm("Launch Responder pivot in background?", true) {
			os.Setenv("LAUNCH_RESPONDER", "yes")
		}
	case "F2":
		opts := []string{"Dynamic MANA (Directed Probes)", "Known Beacon Attack (Loud)"}
		if ui.PromptList("Select Karma Vector", opts) == 1 {
			os.Setenv("KARMA_MODE", "loud")
		} else {
			os.Setenv("KARMA_MODE", "mana")
		}
	case "F3":
		opts := []string{"Generic Corporate", "Microsoft 365 (High-Fidelity)"}
		if ui.PromptList("Select Phishing Template", opts) == 1 {
			os.Setenv("PHISH_TEMPLATE", "m365")
		} else {
			os.Setenv("PHISH_TEMPLATE", "generic")
		}
	case "F5":
		os.Setenv("TUNNEL_DOMAIN", ui.PromptString("Enter tunnel domain", ""))
		os.Setenv("TUNNEL_PASS", ui.PromptString("Enter tunnel password", ""))
	case "G5":
		os.Setenv("ROGUE_BSSID", ui.PromptString("Enter Rogue AP BSSID", ""))
	}

	// 5. Run the Module
	fmt.Printf("\n%s\n", strings.Repeat("┈", 80))
	fmt.Println("🛰️  MISSION FEED:")
	fmt.Printf("%s\n\n", strings.Repeat("┈", 80))

	startTime := time.Now()
	c.Session.DB.Exec("INSERT OR REPLACE INTO module_state (tc_id, status, started_at) VALUES (?, ?, ?)",
		m.ID, constants.StatusRunning, startTime.Format("2006-01-02 15:04:05"))

	c.Running = m.ID
	
	// standardized command formatting for DB
	modFile := filepath.Join(c.ModDir, fmt.Sprintf("%s_*.sh", strings.ToLower(m.ID)))
	matches, _ := filepath.Glob(modFile)
	fullCommand := ""
	if len(matches) > 0 {
		fullCommand = matches[0]
	}

	exitCode, err := c.runModuleWithCode(m.ID)
	c.Running = ""

	endTime := time.Now()
	duration := int(endTime.Sub(startTime).Seconds())

	status := constants.StatusCompleted
	if err != nil || exitCode != 0 {
		status = constants.StatusFailed
	}

	_, dbErr := c.Session.DB.Exec(`UPDATE module_state SET status = ?, exit_code = ?, ended_at = ?, duration_sec = ?, command_run = ?
		WHERE tc_id = ?`, status, exitCode, endTime.Format("2006-01-02 15:04:05"), duration, fullCommand, m.ID)
	
	if dbErr != nil {
		logging.Error("State update failed for %s: %v", m.ID, dbErr)
	}

	fmt.Printf("\n%s\n", strings.Repeat("┈", 80))
	if status == constants.StatusCompleted {
		fmt.Println("✅ MISSION COMPLETE")
	} else {
		fmt.Printf("❌ MISSION FAILED (Exit Code: %d)\n", exitCode)
	}
	fmt.Printf("%s\n", strings.Repeat("┈", 80))

	// 6. Evidence Summary
	c.DisplayEvidence(m.ID)

	// 7. Post-run logic
	c.HandlePostRun(m)

	// 8. Mission Observation Summary
	c.DisplayMissionSummary(m.ID)

	fmt.Printf("\n%s\n", strings.Repeat("═", 80))
	ui.PromptString("Press Enter to return to menu", "")
	return nil
}

func (c *AssessmentController) DisplayMissionSummary(tcID string) {
	fmt.Printf("\n%s 📝 [Mission Observations] %s\n", constants.ThemeHeader, constants.ColorReset)
	
	// 1. Query vulnerabilities
	rows, err := c.Session.DB.Query(`SELECT name, severity, rationale FROM vulnerability WHERE tc_id = ?`, tcID)
	found := false
	if err == nil {
		for rows.Next() {
			var name, sev, rationale string
			if err := rows.Scan(&name, &sev, &rationale); err != nil {
				continue
			}
			found = true
			
			sevColor := constants.ColorWhite
			switch sev {
			case "CRITICAL": sevColor = constants.ThemeCritical
			case "HIGH":     sevColor = constants.ThemeHigh
			case "MEDIUM":   sevColor = constants.ThemeMedium
			}
			
			fmt.Printf("   • %s[%s]%s %s%s%s\n", sevColor, sev, constants.ColorReset, constants.ColorBold, name, constants.ColorReset)
			if rationale != "" {
				fmt.Printf("     %sRationale:%s %s\n", constants.ColorGray, constants.ColorReset, rationale)
			}
		}
		rows.Close()
	}

	// 2. Query credentials
	credRows, err := c.Session.DB.Query(`SELECT username, proto, rationale FROM credential WHERE tc_id = ?`, tcID)
	if err == nil {
		for credRows.Next() {
			var user, proto, rationale string
			if err := credRows.Scan(&user, &proto, &rationale); err != nil {
				continue
			}
			found = true
			fmt.Printf("   • %s[CREDENTIAL]%s %s%s%s captured via %s\n", constants.ThemeSuccess, constants.ColorReset, constants.ColorBold, user, constants.ColorReset, proto)
			if rationale != "" {
				fmt.Printf("     %sRationale:%s %s\n", constants.ColorGray, constants.ColorReset, rationale)
			}
		}
		credRows.Close()
	}

	if !found {
		fmt.Printf("   %s• No findings recorded during this mission.%s\n", constants.ColorGray, constants.ColorReset)
	}
}

func (c *AssessmentController) runModuleWithCode(tcID string) (int, error) {
	modFile := filepath.Join(c.ModDir, fmt.Sprintf("%s_*.sh", strings.ToLower(tcID)))
	matches, _ := filepath.Glob(modFile)
	if len(matches) == 0 {
		return -1, fmt.Errorf("module %s not found", tcID)
	}

	logFile := filepath.Join(c.Session.LogDir, fmt.Sprintf("%s.log", strings.ToLower(tcID)))
	outputCSV := filepath.Join(c.Session.EvidenceDir, strings.ToLower(tcID)+"_results.csv")
	outputPCAP := filepath.Join(c.Session.EvidenceDir, strings.ToLower(tcID)+"_capture.pcap")

	// Set up environment for the module
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", constants.ConfigSessionID, c.Session.ID))
	env = append(env, fmt.Sprintf("SESSION_DIR=%s", c.Session.BaseDir))
	env = append(env, fmt.Sprintf("SESSION_EVIDENCE_DIR=%s", c.Session.EvidenceDir))

	// Binary path for callback
	astraBin, _ := os.Executable()
	env = append(env, fmt.Sprintf("ASTRA_BIN=%s", astraBin))
	env = append(env, fmt.Sprintf("OUTPUT_CSV=%s", outputCSV))
	env = append(env, fmt.Sprintf("OUTPUT_PCAP=%s", outputPCAP))

	// Load config from DB into Env
	rows, err := c.Session.DB.Query("SELECT key, value FROM config")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err == nil {
				env = append(env, fmt.Sprintf("%s=%s", k, v))
			}
		}
	}

	// Inject Colors for Module Highlighting
	env = append(env, "ASTRA_COLOR_PROMPT=\033[1;34m")
	env = append(env, "ASTRA_COLOR_VAR=\033[1;33m")
	env = append(env, "ASTRA_COLOR_BOLD=\033[1m")
	env = append(env, "ASTRA_COLOR_ACTION=\033[1;37;44m") // Bold White on Blue Background
	env = append(env, "ASTRA_COLOR_RESET=\033[0m")

	logging.Info("Starting module %s...", tcID)

	// RESTORE TERMINAL STATE: Close readline before running the module
	ui.GetManager().Close()

	// 🛰️ SMART PROGRESS MONITOR
	pm := ui.NewProgressMonitor(tcID)
	pm.Start(func() (int, string, bool) {
		var p int
		var s string
		var updatedAt string
		err := c.Session.DB.QueryRow("SELECT percent, status_text, updated_at FROM module_progress WHERE tc_id = ?", tcID).Scan(&p, &s, &updatedAt)
		if err != nil {
			return 0, "Initializing...", false
		}
		
		// Stuck Detection: If not updated in 30s
		t, _ := time.Parse("2006-01-02 15:04:05", updatedAt)
		// SQLite CURRENT_TIMESTAMP is UTC
		stuck := time.Since(t.UTC()).Seconds() > 30
		
		return p, s, stuck
	})
	defer pm.Stop()

	ctx := context.Background()
	exitCode, err := c.ExecMgr.RunWithEnv(ctx, tcID, matches[0], []string{}, logFile, env)
	return exitCode, err
}

func (c *AssessmentController) LaunchSupportModule(tcID string) error {
	// Find the module
	modules, _ := module.DiscoverModules(c.ModDir)
	var m *module.Module
	for _, mod := range modules {
		if mod.ID == tcID {
			m = &mod
			break
		}
	}
	if m == nil {
		return fmt.Errorf("support module %s not found", tcID)
	}

	logging.Info("Launching background support module: %s...", m.Name)
	
	// Prepare environment (re-use logic from runModuleWithCode)
	// For brevity, we'll implement a helper or inline it
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", constants.ConfigSessionID, c.Session.ID))
	env = append(env, fmt.Sprintf("SESSION_DIR=%s", c.Session.BaseDir))
	env = append(env, fmt.Sprintf("SESSION_EVIDENCE_DIR=%s", c.Session.EvidenceDir))
	
	// Re-load config from DB
	rows, _ := c.Session.DB.Query("SELECT key, value FROM config")
	defer rows.Close()
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	logFile := filepath.Join(c.Session.LogDir, fmt.Sprintf("%s_bg.log", strings.ToLower(tcID)))
	
	modFile := filepath.Join(c.ModDir, fmt.Sprintf("%s_*.sh", strings.ToLower(tcID)))
	matches, _ := filepath.Glob(modFile)
	
	proc, err := c.ExecMgr.SpawnWithEnv(context.Background(), tcID+"_bg", matches[0], []string{}, logFile, env)
	if err != nil {
		return err
	}
	
	c.SupportProcs[tcID] = proc
	logging.Success("Support module %s is now running in the background.", tcID)
	return nil
}

func (c *AssessmentController) DisplayEvidence(tcID string) {
	fmt.Println("\n📁 [Generated Evidence]")
	files, _ := os.ReadDir(c.Session.EvidenceDir)
	evidenceFound := false
	for _, f := range files {
		if strings.HasPrefix(strings.ToLower(f.Name()), strings.ToLower(tcID)) {
			fmt.Printf("   • %s\n", filepath.Join(c.Session.EvidenceDir, f.Name()))
			evidenceFound = true
		}
	}
	if !evidenceFound {
		fmt.Println("   • No specific evidence files recorded.")
	}
}

func (c *AssessmentController) HandlePostRun(m *module.Module) {
	// 1. Generic result.json ingestion
	if err := ingest.IngestResultJSON(c.Session.DB, m.ID, c.Session.EvidenceDir); err != nil {
		logging.Error("Failed to ingest result JSON: %v", err)
	}

	// 2. Dispatch to registered specialized parsers
	if err := ingest.Dispatch(c.Session.DB, m.ID, c.Session.EvidenceDir); err != nil {
		logging.Error("Ingestion error for %s: %v", m.ID, err)
	}

	// 3. Post-run UI logic
	if m.ID == "A1" {
		c.HandleA1PostRun()
	}
}

func (c *AssessmentController) HandleA1PostRun() {
	csvFile := filepath.Join(c.Session.EvidenceDir, "a1_results.csv")
	if _, err := os.Stat(csvFile); err == nil {
		ingest.IngestAirodumpCSV(c.Session.DB, "A1", csvFile)
		networks, _ := ingest.ParseScanResults(csvFile)

		fmt.Println("\n📊 [Discovery Summary]")
		for i, n := range networks {
			fmt.Printf("   %d) %-25s %-18s CH %d (%ddBm)\n", i+1, n.SSID, n.BSSID, n.Channel, n.Signal)
		}

		choice := ui.PromptString("\nSelect target network to set as session default", "")
		idx, _ := strconv.Atoi(choice)
		if idx >= 1 && idx <= len(networks) {
			target := networks[idx-1]
			c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestSSID, target.SSID)
			c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestBSSID, target.BSSID)
			c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestChannel, strconv.Itoa(target.Channel))
			
			// Redundant Safety: Ensure A1 is marked as completed if target is set
			c.Session.DB.Exec("UPDATE module_state SET status = ? WHERE tc_id = 'A1'", constants.StatusCompleted)
			
			logging.Success("Target set to %s (%s)", target.SSID, target.BSSID)
		}
	}
}
