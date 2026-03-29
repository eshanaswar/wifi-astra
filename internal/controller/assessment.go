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
	Session  *session.Session
	ExecMgr  *executor.Manager
	NetMgr   *executor.NetworkManager
	ModDir   string
	Running  string // ID of currently running module
}

func NewAssessmentController(s *session.Session, mgr *executor.Manager, modDir string) *AssessmentController {
	return &AssessmentController{
		Session: s,
		ExecMgr: mgr,
		ModDir:  modDir,
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
	if m.Category == "F" || strings.Contains(m.Reqs, constants.ReqNAT) {
		uplink := config[constants.ConfigUplinkInterface]
		internalNet := config[constants.ConfigInternalNet]
		internalIP := config[constants.ConfigInternalIP]

		// Set defaults if missing
		if uplink == "" {
			uplink = "eth0" // Fallback to eth0
		}
		if internalNet == "" {
			internalNet = "192.168.44.0/24"
		}
		if internalIP == "" {
			internalIP = "192.168.44.1"
		}

		c.NetMgr = executor.NewNetworkManager(uplink, internalNet, internalIP)
		
		fmt.Printf("   [*] Initializing NAT (Uplink: %s, Subnet: %s)...\n", uplink, internalNet)
		if err := c.NetMgr.SetupNAT(); err != nil {
			logging.Error("NAT Setup Failed: %v", err)
			return err
		}
		defer c.NetMgr.CleanupNAT()

		if err := c.NetMgr.SetupInterfaceIP(iface); err != nil {
			logging.Error("Interface IP Setup Failed: %v", err)
			return err
		}
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

	c.Session.DB.Exec(`UPDATE module_state SET status = ?, exit_code = ?, ended_at = ?, duration_sec = ?, command_run = ?
		WHERE tc_id = ?`, status, exitCode, endTime.Format("2006-01-02 15:04:05"), duration, fullCommand, m.ID)

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

	logging.Info("Starting module %s...", tcID)

	ctx := context.Background()
	exitCode, err := c.ExecMgr.RunWithEnv(ctx, tcID, matches[0], []string{}, logFile, env)
	return exitCode, err
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
			logging.Success("Target set to %s (%s)", target.SSID, target.BSSID)
		}
	}
}
