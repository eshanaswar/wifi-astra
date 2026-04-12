package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	Session      *session.Session
	ExecMgr      *executor.Manager
	NetMgr       *executor.NetworkManager
	ModDir       string
	Running      string // ID of currently running module
	SupportProcs map[string]*executor.Process
	WindowCount  int    // Track number of open tactical windows
}

func NewAssessmentController(s *session.Session, mgr *executor.Manager, modDir string) *AssessmentController {
	return &AssessmentController{
		Session:      s,
		ExecMgr:      mgr,
		ModDir:       modDir,
		SupportProcs: make(map[string]*executor.Process),
		WindowCount:  0,
	}
}

func (c *AssessmentController) getScreenGeometry() (int, int, int, int) {
	// Default fallback (assuming 1080p if detection fails)
	sw, sh := 1920, 1080
	
	out, err := exec.Command("sh", "-c", "xrandr | grep '*' | awk '{print $1}'").Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(out)), "x")
		if len(parts) == 2 {
			w, _ := strconv.Atoi(parts[0])
			h, _ := strconv.Atoi(parts[1])
			if w > 0 && h > 0 {
				sw, sh = w, h
			}
		}
	}

	// Calculate 1/4th size
	w := sw / 2
	h := sh / 2
	
	// Calculate position based on WindowCount
	x, y := 0, 0
	quadrant := c.WindowCount % 4
	switch quadrant {
	case 1: x = w
	case 2: y = h
	case 3: x = w; y = h
	}
	
	c.WindowCount++
	return x, y, w, h
}

func (c *AssessmentController) CheckPreviousRun(m *module.Module) bool {
	// Skip for headless mode
	if os.Getenv("ASTRA_HEADLESS") == "true" {
		return true
	}

	var status string
	err := c.Session.DB.QueryRow("SELECT status FROM module_state WHERE tc_id = ?", m.ID).Scan(&status)
	if err != nil || status != constants.StatusCompleted {
		return true // Proceed if not completed or error
	}

	ui.GetManager().ClearScreen()
	fmt.Printf("\n%s[!] ATTENTION: Module %s (%s) was already completed in this session.%s\n", constants.ThemeHigh, m.ID, m.Name, constants.ColorReset)
	
	c.DisplayMissionSummary(m.ID)

	fmt.Printf("\n%sWould you like to rerun this module?%s\n", constants.ColorBold, constants.ColorReset)
	fmt.Println("Existing findings will be preserved, but rerunning may take additional time.")
	
	rerun := ui.PromptConfirm("Rerun?", false)
	if !rerun {
		ui.PromptString("\nPress Enter to return to menu", "")
	}
	return rerun
}

func (c *AssessmentController) ExecuteModule(m *module.Module) error {
	// 0. Check for previous successful run
	if !c.CheckPreviousRun(m) {
		return nil
	}

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

	// B. Duration Mode (Global for Timed modules)
	if m.Timed {
		durationOpts := []string{"Timed (Surgical - Default)", "Indefinite (Until Ctrl+C)"}
		choice := ui.PromptList("Select Duration Mode", durationOpts)
		if choice == -1 {
			return nil
		}
		if choice == 1 {
			os.Setenv("ASTRA_INDEFINITE", "true")
			// Set very large timeouts to effectively bypass 'timeout' commands in scripts
			os.Setenv("SCAN_TIME", "36000")
			os.Setenv("CAPTURE_TIME", "36000")
			fmt.Printf("\n%s[*] Indefinite mode active. Results will be recorded as they occur.%s\n", constants.ThemeSuccess, constants.ColorReset)
		} else {
			os.Setenv("ASTRA_INDEFINITE", "false")
		}
	}

	// C. Automated Tactical Prompts via Registry
	for _, promptKey := range m.Prompts {
		promptKey = strings.TrimSpace(promptKey)
		if promptFn, ok := module.PromptRegistry[promptKey]; ok {
			if err := promptFn(m, c.Session.DB); err != nil {
				if err.Error() == "interrupted" {
					return nil
				}
				logging.Warn("Tactical prompt %s failed: %v", promptKey, err)
			}
		} else {
			logging.Debug("No registry entry for required prompt: %s", promptKey)
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
	// If exitCode is -1 (interrupted) or 130 (SIGINT in bash), and it's indefinite mode, it's a success
	if (err != nil || exitCode != 0) {
		if os.Getenv("ASTRA_INDEFINITE") == "true" && (exitCode == -1 || exitCode == 130 || exitCode == 143) {
			status = constants.StatusCompleted
			logging.Info("Indefinite mission %s stopped by user. Marking as completed.", m.ID)
		} else {
			status = constants.StatusFailed
		}
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
	if os.Getenv("ASTRA_HEADLESS") != "true" {
		ui.PromptString("Press Enter to return to menu", "")
	}
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

	// 3. Query discovered networks
	netRows, err := c.Session.DB.Query(`SELECT ssid, bssid, channel FROM network WHERE tc_id = ?`, tcID)
	if err == nil {
		for netRows.Next() {
			var ssid, bssid, channel string
			if err := netRows.Scan(&ssid, &bssid, &channel); err != nil {
				continue
			}
			found = true
			fmt.Printf("   • %s[NETWORK]%s %s (%s) on CH %s\n", constants.ThemeSuccess, constants.ColorReset, ssid, bssid, channel)
		}
		netRows.Close()
	}

	// 4. Query client probes
	probeRows, err := c.Session.DB.Query(`SELECT mac, ssid FROM client_probe WHERE tc_id = ?`, tcID)
	if err == nil {
		for probeRows.Next() {
			var mac, ssid string
			if err := probeRows.Scan(&mac, &ssid); err != nil {
				continue
			}
			found = true
			fmt.Printf("   • %s[PROBE]%s Client %s searching for %s\n", constants.ThemeSuccess, constants.ColorReset, mac, ssid)
		}
		probeRows.Close()
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

	// Create a map for easy lookup during window spawning
	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Inject Colors for Module Highlighting
	env = append(env, "ASTRA_COLOR_PROMPT=\033[1;34m")
	env = append(env, "ASTRA_COLOR_VAR=\033[1;33m")
	env = append(env, "ASTRA_COLOR_BOLD=\033[1m")
	env = append(env, "ASTRA_COLOR_ACTION=\033[1;37;44m") // Bold White on Blue Background
	env = append(env, "ASTRA_COLOR_RESET=\033[0m")
	env = append(env, "TERM=xterm-256color") // Ensure interactive tools work in separate windows

	logging.Info("Starting module %s...", tcID)
	c.Running = tcID
	defer func() { c.Running = "" }()

	// RESTORE TERMINAL STATE: Close readline before running the module
	ui.GetManager().Close()

	// 4.8. Tactical Window Selection (Enforced by default if DISPLAY is available and NOT headless)
	useWindow := false
	if os.Getenv("DISPLAY") != "" && os.Getenv("ASTRA_HEADLESS") != "true" {
		useWindow = true
		os.Setenv("ASTRA_IN_WINDOW", "true")
	} else {
		os.Setenv("ASTRA_IN_WINDOW", "false")
	}

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

	// GRACEFUL STOP HANDLER (Ctrl+C for Indefinite Execution)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer signal.Stop(sigChan)

	go func() {
		select {
		case sig := <-sigChan:
			logging.Info("\n[!] Received signal: %v. Stopping module %s gracefully...", sig, tcID)
			c.ExecMgr.Stop(tcID)
		case <-ctx.Done():
			// Normal exit or module finished
		}
	}()

	var exitCode int
	if useWindow {
		termBin, termArgs := c.ExecMgr.GetTerminalEmulator(fmt.Sprintf("Astra: %s", tcID))
		if termBin != "" {
			// Get pixel geometry for 1/4th screen tiling
			winX, winY, winW, winH := c.getScreenGeometry()

			// 1. Create a temporary wrapper script to ensure environment is 100% correct
			wrapperPath := filepath.Join(c.Session.BaseDir, fmt.Sprintf(".astra_%s_wrapper.sh", strings.ToLower(tcID)))
			
			vars := []string{
				"ASTRA_BIN", "SESSION_DIR", "SESSION_EVIDENCE_DIR", 
				"MONITOR_INTERFACE", "WIFI_INTERFACE", 
				"GUEST_SSID", "GUEST_BSSID", "GUEST_CHANNEL", 
				"SCAN_TIME", "CAPTURE_TIME", "ASTRA_INDEFINITE",
			}
			
			wrapperContent := "#!/usr/bin/env bash\n"
			wrapperContent += "export ASTRA_IN_WINDOW=true\n"
			wrapperContent += "export TERM=xterm-256color\n"
			
			// TTY and Environment setup
			wrapperContent += "stty sane\n"
			wrapperContent += "export USER=root\n"
			wrapperContent += "export HOME=/root\n"

			// Pixel-based Tiling (xdotool)
			if os.Getenv("DISPLAY") != "" {
				wrapperContent += fmt.Sprintf("(sleep 0.5; xdotool getactivewindow windowsize %d %d windowmove %d %d) &\n", winW, winH, winX, winY)
			}

			if val := os.Getenv("DISPLAY"); val != "" { wrapperContent += fmt.Sprintf("export DISPLAY='%s'\n", val) }
			if val := os.Getenv("XAUTHORITY"); val != "" { wrapperContent += fmt.Sprintf("export XAUTHORITY='%s'\n", val) }
			if val := os.Getenv("PATH"); val != "" { wrapperContent += fmt.Sprintf("export PATH='%s'\n", val) }

			for _, v := range vars {
				if val, ok := envMap[v]; ok {
					wrapperContent += fmt.Sprintf("export %s='%s'\n", v, val)
				}
			}
			
			absModulePath, _ := filepath.Abs(matches[0])
			projectRoot, _ := os.Getwd()
			wrapperContent += fmt.Sprintf("cd '%s'\n", projectRoot)
			
			wrapperContent += "echo -e \"\\e[1;34m[*] Astra Tactical Bridge Active\\e[0m\"\n"
			wrapperContent += "echo -e \"[*] Starting tool in TTY-safe session...\"\n"
			if os.Getenv("ASTRA_INDEFINITE") == "true" {
				wrapperContent += "echo -e \"\\e[1;33m[!] INDEFINITE MODE: Press Ctrl+C in THIS window to stop mission.\\e[0m\"\n"
			}
			
			// DO NOT trap SIGINT here so it propagates to the module script
			// But we DO want to trap it for the wrapper's own exit so we can still hit the 'read'
			wrapperContent += "trap 'echo -e \"\\n\\e[1;33m[!] Interrupt received in Tactical Window.\\e[0m\"' SIGINT\n"
			
			wrapperContent += fmt.Sprintf("bash '%s'\n", absModulePath)
			wrapperContent += "RET=$?\n"
			
			wrapperContent += "echo -e \"\\n\\e[1;33m[*] Mission finished with exit code $RET\\e[0m\"\n"
			wrapperContent += "echo \"[*] Press ENTER to close this window...\"\n"
			wrapperContent += "read\n"
			wrapperContent += "exit $RET\n"
			
			os.WriteFile(wrapperPath, []byte(wrapperContent), 0755)
			defer os.Remove(wrapperPath)

			// 2. Launch the terminal pointing to our wrapper
			fullArgs := append(termArgs, wrapperPath)
			exitCode, err = c.ExecMgr.RunWithEnv(ctx, tcID, termBin, fullArgs, logFile, env)
		} else {
			logging.Warn("No supported terminal emulator found. Falling back to Standard Feed.")
			// Foreground with Stdin
			exitCode, err = c.ExecMgr.RunWithEnv(ctx, tcID, matches[0], []string{}, logFile, env)
		}
	} else {
		// Standard foreground mode: Stdin is usually wanted here
		exitCode, err = c.ExecMgr.RunWithEnv(ctx, tcID, matches[0], []string{}, logFile, env)
	}
	
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
