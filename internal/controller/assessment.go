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

	"wifi-astra/internal/evidence"
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

// shellSingleQuote wraps v in single quotes, escaping any embedded single quotes
// using the standard '"'"' technique so the result is always valid shell.
func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
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
	ui.PrintHeader(fmt.Sprintf("Module %s: Already Completed", m.ID))
	fmt.Printf("%s%s%s\n", constants.ColorBold, m.Name, constants.ColorReset)

	c.DisplayMissionSummary(m.ID)

	fmt.Printf("\n%sRerun this module?%s Existing findings will be preserved.\n", constants.ColorBold, constants.ColorReset)

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
	fmt.Printf("\n%s%s%s\n", constants.ThemeHeader, strings.Repeat("═", 70), constants.ColorReset)
	fmt.Printf("%s🚀 MISSION START: %s (%s)%s\n", constants.ColorBold, m.Name, m.ID, constants.ColorReset)
	fmt.Printf("%s%s%s\n", constants.ThemeHeader, strings.Repeat("─", 70), constants.ColorReset)
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

	// Scope enforcement: fail gracefully if required target info is not set
	if strings.Contains(m.Reqs, "target_bssid") && config[constants.ConfigGuestBSSID] == "" {
		fmt.Printf("\n%s[!] Scope not set: module %s requires a target BSSID.%s\n",
			constants.ThemeHigh, m.ID, constants.ColorReset)
		fmt.Println("    Run A1 (Identify Networks) first to discover targets and set scope.")
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	}
	if strings.Contains(m.Reqs, "target_ssid") && config[constants.ConfigGuestSSID] == "" {
		fmt.Printf("\n%s[!] Scope not set: module %s requires a target SSID.%s\n",
			constants.ThemeHigh, m.ID, constants.ColorReset)
		fmt.Println("    Run A1 (Identify Networks) first to discover targets and set scope.")
		ui.PromptString("Press Enter to return to menu", "")
		return nil
	}

	// Verify active target is in authorized scope (if scope is set)
	if scopeBSSIDs, ok := config[constants.ConfigScopeBSSIDs]; ok && scopeBSSIDs != "" {
		activeBSSID := config[constants.ConfigGuestBSSID]
		authorized := false
		for _, b := range strings.Split(scopeBSSIDs, ",") {
			if strings.EqualFold(strings.TrimSpace(b), activeBSSID) {
				authorized = true
				break
			}
		}
		if !authorized {
			fmt.Printf("\n%s[!] SCOPE VIOLATION: Active target %s is not in the authorized scope list.%s\n",
				constants.ThemeCritical, activeBSSID, constants.ColorReset)
			fmt.Printf("    Authorized scope: %s\n", scopeBSSIDs)
			ui.PromptString("Press Enter to return to menu", "")
			return nil
		}
	}

	// Pre-run hooks: modules requiring operator input before env is built.
	if m.ID == "G4" {
		c.prepareG4Env()
	}

	// 2. Target Briefing
	fmt.Printf("\n%s📡 [Target Briefing]%s\n", constants.ThemeHeader, constants.ColorReset)
	iface := config[constants.ConfigWifiInterface]
	fmt.Printf("   • Interface: %s\n", iface)
	if config[constants.ConfigGuestSSID] != "" {
		fmt.Printf("   • Target:    %s (%s) [CH %s]\n", config[constants.ConfigGuestSSID], config[constants.ConfigGuestBSSID], config[constants.ConfigGuestChannel])
	} else {
		fmt.Println("   • Target:    <NOT SET - Running Discovery>")
	}

	// 3. Dependency Check
	fmt.Printf("\n%s🛠️  [Pre-flight Check]%s\n", constants.ThemeHeader, constants.ColorReset)
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
				fmt.Printf("   %s[✓]%s %-12s found at %s\n", constants.ThemeSuccess, constants.ColorReset, t, path)
				foundCount++
			} else {
				fmt.Printf("   %s[✗]%s %-12s NOT FOUND\n", constants.ThemeHigh, constants.ColorReset, t)
			}
		}
		if foundCount < len(tools) && m.Critical {
			return fmt.Errorf("missing critical tool dependencies")
		}
	} else {
		fmt.Printf("   %s[✓]%s No tool dependencies.\n", constants.ThemeSuccess, constants.ColorReset)
	}

	// 4. Hardware Prep & Locking
	if err := hw.LockInterface(iface, m.ID); err != nil {
		return fmt.Errorf("Hardware collision: %v. Please wait for the other module to finish", err)
	}
	defer hw.UnlockInterface(iface)

	if strings.Contains(m.Reqs, constants.ReqMonitorIface) {
		fmt.Printf("   %s[*]%s Enabling Monitor Mode... ", constants.ThemeHeader, constants.ColorReset)
		if !hw.IsValidInterfaceName(iface) {
			return fmt.Errorf("invalid interface name: %s", iface)
		}
		monIface, err := hw.EnableMonitorMode(iface)
		if err != nil {
			fmt.Printf("%sFAILED%s\n", constants.ThemeHigh, constants.ColorReset)
			return err
		}
		fmt.Printf("%sSUCCESS%s (%s)\n", constants.ThemeSuccess, constants.ColorReset, monIface)
		
		// Lock the newly created monitor interface as well
		if err := hw.LockInterface(monIface, m.ID); err != nil {
			logging.Warn("failed to lock monitor interface %s: %v", monIface, err)
		}
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
			fmt.Printf("\n%s[*] Indefinite mode active — press Ctrl+C to stop and record results.%s\n", constants.ThemeSuccess, constants.ColorReset)
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
	fmt.Printf("\n%s%s%s\n", constants.ThemeMission, strings.Repeat("┈", 80), constants.ColorReset)
	fmt.Printf("%s🛰️  MISSION FEED:%s\n", constants.ThemeMission, constants.ColorReset)
	fmt.Printf("%s%s%s\n\n", constants.ThemeMission, strings.Repeat("┈", 80), constants.ColorReset)

	startTime := time.Now()
	replayPath := filepath.Join(c.Session.EvidenceDir, "SESSION_REPLAY.log")
	evidence.AppendReplay(replayPath, m.ID, "START",
		fmt.Sprintf("module=%s session=%s", m.Name, c.Session.ID))
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

	// Evidence: write structured run log
	runLog := evidence.ModuleRunLog{
		TCID:        m.ID,
		Name:        m.Name,
		SessionID:   c.Session.ID,
		StartedAt:   startTime,
		EndedAt:     endTime,
		DurationSec: duration,
		ExitCode:    exitCode,
		Status:      status,
		Command:     fullCommand,
	}
	if err != nil {
		runLog.Error = err.Error()
	}
	if logPath, werr := evidence.WriteRunLog(c.Session.EvidenceDir, runLog); werr != nil {
		logging.Warn("evidence run log write failed: %v", werr)
	} else {
		evidence.AppendManifest(
			filepath.Join(c.Session.EvidenceDir, "MANIFEST.sha256"), logPath)
	}

	// Evidence: replay log entry
	replayEvent := "COMPLETE"
	if status == constants.StatusFailed {
		replayEvent = "FAIL"
	}
	evidence.AppendReplay(replayPath, m.ID, replayEvent,
		fmt.Sprintf("exit_code=%d duration=%ds", exitCode, duration))

	// Evidence: update manifest for all evidence files produced by this module.
	// Skip _run.json — it was already added to the manifest above via WriteRunLog.
	if files, err := os.ReadDir(c.Session.EvidenceDir); err == nil {
		manifestPath := filepath.Join(c.Session.EvidenceDir, "MANIFEST.sha256")
		prefix := strings.ToLower(m.ID) + "_"
		for _, f := range files {
			if !f.IsDir() && strings.HasPrefix(f.Name(), prefix) &&
				!strings.HasSuffix(f.Name(), "_run.json") {
				evidence.AppendManifest(manifestPath,
					filepath.Join(c.Session.EvidenceDir, f.Name()))
			}
		}
	}

	// Evidence: regenerate index
	evidence.WriteIndex(c.Session.EvidenceDir,
		filepath.Join(c.Session.EvidenceDir, "EVIDENCE_INDEX.txt"))

	fmt.Printf("\n%s%s%s\n", constants.ThemeMission, strings.Repeat("┈", 80), constants.ColorReset)
	if status == constants.StatusCompleted {
		fmt.Printf("%s✅ MISSION COMPLETE%s\n", constants.ThemeSuccess, constants.ColorReset)
	} else {
		fmt.Printf("%s❌ MISSION FAILED (Exit Code: %d)%s\n", constants.ThemeHigh, exitCode, constants.ColorReset)
	}
	fmt.Printf("%s%s%s\n", constants.ThemeMission, strings.Repeat("┈", 80), constants.ColorReset)

	// 6. Evidence Summary
	c.DisplayEvidence(m.ID)

	// 7. Post-run logic
	c.HandlePostRun(m)

	// 8. Mission Observation Summary
	c.DisplayMissionSummary(m.ID)

	fmt.Printf("\n%s%s%s\n", constants.ThemeHeader, strings.Repeat("═", 70), constants.ColorReset)
	if os.Getenv("ASTRA_HEADLESS") != "true" {
		logFile := filepath.Join(c.Session.LogDir, fmt.Sprintf("%s.log", strings.ToLower(m.ID)))
		if _, statErr := os.Stat(logFile); statErr == nil {
			if ui.PromptConfirm(fmt.Sprintf("View full log (%s.log)?", strings.ToLower(m.ID)), false) {
				var pager *exec.Cmd
				if _, err := exec.LookPath("less"); err == nil {
					pager = exec.Command("less", "-R", logFile)
				} else if _, err := exec.LookPath("more"); err == nil {
					pager = exec.Command("more", logFile)
				}
				if pager != nil {
					pager.Stdin = os.Stdin
					pager.Stdout = os.Stdout
					pager.Stderr = os.Stderr
					pager.Run()
				}
			}
		}
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
					wrapperContent += fmt.Sprintf("export %s=%s\n", v, shellSingleQuote(val))
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
	if cfgRows, err := c.Session.DB.Query("SELECT key, value FROM config"); err == nil {
		defer cfgRows.Close()
		for cfgRows.Next() {
			var k, v string
			cfgRows.Scan(&k, &v)
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	logFile := filepath.Join(c.Session.LogDir, fmt.Sprintf("%s_bg.log", strings.ToLower(tcID)))
	
	modFile := filepath.Join(c.ModDir, fmt.Sprintf("%s_*.sh", strings.ToLower(tcID)))
	matches, _ := filepath.Glob(modFile)
	if len(matches) == 0 {
		return fmt.Errorf("support module script for %s not found in %s", tcID, c.ModDir)
	}

	proc, err := c.ExecMgr.SpawnWithEnv(context.Background(), tcID+"_bg", matches[0], []string{}, logFile, env)
	if err != nil {
		return err
	}
	
	c.SupportProcs[tcID] = proc
	logging.Success("Support module %s is now running in the background.", tcID)
	return nil
}

func (c *AssessmentController) DisplayEvidence(tcID string) {
	fmt.Printf("\n%s📁 [Generated Evidence]%s\n", constants.ThemeHeader, constants.ColorReset)
	files, _ := os.ReadDir(c.Session.EvidenceDir)
	evidenceFound := false
	for _, f := range files {
		if strings.HasPrefix(strings.ToLower(f.Name()), strings.ToLower(tcID)) {
			relPath, err := filepath.Rel(c.Session.BaseDir, filepath.Join(c.Session.EvidenceDir, f.Name()))
			if err != nil {
				relPath = f.Name()
			}
			fmt.Printf("   • %s\n", relPath)
			evidenceFound = true
		}
	}
	if !evidenceFound {
		fmt.Printf("   %s• No specific evidence files recorded.%s\n", constants.ColorGray, constants.ColorReset)
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

	// 3. Post-run UI logic — module-specific handlers
	switch m.ID {
	case "A1":
		c.HandleA1PostRun()
	case "D1":
		c.HandleD1PostRun()
	case "D2":
		c.HandleD2PostRun()
	case "D3":
		c.HandleD3PostRun()
	case "D5":
		c.HandleD5PostRun()
	}
}

// CleanupChecklist walks the operator through post-engagement housekeeping.
// Each item is confirmed interactively; items the operator skips are printed
// as reminders rather than forced.
func (c *AssessmentController) CleanupChecklist() {
	fmt.Printf("\n%s╔══ Post-Engagement Cleanup ══╗%s\n", constants.ThemeHeader, constants.ColorReset)

	items := []struct {
		label string
		auto  func() error
	}{
		{
			"Stop all background support processes",
			func() error {
				for id := range c.SupportProcs {
					c.ExecMgr.Stop(id)
				}
				c.SupportProcs = make(map[string]*executor.Process)
				return nil
			},
		},
		{
			"Remove iptables NAT rules added during SSL/MitM modules",
			func() error {
				var iface string
				c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigWifiInterface).Scan(&iface)
				if iface == "" {
					return nil
				}
				exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080").Run()
				exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8080").Run()
				fmt.Printf("   %siptables NAT rules cleared (or were not present).%s\n", constants.ColorGray, constants.ColorReset)
				return nil
			},
		},
		{
			"Check for lingering wireless attack processes",
			func() error {
				procs := []string{"hostapd", "hostapd-mana", "bettercap", "responder", "mitmproxy", "mitmdump"}
				found := false
				for _, p := range procs {
					out, _ := exec.Command("pgrep", "-x", p).Output()
					if len(strings.TrimSpace(string(out))) > 0 {
						fmt.Printf("   %s[!] Process still running: %s (PIDs: %s)%s\n",
							constants.ThemeHigh, p, strings.TrimSpace(string(out)), constants.ColorReset)
						found = true
					}
				}
				if !found {
					fmt.Printf("   %sNo lingering attack processes detected.%s\n", constants.ColorGray, constants.ColorReset)
				}
				return nil
			},
		},
		{
			"Disable monitor mode on attack adapter (if still active)",
			func() error {
				monIface, err := hw.Roles.Get(hw.RoleMonitor)
				if err != nil || monIface == "" {
					return nil
				}
				hw.DisableMonitorMode(monIface)
				return nil
			},
		},
		{
			"Verify evidence directory and print manifest summary",
			func() error {
				fmt.Printf("   Evidence directory: %s\n", c.Session.EvidenceDir)
				files, _ := os.ReadDir(c.Session.EvidenceDir)
				evidenceCount := 0
				for _, f := range files {
					if !f.IsDir() && f.Name() != "MANIFEST.sha256" && f.Name() != "EVIDENCE_INDEX.txt" {
						evidenceCount++
					}
				}
				fmt.Printf("   Evidence files: %d\n", evidenceCount)
				manifestPath := filepath.Join(c.Session.EvidenceDir, "MANIFEST.sha256")
				if _, err := os.Stat(manifestPath); err == nil {
					data, _ := os.ReadFile(manifestPath)
					lineCount := len(strings.Split(strings.TrimSpace(string(data)), "\n"))
					fmt.Printf("   Manifest entries: %d (see %s)\n", lineCount, manifestPath)
				}
				return nil
			},
		},
	}

	for i, item := range items {
		fmt.Printf("\n%s%d. %s%s\n", constants.ThemeHeader, i+1, item.label, constants.ColorReset)
		if ui.PromptConfirm("   Run this step?", true) {
			if err := item.auto(); err != nil {
				logging.Warn("Cleanup step %d failed: %v", i+1, err)
				fmt.Printf("   %s[!] Step failed: %v%s\n", constants.ThemeHigh, err, constants.ColorReset)
			} else {
				fmt.Printf("   %s[done]%s\n", constants.ThemeSuccess, constants.ColorReset)
			}
		} else {
			fmt.Printf("   %s[skipped — remember to do this manually]%s\n", constants.ColorGray, constants.ColorReset)
		}
	}

	fmt.Printf("\n%s[*] Cleanup complete. Session evidence saved at: %s%s\n",
		constants.ThemeSuccess, c.Session.EvidenceDir, constants.ColorReset)
}

func (c *AssessmentController) HandleA1PostRun() {
	csvFile := filepath.Join(c.Session.EvidenceDir, "a1_results.csv")
	if _, err := os.Stat(csvFile); err != nil {
		fmt.Printf("\n%s[!] A1: No results CSV found — check that airodump-ng ran successfully.%s\n",
			constants.ThemeHigh, constants.ColorReset)
		ui.PromptString("Press Enter to continue", "")
		return
	}

	ingest.IngestAirodumpCSV(c.Session.DB, "A1", csvFile)
	networks, _ := ingest.ParseScanResults(csvFile)

	if len(networks) == 0 {
		fmt.Printf("\n%s[!] A1: CSV found but no networks parsed — scan may have captured no beacons.%s\n",
			constants.ThemeHigh, constants.ColorReset)
		ui.PromptString("Press Enter to continue", "")
		return
	}

	fmt.Printf("\n%s📊 [Discovery Summary]%s\n", constants.ThemeHeader, constants.ColorReset)
	fmt.Printf("   %-4s %-25s %-18s %-5s %-12s %s\n", "#", "SSID", "BSSID", "CH", "ENC", "Signal")
	fmt.Printf("   %s%s%s\n", constants.ThemeHeader, strings.Repeat("─", 72), constants.ColorReset)
	for i, n := range networks {
		vendor := ingest.LookupVendor(n.BSSID)
		vendorShort := vendor
		if len(vendorShort) > 18 {
			vendorShort = vendorShort[:15] + "..."
		}
		enc := n.Encryption
		if enc == "" {
			enc = "OPN"
		}
		encColor := ""
		encReset := ""
		if enc == "OPN" {
			encColor = constants.ThemeHigh
			encReset = constants.ColorReset
		}
		fmt.Printf("   %-4d %-25s %-18s %-5d %s%-12s%s %ddBm  %s\n",
			i+1, n.SSID, n.BSSID, n.Channel, encColor, enc, encReset, n.Signal, vendorShort)
	}

	fmt.Printf("\n%s[?] Enter numbers for ALL authorized targets (e.g. 1,3 for multiple).%s\n", constants.ThemeHeader, constants.ColorReset)
	fmt.Printf("    %sFirst selection becomes the active target for module execution.%s\n", constants.ColorGray, constants.ColorReset)
	for {
		choice := ui.PromptString("Authorized target number(s)", "")
		if choice == "" {
			fmt.Printf("%s[*] No targets set. Run A1 again to select authorized targets.%s\n",
				constants.ColorGray, constants.ColorReset)
			return
		}

		parts := strings.Split(choice, ",")
		var selectedIdxs []int
		valid := true
		for _, p := range parts {
			idx, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || idx < 1 || idx > len(networks) {
				fmt.Printf("%s[!] Invalid selection: %q — enter numbers 1–%d separated by commas.%s\n",
					constants.ThemeHigh, strings.TrimSpace(p), len(networks), constants.ColorReset)
				valid = false
				break
			}
			selectedIdxs = append(selectedIdxs, idx-1)
		}
		if !valid {
			selectedIdxs = nil
			continue
		}

		// First selected = active target
		primary := networks[selectedIdxs[0]]
		c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestSSID, primary.SSID)
		c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestBSSID, primary.BSSID)
		c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigGuestChannel, strconv.Itoa(primary.Channel))

		// All selected = authorized scope
		var bssids []string
		for _, i := range selectedIdxs {
			bssids = append(bssids, networks[i].BSSID)
		}
		c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigScopeBSSIDs, strings.Join(bssids, ","))

		c.Session.DB.Exec("UPDATE module_state SET status = ? WHERE tc_id = 'A1'", constants.StatusCompleted)
		fmt.Printf("%s[✓] Active target: %s (%s) CH%d%s\n",
			constants.ThemeSuccess, primary.SSID, primary.BSSID, primary.Channel, constants.ColorReset)
		if len(selectedIdxs) > 1 {
			fmt.Printf("%s[*] Authorized scope (%d networks):%s\n", constants.ColorGray, len(selectedIdxs), constants.ColorReset)
			for _, idx := range selectedIdxs {
				n := networks[idx]
				if n.BSSID == primary.BSSID {
					fmt.Printf("    %s→%s %-24s %-18s CH%d\n",
						constants.ThemeSuccess, constants.ColorReset, n.SSID, n.BSSID, n.Channel)
				} else {
					fmt.Printf("      %-24s %-18s CH%d\n", n.SSID, n.BSSID, n.Channel)
				}
			}
		}
		return
	}
}

// HandleD2PostRun fires after D2 (WEP Cracking) completes.
// It reads the aircrack-ng log, extracts any recovered WEP key,
// and records it as a credential finding.
func (c *AssessmentController) HandleD2PostRun() {
	logFile := filepath.Join(c.Session.EvidenceDir, "D2_aircrack_results.txt")
	data, err := os.ReadFile(logFile)
	if err != nil {
		return
	}
	key := ParseAircrackKey(string(data))
	if key == "" {
		return
	}

	fmt.Printf("\n%s[!] WEP KEY RECOVERED: %s%s\n", constants.ThemeCritical, key, constants.ColorReset)

	var targetBSSID string
	c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&targetBSSID)

	c.Session.DB.Exec(`
		INSERT OR REPLACE INTO credential (tc_id, proto, target_host, username, password, evidence_file, rationale)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"D2", "WEP", targetBSSID,
		"<WEP network>", key, logFile,
		"WEP encryption is broken — RC4 key stream reuse allows key recovery from ~40,000 IVs. All traffic is decryptable.",
	)
}

// HandleD1PostRun fires after D1 (WPA Handshake & PMKID Capture) completes.
// If capture files are present, it offers the operator an inline hashcat crack.
// The operator can skip by pressing Enter without a wordlist path.
func (c *AssessmentController) HandleD1PostRun() {
	evidenceDir := c.Session.EvidenceDir

	// Prefer PMKID path (mode 22000) — clientless, faster
	pmkidFile := filepath.Join(evidenceDir, "D1_capture_pmkid.hc22000")
	capFile := filepath.Join(evidenceDir, "D1_capture_handshake.cap")

	var captureFile, mode string
	if _, err := os.Stat(pmkidFile); err == nil {
		captureFile = pmkidFile
		mode = "22000"
		fmt.Printf("\n%s[+] PMKID captured (%s).%s\n", constants.ThemeSuccess, pmkidFile, constants.ColorReset)
	} else if _, err := os.Stat(capFile); err == nil {
		// Convert airodump-ng .cap → hashcat 22000 format.
		// Note: the shell module already ran hcxpcapngtool on the hcxdumptool .pcapng capture to
		// produce D1_capture_pmkid.hc22000; this branch handles the airodump .cap (EAPOL path) separately.
		convertedFile := capFile + ".hc22000"
		convertArgs := []string{capFile, "-o", convertedFile}
		if exitCode, convErr := c.ExecMgr.Run(context.Background(), "hcxpcapngtool-d1", "hcxpcapngtool", convertArgs, "/dev/null"); convErr != nil || exitCode != 0 {
			fmt.Printf("%s[!] Could not convert .cap to hashcat format (hcxpcapngtool exit %d). Convert manually and rerun.%s\n",
				constants.ThemeHigh, exitCode, constants.ColorReset)
			return
		}
		captureFile = convertedFile
		mode = "22000"
		fmt.Printf("\n%s[+] EAPOL handshake captured (%s → converted to hc22000).%s\n",
			constants.ThemeSuccess, capFile, constants.ColorReset)
	} else {
		fmt.Printf("\n%s[*] D1: No PMKID or EAPOL handshake capture found — inline crack not available.%s\n",
			constants.ColorGray, constants.ColorReset)
		fmt.Printf("    %sCapture files (if any) are in: %s%s\n",
			constants.ColorGray, evidenceDir, constants.ColorReset)
		logging.Debug("D1 post-run: no crackable capture file found, skipping inline crack offer")
		return
	}

	fmt.Printf("%s[?] Run inline hashcat crack now?%s\n", constants.ThemeHeader, constants.ColorReset)
	wordlist := ui.PromptString("    Wordlist path (or Enter to skip)", "")
	if wordlist == "" {
		fmt.Println("    Skipping inline crack — capture file saved for offline use.")
		return
	}

	if _, err := os.Stat(wordlist); err != nil {
		fmt.Printf("%s[!] Wordlist not found: %s%s\n", constants.ThemeHigh, wordlist, constants.ColorReset)
		return
	}

	fmt.Printf("%s[*] Starting hashcat -m %s%s — stream output below:\n\n",
		constants.ThemeHeader, mode, constants.ColorReset)
	logFile := hashcatLogPath(evidenceDir, "D1")
	result, err := RunHashcat(context.Background(), captureFile, wordlist, mode, logFile, c.ExecMgr)
	if err != nil {
		logging.Warn("D1 inline crack failed: %v", err)
		fmt.Printf("%s[!] Hashcat error: %v%s\n", constants.ThemeHigh, err, constants.ColorReset)
		return
	}

	if result.Found {
		fmt.Printf("\n%s[!!!] PSK CRACKED: %s%s\n", constants.ThemeSuccess, result.PSK, constants.ColorReset)
		bssid := ""
		c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
		ssid := ""
		c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)
		if bssid == "" && ssid == "" {
			logging.Warn("D1 post-run: BSSID and SSID not set in config — credential record will have empty target fields")
		}
		c.Session.DB.Exec(
			`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"D1", ssid, result.PSK, "WPA2-PSK", bssid, captureFile,
			"PSK recovered via offline dictionary attack — network traffic can be decrypted.",
		)
		logging.Info("D1 inline crack: PSK recorded as credential finding")
	} else {
		fmt.Printf("\n%s[*] Wordlist exhausted — PSK not found (duration: %ds).%s\n",
			constants.ColorGray, result.DurationSec, constants.ColorReset)
		logging.Info("D1 inline crack: no PSK found, wordlist=%s, duration=%ds", wordlist, result.DurationSec)
	}
}

// HandleD5PostRun fires after D5 (WPA-Enterprise / EAP Attack) completes.
// It extracts cleartext credentials from the eaphammer log and records each
// as a credential finding. No cracking is needed — EAP-GTC downgrade yields
// the plaintext password directly.
func (c *AssessmentController) HandleD5PostRun() {
	logFile := filepath.Join(c.Session.EvidenceDir, "D5_eaphammer_results.txt")

	data, err := os.ReadFile(logFile)
	if err != nil {
		logging.Debug("D5 post-run: eaphammer log not found at %s", logFile)
		return
	}

	creds := ParseEaphammerCreds(string(data))
	if len(creds) == 0 {
		logging.Debug("D5 post-run: no credentials extracted from eaphammer log")
		return
	}

	ssid := ""
	c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)

	fmt.Printf("\n%s[+] D5: %d EAP credential(s) extracted and recorded.%s\n",
		constants.ThemeSuccess, len(creds), constants.ColorReset)

	for _, cred := range creds {
		c.Session.DB.Exec(
			`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"D5", cred.Username, cred.Password, "EAP-GTC", ssid, logFile,
			"Plaintext credentials captured via EAP-GTC downgrade — no offline cracking required.",
		)
		fmt.Printf("    %s  %-20s → %s%s\n",
			constants.ColorGray, cred.Username, cred.Password, constants.ColorReset)
	}
	logging.Info("D5 post-run: recorded %d credential(s) from EAP-GTC downgrade", len(creds))
}

// HandleD3PostRun fires after D3 (WPS Vulnerability Testing) completes.
// It reads the reaver/bully output log, extracts any recovered PSK or PIN,
// and records the finding in the session credential table.
func (c *AssessmentController) HandleD3PostRun() {
	logFile := filepath.Join(c.Session.EvidenceDir, "D3_reaver_info.txt")
	data, err := os.ReadFile(logFile)
	if err != nil {
		logging.Debug("D3 post-run: reaver log not found at %s", logFile)
		return
	}

	psk, pin := ParseWPSCreds(string(data))

	if psk == "" && pin == "" {
		logging.Debug("D3 post-run: no WPS credentials found in output")
		return
	}

	bssid := ""
	ssid := ""
	c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestBSSID).Scan(&bssid)
	c.Session.DB.QueryRow("SELECT value FROM config WHERE key = ?", constants.ConfigGuestSSID).Scan(&ssid)

	if psk != "" {
		fmt.Printf("\n%s[!!!] WPS PSK RECOVERED: %s%s\n", constants.ThemeSuccess, psk, constants.ColorReset)
		if pin != "" {
			fmt.Printf("      %sWPS PIN:%s %s\n", constants.ColorGray, constants.ColorReset, pin)
		}
		c.Session.DB.Exec(
			`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"D3", ssid, psk, "WPA2-PSK", bssid, logFile,
			"PSK recovered via WPS PIN attack — no handshake capture required.",
		)
		logging.Info("D3 post-run: PSK recorded as credential finding")
		return
	}

	// PIN recovered but no PSK — record for manual follow-up
	fmt.Printf("\n%s[+] WPS PIN recovered (no PSK extracted): %s%s\n", constants.ThemeHeader, pin, constants.ColorReset)
	fmt.Printf("    %sUse this PIN with reaver/bully manually to recover the PSK.%s\n", constants.ColorGray, constants.ColorReset)
	c.Session.DB.Exec(
		`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, rationale)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"D3", "(WPS PIN)", pin, "WPS-PIN", bssid, logFile,
		"WPS PIN recovered; manual reaver/bully run required to extract PSK.",
	)
	logging.Info("D3 post-run: WPS PIN recorded, PSK not recovered")
}

// parseA4ClientMACs reads an airodump-ng CSV produced by A4 and returns the
// list of client (Station) MAC addresses found in the Station MAC section.
// Returns nil when the file does not exist or has no client section.
func parseA4ClientMACs(csvPath string) []string {
	data, err := os.ReadFile(csvPath)
	if err != nil {
		return nil
	}

	var macs []string
	inStationSection := false

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Station MAC") {
			inStationSection = true
			continue
		}
		if inStationSection {
			parts := strings.SplitN(trimmed, ",", 2)
			if len(parts) >= 1 {
				mac := strings.TrimSpace(parts[0])
				if mac != "" {
					macs = append(macs, mac)
				}
			}
		}
	}
	return macs
}

// prepareG4Env is called before G4 runs. It reads the A4 client list from
// evidence, prompts the operator to select a target, and saves TARGET_CLIENT
// to the session DB config so the env injection loop picks it up automatically.
func (c *AssessmentController) prepareG4Env() {
	// Skip if already configured (resumed session or prior run).
	var existing string
	if err := c.Session.DB.QueryRow("SELECT value FROM config WHERE key = 'TARGET_CLIENT'").Scan(&existing); err == nil && strings.TrimSpace(existing) != "" {
		fmt.Printf("%s[G4] TARGET_CLIENT already set: %s%s\n", constants.ThemeHeader, existing, constants.ColorReset)
		return
	}

	csvPath := filepath.Join(c.Session.EvidenceDir, "a4_results.csv")
	macs := parseA4ClientMACs(csvPath)
	if len(macs) == 0 {
		fmt.Printf("%s[G4] No client MACs found in A4 evidence — run A4 first or set TARGET_CLIENT manually.%s\n",
			constants.ThemeHigh, constants.ColorReset)
		return
	}

	fmt.Printf("\n%s[G4] Select target client for NAC bypass:%s\n", constants.ThemeHeader, constants.ColorReset)
	for i, mac := range macs {
		fmt.Printf("   %d) %s\n", i+1, mac)
	}

	choice := ui.PromptString("Selection [1-"+strconv.Itoa(len(macs))+"] (Enter to skip)", "")
	if choice == "" {
		fmt.Println("[G4] No client selected — G4 will exit gracefully.")
		return
	}

	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(macs) {
		fmt.Printf("%s[G4] Invalid selection — G4 will exit gracefully.%s\n", constants.ThemeHigh, constants.ColorReset)
		return
	}

	selected := macs[idx-1]
	if _, dbErr := c.Session.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('TARGET_CLIENT', ?)", selected); dbErr != nil {
		logging.Warn("G4 prepareG4Env: failed to save TARGET_CLIENT: %v", dbErr)
		return
	}
	logging.Info("G4 prepareG4Env: TARGET_CLIENT set to %s", selected)
	fmt.Printf("%s[G4] TARGET_CLIENT set to %s%s\n", constants.ThemeSuccess, selected, constants.ColorReset)
}
