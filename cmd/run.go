package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wifi-astra/internal/controller"
	"wifi-astra/internal/module"
	"wifi-astra/internal/session"
	"wifi-astra/pkg/constants"
	"wifi-astra/pkg/executor"
	"wifi-astra/pkg/hw"
	"wifi-astra/pkg/prereq"

	"github.com/spf13/cobra"
)

// bssidRe validates AA:BB:CC:DD:EE:FF format (case-insensitive).
var bssidRe = regexp.MustCompile(`(?i)^([0-9A-F]{2}:){5}[0-9A-F]{2}$`)

var runCmd = &cobra.Command{
	Use:   "run <MODULE_ID>",
	Short: "Run a single module directly (no TUI session wizard)",
	Long: `Execute a single assessment module without the interactive session wizard.

Useful for automation, CI, and scripted engagements. All output is written to the
specified session directory (or a timestamped default under ./sessions/).

Example:
  sudo wifi-astra run D1 --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6
  sudo wifi-astra run A1 --iface wlan0 --scan-time 30
  sudo wifi-astra run D1 --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --channel 6 --session-dir ./sessions/my-session

The module must exist in the modules directory (default: ./modules).
Scope enforcement applies — the BSSID passed via --bssid becomes the sole authorized target.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		moduleID := strings.ToUpper(args[0])

		iface, _       := cmd.Flags().GetString("iface")
		bssid, _       := cmd.Flags().GetString("bssid")
		ssid, _        := cmd.Flags().GetString("ssid")
		channel, _     := cmd.Flags().GetInt("channel")
		sessionDir, _  := cmd.Flags().GetString("session-dir")
		captureTime, _ := cmd.Flags().GetInt("capture-time")
		scanTime, _    := cmd.Flags().GetInt("scan-time")
		apIface, _     := cmd.Flags().GetString("ap-iface")

		// Validate required flags
		if iface == "" {
			fmt.Fprintln(os.Stderr, "[✗] --iface is required")
			os.Exit(1)
		}
		if !hw.IsValidInterfaceName(iface) {
			fmt.Fprintf(os.Stderr, "[✗] invalid interface name: %s\n", iface)
			os.Exit(1)
		}
		if bssid != "" && !bssidRe.MatchString(bssid) {
			fmt.Fprintf(os.Stderr, "[✗] invalid BSSID format: %s (expected AA:BB:CC:DD:EE:FF)\n", bssid)
			os.Exit(1)
		}
		if channel < 0 || channel > 196 {
			fmt.Fprintf(os.Stderr, "[✗] invalid channel: %d (must be 1–196)\n", channel)
			os.Exit(1)
		}

		// Discover modules
		modules, err := module.DiscoverModules(ModDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[✗] failed to discover modules: %v\n", err)
			os.Exit(1)
		}
		var targetModule *module.Module
		for i := range modules {
			if modules[i].ID == moduleID {
				targetModule = &modules[i]
				break
			}
		}
		if targetModule == nil {
			fmt.Fprintf(os.Stderr, "[✗] module %s not found in %s\n", moduleID, ModDir)
			os.Exit(1)
		}

		// Create or use a session directory; always resolve to absolute path so
		// SESSION_EVIDENCE_DIR injected into module env vars is correct regardless
		// of any directory changes during module execution.
		if sessionDir == "" {
			ts := time.Now().Format("20060102-150405")
			sessionDir = filepath.Join("sessions", fmt.Sprintf("run-%s-%s", strings.ToLower(moduleID), ts))
		}
		if err := os.MkdirAll(sessionDir, 0750); err != nil {
			fmt.Fprintf(os.Stderr, "[✗] cannot create session dir: %v\n", err)
			os.Exit(1)
		}
		if abs, absErr := filepath.Abs(sessionDir); absErr == nil {
			sessionDir = abs
		}

		// Load or create session
		var s *session.Session
		if _, statErr := os.Stat(filepath.Join(sessionDir, "session.db")); statErr == nil {
			s, err = session.LoadSession(sessionDir)
		} else {
			s, err = session.NewSession("run-"+strings.ToLower(moduleID), sessionDir)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[✗] session error: %v\n", err)
			os.Exit(1)
		}
		defer s.Cleanup()

		// Inject config into DB
		set := func(key, val string) {
			if val != "" {
				s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, val)
			}
		}
		set(constants.ConfigWifiInterface, iface)
		set(constants.ConfigMonitorIface, iface)
		set(constants.ConfigGuestBSSID, bssid)
		set(constants.ConfigGuestSSID, ssid)
		set(constants.ConfigAPInterface, apIface)
		if channel > 0 {
			set(constants.ConfigGuestChannel, strconv.Itoa(channel))
		}
		if captureTime > 0 {
			s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "CAPTURE_TIME", strconv.Itoa(captureTime))
		}
		if scanTime > 0 {
			s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "SCAN_TIME", strconv.Itoa(scanTime))
		}

		// If BSSID is provided, add it as the sole authorized scope entry
		if bssid != "" {
			s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", constants.ConfigScopeBSSIDs, bssid)
		}

		// Set ASTRA_BIN so modules can call record-finding / record-progress
		astraBin, _ := os.Executable()
		if err := os.Setenv("ASTRA_BIN", astraBin); err != nil {
			fmt.Fprintf(os.Stderr, "[!] warning: could not set ASTRA_BIN: %v\n", err)
		}

		// Preflight check
		prereq.PreflightModules(prereq.ModuleToolMap)

		// Run the module
		execMgr := executor.NewManager()
		ctrl := controller.NewAssessmentController(s, execMgr, ModDir)

		fmt.Printf("\n[wifi-astra run] Module: %s — %s\n", targetModule.ID, targetModule.Name)
		fmt.Printf("[wifi-astra run] Session: %s\n\n", sessionDir)

		if err := ctrl.ExecuteModule(targetModule); err != nil {
			fmt.Fprintf(os.Stderr, "[✗] module %s failed: %v\n", moduleID, err)
			hw.Recover(false)
			os.Exit(1)
		}

		hw.Recover(false)
		fmt.Printf("\n[wifi-astra run] Module %s complete. Evidence: %s\n", moduleID, s.EvidenceDir)
	},
}

func init() {
	runCmd.Flags().String("iface", "", "Monitor-mode wireless interface (required)")
	runCmd.Flags().String("bssid", "", "Target BSSID (AA:BB:CC:DD:EE:FF)")
	runCmd.Flags().String("ssid", "", "Target SSID")
	runCmd.Flags().Int("channel", 0, "Target channel (1–196)")
	runCmd.Flags().String("session-dir", "", "Session directory (auto-generated if omitted)")
	runCmd.Flags().Int("capture-time", 60, "Capture duration in seconds")
	runCmd.Flags().Int("scan-time", 30, "Scan duration in seconds")
	runCmd.Flags().String("ap-iface", "", "AP interface for Evil Twin modules (F1, F2, F3, D5)")
	RootCmd.AddCommand(runCmd)
}
