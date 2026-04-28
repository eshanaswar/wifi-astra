package headless

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"wifi-astra/internal/config"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/module"
	"wifi-astra/internal/report"
	"wifi-astra/internal/session"
	"wifi-astra/pkg/prereq"
)

type AuditPlan struct {
	SessionName      string   `json:"session_name"`
	Interface        string   `json:"interface"`
	MonitorInterface string   `json:"monitor_interface"`
	APInterface      string   `json:"ap_interface"` // Optional — dedicated managed-mode adapter for F1/F2/F3/D5
	TargetSSID       string   `json:"target_ssid"`
	TargetBSSID      string   `json:"target_bssid"`
	TargetChan       string   `json:"target_channel"`
	Modules          []string `json:"modules"`
	CaptureTime      int      `json:"capture_time"`
	ScanTime         int      `json:"scan_time"`
}

// ModuleResult records whether a single module passed or failed.
type ModuleResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // "passed" or "failed"
}

// FindingCounts holds per-severity vulnerability counts from the session DB.
type FindingCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// AuditSummary is the structured result of a headless audit run.
// It is written to <session>/reports/audit_summary.json and optionally
// printed to stdout via the --json flag.
type AuditSummary struct {
	Session       string         `json:"session"`
	StartedAt     string         `json:"started_at"`
	CompletedAt   string         `json:"completed_at"`
	ModulesRun    int            `json:"modules_run"`
	ModulesFailed int            `json:"modules_failed"`
	Findings      FindingCounts  `json:"findings"`
	ModuleResults []ModuleResult `json:"module_results"`
	ExitCode      int            `json:"exit_code"`
	ReportPath    string         `json:"report_path"`
	CSVPath       string         `json:"csv_path"`
	SessionDir    string         `json:"session_dir"`
}

// computeExitCode returns the process exit code for a headless audit:
//
//	0 — clean: no module failures, no CRITICAL/HIGH findings
//	2 — module failure(s) occurred
//	3 — CRITICAL or HIGH findings detected (takes priority over exit 2)
func computeExitCode(modulesFailed, highCriticalCount int) int {
	if highCriticalCount > 0 {
		return 3
	}
	if modulesFailed > 0 {
		return 2
	}
	return 0
}

// queryFindingCounts reads per-severity finding counts from the session DB.
func queryFindingCounts(s *session.Session) FindingCounts {
	var counts FindingCounts
	rows, err := s.DB.Query(
		`SELECT severity, COUNT(*) FROM vulnerability
		 WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')
		 GROUP BY severity`)
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			continue
		}
		switch sev {
		case "CRITICAL":
			counts.Critical = n
		case "HIGH":
			counts.High = n
		case "MEDIUM":
			counts.Medium = n
		case "LOW":
			counts.Low = n
		case "INFO":
			counts.Info = n
		}
	}
	if err := rows.Err(); err != nil {
		return FindingCounts{}
	}
	return counts
}

// RunAutonomousAudit executes an assessment without user interaction based on a plan file.
func RunAutonomousAudit(planPath string, modDir string, runModuleFunc func(*session.Session, *module.Module) error) error {
	os.Setenv("ASTRA_HEADLESS", "true")
	data, err := os.ReadFile(planPath)
	if err != nil {
		return fmt.Errorf("failed to read audit plan: %v", err)
	}

	var plan AuditPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return fmt.Errorf("failed to parse audit plan: %v", err)
	}

	logging.Info("🚀 Starting Autonomous Audit: %s", plan.SessionName)

	baseDir := "./sessions" // Fallback
	if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
		baseDir = config.GlobalConfig.SessionDir
	}
	
	// Pre-create and chown
	os.MkdirAll(baseDir, 0755)
	if user, err := prereq.GetSudoUser(); err == nil {
		os.Chown(baseDir, user.UID, user.GID)
	}
	
	s, err := session.NewSession(plan.SessionName, baseDir)
	if err != nil {
		return err
	}
	defer s.Cleanup()

	logging.InitLogger(s.LogDir, true)

	// Persist plan configuration
	if plan.Interface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "WIFI_INTERFACE", plan.Interface)
	}
	if plan.MonitorInterface != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "MONITOR_INTERFACE", plan.MonitorInterface)
	}
	if plan.APInterface != "" {
		os.Setenv("AP_INTERFACE", plan.APInterface)
		if _, err := s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "AP_INTERFACE", plan.APInterface); err != nil {
			log.Printf("[warn] headless: failed to persist AP_INTERFACE: %v", err)
		}
	}
	if plan.TargetSSID != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_SSID", plan.TargetSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_BSSID", plan.TargetBSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_CHANNEL", plan.TargetChan)
		// Seed SCOPE_BSSIDS so resumed interactive sessions have a consistent scope list.
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "SCOPE_BSSIDS", plan.TargetBSSID)
	}

	// Discover all modules to get metadata
	modules, err := module.DiscoverModules(modDir)
	if err != nil {
		return err
	}
	modMap := make(map[string]*module.Module)
	for i := range modules {
		modMap[modules[i].ID] = &modules[i]
	}

	// Inject timing env vars from plan (modules default gracefully if unset, but
	// headless plans should be able to override them).
	if plan.CaptureTime > 0 {
		os.Setenv("CAPTURE_TIME", fmt.Sprintf("%d", plan.CaptureTime))
	}
	if plan.ScanTime > 0 {
		os.Setenv("SCAN_TIME", fmt.Sprintf("%d", plan.ScanTime))
	}

	// Execute planned modules
	for _, modID := range plan.Modules {
		m, exists := modMap[modID]
		if !exists {
			logging.Warn("Module %s not found, skipping.", modID)
			continue
		}

		if err := runModuleFunc(s, m); err != nil {
			logging.Error("Module %s failed: %v", modID, err)
		}
	}

	logging.Info("🏁 Autonomous Audit Complete. Generating report...")
	reportPath, err := report.GenerateReport(s, modDir)
	if err != nil {
		logging.Error("Report generation failed: %v", err)
	} else {
		logging.Success("Final report saved to: %s", reportPath)
	}

	return nil
}
