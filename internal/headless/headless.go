package headless

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

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
	SessionDir    string         `json:"session_dir"` // absolute path to this session's root directory (contains evidence/, logs/, reports/)
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
		logging.Warn("queryFindingCounts: DB iteration error (returning partial counts): %v", err)
	}
	return counts
}

// RunAutonomousAudit executes an assessment without user interaction based on a plan file.
// Fatal startup errors (bad plan, session failure) return (nil, err) — caller should exit 1.
// Successful completion returns (*AuditSummary, nil) — caller uses summary.ExitCode.
func RunAutonomousAudit(planPath string, modDir string, runModuleFunc func(*session.Session, *module.Module) error) (*AuditSummary, error) {
	os.Setenv("ASTRA_HEADLESS", "true")
	startedAt := time.Now()

	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit plan: %v", err)
	}

	var plan AuditPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse audit plan: %v", err)
	}

	logging.Info("Starting Autonomous Audit: %s", plan.SessionName)

	baseDir := "./sessions"
	if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
		baseDir = config.GlobalConfig.SessionDir
	}

	os.MkdirAll(baseDir, 0755)
	if user, err := prereq.GetSudoUser(); err == nil {
		os.Chown(baseDir, user.UID, user.GID)
	}

	s, err := session.NewSession(plan.SessionName, baseDir)
	if err != nil {
		return nil, err
	}
	defer s.Cleanup()

	logging.InitLogger(s.LogDir, true)

	// Persist plan configuration to DB
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
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "SCOPE_BSSIDS", plan.TargetBSSID)
	}
	// Timing: write to DB so the controller injects as env vars for each module subprocess.
	// This matches how astra run handles timing and ensures values persist in the session record.
	if plan.CaptureTime > 0 {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "CAPTURE_TIME", strconv.Itoa(plan.CaptureTime))
	}
	if plan.ScanTime > 0 {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "SCAN_TIME", strconv.Itoa(plan.ScanTime))
	}

	// Discover modules
	modules, err := module.DiscoverModules(modDir)
	if err != nil {
		return nil, err
	}
	modMap := make(map[string]*module.Module)
	for i := range modules {
		modMap[modules[i].ID] = &modules[i]
	}

	// Execute modules, tracking per-module results
	var moduleResults []ModuleResult
	modulesFailed := 0
	for _, modID := range plan.Modules {
		m, exists := modMap[modID]
		if !exists {
			logging.Warn("Module %s not found, skipping.", modID)
			continue
		}
		status := "passed"
		if err := runModuleFunc(s, m); err != nil {
			logging.Error("Module %s failed: %v", modID, err)
			status = "failed"
			modulesFailed++
		}
		moduleResults = append(moduleResults, ModuleResult{
			ID:     m.ID,
			Name:   m.Name,
			Status: status,
		})
	}

	// Generate reports
	logging.Info("Autonomous Audit Complete. Generating report...")
	reportPath, err := report.GenerateReport(s, modDir)
	if err != nil {
		logging.Warn("Report generation failed: %v", err)
	}
	csvPath, err := report.GenerateCSVReport(s, modDir)
	if err != nil {
		logging.Warn("CSV report generation failed: %v", err)
	}

	// Compute exit code from module results and finding counts
	findings := queryFindingCounts(s)
	exitCode := computeExitCode(modulesFailed, findings.Critical+findings.High)

	summary := &AuditSummary{
		Session:       plan.SessionName,
		StartedAt:     startedAt.UTC().Format(time.RFC3339),
		CompletedAt:   time.Now().UTC().Format(time.RFC3339),
		ModulesRun:    len(moduleResults),
		ModulesFailed: modulesFailed,
		Findings:      findings,
		ModuleResults: moduleResults,
		ExitCode:      exitCode,
		ReportPath:    reportPath,
		CSVPath:       csvPath,
		SessionDir:    s.BaseDir,
	}

	// Always write audit_summary.json to the report directory
	summaryPath := filepath.Join(s.ReportDir, "audit_summary.json")
	if summaryData, err := json.MarshalIndent(summary, "", "  "); err != nil {
		logging.Warn("Failed to marshal audit summary: %v", err)
	} else if err := os.WriteFile(summaryPath, summaryData, 0644); err != nil {
		logging.Warn("Failed to write audit summary: %v", err)
	} else {
		logging.Info("Audit summary: %s", summaryPath)
	}

	return summary, nil
}
