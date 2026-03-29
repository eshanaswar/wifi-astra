package headless

import (
	"encoding/json"
	"fmt"
	"os"
	"wifi-astra/internal/config"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/module"
	"wifi-astra/internal/report"
	"wifi-astra/internal/session"
	"wifi-astra/pkg/prereq"
)

type AuditPlan struct {
	SessionName string   `json:"session_name"`
	Interface   string   `json:"interface"`
	TargetSSID  string   `json:"target_ssid"`
	TargetBSSID string   `json:"target_bssid"`
	TargetChan  string   `json:"target_channel"`
	Modules     []string `json:"modules"`
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
	if plan.TargetSSID != "" {
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_SSID", plan.TargetSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_BSSID", plan.TargetBSSID)
		s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "GUEST_CHANNEL", plan.TargetChan)
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
	reportPath, err := report.GenerateReport(s)
	if err != nil {
		logging.Error("Report generation failed: %v", err)
	} else {
		logging.Success("Final report saved to: %s", reportPath)
	}

	return nil
}
