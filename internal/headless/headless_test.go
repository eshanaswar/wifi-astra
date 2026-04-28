package headless

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"wifi-astra/internal/module"
	"wifi-astra/internal/session"
)

func TestRunAutonomousAudit(t *testing.T) {
	// Setup
	tmpDir := "test_headless_sessions"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	// Create a dummy plan
	plan := AuditPlan{
		SessionName: "test_auto",
		Modules:     []string{"MOCK"},
	}
	planPath := "test_plan.json"
	data, _ := json.Marshal(plan)
	os.WriteFile(planPath, data, 0644)
	defer os.Remove(planPath)

	// Create a dummy module file
	modDir := "test_mods"
	os.MkdirAll(modDir, 0755)
	defer os.RemoveAll(modDir)
	modFile := filepath.Join(modDir, "mock_test.sh")
	os.WriteFile(modFile, []byte("# MODULE_META\n# NAME=\"Mock\"\n# CATEGORY=\"M\"\n"), 0755)

	runCount := 0
	mockRunFunc := func(s *session.Session, m *module.Module) error {
		runCount++
		if m.ID != "MOCK" {
			t.Errorf("expected module MOCK, got %s", m.ID)
		}
		return nil
	}

	// Move into the tmpDir context for session creation
	cwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(cwd)

	summary, err := RunAutonomousAudit(filepath.Join("..", planPath), filepath.Join("..", modDir), mockRunFunc)
	if err != nil {
		t.Fatalf("RunAutonomousAudit failed: %v", err)
	}
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if summary.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", summary.ExitCode)
	}

	if runCount != 1 {
		t.Errorf("expected 1 module run, got %d", runCount)
	}
}

func TestAuditPlanTimingInjected(t *testing.T) {
	// Verify that capture_time and scan_time from the plan are persisted to the session DB.
	// The controller reads them from DB and injects as env vars for each module subprocess.
	tmpDir := "test_timing_sessions"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	plan := AuditPlan{
		SessionName: "timing_test",
		Modules:     []string{"MOCK"},
		CaptureTime: 120,
		ScanTime:    45,
	}
	planPath := "test_timing_plan.json"
	data, _ := json.Marshal(plan)
	os.WriteFile(planPath, data, 0644)
	defer os.Remove(planPath)

	modDir := "test_timing_mods"
	os.MkdirAll(modDir, 0755)
	defer os.RemoveAll(modDir)
	modFile := filepath.Join(modDir, "mock_test.sh")
	os.WriteFile(modFile, []byte("# MODULE_META\n# NAME=\"Mock\"\n# CATEGORY=\"M\"\n"), 0755)

	var captureTime, scanTime string
	mockRunFunc := func(s *session.Session, m *module.Module) error {
		// Timing values are written to DB, not os.Setenv
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", "CAPTURE_TIME").Scan(&captureTime)
		s.DB.QueryRow("SELECT value FROM config WHERE key = ?", "SCAN_TIME").Scan(&scanTime)
		return nil
	}

	cwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(cwd)

	if _, err := RunAutonomousAudit(filepath.Join("..", planPath), filepath.Join("..", modDir), mockRunFunc); err != nil {
		t.Fatalf("RunAutonomousAudit failed: %v", err)
	}

	if captureTime != "120" {
		t.Errorf("expected CAPTURE_TIME=120 in DB, got %q", captureTime)
	}
	if scanTime != "45" {
		t.Errorf("expected SCAN_TIME=45 in DB, got %q", scanTime)
	}
}

func TestHeadlessAPInterfaceInjected(t *testing.T) {
	// Verify that ap_interface from the plan is injected as AP_INTERFACE env var
	// and persisted to the session DB config table.
	os.Unsetenv("AP_INTERFACE")

	tmpDir := "test_apif_sessions"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	plan := AuditPlan{
		SessionName: "apif_test",
		APInterface: "wlan2",
		Modules:     []string{"MOCK"},
	}
	planPath := "test_apif_plan.json"
	data, _ := json.Marshal(plan)
	os.WriteFile(planPath, data, 0644)
	defer os.Remove(planPath)

	modDir := "test_apif_mods"
	os.MkdirAll(modDir, 0755)
	defer os.RemoveAll(modDir)
	modFile := filepath.Join(modDir, "mock_test.sh")
	os.WriteFile(modFile, []byte("# MODULE_META\n# NAME=\"Mock\"\n# CATEGORY=\"M\"\n"), 0755)

	var observedAPInterface string
	var observedHeadless string
	var observedDBVal string
	var dbErr error
	mockRunFunc := func(s *session.Session, m *module.Module) error {
		observedAPInterface = os.Getenv("AP_INTERFACE")
		observedHeadless = os.Getenv("ASTRA_HEADLESS")
		// Query DB while the session is still open (defer s.Cleanup runs after RunAutonomousAudit returns)
		row := s.DB.QueryRow("SELECT value FROM config WHERE key = ?", "AP_INTERFACE")
		dbErr = row.Scan(&observedDBVal)
		return nil
	}

	cwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(cwd)

	if _, err := RunAutonomousAudit(filepath.Join("..", planPath), filepath.Join("..", modDir), mockRunFunc); err != nil {
		t.Fatalf("RunAutonomousAudit failed: %v", err)
	}

	// Verify env var injection
	if observedAPInterface != "wlan2" {
		t.Errorf("expected AP_INTERFACE=wlan2, got %q", observedAPInterface)
	}

	// Verify ASTRA_HEADLESS is set during headless runs
	if observedHeadless != "true" {
		t.Errorf("expected ASTRA_HEADLESS=true, got %q", observedHeadless)
	}

	// Verify DB persistence
	if dbErr != nil {
		t.Fatalf("AP_INTERFACE not found in DB: %v", dbErr)
	}
	if observedDBVal != "wlan2" {
		t.Errorf("expected DB AP_INTERFACE=wlan2, got %q", observedDBVal)
	}
}

func TestComputeExitCode(t *testing.T) {
	cases := []struct {
		modulesFailed int
		highCritical  int
		expected      int
	}{
		{modulesFailed: 0, highCritical: 0, expected: 0},
		{modulesFailed: 1, highCritical: 0, expected: 2},
		{modulesFailed: 0, highCritical: 1, expected: 3},
		{modulesFailed: 1, highCritical: 1, expected: 3},
		{modulesFailed: 3, highCritical: 5, expected: 3},
	}
	for _, tc := range cases {
		got := computeExitCode(tc.modulesFailed, tc.highCritical)
		if got != tc.expected {
			t.Errorf("computeExitCode(%d, %d) = %d, want %d",
				tc.modulesFailed, tc.highCritical, got, tc.expected)
		}
	}
}
