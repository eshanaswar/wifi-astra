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

	err := RunAutonomousAudit(filepath.Join("..", planPath), filepath.Join("..", modDir), mockRunFunc)
	if err != nil {
		t.Fatalf("RunAutonomousAudit failed: %v", err)
	}

	if runCount != 1 {
		t.Errorf("expected 1 module run, got %d", runCount)
	}
}
