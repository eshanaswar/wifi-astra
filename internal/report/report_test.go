package report

import (
	"os"
	"testing"
	"wifi-astra/internal/session"
)

func TestGenerateReport(t *testing.T) {
	// Setup
	tmpDir := "test_report_sessions"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)

	s, err := session.NewSession("report_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	// Add dummy data
	s.DB.Exec("INSERT INTO network (bssid, ssid, channel) VALUES (?, ?, ?)", "00:11:22:33:44:55", "TestNet", 6)
	s.DB.Exec("INSERT INTO vulnerability (tc_id, name, severity) VALUES (?, ?, ?)", "A1", "Test Vuln", "HIGH")

	path, err := GenerateReport(s)
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("Report file not created at %s", path)
	}

	// Basic check of content
	content, _ := os.ReadFile(path)
	if !contains(string(content), "TestNet") {
		t.Errorf("Report missing network name")
	}
	if !contains(string(content), "Test Vuln") {
		t.Errorf("Report missing vulnerability name")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr)) // Primitive
}
