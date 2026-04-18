package report

import (
	"os"
	"strings"
	"testing"
	"wifi-astra/internal/session"
)

func TestGenerateReport(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := session.NewSession("report_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	s.DB.Exec("INSERT INTO network (bssid, ssid, channel) VALUES (?, ?, ?)", "00:11:22:33:44:55", "TestNet", 6)
	s.DB.Exec("INSERT INTO vulnerability (tc_id, name, severity) VALUES (?, ?, ?)", "A1", "Test Vuln", "HIGH")

	path, err := GenerateReport(s, "./modules")
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("report file not created at %s", path)
	}
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "TestNet") {
		t.Errorf("report missing network name")
	}
	if !strings.Contains(string(content), "Test Vuln") {
		t.Errorf("report missing vulnerability name")
	}
}

func TestFindingsCounterIgnoresFailedRuns(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := session.NewSession("counter_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	// Insert a failed module run — should NOT count as a finding
	s.DB.Exec(`INSERT INTO module_state (tc_id, status, exit_code) VALUES (?, ?, ?)`, "D1", "failed", 1)
	// Insert one real vulnerability finding
	s.DB.Exec(`INSERT INTO vulnerability (tc_id, name, severity) VALUES (?, ?, ?)`, "D1", "WPA2 Handshake Captured", "HIGH")

	data := buildReportData(s, "./modules")
	if data.Summary.Findings != 1 {
		t.Errorf("expected 1 finding (from vulnerability table only), got %d", data.Summary.Findings)
	}
}

func TestSummarySecureIsSet(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := session.NewSession("secure_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	// One completed module with no vulnerability
	s.DB.Exec(`INSERT INTO module_state (tc_id, status) VALUES (?, ?)`, "H2", "completed")

	data := buildReportData(s, "./modules")
	if data.Summary.Secure == 0 {
		t.Errorf("expected Summary.Secure > 0 for a completed module with no findings, got 0")
	}
}

func TestMediumSeverityCSS(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := session.NewSession("css_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	s.DB.Exec(`INSERT INTO vulnerability (tc_id, name, severity) VALUES (?, ?, ?)`, "C3", "VLAN Hop Possible", "MEDIUM")

	path, _ := GenerateReport(s, "./modules")
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "finding-medium") {
		t.Errorf("MEDIUM severity finding should use finding-medium CSS class")
	}
}

func TestGenerateMarkdownReport(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := session.NewSession("md_test", tmpDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	s.DB.Exec("INSERT INTO vulnerability (tc_id, name, severity, description) VALUES (?, ?, ?, ?)",
		"D1", "WPA2 Handshake Captured", "CRITICAL", "4-way handshake captured.")
	s.DB.Exec("INSERT INTO network (bssid, ssid, channel) VALUES (?, ?, ?)", "AA:BB:CC:DD:EE:FF", "CorpWiFi", 6)

	path, err := GenerateMarkdownReport(s, "./modules")
	if err != nil {
		t.Fatalf("GenerateMarkdownReport failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "WPA2 Handshake Captured") {
		t.Errorf("markdown report missing vulnerability name")
	}
	if !strings.Contains(string(content), "CorpWiFi") {
		t.Errorf("markdown report missing network name")
	}
	if !strings.Contains(string(content), "## Vulnerabilities") {
		t.Errorf("markdown report missing Vulnerabilities section header")
	}
}

