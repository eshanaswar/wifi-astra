package evidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wifi-astra/internal/evidence"
)

func TestWriteRunLog(t *testing.T) {
	dir := t.TempDir()
	log := evidence.ModuleRunLog{
		TCID:        "D1",
		Name:        "WPA Handshake Capture",
		SessionID:   "sess_001",
		StartedAt:   time.Now().UTC(),
		EndedAt:     time.Now().UTC(),
		DurationSec: 120,
		ExitCode:    0,
		Status:      "completed",
		Command:     "/modules/d1_wpa_handshake.sh",
	}

	path, err := evidence.WriteRunLog(dir, log)
	if err != nil {
		t.Fatalf("WriteRunLog failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read written log: %v", err)
	}

	var parsed evidence.ModuleRunLog
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed.TCID != "D1" {
		t.Errorf("expected TCID D1, got %s", parsed.TCID)
	}
	if filepath.Base(path) != "d1_run.json" {
		t.Errorf("expected filename d1_run.json, got %s", filepath.Base(path))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file perm 0600, got %04o", perm)
	}
}

func TestWriteRunLogInvalidTCID(t *testing.T) {
	dir := t.TempDir()
	_, err := evidence.WriteRunLog(dir, evidence.ModuleRunLog{TCID: "../etc/passwd"})
	if err == nil {
		t.Error("expected error for path-traversal TCID, got nil")
	}
}

func TestWriteRunLogEmptyTCID(t *testing.T) {
	dir := t.TempDir()
	_, err := evidence.WriteRunLog(dir, evidence.ModuleRunLog{TCID: ""})
	if err == nil {
		t.Error("expected error for empty TCID, got nil")
	}
}

func TestAppendManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "MANIFEST.sha256")

	// Create a test file to hash
	testFile := filepath.Join(dir, "d1_capture.pcap")
	if err := os.WriteFile(testFile, []byte("fake pcap data"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := evidence.AppendManifest(manifestPath, testFile); err != nil {
		t.Fatalf("AppendManifest failed: %v", err)
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "d1_capture.pcap") {
		t.Errorf("manifest missing filename: %s", content)
	}
	// SHA256 hex is 64 chars; check format: "<hash>  <name>"
	parts := strings.Fields(content)
	if len(parts) < 2 || len(parts[0]) != 64 {
		t.Errorf("unexpected manifest format: %s", content)
	}
}

func TestAppendManifestSkipsMissing(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "MANIFEST.sha256")

	// File that doesn't exist — should be silently skipped
	err := evidence.AppendManifest(manifestPath, filepath.Join(dir, "nonexistent.pcap"))
	if err != nil {
		t.Errorf("expected nil error for missing file, got: %v", err)
	}
	// Manifest should not have been created at all
	if _, statErr := os.Stat(manifestPath); statErr == nil {
		t.Error("manifest should not be created when source file is missing")
	}
}

func TestAppendReplay(t *testing.T) {
	dir := t.TempDir()
	replayPath := filepath.Join(dir, "SESSION_REPLAY.log")

	events := []struct{ tcID, event, detail string }{
		{"D1", "START", "WPA Handshake Capture began"},
		{"D1", "COMPLETE", "exit_code=0 duration=120s"},
	}
	for _, e := range events {
		if err := evidence.AppendReplay(replayPath, e.tcID, e.event, e.detail); err != nil {
			t.Fatalf("AppendReplay(%s) failed: %v", e.event, err)
		}
	}

	data, err := os.ReadFile(replayPath)
	if err != nil {
		t.Fatalf("replay log not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "[D1] START") {
		t.Errorf("missing START event: %s", content)
	}
	if !strings.Contains(content, "[D1] COMPLETE") {
		t.Errorf("missing COMPLETE event: %s", content)
	}
	// Verify RFC3339 timestamp format at the start of each line
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for _, line := range lines {
		// First token must be parseable as RFC3339
		parts := strings.Fields(line)
		if len(parts) == 0 {
			t.Error("empty line in replay log")
			continue
		}
		if _, err := time.Parse(time.RFC3339, parts[0]); err != nil {
			t.Errorf("first token is not RFC3339 timestamp: %q", parts[0])
		}
	}
}
