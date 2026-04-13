package evidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
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
}
