package module

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseModuleMeta_Timed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "module_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `#!/bin/bash
# MODULE_META
# NAME="Test Module"
# CATEGORY="Testing"
# TIMED="yes"
# DECODE="test"
`
	filePath := filepath.Join(tmpDir, "t1_test.sh")
	if err := os.WriteFile(filePath, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	m, err := parseModuleMeta(filePath)
	if err != nil {
		t.Fatalf("Failed to parse module meta: %v", err)
	}

	if m.ID != "T1" {
		t.Errorf("Expected ID T1, got %s", m.ID)
	}
	if !m.Timed {
		t.Errorf("Expected Timed to be true, got %v", m.Timed)
	}
}

func TestParseModuleMeta_NotTimed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "module_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := `#!/bin/bash
# MODULE_META
# NAME="Untimed Module"
# CATEGORY="Testing"
# TIMED="no"
`
	filePath := filepath.Join(tmpDir, "u1_test.sh")
	if err := os.WriteFile(filePath, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	m, err := parseModuleMeta(filePath)
	if err != nil {
		t.Fatalf("Failed to parse module meta: %v", err)
	}

	if m.Timed {
		t.Errorf("Expected Timed to be false, got %v", m.Timed)
	}
}
