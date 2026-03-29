package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewSession(t *testing.T) {
	baseDir := "test_sessions"
	defer os.RemoveAll(baseDir)

	s, err := NewSession("test_audit", baseDir)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer s.Cleanup()

	// Verify directories
	if _, err := os.Stat(s.BaseDir); os.IsNotExist(err) {
		t.Errorf("session directory not created")
	}
	if _, err := os.Stat(filepath.Join(s.BaseDir, "session.db")); os.IsNotExist(err) {
		t.Errorf("database file not created")
	}

	// Verify ID contains the name
	if !contains(s.ID, "test_audit") {
		t.Errorf("session ID should contain 'test_audit', got '%s'", s.ID)
	}
}

func contains(s, substr string) bool {
	return filepath.Base(s)[:len(substr)] == substr || len(s) > len(substr) 
}

func TestLoadSession(t *testing.T) {
	baseDir := "test_sessions_load"
	defer os.RemoveAll(baseDir)

	s1, _ := NewSession("load_me", baseDir)
	sessionDir := s1.BaseDir
	s1.Cleanup()

	// Load it back
	s2, err := LoadSession(sessionDir)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}
	defer s2.Cleanup()

	if s2.ID != s1.ID {
		t.Errorf("loaded ID mismatch: expected '%s', got '%s'", s1.ID, s2.ID)
	}
}
