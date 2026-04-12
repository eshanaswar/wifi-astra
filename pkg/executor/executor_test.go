package executor

import (
	"context"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	// Run a simple command
	code, err := m.Run(ctx, "test_run", "echo", []string{"hello"}, "")
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestSpawnAndStop(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	// Spawn a command that sleeps
	p, err := m.Spawn(ctx, "test_spawn", "sleep", []string{"10"}, "")
	if err != nil {
		t.Fatalf("spawn failed: %v", err)
	}

	if p.Status != "running" {
		t.Errorf("expected status 'running', got '%s'", p.Status)
	}

	// Stop it
	err = m.Stop("test_spawn")
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// Verify it's removed from manager
	m.mu.RLock()
	_, exists := m.processes["test_spawn"]
	m.mu.RUnlock()
	if exists {
		t.Errorf("process should have been removed from manager")
	}
}

func TestCleanup(t *testing.T) {
	m := NewManager()
	ctx := context.Background()

	m.Spawn(ctx, "p1", "sleep", []string{"10"}, "")
	m.Spawn(ctx, "p2", "sleep", []string{"10"}, "")

	m.Cleanup()

	m.mu.RLock()
	count := len(m.processes)
	m.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 processes after cleanup, got %d", count)
	}
}

func TestSanitizeEnvLogsWarning(t *testing.T) {
	// SanitizeEnv should strip metacharacters and not panic
	dangerous := []string{
		"SSID=Corp;Net",
		"BSSID=AA:BB:CC:DD:EE:FF",        // safe — should pass through unchanged
		"GUEST_SSID=Acme&Partners|WiFi",
		"TARGET_CLIENT=`whoami`",
	}
	result := SanitizeEnv(dangerous)

	if len(result) != len(dangerous) {
		t.Fatalf("expected %d entries, got %d", len(dangerous), len(result))
	}
	// Safe value must be unchanged
	if result[1] != "BSSID=AA:BB:CC:DD:EE:FF" {
		t.Errorf("safe value was modified: %s", result[1])
	}
	// Dangerous values must have metacharacters removed
	for _, v := range []string{result[0], result[2], result[3]} {
		for _, ch := range []string{";", "&", "|", "`"} {
			if strings.Contains(v, ch) {
				t.Errorf("dangerous char %q not stripped from %q", ch, v)
			}
		}
	}
}

func TestSanitizeEnvPreservesEqualsSign(t *testing.T) {
	// KEY=VALUE format must be preserved — only the value part is sanitized
	input := []string{"MY_KEY=some=value=with=equals"}
	result := SanitizeEnv(input)
	if result[0] != "MY_KEY=some=value=with=equals" {
		t.Errorf("equals signs in value should not be stripped: %s", result[0])
	}
}
