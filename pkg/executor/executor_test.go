package executor

import (
	"context"
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
