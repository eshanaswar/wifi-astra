package ingest

import (
	"database/sql"
	"os"
	"testing"
	"wifi-astra/internal/db"
)

func TestRegistryDispatch(t *testing.T) {
	dbPath := "test_registry.db"
	defer os.Remove(dbPath)
	database, _ := db.InitDB(dbPath)
	defer database.Close()

	runCount := 0
	RegisterParser("MOCK", func(d *sql.DB, tcID string, evidenceDir string) error {
		runCount++
		return nil
	})

	// Test exact match
	err := Dispatch(database, "MOCK", ".")
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if runCount != 1 {
		t.Errorf("expected 1 run, got %d", runCount)
	}

	// Test case insensitivity
	err = Dispatch(database, "mock", ".")
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if runCount != 2 {
		t.Errorf("expected 2 runs, got %d", runCount)
	}

	// Test category match (already registered 'B' in nmap.go)
	// We just check it doesn't return error even if file doesn't exist
	err = Dispatch(database, "B1", ".")
	if err != nil {
		t.Errorf("category dispatch failed: %v", err)
	}
}
