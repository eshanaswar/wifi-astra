package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseA4ClientMACs_Basic(t *testing.T) {
	csv := "BSSID, First time seen, Last time seen\n\nStation MAC, First time seen, Last time seen, Power\nAA:BB:CC:DD:EE:01, 2024-01-01, 2024-01-01, -65\nAA:BB:CC:DD:EE:02, 2024-01-01, 2024-01-01, -72\n"
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 2 {
		t.Fatalf("expected 2 clients, got %d: %v", len(macs), macs)
	}
	if macs[0] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("unexpected first MAC: %s", macs[0])
	}
	if macs[1] != "AA:BB:CC:DD:EE:02" {
		t.Errorf("unexpected second MAC: %s", macs[1])
	}
}

func TestParseA4ClientMACs_NoStationSection(t *testing.T) {
	csv := "BSSID, First time seen\n00:11:22:33:44:55, 2024-01-01\n"
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 0 {
		t.Errorf("expected 0 clients, got %d: %v", len(macs), macs)
	}
}

func TestParseA4ClientMACs_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a4_results.csv")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	macs := parseA4ClientMACs(path)
	if len(macs) != 0 {
		t.Errorf("expected 0 clients for empty file, got %d", len(macs))
	}
}

func TestParseA4ClientMACs_NonexistentFile(t *testing.T) {
	macs := parseA4ClientMACs("/nonexistent/path/a4_results.csv")
	if len(macs) != 0 {
		t.Errorf("expected 0 clients for missing file, got %d", len(macs))
	}
}
