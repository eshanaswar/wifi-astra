// internal/controller/cracking_test.go
package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCrackOutputFound(t *testing.T) {
	dir := t.TempDir()
	outfile := filepath.Join(dir, "result.txt")
	// hashcat --outfile-format 2 writes one line per cracked hash: just the plaintext
	os.WriteFile(outfile, []byte("CorrectHorseBatteryStaple\n"), 0600)

	psk := parseCrackOutput(outfile)
	if psk != "CorrectHorseBatteryStaple" {
		t.Errorf("expected PSK %q, got %q", "CorrectHorseBatteryStaple", psk)
	}
}

func TestParseCrackOutputEmpty(t *testing.T) {
	dir := t.TempDir()
	outfile := filepath.Join(dir, "result.txt")
	os.WriteFile(outfile, []byte(""), 0600)

	psk := parseCrackOutput(outfile)
	if psk != "" {
		t.Errorf("expected empty PSK for empty outfile, got %q", psk)
	}
}

func TestParseCrackOutputMissing(t *testing.T) {
	psk := parseCrackOutput("/tmp/this-file-does-not-exist-cracking-test")
	if psk != "" {
		t.Errorf("expected empty PSK for missing outfile, got %q", psk)
	}
}

func TestParseEaphammerCredsFound(t *testing.T) {
	logContent := `
[*] Starting evil twin AP...
[*] Captured credentials:
    Username: jsmith
    Password: Passw0rd!
[*] Captured credentials:
    Username: alee
    Password: Summer2026
[*] Done.
`
	creds := ParseEaphammerCreds(logContent)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].Username != "jsmith" || creds[0].Password != "Passw0rd!" {
		t.Errorf("first cred mismatch: %+v", creds[0])
	}
	if creds[1].Username != "alee" || creds[1].Password != "Summer2026" {
		t.Errorf("second cred mismatch: %+v", creds[1])
	}
}

func TestParseEaphammerCredsNone(t *testing.T) {
	logContent := "[*] No clients connected.\n"
	creds := ParseEaphammerCreds(logContent)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}
