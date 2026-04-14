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
	if err := os.WriteFile(outfile, []byte("CorrectHorseBatteryStaple\n"), 0600); err != nil {
		t.Fatalf("setup: write outfile: %v", err)
	}

	psk := parseCrackOutput(outfile)
	if psk != "CorrectHorseBatteryStaple" {
		t.Errorf("expected PSK %q, got %q", "CorrectHorseBatteryStaple", psk)
	}
}

func TestParseCrackOutputEmpty(t *testing.T) {
	dir := t.TempDir()
	outfile := filepath.Join(dir, "result.txt")
	if err := os.WriteFile(outfile, []byte(""), 0600); err != nil {
		t.Fatalf("setup: write outfile: %v", err)
	}

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

func TestParseEaphammerCredsOrphanedPassword(t *testing.T) {
	// Password: line before any Username: — must not produce a credential
	logContent := "    Password: orphan\n    Username: jdoe\n    Password: secret\n"
	creds := ParseEaphammerCreds(logContent)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (orphaned password dropped), got %d", len(creds))
	}
	if creds[0].Username != "jdoe" || creds[0].Password != "secret" {
		t.Errorf("credential mismatch: %+v", creds[0])
	}
}

func TestParseEaphammerCredsDanglingUsername(t *testing.T) {
	// Username: with no following Password: — must not produce a credential
	logContent := "    Username: ghost\n[*] Session ended.\n"
	creds := ParseEaphammerCreds(logContent)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials for dangling username, got %d", len(creds))
	}
}

func TestParseWPSCreds_ReaverFormat(t *testing.T) {
	input := "[+] WPS PIN: '12345670'\n[+] WPA PSK: 'password123'"
	psk, pin := ParseWPSCreds(input)
	if psk != "password123" {
		t.Errorf("expected PSK 'password123', got '%s'", psk)
	}
	if pin != "12345670" {
		t.Errorf("expected PIN '12345670', got '%s'", pin)
	}
}

func TestParseWPSCreds_BullyFormat(t *testing.T) {
	input := "[+] Passphrase is: 'password123'\n[+] WPS pin is: 12345670"
	psk, pin := ParseWPSCreds(input)
	if psk != "password123" {
		t.Errorf("expected PSK 'password123', got '%s'", psk)
	}
	if pin != "12345670" {
		t.Errorf("expected PIN '12345670', got '%s'", pin)
	}
}

func TestParseWPSCreds_Empty(t *testing.T) {
	psk, pin := ParseWPSCreds("")
	if psk != "" || pin != "" {
		t.Errorf("expected empty results, got psk='%s' pin='%s'", psk, pin)
	}
}

func TestParseWPSCreds_PINOnly(t *testing.T) {
	input := "[+] WPS PIN: '87654321'"
	psk, pin := ParseWPSCreds(input)
	if psk != "" {
		t.Errorf("expected empty PSK, got '%s'", psk)
	}
	if pin != "87654321" {
		t.Errorf("expected PIN '87654321', got '%s'", pin)
	}
}
