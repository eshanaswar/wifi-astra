// internal/controller/cracking.go
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wifi-astra/internal/logging"
	"wifi-astra/pkg/executor"
)

var (
	wpsReavPINRe  = regexp.MustCompile(`(?i)\[\+\]\s+WPS PIN:\s+'?([0-9]+)'?`)
	wpsReavPSKRe  = regexp.MustCompile(`(?i)\[\+\]\s+WPA PSK:\s+(?:'([^'\n]*)'|([^\n]+))`)
	wpsBullyPINRe = regexp.MustCompile(`(?i)\[\+\]\s+WPS pin is:\s+'?([0-9]+)'?`)
	wpsBullyPSKRe = regexp.MustCompile(`(?i)\[\+\]\s+Passphrase is:\s+(?:'([^'\n]*)'|([^\n]+))`)
)

// CrackResult holds the outcome of an inline cracking attempt.
type CrackResult struct {
	Found        bool
	PSK          string
	Mode         string // hashcat mode used, e.g. "22000" or "2500"
	WordlistUsed string
	DurationSec  int
}

// EapCred is a username/password pair extracted from eaphammer output.
type EapCred struct {
	Username string
	Password string
}

// parseCrackOutput reads a hashcat --outfile written with --outfile-format 2
// (plaintext only). Returns the trimmed first non-empty line, or "" if not cracked.
func parseCrackOutput(outfilePath string) string {
	data, err := os.ReadFile(outfilePath)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			return l
		}
	}
	return ""
}

// RunHashcat runs hashcat in dictionary mode against captureFile using wordlist.
// mode: hashcat hash-mode string — "22000" (PMKID/EAPOL hcxtools) or "2500" (legacy EAPOL).
// captureFile: path to .hc22000 or .cap file.
// wordlist: path to wordlist file.
// logFile: path for hashcat stdout/stderr evidence.
// rules: optional list of --rules-file paths (nil or empty = no rules).
// Returns CrackResult. Exit code 1 means exhausted (not an error). Exit code 255 = error.
func RunHashcat(ctx context.Context, captureFile, wordlist, mode, logFile string, rules []string, execMgr *executor.Manager) (*CrackResult, error) {
	outfile := captureFile + ".cracked"
	args := []string{
		"-m", mode,
		"-a", "0",
		"--outfile", outfile,
		"--outfile-format", "2",
		"--status",
		"--status-timer=10",
		"--force",
		"--potfile-disable",
	}
	for _, r := range rules {
		args = append(args, "--rules-file", r)
	}
	args = append(args, captureFile, wordlist)

	start := time.Now()
	exitCode, err := execMgr.Run(ctx, "hashcat-inline", "hashcat", args, logFile)
	duration := int(time.Since(start).Seconds())

	result := &CrackResult{
		Mode:         mode,
		WordlistUsed: wordlist,
		DurationSec:  duration,
	}

	if err != nil {
		// err is non-nil only when hashcat failed to launch (exec error, not an exit code).
		return result, err
	}

	// The executor converts *exec.ExitError → (exitCode, nil), so branch on exitCode directly.
	// hashcat exit codes: 0 = cracked, 1 = exhausted (no crack), 255 = runtime error.
	switch exitCode {
	case 0:
		result.PSK = parseCrackOutput(outfile)
		result.Found = result.PSK != ""
	case 1:
		// --force: hashcat --force disables GPU safety guards; used here for portability on pentest
		// hardware where GPU drivers may not be fully configured. CPU fallback is acceptable.
		logging.Info("Hashcat: wordlist exhausted, no PSK found (duration %ds)", duration)
	case 255:
		return result, fmt.Errorf("hashcat reported an error (exit 255); check log at %s", logFile)
	default:
		logging.Warn("Hashcat: unexpected exit code %d (duration %ds)", exitCode, duration)
	}

	return result, nil
}

// ParseEaphammerCreds scans eaphammer log text for captured credential blocks.
// Looks for consecutive "Username:" / "Password:" lines (case-insensitive).
func ParseEaphammerCreds(logText string) []EapCred {
	var creds []EapCred
	var pendingUser string

	for _, raw := range strings.Split(logText, "\n") {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "username:") {
			pendingUser = strings.TrimSpace(line[len("username:"):])
		} else if strings.HasPrefix(lower, "password:") && pendingUser != "" {
			pass := strings.TrimSpace(line[len("password:"):])
			creds = append(creds, EapCred{Username: pendingUser, Password: pass})
			pendingUser = ""
		} else if line == "" || strings.HasPrefix(lower, "[") {
			pendingUser = ""
		}
	}
	return creds
}

// ParseWPSCreds extracts WPS PIN and WPA PSK from reaver or bully output logs.
// Supports reaver format ([+] WPS PIN / [+] WPA PSK) and
// bully format ([+] WPS pin is / [+] Passphrase is).
// Handles both quoted ('password') and unquoted forms. Returns empty strings if not found.
func ParseWPSCreds(logText string) (string, string) {
	var psk, pin string

	// PIN extraction (reaver takes priority)
	if m := wpsReavPINRe.FindStringSubmatch(logText); len(m) > 1 {
		pin = strings.TrimSpace(m[1])
	} else if m := wpsBullyPINRe.FindStringSubmatch(logText); len(m) > 1 {
		pin = strings.TrimSpace(m[1])
	}

	// PSK extraction — alternation groups handle quoted vs unquoted
	extractPSK := func(m []string) string {
		if len(m) > 2 && m[1] != "" {
			return strings.TrimSpace(m[1]) // quoted form: group 1
		}
		if len(m) > 2 && m[2] != "" {
			return strings.TrimSpace(m[2]) // unquoted form: group 2
		}
		return ""
	}
	if m := wpsReavPSKRe.FindStringSubmatch(logText); len(m) > 0 {
		psk = extractPSK(m)
	} else if m := wpsBullyPSKRe.FindStringSubmatch(logText); len(m) > 0 {
		psk = extractPSK(m)
	}

	return psk, pin
}

var aircrackKeyRe = regexp.MustCompile(`KEY FOUND!\s*\[\s*([0-9A-Fa-f:]+)\s*\]`)

// ParseAircrackKey extracts the recovered WEP key from aircrack-ng stdout.
// Returns empty string if no key was found.
func ParseAircrackKey(log string) string {
	m := aircrackKeyRe.FindStringSubmatch(log)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// hashcatLogPath returns the evidence path for a hashcat run log.
func hashcatLogPath(evidenceDir, tcID string) string {
	return filepath.Join(evidenceDir, strings.ToLower(tcID)+"_hashcat.log")
}
