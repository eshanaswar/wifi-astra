// internal/controller/cracking.go
package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wifi-astra/internal/logging"
	"wifi-astra/pkg/executor"
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
// Returns CrackResult. Exit code 1 means exhausted (not an error). Exit code 255 = error.
func RunHashcat(ctx context.Context, captureFile, wordlist, mode, logFile string, execMgr *executor.Manager) (*CrackResult, error) {
	outfile := captureFile + ".cracked"
	args := []string{
		"-m", mode,
		"-a", "0",
		"--outfile", outfile,
		"--outfile-format", "2",
		"--status",
		"--status-timer=10",
		"--force",
		captureFile,
		wordlist,
	}

	start := time.Now()
	exitCode, err := execMgr.Run(ctx, "hashcat-inline", "hashcat", args, logFile)
	duration := int(time.Since(start).Seconds())

	result := &CrackResult{
		Mode:         mode,
		WordlistUsed: wordlist,
		DurationSec:  duration,
	}

	if err != nil {
		if exitCode == 1 {
			// Exit 1 = exhausted — wordlist tried, nothing found. Not a real error.
			logging.Info("Hashcat: wordlist exhausted, no PSK found (duration %ds)", duration)
			return result, nil
		}
		return result, err
	}

	// exitCode 0 = at least one hash cracked
	if exitCode == 0 {
		result.PSK = parseCrackOutput(outfile)
		result.Found = result.PSK != ""
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

// hashcatLogPath returns the evidence path for a hashcat run log.
func hashcatLogPath(evidenceDir, tcID string) string {
	return filepath.Join(evidenceDir, strings.ToLower(tcID)+"_hashcat.log")
}
