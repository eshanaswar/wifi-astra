package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// tcidRe validates that a TCID contains only safe characters (alphanumeric, underscore, hyphen).
var tcidRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ModuleRunLog is the structured record written to evidence/<tcid>_run.json
// after every module execution.
type ModuleRunLog struct {
	TCID        string    `json:"tc_id"`
	Name        string    `json:"name"`
	SessionID   string    `json:"session_id"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	DurationSec int       `json:"duration_sec"`
	ExitCode    int       `json:"exit_code"`
	Status      string    `json:"status"`
	Command     string    `json:"command"`
	Error       string    `json:"error,omitempty"`
}

// WriteRunLog serialises entry to <dir>/<tcid>_run.json and returns the path.
func WriteRunLog(dir string, entry ModuleRunLog) (string, error) {
	if entry.TCID == "" || !tcidRe.MatchString(entry.TCID) {
		return "", fmt.Errorf("evidence: invalid TCID %q", entry.TCID)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("evidence dir: %w", err)
	}
	path := filepath.Join(dir, strings.ToLower(entry.TCID)+"_run.json")
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return "", fmt.Errorf("evidence: marshal %s: %w", entry.TCID, err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("evidence: write %s: %w", path, err)
	}
	return path, nil
}
