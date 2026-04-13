package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

// WriteRunLog serialises log to <dir>/<tcid>_run.json and returns the path.
func WriteRunLog(dir string, log ModuleRunLog) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("evidence dir: %w", err)
	}
	path := filepath.Join(dir, strings.ToLower(log.TCID)+"_run.json")
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}
