package evidence

import (
	"fmt"
	"os"
	"time"
)

// AppendReplay appends a timestamped event line to the session replay log.
// Format: "<RFC3339-UTC> [TCID] EVENT      detail"
// The EVENT field is left-padded to 10 chars for alignment.
func AppendReplay(replayPath, tcID, event, detail string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%s [%s] %-10s %s\n", ts, tcID, event, detail)
	f, err := os.OpenFile(replayPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("evidence: open replay log: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("evidence: write replay log: %w", err)
	}
	return nil
}
