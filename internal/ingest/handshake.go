package ingest

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"wifi-astra/internal/logging"
)

func init() {
	// Register for Category D (Encryption Attacks)
	RegisterParser("D1", func(db *sql.DB, tcID string, evidenceDir string) error {
		capFile := filepath.Join(evidenceDir, "d1_capture_handshake.cap")
		if _, err := os.Stat(capFile); os.IsNotExist(err) {
			return nil
		}
		return VerifyHandshake(db, tcID, capFile)
	})
}

// VerifyHandshake uses aircrack-ng to verify if a captured file contains a valid WPA handshake.
func VerifyHandshake(database *sql.DB, tcID, filePath string) error {
	logging.Info("Verifying captured handshake: %s", filePath)

	// Run aircrack-ng to check for handshakes
	cmd := exec.Command("aircrack-ng", filePath)
	output, _ := cmd.CombinedOutput()
	outStr := string(output)

	if strings.Contains(outStr, "1 handshake") || strings.Contains(outStr, "handshake(s)") {
		logging.Success("Valid WPA handshake detected in %s", filepath.Base(filePath))
		
		// Record as a high-severity vulnerability only if not already present.
		// The D1 bash module records this finding via record-finding; skip if duplicate.
		var existing int
		database.QueryRow(`SELECT COUNT(*) FROM vulnerability WHERE tc_id = ? AND name = ?`,
			tcID, "WPA Handshake Captured").Scan(&existing)
		if existing == 0 {
			database.Exec(`INSERT INTO vulnerability (tc_id, name, severity, description, evidence_file)
				VALUES (?, ?, ?, ?, ?)`,
				tcID, "WPA Handshake Captured", "CRITICAL",
				"A valid 4-way WPA handshake was captured, allowing for offline brute-force attacks.",
				filePath)
		}
	} else {
		logging.Warn("No valid handshake found in %s", filepath.Base(filePath))
	}

	return nil
}
