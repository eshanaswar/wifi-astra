package ingest

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"wifi-astra/internal/logging"
)

type BettercapEvent struct {
	Tag  string `json:"tag"`
	Data struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Protocol string `json:"protocol"`
		Username string `json:"user"`
		Password string `json:"pass"`
		Host     string `json:"hostname"`
	} `json:"data"`
}

func init() {
	// Register for Category G (MITM)
	RegisterParser("G", func(db *sql.DB, tcID string, evidenceDir string) error {
		jsonFile := filepath.Join(evidenceDir, strings.ToLower(tcID)+"_bettercap.json")
		if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
			return nil
		}
		return IngestBettercapJSON(db, tcID, jsonFile)
	})
}

// IngestBettercapJSON parses a Bettercap JSON log and extracts credentials.
func IngestBettercapJSON(database *sql.DB, tcID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	count := 0
	for decoder.More() {
		var event BettercapEvent
		if err := decoder.Decode(&event); err != nil {
			continue
		}

		// Look for credential tags
		if strings.Contains(event.Tag, "credentials") || (event.Data.Username != "" && event.Data.Password != "") {
			_, err = database.Exec(`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file) 
				VALUES (?, ?, ?, ?, ?, ?)`, 
				tcID, event.Data.Username, event.Data.Password, event.Data.Protocol, event.Data.Host, filePath)
			if err == nil {
				count++
			}
		}
	}

	if count > 0 {
		logging.Success("Ingested %d credentials from Bettercap log.", count)
	}
	return nil
}
