package ingest

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"wifi-astra/internal/db"
	"wifi-astra/internal/logging"
)

// ParserFunc is a function that parses a specific module's evidence and updates the DB.
type ParserFunc func(db *sql.DB, tcID string, evidenceDir string) error

var (
	registry = make(map[string]ParserFunc)
	regMu    sync.RWMutex
)

// RegisterParser registers a parsing function for a specific test case ID or Category.
func RegisterParser(id string, fn ParserFunc) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[strings.ToUpper(id)] = fn
}

// Dispatch routes the evidence ingestion to the appropriate registered parser.
func Dispatch(database *sql.DB, tcID string, evidenceDir string) error {
	regMu.RLock()
	defer regMu.RUnlock()

	tcID = strings.ToUpper(tcID)

	// 1. Proactive/Greedy Ingestion: Check for standard patterns regardless of registry
	// This ensures that any module producing an Airodump CSV gets its data ingested.
	csvFile := filepath.Join(evidenceDir, strings.ToLower(tcID)+"_results.csv")
	if _, err := os.Stat(csvFile); err == nil {
		IngestAirodumpCSV(database, tcID, csvFile)
	} else {
		// Silence the missing file case as it's expected for analysis modules
		logging.Debug("No discovery CSV found for %s, skipping greedy ingest.", tcID)
	}

	// 2. Try exact match (e.g., "A1")
	if fn, ok := registry[tcID]; ok {
		return fn(database, tcID, evidenceDir)
	}

	// 3. Try category match (e.g., "B" for all Category B modules)
	if len(tcID) > 0 {
		category := tcID[:1]
		if fn, ok := registry[category]; ok {
			return fn(database, tcID, evidenceDir)
		}
	}

	logging.Debug("No specialized parser registered for %s", tcID)
	return nil
}

// IngestResultJSON parses a generic result.json produced by a module.
func IngestResultJSON(database *sql.DB, tcID string, evidenceDir string) error {
	path := filepath.Join(evidenceDir, strings.ToLower(tcID)+"_result.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var result struct {
		Vulnerabilities []db.Vulnerability `json:"vulnerabilities"`
		Credentials     []db.Credential    `json:"credentials"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("failed to parse result JSON for %s: %v", tcID, err)
	}

	for _, v := range result.Vulnerabilities {
		database.Exec(`INSERT INTO vulnerability (tc_id, target_host, name, severity, description, remediation, evidence_file) 
			VALUES (?, ?, ?, ?, ?, ?, ?)`, tcID, v.TargetHost, v.Name, v.Severity, v.Description, v.Remediation, v.EvidenceFile)
	}

	for _, cred := range result.Credentials {
		database.Exec(`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file) 
			VALUES (?, ?, ?, ?, ?, ?, ?)`, tcID, cred.Username, cred.Password, cred.Proto, cred.TargetHost, cred.EvidenceFile)
	}

	if len(result.Vulnerabilities) > 0 || len(result.Credentials) > 0 {
		logging.Success("Ingested %d findings from %s results.",
			len(result.Vulnerabilities)+len(result.Credentials), tcID)
	}

	return nil
}
