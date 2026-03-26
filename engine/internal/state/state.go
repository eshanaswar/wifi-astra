package state

import (
	"database/sql"
)

type StateManager struct {
	db *sql.DB
}

func NewStateManager(database *sql.DB) *StateManager {
	return &StateManager{db: database}
}

// SetConfig sets a configuration value.
func (s *StateManager) SetConfig(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?);`, key, value)
	return err
}

// GetConfig gets a configuration value.
func (s *StateManager) GetConfig(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key = ?;`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// UpdateModuleStatus updates the status of a test case.
func (s *StateManager) UpdateModuleStatus(tcID, status string, exitCode int) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO module_state (tc_id, status, exit_code) 
		VALUES (?, ?, ?) 
		ON CONFLICT(tc_id) DO UPDATE SET status=excluded.status, exit_code=excluded.exit_code;`,
		tcID, status, exitCode)
	return err
}

// GetModuleStatus gets the status of a test case.
func (s *StateManager) GetModuleStatus(tcID string) (string, error) {
	var status string
	err := s.db.QueryRow(`SELECT status FROM module_state WHERE tc_id = ?;`, tcID).Scan(&status)
	if err == sql.ErrNoRows {
		return "not_run", nil
	}
	return status, err
}

type StatusSummary struct {
	Total      int `json:"total"`
	Done       int `json:"done"`
	Failed     int `json:"failed"`
	Aborted    int `json:"aborted"`
	Running    int `json:"running"`
	NotRun     int `json:"not_run"`
	Percentage int `json:"percentage"`
}

func (s *StateManager) GetStatusSummary() (*StatusSummary, error) {
	rows, err := s.db.Query(`SELECT status FROM module_state;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summary := &StatusSummary{}
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return nil, err
		}
		summary.Total++
		switch status {
		case "done":
			summary.Done++
		case "failed":
			summary.Failed++
		case "aborted":
			summary.Aborted++
		case "running":
			summary.Running++
		default:
			summary.NotRun++
		}
	}

	if summary.Total > 0 {
		summary.Percentage = (summary.Done * 100) / summary.Total
	}

	return summary, nil
}
