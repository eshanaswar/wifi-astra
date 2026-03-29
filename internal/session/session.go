package session

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"wifi-astra/internal/db"
)

type Session struct {
	ID          string
	Name        string
	BaseDir     string
	LogDir      string
	EvidenceDir string
	ReportDir   string
	ResultsDir  string
	DBPath      string
	DB          *sql.DB
}

func NewSession(name string, baseDir string) (*Session, error) {
	timestamp := time.Now().Format("20060102_150405")
	var id string
	if name != "" {
		// Clean name
		cleanName := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, name)
		id = fmt.Sprintf("%s_%s", cleanName, timestamp)
	} else {
		id = fmt.Sprintf("session_%s", timestamp)
		name = "Unnamed"
	}

	sessionDir := filepath.Join(baseDir, id)
	s := &Session{
		ID:          id,
		Name:        name,
		BaseDir:     sessionDir,
		LogDir:      filepath.Join(sessionDir, "logs"),
		EvidenceDir: filepath.Join(sessionDir, "evidence"),
		ReportDir:   filepath.Join(sessionDir, "reports"),
		ResultsDir:  filepath.Join(sessionDir, "results"),
		DBPath:      filepath.Join(sessionDir, "session.db"),
	}

	// Create directories
	dirs := []string{s.BaseDir, s.LogDir, s.EvidenceDir, s.ReportDir, s.ResultsDir}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", d, err)
		}
	}

	// Initialize DB
	database, err := db.InitDB(s.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}
	s.DB = database

	// Insert session record
	_, err = s.DB.Exec("INSERT INTO session (id, name) VALUES (?, ?)", s.ID, s.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to insert session record: %v", err)
	}

	return s, nil
}

func LoadSession(sessionDir string) (*Session, error) {
	dbPath := filepath.Join(sessionDir, "session.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("session database not found at %s", dbPath)
	}

	database, err := db.InitDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open session database: %v", err)
	}

	var id, name string
	err = database.QueryRow("SELECT id, name FROM session LIMIT 1").Scan(&id, &name)
	if err != nil {
		return nil, fmt.Errorf("failed to read session info from database: %v", err)
	}

	return &Session{
		ID:          id,
		Name:        name,
		BaseDir:     sessionDir,
		LogDir:      filepath.Join(sessionDir, "logs"),
		EvidenceDir: filepath.Join(sessionDir, "evidence"),
		ReportDir:   filepath.Join(sessionDir, "reports"),
		ResultsDir:  filepath.Join(sessionDir, "results"),
		DBPath:      dbPath,
		DB:          database,
	}, nil
}

func (s *Session) Cleanup() {
	if s.DB != nil {
		s.DB.Close()
	}
}
