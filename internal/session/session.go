package session

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	ScopeSecret []byte // 32-byte random key; generated once per session, persisted in SQLite
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

	// Generate and persist per-session HMAC scope secret
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("failed to generate scope secret: %w", err)
	}
	s.ScopeSecret = raw[:]
	s.DB.Exec(`INSERT OR REPLACE INTO scope_secret (id, secret) VALUES (1, ?)`,
		hex.EncodeToString(s.ScopeSecret))

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

	s := &Session{
		ID:          id,
		Name:        name,
		BaseDir:     sessionDir,
		LogDir:      filepath.Join(sessionDir, "logs"),
		EvidenceDir: filepath.Join(sessionDir, "evidence"),
		ReportDir:   filepath.Join(sessionDir, "reports"),
		ResultsDir:  filepath.Join(sessionDir, "results"),
		DBPath:      dbPath,
		DB:          database,
	}

	// Load persisted scope secret
	var secretHex string
	if err := s.DB.QueryRow(`SELECT secret FROM scope_secret WHERE id = 1`).Scan(&secretHex); err == nil {
		if raw, decErr := hex.DecodeString(secretHex); decErr == nil {
			s.ScopeSecret = raw
		}
	}
	// Legacy session or DB error: generate a fresh secret and persist it
	if len(s.ScopeSecret) == 0 {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, fmt.Errorf("failed to generate scope secret: %w", err)
		}
		s.ScopeSecret = raw[:]
		s.DB.Exec(`INSERT OR REPLACE INTO scope_secret (id, secret) VALUES (1, ?)`,
			hex.EncodeToString(s.ScopeSecret))
	}

	return s, nil
}

func (s *Session) Cleanup() {
	if s.DB != nil {
		s.DB.Close()
	}
}

// SessionMeta holds lightweight display info for the session picker.
type SessionMeta struct {
	ID           string
	Name         string
	CreatedAt    string
	ModulesDone  int
	FindingCount int
}

// QueryMeta opens the session DB and returns display metadata without
// loading the full session into memory.
func QueryMeta(sessionDir string) (SessionMeta, error) {
	dbPath := filepath.Join(sessionDir, "session.db")
	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return SessionMeta{}, err
	}
	defer database.Close()

	var m SessionMeta
	database.QueryRow("SELECT id, name, created_at FROM session LIMIT 1").Scan(&m.ID, &m.Name, &m.CreatedAt)
	database.QueryRow("SELECT COUNT(*) FROM module_state WHERE status = 'completed'").Scan(&m.ModulesDone)
	database.QueryRow("SELECT COUNT(*) FROM vulnerability WHERE severity != 'INFO'").Scan(&m.FindingCount)
	return m, nil
}
