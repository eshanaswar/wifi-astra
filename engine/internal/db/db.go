package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// InitDB initializes the SQLite database and creates the necessary tables.
func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for better concurrency during simultaneous background tasks
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`)
	if err != nil {
		return nil, err
	}

	schemas := []string{
		`CREATE TABLE IF NOT EXISTS session (
			id TEXT PRIMARY KEY,
			name TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS module_state (
			tc_id TEXT PRIMARY KEY,
			status TEXT DEFAULT 'not_run',
			exit_code INTEGER DEFAULT 0,
			started_at TEXT,
			ended_at TEXT,
			duration_sec INTEGER DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS network (
			bssid TEXT PRIMARY KEY,
			ssid TEXT,
			channel INTEGER,
			encryption TEXT,
			signal INTEGER,
			beacons INTEGER,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS client (
			mac TEXT PRIMARY KEY,
			vendor TEXT,
			ip TEXT,
			hostname TEXT,
			last_signal INTEGER,
			last_bssid TEXT,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			os_guess TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS client_probe (
			mac TEXT,
			ssid TEXT,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (mac, ssid)
		);`,
		`CREATE TABLE IF NOT EXISTS credential (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tc_id TEXT,
			client_mac TEXT,
			target_host TEXT,
			username TEXT,
			password TEXT,
			hash TEXT,
			proto TEXT,
			captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS vulnerability (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tc_id TEXT,
			client_mac TEXT,
			target_host TEXT,
			name TEXT,
			severity TEXT,
			description TEXT,
			remediation TEXT,
			detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, schema := range schemas {
		_, err = db.Exec(schema)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

type Network struct {
	BSSID      string `json:"bssid"`
	SSID       string `json:"ssid"`
	Channel    int    `json:"channel"`
	Encryption string `json:"encryption"`
	Signal     int    `json:"signal"`
	Beacons    int    `json:"beacons"`
	LastSeen   string `json:"last_seen"`
}

func ListNetworks(d *sql.DB) ([]Network, error) {
	rows, err := d.Query("SELECT bssid, ssid, channel, encryption, signal, beacons, last_seen FROM network")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.BSSID, &n.SSID, &n.Channel, &n.Encryption, &n.Signal, &n.Beacons, &n.LastSeen); err != nil {
			return nil, err
		}
		networks = append(networks, n)
	}
	return networks, nil
}

type Client struct {
	MAC        string   `json:"mac"`
	Vendor     string   `json:"vendor"`
	IP         string   `json:"ip"`
	Hostname   string   `json:"hostname"`
	LastSignal int      `json:"last_signal"`
	LastBSSID  string   `json:"last_bssid"`
	LastSeen   string   `json:"last_seen"`
	OSGuess    string   `json:"os_guess"`
	Probes     []string `json:"probes"`
}

type Credential struct {
	ID         int    `json:"id"`
	TCID       string `json:"tc_id"`
	ClientMAC  string `json:"client_mac"`
	TargetHost string `json:"target_host"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Hash       string `json:"hash"`
	Proto      string `json:"proto"`
	CapturedAt string `json:"captured_at"`
}

type Vulnerability struct {
	ID          int    `json:"id"`
	TCID        string `json:"tc_id"`
	ClientMAC   string `json:"client_mac"`
	TargetHost  string `json:"target_host"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	DetectedAt  string `json:"detected_at"`
}

func ListClients(d *sql.DB) ([]Client, error) {
	rows, err := d.Query("SELECT mac, vendor, ip, hostname, last_signal, last_bssid, last_seen, os_guess FROM client")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var vendor, ip, hostname, osGuess sql.NullString
		if err := rows.Scan(&c.MAC, &vendor, &ip, &hostname, &c.LastSignal, &c.LastBSSID, &c.LastSeen, &osGuess); err != nil {
			return nil, err
		}
		c.Vendor = vendor.String
		c.IP = ip.String
		c.Hostname = hostname.String
		c.OSGuess = osGuess.String

		// Fetch probes
		probeRows, err := d.Query("SELECT ssid FROM client_probe WHERE mac = ?", c.MAC)
		if err == nil {
			for probeRows.Next() {
				var ssid string
				if err := probeRows.Scan(&ssid); err == nil {
					c.Probes = append(c.Probes, ssid)
				}
			}
			probeRows.Close()
		}

		clients = append(clients, c)
	}
	return clients, nil
}

func ListCredentials(d *sql.DB) ([]Credential, error) {
	rows, err := d.Query("SELECT id, tc_id, client_mac, target_host, username, password, hash, proto, captured_at FROM credential")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []Credential
	for rows.Next() {
		var c Credential
		var clientMac, targetHost, username, password, hash, proto sql.NullString
		if err := rows.Scan(&c.ID, &c.TCID, &clientMac, &targetHost, &username, &password, &hash, &proto, &c.CapturedAt); err != nil {
			return nil, err
		}
		c.ClientMAC = clientMac.String
		c.TargetHost = targetHost.String
		c.Username = username.String
		c.Password = password.String
		c.Hash = hash.String
		c.Proto = proto.String
		creds = append(creds, c)
	}
	return creds, nil
}

func ListVulnerabilities(d *sql.DB) ([]Vulnerability, error) {
	rows, err := d.Query("SELECT id, tc_id, client_mac, target_host, name, severity, description, remediation, detected_at FROM vulnerability")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var clientMac, targetHost, name, severity, description, remediation sql.NullString
		if err := rows.Scan(&v.ID, &v.TCID, &clientMac, &targetHost, &name, &severity, &description, &remediation, &v.DetectedAt); err != nil {
			return nil, err
		}
		v.ClientMAC = clientMac.String
		v.TargetHost = targetHost.String
		v.Name = name.String
		v.Severity = severity.String
		v.Description = description.String
		v.Remediation = remediation.String
		vulns = append(vulns, v)
	}
	return vulns, nil
}

type TestResult struct {
	TCID            string   `json:"tc_id"`
	Status          string   `json:"status"`
	ExitCode        int      `json:"exit_code"`
	StartedAt       string   `json:"started_at"`
	EndedAt         string   `json:"ended_at"`
	DurationSec     int      `json:"duration_sec"`
	Summary         string   `json:"summary"`
	Details         string   `json:"details"`
	Recommendations string   `json:"recommendations"`
	EvidenceFiles   []string `json:"evidence_files"`
}

func GetTestResults(d *sql.DB) ([]TestResult, error) {
	rows, err := d.Query(`SELECT tc_id, status, exit_code, started_at, ended_at, duration_sec FROM module_state WHERE status != 'not_run'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TestResult
	for rows.Next() {
		var tr TestResult
		var started, ended sql.NullString
		if err := rows.Scan(&tr.TCID, &tr.Status, &tr.ExitCode, &started, &ended, &tr.DurationSec); err != nil {
			return nil, err
		}
		tr.StartedAt = started.String
		tr.EndedAt = ended.String
		results = append(results, tr)
	}
	return results, nil
}
