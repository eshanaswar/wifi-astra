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

	// Create tables
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
