package ingest

import (
	"bufio"
	"database/sql"
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"wifi-astra/internal/db"
	"wifi-astra/internal/logging"
)

func init() {
	// Register for Category A (Discovery)
	parser := func(db *sql.DB, tcID string, evidenceDir string) error {
		// Airodump modules usually produce <id>_results.csv
		csvFile := filepath.Join(evidenceDir, strings.ToLower(tcID)+"_results.csv")
		if _, err := os.Stat(csvFile); os.IsNotExist(err) {
			// Fallback for A1 legacy or renamed output
			if tcID == "A1" {
				csvFile = filepath.Join(evidenceDir, "a1_results.csv")
			}
		}
		
		if _, err := os.Stat(csvFile); err == nil {
			return IngestAirodumpCSV(db, tcID, csvFile)
		}
		return nil
	}

	RegisterParser("A", parser)
	RegisterParser("A1", parser) // Backward compat
}

//go:embed data/oui.json
var dataFS embed.FS

var (
	ouiDB map[string]string
	ouiOnce sync.Once
)

func loadOUIDB() {
	ouiOnce.Do(func() {
		data, err := dataFS.ReadFile("data/oui.json")
		if err != nil {
			logging.Error("Failed to read embedded OUI data: %v", err)
			return
		}
		if err := json.Unmarshal(data, &ouiDB); err != nil {
			logging.Error("Failed to parse OUI data: %v", err)
		}
	})
}

func lookupVendor(mac string) string {
	loadOUIDB()
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) < 8 {
		return "Unknown"
	}
	prefix := mac[:8]
	if vendor, ok := ouiDB[prefix]; ok {
		return vendor
	}

	// Check for randomized MAC
	if firstByte, err := strconv.ParseInt(mac[:2], 16, 64); err == nil {
		if firstByte&0x02 != 0 {
			return "Randomized/Private MAC"
		}
	}

	return "Unknown (" + prefix + ")"
}

// IngestAirodumpCSV parses an airodump-ng CSV and updates the database.
func IngestAirodumpCSV(database *sql.DB, tcID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Use scanner for robust line-by-line reading (airodump CSV is not standard)
	scanner := bufio.NewScanner(f)
	isBSSIDSection := false
	isStationSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "BSSID, First time seen") {
			isBSSIDSection = true
			isStationSection = false
			continue
		}

		if strings.HasPrefix(line, "Station MAC, First time seen") {
			isBSSIDSection = false
			isStationSection = true
			continue
		}

		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		if isBSSIDSection && len(parts) >= 14 {
			bssid := parts[0]
			if bssid == "BSSID" || len(bssid) != 17 {
				continue
			}

			channel, _ := strconv.Atoi(parts[3])
			encryption := parts[5]
			if parts[6] != "" && parts[6] != " " {
				encryption += "/" + parts[6]
			}
			if parts[7] != "" && parts[7] != " " {
				encryption += "/" + parts[7]
			}
			
			signal, _ := strconv.Atoi(parts[8])
			beacons, _ := strconv.Atoi(parts[9])
			ssid := parts[13]
			isHidden := false
			if ssid == "" || strings.HasPrefix(ssid, "<length:") {
				ssid = "<HIDDEN>"
				isHidden = true
			}

			_, err = database.Exec(`INSERT OR REPLACE INTO network (bssid, ssid, channel, encryption, signal, beacons, tc_id, evidence_file)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?);`,
				bssid, ssid, channel, encryption, signal, beacons, tcID, filePath)
			if err != nil {
				logging.Error("DB Error (Network): %v", err)
			}

			// If we just discovered a name for a previously hidden SSID, update old records
			if !isHidden && ssid != "<HIDDEN>" {
				database.Exec("UPDATE network SET ssid = ? WHERE bssid = ? AND ssid = '<HIDDEN>'", ssid, bssid)
			}
		} else if isStationSection && len(parts) >= 6 {
			mac := parts[0]
			if mac == "Station MAC" || len(mac) != 17 {
				continue
			}
			signal, _ := strconv.Atoi(parts[3])
			lastBSSID := parts[5]
			vendor := lookupVendor(mac)
			
			_, err = database.Exec(`INSERT OR REPLACE INTO client (mac, vendor, last_signal, last_bssid, last_seen)
				VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);`,
				mac, vendor, signal, lastBSSID)
			if err != nil {
				logging.Error("DB Error (Client): %v", err)
			}

			// Probed SSIDs start at index 6 and continue through all subsequent fields
			if len(parts) > 6 {
				for i := 6; i < len(parts); i++ {
					ssid := strings.TrimSpace(parts[i])
					if ssid == "" {
						continue
					}
					database.Exec(`INSERT OR IGNORE INTO client_probe (mac, ssid, tc_id) VALUES (?, ?, ?);`, mac, ssid, tcID)
				}
			}
		}
	}

	return nil
}

func ParseScanResults(filePath string) ([]db.Network, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var networks []db.Network
	scanner := bufio.NewScanner(f)
	isBSSIDSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "BSSID, First time seen") {
			isBSSIDSection = true
			continue
		}
		if strings.HasPrefix(line, "Station MAC, First time seen") {
			break
		}

		if isBSSIDSection {
			parts := strings.Split(line, ",")
			if len(parts) < 14 {
				continue
			}
			bssid := strings.TrimSpace(parts[0])
			if bssid == "BSSID" || len(bssid) != 17 {
				continue
			}

			ssid := strings.TrimSpace(parts[13])
			if ssid == "" {
				ssid = "<HIDDEN>"
			}
			channel, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
			signal, _ := strconv.Atoi(strings.TrimSpace(parts[8]))
			beacons, _ := strconv.Atoi(strings.TrimSpace(parts[9]))
			encryption := strings.TrimSpace(parts[5])

			networks = append(networks, db.Network{
				BSSID:      bssid,
				SSID:       ssid,
				Channel:    channel,
				Encryption: encryption,
				Signal:     signal,
				Beacons:    beacons,
			})
		}
	}
	return networks, nil
}
