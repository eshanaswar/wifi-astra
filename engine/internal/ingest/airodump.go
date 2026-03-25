package ingest

import (
	"database/sql"
	"encoding/csv"
	"io"
	"os"
	"strconv"
	"strings"
)

var ouiDB = map[string]string{
	"00:03:93": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
	"00:16:CB": "Apple", "00:17:C4": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
	"00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
	"00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
	"00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple",
	"00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple",
	"00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple", "3C:22:FB": "Apple",
	"F0:D5:BF": "Apple", "AC:BC:32": "Apple", "78:4F:43": "Apple", "A4:83:E7": "Apple",
	"DC:A9:04": "Apple", "70:56:81": "Apple", "14:7D:DA": "Apple", "D8:CF:9C": "Apple",
	"00:00:F0": "Samsung", "00:02:D1": "Samsung", "00:07:AB": "Samsung", "00:0D:E6": "Samsung",
	"00:12:47": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung", "00:15:99": "Samsung",
	"00:15:B9": "Samsung", "00:16:6B": "Samsung", "00:16:DB": "Samsung", "00:17:C9": "Samsung",
	"00:17:D1": "Samsung", "00:18:AF": "Samsung", "00:19:2D": "Samsung", "00:1A:8A": "Samsung",
	"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:08:A1": "Intel",
	"00:0C:F1": "Intel", "00:0E:35": "Intel", "00:13:02": "Intel", "00:13:E8": "Intel",
	"00:15:00": "Intel", "00:16:6F": "Intel", "00:16:EA": "Intel", "00:18:DE": "Intel",
	"00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:1E:68": "Cisco",
	"00:03:FF": "Microsoft", "00:12:5A": "Microsoft", "00:15:5D": "Microsoft",
	"00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google",
	"00:BB:3A": "Amazon", "18:74:2E": "Amazon", "34:D2:70": "Amazon",
	"00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
	"B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
}

func lookupVendor(mac string) string {
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

	return "Unknown"
}

// IngestAirodumpCSV parses an airodump-ng CSV and updates the database.
func IngestAirodumpCSV(db *sql.DB, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	// Airodump CSV has two sections: BSSIDs and Station MACs
	// We only care about BSSIDs for now
	isBSSIDSection := true

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) == 0 || strings.TrimSpace(record[0]) == "" {
			continue
		}

		if strings.Contains(record[0], "Station MAC") {
			isBSSIDSection = false
			continue
		}

		if strings.Contains(record[0], "BSSID") {
			continue // Skip header (for either section)
		}

		if isBSSIDSection && len(record) >= 14 {
			bssid := strings.TrimSpace(record[0])
			channel, _ := strconv.Atoi(strings.TrimSpace(record[3]))
			encryption := strings.TrimSpace(record[5])
			signal, _ := strconv.Atoi(strings.TrimSpace(record[8]))
			beacons, _ := strconv.Atoi(strings.TrimSpace(record[9]))
			ssid := strings.TrimSpace(record[13])

			_, err = db.Exec(`INSERT OR REPLACE INTO network (bssid, ssid, channel, encryption, signal, beacons)
				VALUES (?, ?, ?, ?, ?, ?);`,
				bssid, ssid, channel, encryption, signal, beacons)
			if err != nil {
				return err
			}
		} else if !isBSSIDSection && len(record) >= 6 {
			mac := strings.TrimSpace(record[0])
			signal, _ := strconv.Atoi(strings.TrimSpace(record[3]))
			lastBSSID := strings.TrimSpace(record[5])
			vendor := lookupVendor(mac)
			
			// Airodump CSV Station structure:
			// Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed SSIDs
			// Probed SSIDs is at index 6 if it exists
			probes := ""
			if len(record) > 6 {
				probes = strings.TrimSpace(record[6])
			}

			_, err = db.Exec(`INSERT OR REPLACE INTO client (mac, vendor, last_signal, last_bssid, last_seen)
				VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);`,
				mac, vendor, signal, lastBSSID)
			if err != nil {
				return err
			}

			// Ingest probes
			if probes != "" {
				ssidList := strings.Split(probes, ",")
				for _, ssid := range ssidList {
					ssid = strings.TrimSpace(ssid)
					if ssid == "" {
						continue
					}
					_, err = db.Exec(`INSERT OR IGNORE INTO client_probe (mac, ssid) VALUES (?, ?);`, mac, ssid)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
