package ingest

import (
	"os"
	"testing"
	"wifi-astra/internal/db"
)

func TestIngestAirodumpCSV(t *testing.T) {
	// Create a temporary DB
	dbPath := "test_airodump.db"
	defer os.Remove(dbPath)
	
	database, err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	// Create a mock CSV
	csvContent := `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:11:22:33:44:55, 2026-03-27 10:00:00, 2026-03-27 10:05:00, 6, 54, WPA2, CCMP, PSK, -50, 100, 0, 0.0.0.0, 9, TestWiFi, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed SSIDs
AA:BB:CC:DD:EE:FF, 2026-03-27 10:01:00, 2026-03-27 10:02:00, -60, 10, 00:11:22:33:44:55, TestWiFi,HomeNetwork
`
	csvPath := "test_airodump.csv"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("failed to write mock csv: %v", err)
	}
	defer os.Remove(csvPath)

	// Run Ingest
	if err := IngestAirodumpCSV(database, "A1", csvPath); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	// Verify Network
	networks, err := db.ListNetworks(database)
	if err != nil {
		t.Fatalf("failed to list networks: %v", err)
	}
	if len(networks) != 1 {
		t.Errorf("expected 1 network, got %d", len(networks))
	} else if networks[0].SSID != "TestWiFi" {
		t.Errorf("expected SSID 'TestWiFi', got '%s'", networks[0].SSID)
	}

	// Verify Client
	clients, err := db.ListClients(database)
	if err != nil {
		t.Fatalf("failed to list clients: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	} else {
		if clients[0].MAC != "AA:BB:CC:DD:EE:FF" {
			t.Errorf("expected MAC 'AA:BB:CC:DD:EE:FF', got '%s'", clients[0].MAC)
		}
		if len(clients[0].Probes) != 2 {
			t.Errorf("expected 2 probes, got %d", len(clients[0].Probes))
		}
	}
}

func TestParseScanResults(t *testing.T) {
	csvContent := `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
00:11:22:33:44:55, 2026-03-27 10:00:00, 2026-03-27 10:05:00, 11, 54, WPA2, CCMP, PSK, -45, 50, 0, 0.0.0.0, 8, TargetAP, 
`
	csvPath := "test_parse.csv"
	os.WriteFile(csvPath, []byte(csvContent), 0644)
	defer os.Remove(csvPath)

	networks, err := ParseScanResults(csvPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(networks) != 1 {
		t.Errorf("expected 1 network, got %d", len(networks))
	} else {
		if networks[0].SSID != "TargetAP" {
			t.Errorf("expected SSID 'TargetAP', got '%s'", networks[0].SSID)
		}
		if networks[0].Channel != 11 {
			t.Errorf("expected Channel 11, got %d", networks[0].Channel)
		}
	}
}
