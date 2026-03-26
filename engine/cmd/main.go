package main

import (
	"encoding/json"
	"fmt"
	"os"
	"wifi-astra/engine/internal/api"
	"wifi-astra/engine/internal/db"
	"wifi-astra/engine/internal/ingest"
	"wifi-astra/engine/internal/state"

	"github.com/spf13/cobra"
)

var dbPath string
var socketPath string

func main() {
	var rootCmd = &cobra.Command{Use: "astra-engine"}
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "sessions/session.db", "Path to SQLite database")

	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the engine API server",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			server := api.NewServer(database, socketPath)
			fmt.Printf("Starting engine server on %s\n", socketPath)
			if err := server.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	serveCmd.Flags().StringVar(&socketPath, "socket", "/tmp/astra-engine.sock", "Path to UNIX domain socket")
	rootCmd.AddCommand(serveCmd)

	// --- State Commands ---
	var stateCmd = &cobra.Command{Use: "state"}
	
	var updateStatusCmd = &cobra.Command{
		Use:   "update-status",
		Short: "Update module status",
		Run: func(cmd *cobra.Command, args []string) {
			tcID, _ := cmd.Flags().GetString("tc")
			status, _ := cmd.Flags().GetString("status")
			exitCode, _ := cmd.Flags().GetInt("exit-code")

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			if err := s.UpdateModuleStatus(tcID, status, exitCode); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	updateStatusCmd.Flags().String("tc", "", "Test case ID (e.g. A1)")
	updateStatusCmd.Flags().String("status", "", "Status (e.g. done)")
	updateStatusCmd.Flags().Int("exit-code", 0, "Exit code")
	stateCmd.AddCommand(updateStatusCmd)

	var getStatusCmd = &cobra.Command{
		Use:   "get-status",
		Short: "Get module status",
		Run: func(cmd *cobra.Command, args []string) {
			tcID, _ := cmd.Flags().GetString("tc")
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			status, err := s.GetModuleStatus(tcID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(status)
		},
	}
	getStatusCmd.Flags().String("tc", "", "Test case ID")
	stateCmd.AddCommand(getStatusCmd)

	var getDashboardCmd = &cobra.Command{
		Use:   "get-dashboard",
		Short: "Get module status summary",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			summary, err := s.GetStatusSummary()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(summary)
		},
	}
	stateCmd.AddCommand(getDashboardCmd)

	// Batch status update
	var batchUpdateStatusCmd = &cobra.Command{
		Use:   "batch-update-status",
		Short: "Update multiple module statuses from JSON map",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var statuses map[string]string
			if err := json.Unmarshal([]byte(jsonInput), &statuses); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			for tcID, status := range statuses {
				if err := s.UpdateModuleStatus(tcID, status, 0); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating %s: %v\n", tcID, err)
				}
			}
		},
	}
	batchUpdateStatusCmd.Flags().String("json", "{}", "JSON map of TC IDs to statuses")
	stateCmd.AddCommand(batchUpdateStatusCmd)

	var setConfigCmd = &cobra.Command{
		Use:   "set-config",
		Short: "Set configuration value",
		Run: func(cmd *cobra.Command, args []string) {
			key, _ := cmd.Flags().GetString("key")
			value, _ := cmd.Flags().GetString("value")

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			if err := s.SetConfig(key, value); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	setConfigCmd.Flags().String("key", "", "Config key")
	setConfigCmd.Flags().String("value", "", "Config value")
	stateCmd.AddCommand(setConfigCmd)

	// Batch config update
	var batchSetConfigCmd = &cobra.Command{
		Use:   "batch-set-config",
		Short: "Set multiple config values from JSON map",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var configs map[string]string
			if err := json.Unmarshal([]byte(jsonInput), &configs); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			for key, value := range configs {
				if err := s.SetConfig(key, value); err != nil {
					fmt.Fprintf(os.Stderr, "Error setting %s: %v\n", key, err)
				}
			}
		},
	}
	batchSetConfigCmd.Flags().String("json", "{}", "JSON map of keys to values")
	stateCmd.AddCommand(batchSetConfigCmd)

	var getConfigCmd = &cobra.Command{
		Use:   "get-config",
		Short: "Get configuration value",
		Run: func(cmd *cobra.Command, args []string) {
			key, _ := cmd.Flags().GetString("key")
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			s := state.NewStateManager(database)
			val, err := s.GetConfig(key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(val)
		},
	}
	getConfigCmd.Flags().String("key", "", "Config key")
	stateCmd.AddCommand(getConfigCmd)

	// --- Ingest Commands ---
	var ingestCmd = &cobra.Command{Use: "ingest"}

	var ingestAirodumpCmd = &cobra.Command{
		Use:   "airodump",
		Short: "Ingest airodump CSV",
		Run: func(cmd *cobra.Command, args []string) {
			file, _ := cmd.Flags().GetString("file")

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			if err := ingest.IngestAirodumpCSV(database, file); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	ingestAirodumpCmd.Flags().String("file", "", "Path to CSV file")
	ingestCmd.AddCommand(ingestAirodumpCmd)

	var listNetworksCmd = &cobra.Command{
		Use:   "list",
		Short: "List all ingested networks as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			networks, err := db.ListNetworks(database)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(networks)
		},
	}
	ingestCmd.AddCommand(listNetworksCmd)

	var listClientsCmd = &cobra.Command{
		Use:   "list-clients",
		Short: "List all ingested clients as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			clients, err := db.ListClients(database)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(clients)
		},
	}
	ingestCmd.AddCommand(listClientsCmd)

	var ingestClientCmd = &cobra.Command{
		Use:   "client",
		Short: "Ingest a single client as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var c db.Client
			if err := json.Unmarshal([]byte(jsonInput), &c); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			
			// Ingest client
			_, err = database.Exec(`INSERT OR REPLACE INTO client (mac, vendor, ip, hostname, last_signal, last_bssid, os_guess, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
				c.MAC, c.Vendor, c.IP, c.Hostname, c.LastSignal, c.LastBSSID, c.OSGuess)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Ingest probes
			for _, ssid := range c.Probes {
				if ssid == "" {
					continue
				}
				_, err = database.Exec(`INSERT OR IGNORE INTO client_probe (mac, ssid) VALUES (?, ?);`, c.MAC, ssid)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error inserting probe %s: %v\n", ssid, err)
				}
			}
		},
	}
	ingestClientCmd.Flags().String("json", "{}", "Client JSON object")
	ingestCmd.AddCommand(ingestClientCmd)

	var batchIngestClientsCmd = &cobra.Command{
		Use:   "batch-clients",
		Short: "Ingest multiple clients as JSON array",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var clients []db.Client
			if err := json.Unmarshal([]byte(jsonInput), &clients); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			
			tx, err := database.Begin()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error starting transaction: %v\n", err)
				os.Exit(1)
			}

			for _, c := range clients {
				_, err = tx.Exec(`INSERT OR REPLACE INTO client (mac, vendor, ip, hostname, last_signal, last_bssid, os_guess, last_seen)
					VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
					c.MAC, c.Vendor, c.IP, c.Hostname, c.LastSignal, c.LastBSSID, c.OSGuess)
				if err != nil {
					tx.Rollback()
					fmt.Fprintf(os.Stderr, "Error inserting client %s: %v\n", c.MAC, err)
					os.Exit(1)
				}

				for _, ssid := range c.Probes {
					if ssid == "" {
						continue
					}
					_, err = tx.Exec(`INSERT OR IGNORE INTO client_probe (mac, ssid) VALUES (?, ?);`, c.MAC, ssid)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error inserting probe %s for client %s: %v\n", ssid, c.MAC, err)
					}
				}
			}
			tx.Commit()
		},
	}
	batchIngestClientsCmd.Flags().String("json", "[]", "JSON array of client objects")
	ingestCmd.AddCommand(batchIngestClientsCmd)

	var listHiddenNetworksCmd = &cobra.Command{
		Use:   "list-hidden",
		Short: "List all ingested hidden networks as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			networks, err := db.ListNetworks(database)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			var hidden []db.Network
			for _, n := range networks {
				if n.SSID == "" || n.SSID == "<HIDDEN>" {
					hidden = append(hidden, n)
				}
			}
			json.NewEncoder(os.Stdout).Encode(hidden)
		},
	}
	ingestCmd.AddCommand(listHiddenNetworksCmd)

	var ingestNetworkCmd = &cobra.Command{
		Use:   "network",
		Short: "Ingest a single network as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var n db.Network
			if err := json.Unmarshal([]byte(jsonInput), &n); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			
			_, err = database.Exec(`INSERT OR REPLACE INTO network (bssid, ssid, channel, encryption, signal, beacons, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
				n.BSSID, n.SSID, n.Channel, n.Encryption, n.Signal, n.Beacons)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	ingestNetworkCmd.Flags().String("json", "{}", "Network JSON object")
	ingestCmd.AddCommand(ingestNetworkCmd)

	var ingestCredentialCmd = &cobra.Command{
		Use:   "credential",
		Short: "Ingest a single credential as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var c db.Credential
			if err := json.Unmarshal([]byte(jsonInput), &c); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			
			_, err = database.Exec(`INSERT INTO credential (tc_id, client_mac, target_host, username, password, hash, proto)
				VALUES (?, ?, ?, ?, ?, ?, ?);`,
				c.TCID, c.ClientMAC, c.TargetHost, c.Username, c.Password, c.Hash, c.Proto)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	ingestCredentialCmd.Flags().String("json", "{}", "Credential JSON object")
	ingestCmd.AddCommand(ingestCredentialCmd)

	var ingestVulnerabilityCmd = &cobra.Command{
		Use:   "vulnerability",
		Short: "Ingest a single vulnerability as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			jsonInput, _ := cmd.Flags().GetString("json")
			var v db.Vulnerability
			if err := json.Unmarshal([]byte(jsonInput), &v); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			
			_, err = database.Exec(`INSERT INTO vulnerability (tc_id, client_mac, target_host, name, severity, description, remediation)
				VALUES (?, ?, ?, ?, ?, ?, ?);`,
				v.TCID, v.ClientMAC, v.TargetHost, v.Name, v.Severity, v.Description, v.Remediation)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	ingestVulnerabilityCmd.Flags().String("json", "{}", "Vulnerability JSON object")
	ingestCmd.AddCommand(ingestVulnerabilityCmd)

	var listCredentialsCmd = &cobra.Command{
		Use:   "list-credentials",
		Short: "List all ingested credentials as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			creds, err := db.ListCredentials(database)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(creds)
		},
	}
	ingestCmd.AddCommand(listCredentialsCmd)

	var listVulnerabilitiesCmd = &cobra.Command{
		Use:   "list-vulnerabilities",
		Short: "List all ingested vulnerabilities as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			database, err := db.InitDB(dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			vulns, err := db.ListVulnerabilities(database)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			json.NewEncoder(os.Stdout).Encode(vulns)
		},
	}
	ingestCmd.AddCommand(listVulnerabilitiesCmd)

	rootCmd.AddCommand(stateCmd, ingestCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
