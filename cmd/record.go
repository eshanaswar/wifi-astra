package cmd

import (
	"os"
	"wifi-astra/internal/session"

	"github.com/spf13/cobra"
)

var recordCmd = &cobra.Command{
	Use:    "record-finding",
	Short:  "Internal use only: Record a finding from a module",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		sessionDir, _ := cmd.Flags().GetString("session-dir")
		if sessionDir == "" {
			os.Exit(1)
		}

		s, err := session.LoadSession(sessionDir)
		if err != nil {
			os.Exit(1)
		}
		defer s.Cleanup()

		fType, _ := cmd.Flags().GetString("type")
		tcID, _ := cmd.Flags().GetString("tc")

		if fType == "vulnerability" {
			name, _ := cmd.Flags().GetString("name")
			sev, _ := cmd.Flags().GetString("severity")
			desc, _ := cmd.Flags().GetString("desc")
			rem, _ := cmd.Flags().GetString("rem")
			target, _ := cmd.Flags().GetString("target")
			evidence, _ := cmd.Flags().GetString("evidence")
			clientMac, _ := cmd.Flags().GetString("client-mac")
			rationale, _ := cmd.Flags().GetString("rationale")

			s.DB.Exec(`INSERT INTO vulnerability (tc_id, target_host, name, severity, description, remediation, evidence_file, client_mac, rationale) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, tcID, target, name, sev, desc, rem, evidence, clientMac, rationale)
		} else if fType == "credential" {
			user, _ := cmd.Flags().GetString("user")
			pass, _ := cmd.Flags().GetString("pass")
			proto, _ := cmd.Flags().GetString("proto")
			target, _ := cmd.Flags().GetString("target")
			evidence, _ := cmd.Flags().GetString("evidence")
			clientMac, _ := cmd.Flags().GetString("client-mac")
			rationale, _ := cmd.Flags().GetString("rationale")

			s.DB.Exec(`INSERT INTO credential (tc_id, username, password, proto, target_host, evidence_file, client_mac, rationale) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, tcID, user, pass, proto, target, evidence, clientMac, rationale)
		}
	},
}

func init() {
	recordCmd.Flags().String("session-dir", "", "Session directory")
	recordCmd.Flags().String("type", "vulnerability", "Finding type")
	recordCmd.Flags().String("tc", "", "Test Case ID")
	recordCmd.Flags().String("name", "", "Vulnerability name")
	recordCmd.Flags().String("severity", "INFO", "Severity")
	recordCmd.Flags().String("desc", "", "Description")
	recordCmd.Flags().String("rem", "", "Remediation")
	recordCmd.Flags().String("target", "", "Target host/IP/BSSID")
	recordCmd.Flags().String("user", "", "Username")
	recordCmd.Flags().String("pass", "", "Password")
	recordCmd.Flags().String("proto", "", "Protocol")
	recordCmd.Flags().String("evidence", "", "Path to evidence file")
	recordCmd.Flags().String("client-mac", "", "MAC address of associated client")
	recordCmd.Flags().String("rationale", "", "Why this finding matters")
	RootCmd.AddCommand(recordCmd)
}
