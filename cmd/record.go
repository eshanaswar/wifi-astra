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
	recordCmd.Flags().String("session-dir", "", "Absolute path to the active session directory (set by the controller via $SESSION_DIR)")
	recordCmd.Flags().String("type", "vulnerability", "Finding type: 'vulnerability' or 'credential'")
	recordCmd.Flags().String("tc", "", "Test case ID matching the module (e.g. D1, F2)")
	recordCmd.Flags().String("name", "", "Short title for the finding (e.g. 'WPA2 Handshake Captured')")
	recordCmd.Flags().String("severity", "INFO", "Risk severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO")
	recordCmd.Flags().String("desc", "", "Full description of what was found and why it is a risk")
	recordCmd.Flags().String("rem", "", "Recommended remediation steps for the finding")
	recordCmd.Flags().String("target", "", "Affected target: hostname, IP address, or BSSID")
	recordCmd.Flags().String("user", "", "Captured username (credential findings only)")
	recordCmd.Flags().String("pass", "", "Captured plaintext password (credential findings only)")
	recordCmd.Flags().String("proto", "", "Network protocol the credential was captured over (e.g. WPA2, EAP, HTTP, NTLM)")
	recordCmd.Flags().String("evidence", "", "Absolute path to the supporting evidence file in $SESSION_EVIDENCE_DIR")
	recordCmd.Flags().String("client-mac", "", "MAC address of the associated wireless client, if applicable")
	recordCmd.Flags().String("rationale", "", "Explanation of how this finding affects the target environment")
	RootCmd.AddCommand(recordCmd)
}
