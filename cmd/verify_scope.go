package cmd

import (
	"fmt"
	"os"

	"wifi-astra/internal/scopetoken"
	"wifi-astra/internal/session"

	"github.com/spf13/cobra"
)

var verifyScopeCmd = &cobra.Command{
	Use:    "verify-scope",
	Short:  "Internal use only: Verify a scope launch token",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		sessionDir, _ := cmd.Flags().GetString("session-dir")
		tcID, _ := cmd.Flags().GetString("tc")
		bssid, _ := cmd.Flags().GetString("bssid")
		token, _ := cmd.Flags().GetString("token")

		if sessionDir == "" || tcID == "" || bssid == "" || token == "" {
			fmt.Fprintln(os.Stderr, "[!] verify-scope: --session-dir, --tc, --bssid, and --token are all required")
			os.Exit(1)
		}

		s, err := session.LoadSession(sessionDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] verify-scope: cannot load session: %v\n", err)
			os.Exit(1)
		}
		defer s.Cleanup()

		if err := scopetoken.Verify(s.ScopeSecret, token, tcID, bssid); err != nil {
			fmt.Fprintf(os.Stderr, "[!] SCOPE GUARDRAIL: %v\n", err)
			fmt.Fprintln(os.Stderr, "    This module must be launched through the wifi-astra controller.")
			os.Exit(1)
		}
		// Silent success — exit 0
	},
}

func init() {
	verifyScopeCmd.Flags().String("session-dir", "", "Session directory")
	verifyScopeCmd.Flags().String("tc", "", "Module TC ID (e.g. D1)")
	verifyScopeCmd.Flags().String("bssid", "", "Target BSSID")
	verifyScopeCmd.Flags().String("token", "", "HMAC scope token")
	RootCmd.AddCommand(verifyScopeCmd)
}
