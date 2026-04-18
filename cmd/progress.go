package cmd

import (
	"os"
	"wifi-astra/internal/session"

	"github.com/spf13/cobra"
)

var progressCmd = &cobra.Command{
	Use:    "record-progress",
	Short:  "Internal use only: Record progress of a module",
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

		tcID, _ := cmd.Flags().GetString("tc")
		percent, _ := cmd.Flags().GetInt("percent")
		status, _ := cmd.Flags().GetString("status")

		s.DB.Exec(`INSERT OR REPLACE INTO module_progress (tc_id, percent, status_text, updated_at) 
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)`, tcID, percent, status)
	},
}

func init() {
	progressCmd.Flags().String("session-dir", "", "Absolute path to the active session directory (set by the controller via $SESSION_DIR)")
	progressCmd.Flags().String("tc", "", "Test case ID of the reporting module (e.g. D1)")
	progressCmd.Flags().Int("percent", 0, "Completion percentage (0–100)")
	progressCmd.Flags().String("status", "", "Human-readable status message displayed in the TUI progress bar")
	RootCmd.AddCommand(progressCmd)
}
