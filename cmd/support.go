package cmd

import (
	"fmt"
	"os"
	"wifi-astra/internal/controller"
	"wifi-astra/internal/session"
	"wifi-astra/pkg/executor"

	"github.com/spf13/cobra"
)

var launchSupportCmd = &cobra.Command{
	Use:    "launch-support",
	Short:  "Internal use only: Launch a background support module",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		sessionDir, _ := cmd.Flags().GetString("session-dir")
		tcID, _ := cmd.Flags().GetString("tc")

		s, err := session.LoadSession(sessionDir)
		if err != nil {
			fmt.Printf("Error loading session: %v\n", err)
			os.Exit(1)
		}

		mgr := executor.NewManager()
		c := controller.NewAssessmentController(s, mgr, "./modules")
		
		err = c.LaunchSupportModule(tcID)
		if err != nil {
			fmt.Printf("Error launching support module: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	launchSupportCmd.Flags().String("session-dir", "", "Absolute path to the active session directory (set by the controller via $SESSION_DIR)")
	launchSupportCmd.Flags().String("tc", "", "Test case ID of the support module to launch (e.g. B10)")
	RootCmd.AddCommand(launchSupportCmd)
}
