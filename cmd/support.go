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

		// We need an AssessmentController instance
		// In a real environment, we'd use a singleton or a running instance via a socket
		// But for now, we can instantiate a temporary one to spawn the process
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
	launchSupportCmd.Flags().String("session-dir", "", "Session directory")
	launchSupportCmd.Flags().String("tc", "", "Support module TC ID")
	RootCmd.AddCommand(launchSupportCmd)
}
