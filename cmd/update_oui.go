package cmd

import (
	"os"
	"wifi-astra/internal/ingest"
	"wifi-astra/internal/logging"

	"github.com/spf13/cobra"
)

var updateOuiCmd = &cobra.Command{
	Use:   "update-oui",
	Short: "Download the latest OUI database from IEEE",
	Run: func(cmd *cobra.Command, args []string) {
		// Determine data directory (default to internal/ingest/data in the source or current working directory)
		dataDir := "./internal/ingest/data"
		
		if err := ingest.UpdateOUIDatabase(dataDir); err != nil {
			logging.Error("Update failed: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(updateOuiCmd)
}
