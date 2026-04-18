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
	Long: `Fetch the current IEEE MA-L OUI registry and cache it locally for vendor lookups.

The database is used by WiFi-Astra to map BSSID prefixes to hardware manufacturers
during discovery and client fingerprinting. WiFi-Astra refreshes it automatically in
the background when it is missing or older than 30 days; this command forces an
immediate update.

The file is saved to ./internal/ingest/data/oui.json.`,
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
